const express = require('express');
const WebSocket = require('ws');
const { keccak256 } = require('ethers');
const { createCustomCommon, Hardfork, Mainnet } = require('@ethereumjs/common');
const { createTxFromRLP } = require('@ethereumjs/tx');
const { encode: encodeRlp } = require('@ethereumjs/rlp');
const { hexToBytes, bytesToHex } = require('@ethereumjs/util');
const { evmTxDigest, evmTxHash, signatureFromHex, recoverTransactionSender, isValidAddress, toChecksumAddress, sha256hex } = require('../crypto-utils/crypto');
const { logsToBloom, receiptsRoot } = require('./evm-bloom');
const { log } = require('../../config/config');
const { GAS_PARAMS, estimateIntrinsicGas, minimumFee } = require('../consensus/gas');
const { DEFAULT_CHAIN_ID } = require('../consensus/protocol');

const ZERO_ADDRESS = '0x' + '0'.repeat(40);
const ZERO_HASH = '0'.repeat(64);

function toQuantity(n) {
  const b = (typeof n === 'bigint') ? n : (() => { try { return BigInt(n == null || n === '' ? 0 : n); } catch { return 0n; } })();
  if (b === 0n) return '0x0';
  return '0x' + b.toString(16);
}

function toQuantityNumber(n) {
  return toQuantity((typeof n === 'bigint') ? n : BigInt(n || 0));
}

function parseQuantity(v, label) {
  if (v === undefined || v === null) return 0n;
  let s = String(v);
  if (!/^0x[0-9a-fA-F]+$/.test(s)) throw rpcError(-32602, `invalid ${label || 'quantity'}`);
  return BigInt(s);
}

function normalizeHex(v) {
  let s = String(v);
  if (!s.startsWith('0x')) s = '0x' + s;
  return s.toLowerCase();
}

function rpcError(code, message) {
  const e = new Error(message);
  e.rpcCode = code;
  return e;
}

function hexData(bytesOrHex) {
  if (bytesOrHex == null) return '0x';
  if (Buffer.isBuffer(bytesOrHex)) return '0x' + bytesOrHex.toString('hex');
  if (bytesOrHex instanceof Uint8Array) return bytesToHex(bytesOrHex);
  let h = String(bytesOrHex).replace(/^0x/i, '');
  if (h.length % 2) h = '0' + h;
  return '0x' + h;
}

function normalizeAddr(addr) {
  if (!addr) return '';
  let a = String(addr).toLowerCase();
  if (!a.startsWith('0x')) a = '0x' + a;
  return a;
}

function resolveBlockTag(chain, tag) {
  if (tag === undefined || tag === null || tag === 'latest' || tag === 'pending' || tag === '') {
    return chain.height;
  }
  if (tag === 'earliest') return 0;
  if (typeof tag === 'string' && /^0x[0-9a-fA-F]+$/.test(tag)) {
    const h = Number(BigInt(tag));
    return h;
  }
  if (typeof tag === 'number') return Math.floor(tag);
  return null;
}

function getBlockFromDatabase(db, heightOrHash) {
  if (typeof heightOrHash === 'number' || /^[0-9]+$/.test(String(heightOrHash).replace(/^0x/i, '')) && !/^[0-9a-fA-F]{64}$/.test(String(heightOrHash).replace(/^0x/i, ''))) {
    const h = Number(BigInt(String(heightOrHash).replace(/^0x/i, '') || 0));
    return db.prepare('SELECT * FROM blocks WHERE height = ?').get(h) || null;
  }
  const hash = String(heightOrHash).replace(/^0x/i, '').toLowerCase();
  return db.prepare('SELECT * FROM blocks WHERE lower(hash) = ?').get(hash) || null;
}

function recoverableSignatureFromParsed(parsed) {
  const vn = BigInt(parsed.v || 0n);
  let recovery = 0;
  if (vn === 27n || vn === 28n) recovery = Number(vn - 27n);
  else if (vn >= 35n) recovery = Number((vn - 35n) % 2n);
  const to32 = (b) => Buffer.from(b.toString(16).padStart(64, '0'), 'hex');
  return Buffer.concat([Buffer.from([recovery]), to32(parsed.r), to32(parsed.s)]);
}

class EthereumRPC {
  constructor(cfg, db, chain, sync, peers, smartContracts, nodeId) {
    this.cfg = cfg;
    this.db = db;
    this.chain = chain;
    this.sync = sync;
    this.peers = peers;
    this.smartContracts = smartContracts;
    this.nodeId = nodeId;
    this._filters = new Map();
    this._nextFilterId = 1;
    this._writeHits = new Map();
    this._subs = new Map();
    this._nextSubId = 1;
    this._wss = null;
    this._notifyTimer = null;
    this._notifyHeights = new Map();
    this._networkChainId = this._resolveChainId(cfg.chainId);
    try {
      this.common = createCustomCommon({ chainId: this._networkChainId, networkId: this._networkChainId, name: 'ChocoNode' }, Mainnet, { hardfork: Hardfork.Shanghai });
    } catch {
      this.common = new (require('@ethereumjs/common').Common)({ chain: Mainnet, hardfork: Hardfork.Shanghai });
    }
  }

  _resolveChainId(cfgChainId) {
    let n = Number(cfgChainId);
    if (!Number.isInteger(n) || n <= 0) n = DEFAULT_CHAIN_ID;
    return n;
  }

  _chainId() {
    return this._networkChainId;
  }

  _balanceOf(address) {
    const addr = normalizeAddr(address);
    if (!isValidAddress(addr)) return 0n;
    const u = this.db.prepare('SELECT balance FROM users WHERE lower(address) = lower(?)').get(addr);
    if (u) return (() => { try { return BigInt(u.balance || 0); } catch { return 0n; } })();
    const c = this.db.prepare('SELECT balance FROM smart_contract_accounts WHERE lower(address) = lower(?)').get(addr);
    if (c) return (() => { try { return BigInt(c.balance || 0); } catch { return 0n; } })();
    return 0n;
  }

  _nonceOf(address) {
    const addr = normalizeAddr(address);
    if (!isValidAddress(addr)) return 0;
    const u = this.db.prepare('SELECT nonce FROM users WHERE lower(address) = lower(?)').get(addr);
    return u ? (u.nonce || 0) : 0;
  }

  _pendingNonceOf(address) {
    const addr = normalizeAddr(address);
    let base = this._nonceOf(addr);
    try {
      const rows = this.db.prepare('SELECT raw FROM mempool').all();
      for (const r of rows) {
        let tx;
        try { tx = JSON.parse(r.raw); } catch { continue; }
        if (tx && String(tx.from_addr || '').toLowerCase() === addr) {
          const n = Number(tx.nonce || 0) || 0;
          if (n + 1 > base) base = n + 1;
        }
      }
    } catch {}
    return base;
  }

  _codeOf(address) {
    const addr = normalizeAddr(address);
    if (!isValidAddress(addr)) return '0x';
    const c = this.db.prepare('SELECT code FROM smart_contracts WHERE lower(address) = lower(?)').get(addr);
    if (!c || !c.code) return '0x';
    return normalizeHex(c.code);
  }

  _storageAt(address, position) {
    const addr = normalizeAddr(address);
    const slot = normalizeHex(position).replace(/^0x/, '');
    const row = this.db.prepare('SELECT value FROM smart_contract_storage WHERE lower(contract_address) = lower(?) AND slot = ?').get(addr, slot);
    if (!row) return '0x0000000000000000000000000000000000000000000000000000000000000000';
    return normalizeHex(String(row.value)).replace(/^0x/, '').padStart(64, '0');
  }

  async _handleCall(txObj) {
    const to = normalizeAddr(txObj.to);
    const from = normalizeAddr(txObj.from || ZERO_ADDRESS);
    const data = normalizeHex(txObj.data || '0x');
    const value = txObj.value != null ? parseQuantity(txObj.value, 'value') : 0n;
    if (!this.smartContracts) return '0x';
    if (!to) return '0x';
    if (!isValidAddress(to)) return '0x';
    const c = this.db.prepare('SELECT code FROM smart_contracts WHERE lower(address) = lower(?)').get(to);
    if (!c || !c.code) return '0x';
    try {
      const result = await this.smartContracts.runSmartContract(to, isValidAddress(from) ? from : ZERO_ADDRESS, data, Number(value));
      return normalizeHex(result.returnValue || '0x');
    } catch (e) {
      if (e && e.revertData) return e.revertData;
      if (e && e.reason) {
        const err = rpcError(-32000, e.reason);
        err.data = '0x' + '08c379a0'.padEnd(8, '0');
        throw err;
      }
      throw rpcError(-32000, (e && e.message) || 'execution reverted');
    }
  }

  async _handleEstimate(txObj) {
    const to = normalizeAddr(txObj.to);
    const from = normalizeAddr(txObj.from || ZERO_ADDRESS);
    const data = normalizeHex(txObj.data || '0x');
    const value = parseQuantity(txObj.value == null ? 0 : txObj.value, 'value');
    const hasData = data.length > 2 && data !== '0x';
    const intrinsic = BigInt(estimateIntrinsicGas({ data }));
    if (!this.smartContracts) return toQuantity(intrinsic);
    if (!to && !hasData) return toQuantity(intrinsic);
    try {
      let result;
      if (!to && hasData) {
        const nonce = this._nonceOf(from);
        result = await this.smartContracts.CreateSmartContract(data, undefined, from, nonce, String(value), this.chain ? this.chain.cfg?.gasLimit : undefined, undefined, false);
      } else if (to && this.db.prepare('SELECT 1 FROM smart_contracts WHERE lower(address) = lower(?)').get(to)) {
        result = await this.smartContracts.runSmartContract(to, from, data, Number(value));
      } else {
        return toQuantity(intrinsic);
      }
      const used = result && result.gasUsed ? BigInt(result.gasUsed) : 0n;
      return toQuantity(intrinsic + used);
    } catch (e) {
      if (e && e.revertData) throw rpcError(-32000, e.message || 'execution reverted');
      throw rpcError(-32000, (e && e.message) || 'execution reverted');
    }
  }

  _txIndex(tx) {
    if (!tx || !tx.block_hash) return 0;
    try {
      const rows = this.db.prepare('SELECT hash FROM transactions WHERE block_hash = ? ORDER BY rowid ASC').all(tx.block_hash);
      const h = normalizeHex(tx.hash || '');
      for (let i = 0; i < rows.length; i++) {
        if (normalizeHex(rows[i].hash) === h) return i;
      }
    } catch {}
    return 0;
  }

  _txToRPC(tx, indexProvided) {
    if (!tx) return null;
    const value = String(tx.value || 0);
    const gasLimit = String(tx.gas_limit || tx.gas || 21000);
    const gasPrice = String(tx.gas_price || '1');
    const v = tx.v != null ? normalizeHex(String(tx.v)) : '0x0';
    const r = tx.r != null ? normalizeHex(String(tx.r)).replace(/^0x/, '').padStart(64, '0') : '0'.repeat(64);
    const s = tx.s != null ? normalizeHex(String(tx.s)).replace(/^0x/, '').padStart(64, '0') : '0'.repeat(64);
    const txIndex = indexProvided != null ? indexProvided : this._txIndex(tx);
    const rpc = {
      hash: normalizeHex(tx.hash || evmTxHash(tx)),
      nonce: toQuantityNumber(tx.nonce || 0),
      blockHash: tx.block_hash ? normalizeHex(tx.block_hash) : null,
      blockNumber: tx.block_height != null ? toQuantityNumber(tx.block_height) : null,
      transactionIndex: tx.block_height != null ? toQuantityNumber(txIndex) : null,
      from: normalizeAddr(tx.from_addr),
      to: tx.to_addr ? normalizeAddr(tx.to_addr) : null,
      value: toQuantity(BigInt(value || 0)),
      gasPrice: toQuantity(BigInt(gasPrice)),
      gas: toQuantity(BigInt(gasLimit)),
      input: normalizeHex(tx.data || '0x'),
      chainId: toQuantityNumber(this._networkChainId || 0),
      v: '0x' + v.replace(/^0x/, ''),
      r: '0x' + r,
      s: '0x' + s,
      type: tx.tx_type != null ? toQuantityNumber(tx.tx_type) : (tx.type != null ? toQuantityNumber(tx.type) : '0x0'),
    };
    const maxFeePerGas = tx.maxFeePerGas ?? tx.max_fee_per_gas;
    const maxPriorityFeePerGas = tx.maxPriorityFeePerGas ?? tx.max_priority_fee_per_gas;
    if (maxFeePerGas != null && maxFeePerGas !== '' && maxPriorityFeePerGas != null && maxPriorityFeePerGas !== '') {
      rpc.maxFeePerGas = toQuantity(BigInt(maxFeePerGas));
      rpc.maxPriorityFeePerGas = toQuantity(BigInt(maxPriorityFeePerGas));
    }
    return rpc;
  }

  _blockToRPC(blockDbRow, full) {
    if (!blockDbRow) return null;
    const txs = blockDbRow.hash
      ? this.db.prepare('SELECT * FROM transactions WHERE block_hash = ? ORDER BY rowid ASC').all(blockDbRow.hash)
      : [];
    const baseFee = blockDbRow.base_fee || '0';
    const blockLogs = this._logsForBlock(blockDbRow.hash).map(lg => this._logToRPC(lg));
    const rpc = {
      number: toQuantityNumber(blockDbRow.height || 0),
      hash: normalizeHex(blockDbRow.hash || ''),
      parentHash: normalizeHex(blockDbRow.parent_hash || ZERO_HASH),
      nonce: '0x0000000000000000',
      sha3Uncles: '0x' + '1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347',
      logsBloom: logsToBloom(blockLogs),
      transactionsRoot: normalizeHex(blockDbRow.tx_root || ZERO_HASH),
      stateRoot: normalizeHex(blockDbRow.state_root || ZERO_HASH),
      receiptsRoot: this._blockReceiptsRoot(txs),
      miner: normalizeAddr(blockDbRow.miner || ZERO_ADDRESS),
      difficulty: '0x0',
      totalDifficulty: toQuantity(blockDbRow.chain_work || '0'),
      extraData: '0x',
      size: '0x0',
      gasLimit: toQuantity(blockDbRow.gas_limit || 30000000),
      gasUsed: toQuantity(blockDbRow.gas_used || 0),
      timestamp: toQuantityNumber(blockDbRow.timestamp || 0),
      baseFeePerGas: toQuantity(BigInt(baseFee)),
      mixHash: '0x' + '0'.repeat(64),
      uncles: [],
      transactions: full ? txs.map((t, i) => this._txToRPC(t, i)) : txs.map(t => normalizeHex(t.hash || evmTxHash(t))),
    };
    return rpc;
  }

  _blockReceiptsRoot(txs) {
    const receipts = txs.map(t => {
      const logged = this._logsForTx(t.hash || evmTxHash(t)).map(lg => this._logToRPC(lg));
      const stored = this.db.prepare('SELECT receipt_status, gas_used, cumulative_gas_used FROM transactions WHERE hash = ?').get(t.hash || evmTxHash(t));
      const toBytes = value => Buffer.from(String(value || '').replace(/^0x/i, ''), 'hex');
      const gasUsed = BigInt(stored ? stored.gas_used : estimateIntrinsicGas(t));
      const cumulativeGasUsed = BigInt(stored ? stored.cumulative_gas_used : 0);
      const status = !stored || stored.receipt_status ? Buffer.from([1]) : Buffer.alloc(0);
      const logs = logged.map(lg => [
        toBytes(lg.address),
        (lg.topics || []).map(toBytes),
        toBytes(lg.data),
      ]);
      const encoded = Buffer.from(encodeRlp([
        status,
        this._bigIntBytes(cumulativeGasUsed),
        toBytes(logsToBloom(logged)),
        logs,
      ]));
      const txType = Number(t.tx_type ?? t.type ?? 0);
      return txType > 0 ? Buffer.concat([Buffer.from([txType]), encoded]) : encoded;
    });
    return receiptsRoot(receipts);
  }

  _bigIntBytes(value) {
    if (value === 0n) return Buffer.alloc(0);
    let hex = value.toString(16);
    if (hex.length % 2) hex = '0' + hex;
    return Buffer.from(hex, 'hex');
  }

  _logsForTx(txHash) {
    if (!txHash) return [];
    return this.db.prepare('SELECT * FROM contract_logs WHERE lower(tx_hash) = lower(?) ORDER BY log_index ASC').all(String(txHash));
  }

  _logsForBlock(blockHash) {
    if (!blockHash) return [];
    return this.db.prepare('SELECT * FROM contract_logs WHERE lower(block_hash) = lower(?) ORDER BY block_height ASC, log_index ASC').all(String(blockHash));
  }

  _logToRPC(lg) {
    let topics = [];
    try { topics = JSON.parse(lg.topics || '[]'); } catch {}
    let txIndex = 0;
    if (lg.tx_hash) {
      try {
        const tx = this.db.prepare('SELECT hash, block_hash FROM transactions WHERE lower(hash) = lower(?)').get(lg.tx_hash);
        txIndex = this._txIndex(tx);
      } catch {}
    }
    return {
      address: lg.address,
      topics,
      data: String(lg.data || '0x'),
      blockNumber: lg.block_height != null ? toQuantityNumber(lg.block_height) : null,
      transactionHash: lg.tx_hash ? normalizeHex(lg.tx_hash) : null,
      transactionIndex: toQuantityNumber(txIndex),
      blockHash: lg.block_hash ? normalizeHex(lg.block_hash) : null,
      logIndex: lg.log_index != null ? toQuantityNumber(lg.log_index) : null,
      removed: false,
    };
  }

  _contractAddressFor(tx) {
    if (!tx) return null;
    if (tx.to_addr) return null;
    try {
      if (this.smartContracts && typeof this.smartContracts.deriveContractAddress === 'function' && tx.from_addr) {
        let nonce = 0;
        try { nonce = Number(tx.nonce || 0) || 0; } catch {}
        return this.smartContracts.deriveContractAddress(tx.from_addr, nonce);
      }
    } catch {}
    return null;
  }

  _receiptToRPC(tx) {
    if (!tx) return null;
    const txHash = normalizeHex(tx.hash || evmTxHash(tx));
    const to = tx.to_addr ? normalizeAddr(tx.to_addr) : null;
    const logs = this._logsForTx(txHash).map(lg => this._logToRPC(lg));
    const txIndex = this._txIndex(tx);
    return {
      transactionHash: txHash,
      transactionIndex: toQuantityNumber(txIndex),
      blockHash: tx.block_hash ? normalizeHex(tx.block_hash) : null,
      blockNumber: tx.block_height != null ? toQuantityNumber(tx.block_height) : null,
      from: normalizeAddr(tx.from_addr),
      to,
      contractAddress: tx.receipt_status === 0 ? null : this._contractAddressFor(tx),
      cumulativeGasUsed: toQuantity(tx.cumulative_gas_used || 0),
      gasUsed: toQuantity(tx.gas_used || estimateIntrinsicGas(tx)),
      effectiveGasPrice: toQuantity(tx.gas_used ? BigInt(tx.fee || 0) / BigInt(tx.gas_used) : 0n),
      logs,
      logsBloom: logsToBloom(logs),
      status: tx.receipt_status ? '0x1' : '0x0',
      type: '0x0',
    };
  }

  async _sendRawTransaction(rawHex) {
    if (!rawHex) throw rpcError(-32602, 'missing raw transaction');
    let rawBytes;
    try {
      const h = String(rawHex).replace(/^0x/i, '');
      if (h.length % 2) throw new Error('odd hex');
      rawBytes = Buffer.from(h, 'hex');
    } catch (e) {
      throw rpcError(-32602, 'invalid raw transaction: ' + e.message);
    }
    let parsed;
    try {
      parsed = createTxFromRLP(Uint8Array.from(rawBytes), { common: this.common });
    } catch (e) {
      throw rpcError(-32602, 'invalid raw transaction encoding: ' + e.message);
    }
    const sender = parsed.getSenderAddress().toString().toLowerCase();
    const to = parsed.to ? normalizeAddr(parsed.to.toString()) : '';
    const chainId = (parsed.common && parsed.common.chainId ? parsed.common.chainId() : 0n).toString();
    if (chainId !== String(this._networkChainId)) throw rpcError(-32000, 'wrong chain id');
    const gasPrice = String(parsed.gasPrice || 0n);
    const recoverableSig = recoverableSignatureFromParsed(parsed);
    const dataHex = hexData(parsed.data);
    const gasLimit = Number(parsed.gasLimit || 0n);
    const effectiveGasPrice = parsed.maxFeePerGas != null && parsed.maxFeePerGas > 0n ? parsed.maxFeePerGas : (parsed.gasPrice || 0n);
    const fee = (BigInt(gasLimit) * effectiveGasPrice).toString();
    const tx = {
      from_addr: sender,
      to_addr: to,
      value: String(parsed.value || 0n),
      nonce: Number(parsed.nonce || 0n),
      gas_limit: gasLimit,
      gas_price: gasPrice,
      fee,
      chain_id: chainId,
      priority_fee: parsed.maxPriorityFeePerGas != null ? String((parsed.maxPriorityFeePerGas) || 0n) : '0',
      data: dataHex,
      signature: recoverableSig.toString('base64'),
      rpc_signature: '0x' + rawBytes.toString('hex'),
      raw: '0x' + rawBytes.toString('hex'),
      rpc_type: 'evm',
      type: parsed.type || 0,
      v: parsed.v != null ? String(parsed.v) : undefined,
      r: parsed.r != null ? '0x' + parsed.r.toString(16) : undefined,
      s: parsed.s != null ? '0x' + parsed.s.toString(16) : undefined,
      maxFeePerGas: parsed.maxFeePerGas != null ? String(parsed.maxFeePerGas) : undefined,
      maxPriorityFeePerGas: parsed.maxPriorityFeePerGas != null ? String(parsed.maxPriorityFeePerGas) : undefined,
    };
    tx.hash = keccak256('0x' + rawBytes.toString('hex'));
    tx.status = 1;
    const validation = await this.chain.validateTxForMempool(tx);
    if (!validation.ok) throw rpcError(-32000, validation.motivo || 'transaction rejected');
    const result = this.chain.addMempoolTx(tx);
    if (!result.ok) {
      if (result.motivo && /already in (mempool|chain)/i.test(result.motivo)) throw rpcError(-32000, result.motivo);
      throw rpcError(-32000, result.motivo || 'failed to add transaction');
    }
    if (this.sync) setImmediate(() => { try { this.sync.broadcastTx(tx); } catch {} });
    return tx.hash;
  }

  _normalizeAddressFilter(filter) {
    if (!filter) return null;
    const list = Array.isArray(filter) ? filter : [filter];
    const out = new Set();
    for (const a of list) {
      if (typeof a === 'string' && a) out.add(normalizeAddr(a));
    }
    return out.size ? out : null;
  }

  _matchTopics(filterTopics, logTopics) {
    if (!filterTopics || !filterTopics.length) return true;
    if (!Array.isArray(logTopics)) logTopics = [];
    for (let i = 0; i < filterTopics.length; i++) {
      const f = filterTopics[i];
      if (f === null || f === undefined) continue;
      const values = Array.isArray(f) ? f : [f];
      const logT = logTopics[i];
      if (logT === undefined || logT === null) return false;
      if (!values.some(v => String(v).toLowerCase() === String(logT).toLowerCase())) return false;
    }
    return true;
  }

  _queryLogs(filterObj) {
    const f = filterObj || {};
    const from = f.fromBlock;
    const to = f.toBlock;
    let fromNum = resolveBlockTag(this.chain, from == null ? 'latest' : from);
    let toNum = resolveBlockTag(this.chain, to == null ? 'latest' : to);
    if (fromNum === -1) fromNum = 0;
    if (toNum === -1) toNum = this.chain.height;
    if (fromNum == null || toNum == null) return [];
    if (fromNum > toNum) return [];
    const addresses = this._normalizeAddressFilter(f.address);
    const topics = f.topics || [];
    const rows = this.db.prepare('SELECT * FROM contract_logs WHERE block_height >= ? AND block_height <= ? ORDER BY block_height ASC, log_index ASC').all(fromNum, toNum);
    const out = [];
    for (const lg of rows) {
      if (addresses && !addresses.has(lg.address.toLowerCase())) continue;
      let logTopics = [];
      try { logTopics = JSON.parse(lg.topics || '[]'); } catch {}
      if (!this._matchTopics(topics, logTopics)) continue;
      out.push(this._logToRPC(lg));
    }
    return out;
  }

  _newFilterId() {
    return '0x' + (this._nextFilterId++).toString(16).padStart(8, '0');
  }

  async _handleNewFilter(filterObj) {
    const id = this._newFilterId();
    this._filters.set(id, { type: 'log', fromBlock: filterObj.fromBlock, toBlock: filterObj.toBlock, address: filterObj.address, topics: filterObj.topics, latestSeen: this.chain.height });
    return id;
  }
  async _handleGetFilterChanges(id) {
    const f = this._filters.get(id);
    if (!f) throw rpcError(-32000, 'filter not found');
    if (f.type === 'block') {
      const start = f.latestSeen;
      f.latestSeen = this.chain.height;
      const out = [];
      for (let h = start + 1; h <= this.chain.height; h++) {
        const b = this.db.prepare('SELECT hash FROM blocks WHERE height = ?').get(h);
        out.push(b ? normalizeHex(b.hash) : '0x' + h.toString(16));
      }
      return out;
    }
    if (f.type === 'pending') {
      const pending = this.db.prepare('SELECT hash FROM mempool ORDER BY timestamp ASC').all().map(r => normalizeHex(r.hash));
      const seen = f.latestSeen;
      const out = pending.filter(h => h !== seen);
      f.latestSeen = pending.length ? pending[pending.length - 1] : seen;
      return out;
    }
    const from = f.lastPollHeight != null ? f.lastPollHeight + 1 : resolveBlockTag(this.chain, f.fromBlock == null ? 'latest' : f.fromBlock);
    f.lastPollHeight = this.chain.height;
    const logs = this._queryLogs({ fromBlock: from, toBlock: 'latest', address: f.address, topics: f.topics });
    return logs;
  }

  async _handleUninstallFilter(id) {
    return this._filters.delete(id);
  }

  async handle(method, params) {
    params = params || [];
    const [p0, p1, p2] = params;
    switch (method) {
      case 'web3_clientVersion':
        return 'choconode/' + (this.cfg.version || '3.6.0-js');
      case 'web3_sha3': {
        const h = String(p0 || '0x').replace(/^0x/i, '');
        return keccak256('0x' + (h.length % 2 ? '0' + h : h));
      }
      case 'net_version':
        return String(this._networkChainId || 0);
      case 'net_listening':
        return true;
      case 'net_peerCount':
        return toQuantityNumber(this.peers ? this.peers.count() : 0);
      case 'eth_chainId':
        return toQuantityNumber(this._networkChainId || 0);
      case 'eth_protocolVersion':
        return '0x41';
      case 'eth_syncing':
        return false;
      case 'eth_coinbase':
        return this.cfg.minerAddress ? normalizeAddr(this.cfg.minerAddress) : ZERO_ADDRESS;
      case 'eth_mining':
        return false;
      case 'eth_hashrate':
        return '0x0';
      case 'eth_gasPrice':
        return toQuantity(this.chain ? this.chain._baseFeeForHeight(this.chain.height + 1) : 0);
      case 'eth_maxPriorityFeePerGas':
        return toQuantity(0);
      case 'eth_blockNumber':
        return toQuantityNumber(this.chain.height);
      case 'eth_accounts':
        return [];
      case 'eth_getBalance': {
        const addr = normalizeAddr(p0);
        return toQuantity(this._balanceOf(addr));
      }
      case 'eth_getTransactionCount': {
        const addr = normalizeAddr(p0);
        const tag = p1 == null ? 'latest' : String(p1).toLowerCase();
        const nonce = tag === 'pending' ? this._pendingNonceOf(addr) : this._nonceOf(addr);
        return toQuantityNumber(nonce);
      }
      case 'eth_getCode':
        return this._codeOf(normalizeAddr(p0));
      case 'eth_getStorageAt': {
        const addr = normalizeAddr(p0);
        const pos = normalizeHex(p1 != null ? p1 : '0x0');
        const val = this._storageAt(addr, pos);
        return normalizeHex(val).replace(/^0x/, '').padStart(64, '0');
      }
      case 'eth_call':
        return await this._handleCall(p0 || {});
      case 'eth_estimateGas':
        return await this._handleEstimate(p0 || {});
      case 'eth_sendRawTransaction':
        return await this._sendRawTransaction(p0);
      case 'eth_sendTransaction': {
        if (!this.cfg.rpcEnableSendTransaction) throw rpcError(-32601, 'eth_sendTransaction disabled by default (set rpcEnableSendTransaction=true to allow node-side signing with minerPrivateKey)');
        const txObj = p0 || {};
        const from = normalizeAddr(txObj.from);
        const pk = this.cfg.minerPrivateKey;
        if (!pk) throw rpcError(-32000, 'no unlocked account on node');
        const minerAddr = normalizeAddr(this.cfg.minerAddress || '');
        if (from && minerAddr && from !== minerAddr) throw rpcError(-32000, 'can only send from node miner account');
        const to = txObj.to ? normalizeAddr(txObj.to) : '';
        const nonce = txObj.nonce != null ? Number(parseQuantity(txObj.nonce, 'nonce')) : this._pendingNonceOf(from || minerAddr);
        const baseFee = this.chain._baseFeeForHeight(this.chain.height + 1);
        const dataHex = normalizeHex(txObj.data || '0x');
        const rawGas = txObj.gas ? Number(parseQuantity(txObj.gas, 'gas')) : (dataHex && dataHex !== '0x' && dataHex.length > 2 ? 3000000 : 21000);
        const intrinsic = estimateIntrinsicGas({ data: dataHex });
        const gasLimit = Math.min(GAS_PARAMS.maxGasPerTx, Math.max(rawGas, intrinsic));

        const min = minimumFee({ data: dataHex, gas_limit: gasLimit, gas_price: String(baseFee) }, baseFee);
        const cap = this.cfg.maxMempoolSize && this.cfg.maxMempoolSize > 0 ? this.cfg.maxMempoolSize : 5000;
        let pending = 0;
        try { pending = this.db.prepare('SELECT COUNT(*) AS c FROM mempool').get().c; } catch {}
        const congested = pending >= cap / 2;
        const fee = congested ? min + (min / 10n) : min;
        const internalTx = {
          from_addr: minerAddr,
          to_addr: to,
          value: String(parseQuantity(txObj.value || 0, 'value')),
          nonce,
          gas_limit: gasLimit,
          gas_price: String(baseFee),
          fee: fee.toString(),
          chain_id: String(this._networkChainId || 0),
          priority_fee: '0',
          data: dataHex,
        };
        const { signTransactionTx } = require('../crypto-utils/crypto');
        internalTx.signature = signTransactionTx(internalTx, pk);
        internalTx.hash = evmTxHash(internalTx);
        internalTx.status = 1;
        const validation = await this.chain.validateTxForMempool(internalTx);
        if (!validation.ok) throw rpcError(-32000, validation.motivo || 'transaction rejected');
        const result = this.chain.addMempoolTx(internalTx);
        if (!result.ok) throw rpcError(-32000, result.motivo || 'failed to add transaction');
        if (this.sync) setImmediate(() => { try { this.sync.broadcastTx(internalTx); } catch {} });
        return internalTx.hash;
      }
      case 'eth_getTransactionByHash': {
        const hash = normalizeHex(p0);
        const tx = this.db.prepare('SELECT * FROM transactions WHERE lower(hash) = lower(?)').get(hash)
          || this.db.prepare('SELECT raw FROM mempool WHERE lower(hash) = lower(?)').get(hash);
        if (tx && tx.raw) {
          try { return this._txToRPC(JSON.parse(tx.raw)); } catch { return null; }
        }
        return this._txToRPC(tx);
      }
      case 'eth_getTransactionReceipt': {
        const hash = normalizeHex(p0);
        const tx = this.db.prepare('SELECT * FROM transactions WHERE lower(hash) = lower(?)').get(hash);
        return this._receiptToRPC(tx);
      }
      case 'eth_getBlockByNumber': {
        const height = resolveBlockTag(this.chain, p0);
        if (height == null) return null;
        const full = !!p1;
        return this._blockToRPC(this.db.prepare('SELECT * FROM blocks WHERE height = ?').get(height), full);
      }
      case 'eth_getBlockByHash': {
        const full = !!p1;
        const b = this.db.prepare('SELECT * FROM blocks WHERE lower(hash) = lower(?)').get(String(p0 || '').replace(/^0x/i, ''));
        return this._blockToRPC(b, full);
      }
      case 'eth_getBlockTransactionCountByHash': {
        const b = this.db.prepare('SELECT hash FROM blocks WHERE lower(hash) = lower(?)').get(String(p0 || '').replace(/^0x/i, ''));
        if (!b) return null;
        const c = this.db.prepare('SELECT COUNT(*) as c FROM transactions WHERE block_hash = ?').get(b.hash).c;
        return toQuantityNumber(c);
      }
      case 'eth_getBlockTransactionCountByNumber': {
        const height = resolveBlockTag(this.chain, p0);
        if (height == null) return null;
        const b = this.db.prepare('SELECT hash FROM blocks WHERE height = ?').get(height);
        if (!b) return null;
        const c = this.db.prepare('SELECT COUNT(*) as c FROM transactions WHERE block_hash = ?').get(b.hash).c;
        return toQuantityNumber(c);
      }
      case 'eth_getTransactionByBlockHashAndIndex': {
        const b = this.db.prepare('SELECT hash FROM blocks WHERE lower(hash) = lower(?)').get(String(p0 || '').replace(/^0x/i, ''));
        if (!b) return null;
        const idx = Number(parseQuantity(p1 == null ? 0 : p1, 'index'));
        const txs = this.db.prepare('SELECT * FROM transactions WHERE block_hash = ? ORDER BY rowid ASC').all(b.hash);
        return this._txToRPC(txs[idx] || null);
      }
      case 'eth_getTransactionByBlockNumberAndIndex': {
        const height = resolveBlockTag(this.chain, p0);
        if (height == null) return null;
        const b = this.db.prepare('SELECT hash FROM blocks WHERE height = ?').get(height);
        if (!b) return null;
        const idx = Number(parseQuantity(p1 == null ? 0 : p1, 'index'));
        const txs = this.db.prepare('SELECT * FROM transactions WHERE block_hash = ? ORDER BY rowid ASC').all(b.hash);
        return this._txToRPC(txs[idx] || null);
      }
      case 'eth_getUncleCountByBlockHash':
      case 'eth_getUncleCountByBlockNumber':
        return '0x0';
      case 'eth_getUncleByBlockHashAndIndex':
      case 'eth_getUncleByBlockNumberAndIndex':
        return null;
      case 'eth_getLogs':
        return this._queryLogs(p0 || {});
      case 'eth_newFilter':
        return await this._handleNewFilter(p0 || {});
      case 'eth_newBlockFilter': {
        const id = this._newFilterId();
        this._filters.set(id, { type: 'block', latestSeen: this.chain.height });
        return id;
      }
      case 'eth_newPendingTransactionFilter': {
        const id = this._newFilterId();
        this._filters.set(id, { type: 'pending', latestSeen: this.db.prepare('SELECT hash FROM mempool ORDER BY rowid DESC LIMIT 1').get()?.hash || null });
        return id;
      }
      case 'eth_getFilterChanges':
        return await this._handleGetFilterChanges(p0);
      case 'eth_getFilterLogs': {
        const f = this._filters.get(String(p0));
        if (!f) throw rpcError(-32000, 'filter not found');
        if (f.type === 'log') return this._queryLogs({ fromBlock: f.fromBlock, toBlock: f.toBlock, address: f.address, topics: f.topics });
        throw rpcError(-32602, 'filter is not a log filter');
      }
      case 'eth_uninstallFilter':
        return await this._handleUninstallFilter(p0);
      case 'eth_getProof':
        throw rpcError(-32601, 'eth_getProof not supported');
      case 'eth_feeHistory': {
        let count = Number(parseQuantity(p0, 'block count'));
        if (!Number.isFinite(count) || count < 1) count = 1;
        count = Math.min(count, 1024);
        const newest = resolveBlockTag(this.chain, p1);
        if (typeof newest !== 'number') throw rpcError(-32602, 'invalid block tag');
        const percentiles = Array.isArray(p2) ? p2.map(Number) : [];
        if (percentiles.some((p, i) => !Number.isFinite(p) || p < 0 || p > 100 || (i > 0 && p < percentiles[i - 1]))) {
          throw rpcError(-32602, 'reward percentiles must be sorted values from 0 to 100');
        }
        const first = Math.max(0, newest - count + 1);
        const rows = this.db.prepare('SELECT height, gas_used, gas_limit, base_fee FROM blocks WHERE height BETWEEN ? AND ? ORDER BY height ASC').all(first, newest);
        const byHeight = new Map(rows.map(row => [Number(row.height), row]));
        const baseFees = [];
        const gasUsedRatio = [];
        const reward = [];
        for (let height = first; height <= newest; height++) {
          const row = byHeight.get(height);
          const base = row && row.base_fee != null ? BigInt(row.base_fee) : BigInt(this.chain._baseFeeForHeight(height));
          baseFees.push(toQuantity(base));
          gasUsedRatio.push(row && Number(row.gas_limit) > 0 ? Number(row.gas_used || 0) / Number(row.gas_limit) : 0);
          const tips = row ? this.db.prepare('SELECT fee, gas_used FROM transactions WHERE block_height = ?').all(height)
            .map(tx => {
              const price = tx.gas_used ? BigInt(tx.fee || 0) / BigInt(tx.gas_used) : 0n;
              return { tip: price > base ? price - base : 0n, gas: Number(tx.gas_used || 0) };
            }).sort((a, b) => a.tip < b.tip ? -1 : a.tip > b.tip ? 1 : 0) : [];
          const totalGas = tips.reduce((sum, tip) => sum + tip.gas, 0);
          reward.push(percentiles.map(percentile => {
            const targetGas = Math.ceil(totalGas * percentile / 100);
            let used = 0;
            let selected = 0n;
            for (const tip of tips) {
              used += tip.gas;
              selected = tip.tip;
              if (used >= targetGas) break;
            }
            return toQuantity(selected);
          }));
        }
        baseFees.push(toQuantity(BigInt(this.chain._baseFeeForHeight(newest + 1))));
        return {
          oldestBlock: toQuantityNumber(first),
          baseFeePerGas: baseFees,
          gasUsedRatio,
          reward,
        };
      }
      case 'eth_createAccessList':
        return { accessList: [], gasUsed: '0x0' };
      case 'eth_sign':
        throw rpcError(-32601, 'eth_sign not supported');
      case 'personal_ecRecover':
        throw rpcError(-32601, 'personal_ecRecover not supported');
      case 'eth_getCompilers':
        return [];
      case 'eth_compileSolidity':
        throw rpcError(-32601, 'eth_compileSolidity not supported');
      case 'trace_transaction':
      case 'trace_block':
      case 'trace_call':
        throw rpcError(-32601, 'trace not supported');
      case 'eth_getWork':
        return [];
      case 'eth_submitWork':
      case 'eth_submitHashrate':
        return false;
      default:
        throw rpcError(-32601, `the method ${method} does not exist/is not available`);
    }
  }

  router() {
    const router = express.Router();
    router.post('/', async (req, res) => {
      const body = req.body;
      if (Array.isArray(body)) {
        const results = [];
        for (const item of body) {
          results.push(await this._dispatch(item));
        }
        return res.json(results);
      }
      return res.json(await this._dispatch(body));
    });
    return router;
  }

  attachWSServer(wss) {
    this._wss = wss;
    if (wss) {
      wss.on('connection', (ws) => {
        ws.subscriptions = new Set();
        ws.on('message', (data) => {
          let raw = data;
          if (data && data.toString) raw = data.toString();
          try { this._wsMessage(ws, raw); } catch {}
        });
        ws.on('close', () => this._dropSubsFor(ws));
      });
      if (!this._notifyTimer) {
        this._notifyTimer = setInterval(() => { try { this._pollAndNotify(); } catch {} }, 1500);
        if (this._notifyTimer.unref) this._notifyTimer.unref();
      }
    }
  }

  _wsSend(ws, payload) {
    try { if (ws && ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify(payload)); } catch {}
  }

  _wsMessage(ws, raw) {
    let msg;
    try { msg = JSON.parse(raw); } catch { return; }
    if (Array.isArray(msg)) {
      return this._wsSend(ws, { jsonrpc: '2.0', id: null, error: { code: -32600, message: 'Batch over WebSocket is not supported' } });
    }
    if (msg && (msg.method === 'eth_subscribe' || msg.method === 'eth_unsubscribe')) {
      this._handleWsSubscribe(ws, msg);
      return;
    }
    const release = this.chain && this.chain.tryAcquireStableRead ? this.chain.tryAcquireStableRead() : () => {};
    if (!release) {
      return this._wsSend(ws, { jsonrpc: '2.0', id: msg && msg.id != null ? msg.id : null, error: { code: -32005, message: 'canonical chain transition in progress; retry shortly' } });
    }
    this._dispatch(msg).then(resp => this._wsSend(ws, resp)).catch(() => {}).finally(release);
  }

  _handleWsSubscribe(ws, msg) {
    const id = msg.id == null ? null : msg.id;
    if (!msg || !msg.method) return;
    if (this.chain && this.chain._stateTransitionPending) {
      return this._wsSend(ws, { jsonrpc: '2.0', id, error: { code: -32005, message: 'canonical chain transition in progress; retry shortly' } });
    }
    if (msg.method === 'eth_unsubscribe') {
      const subId = msg.params && msg.params[0];
      const sub = this._subs.get(subId);
      if (sub && sub.ws === ws) {
        this._subs.delete(subId);
        if (ws.subscriptions) ws.subscriptions.delete(subId);
        return this._wsSend(ws, { jsonrpc: '2.0', id, result: true });
      }
      return this._wsSend(ws, { jsonrpc: '2.0', id, result: false });
    }
    const type = String(msg.params && msg.params[0] || '').toLowerCase();
    const filter = (msg.params && msg.params[1]) || {};
    if (type !== 'newheads' && type !== 'logs' && type !== 'newpendingtransactions') {
      return this._wsSend(ws, { jsonrpc: '2.0', id, error: { code: -32602, message: `Unknown subscription type: ${type}` } });
    }
    const subId = '0x' + this._nextSubId.toString(16);
    this._nextSubId++;
    const height = (this.chain && this.chain.height) || 0;
    this._subs.set(subId, { ws, type, filter, lastSeen: height, lastPending: new Set() });
    this._notifyHeights.set(subId, height);
    if (ws.subscriptions) ws.subscriptions.add(subId);
    this._wsSend(ws, { jsonrpc: '2.0', id, result: subId });
  }

  _dropSubsFor(ws) {
    for (const [subId, sub] of this._subs) {
      if (sub.ws === ws) { this._subs.delete(subId); this._notifyHeights.delete(subId); }
    }
  }

  _emit(ws, subId, result) {
    this._wsSend(ws, { jsonrpc: '2.0', method: 'eth_subscription', params: { subscription: subId, result } });
  }

  _pollAndNotify() {
    if (!this._subs.size || !this.chain || this.chain._stateTransitionPending) return;
    const height = (this.chain && this.chain.height) || 0;
    for (const [subId, sub] of Array.from(this._subs)) {
      try {
        if (sub.type === 'newheads') {
          const last = this._notifyHeights.get(subId) || sub.lastSeen || 0;
          if (height > last) {
            const block = this._blockToRPC(this.db.prepare('SELECT * FROM blocks WHERE height = ?').get(height), false);
            if (block) { this._emit(sub.ws, subId, block); this._notifyHeights.set(subId, height); sub.lastSeen = height; }
          }
        } else if (sub.type === 'newpendingtransactions') {
          const seen = sub.lastPending || new Set();
          let rows = [];
          try { rows = this.db.prepare('SELECT hash FROM mempool').all(); } catch {}
          const current = new Set();
          const fresh = [];
          for (const r of rows) { const h = r.hash; current.add(h); if (!seen.has(h)) fresh.push(normalizeHex(h)); }
          sub.lastPending = current;
          for (const h of fresh) this._emit(sub.ws, subId, h);
        } else if (sub.type === 'logs') {
          const last = this._notifyHeights.get(subId) || sub.lastSeen || 0;
          if (height > last) {
            for (let h = last + 1; h <= height; h++) {
              const block = this.db.prepare('SELECT * FROM blocks WHERE height = ?').get(h);
              if (!block) continue;
              const logs = this._queryLogs({ fromBlock: toQuantityNumber(h), toBlock: toQuantityNumber(h), address: sub.filter.address, topics: sub.filter.topics });
              for (const lg of logs) this._emit(sub.ws, subId, lg);
            }
            this._notifyHeights.set(subId, height);
            sub.lastSeen = height;
          }
        }
      } catch {}
    }
  }

  async _dispatch(reqJson) {
    if (!reqJson || typeof reqJson !== 'object' || reqJson.jsonrpc !== '2.0' || !reqJson.method) {
      return { jsonrpc: '2.0', id: reqJson && reqJson.id != null ? reqJson.id : null, error: { code: -32600, message: 'Invalid Request' } };
    }
    const id = reqJson.id == null ? null : reqJson.id;
    try {
      if (this._isWriteMethod(reqJson.method)) this._assertWriteLimit(reqJson.method);
      const result = await this.handle(reqJson.method, reqJson.params);
      return { jsonrpc: '2.0', id, result };
    } catch (e) {
      const code = e.rpcCode || -32603;
      return { jsonrpc: '2.0', id, error: { code, message: e.message || 'internal error' } };
    }
  }

  _isWriteMethod(method) {
    return method === 'eth_sendRawTransaction' || method === 'eth_sendTransaction' || method === 'eth_signTransaction';
  }

  _assertWriteLimit(method) {
    const now = Date.now();
    const windowMs = 60000;
    const max = 30;
    const arr = (this._writeHits.get(method) || []).filter(t => now - t < windowMs);
    if (arr.length >= max) {
      const e = rpcError(-32005, 'limit exceeded');
      e.rpcCode = -32005;
      throw e;
    }
    arr.push(now);
    this._writeHits.set(method, arr);
  }
}

module.exports = { EthereumRPC };
