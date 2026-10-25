const { GAS_PARAMS } = require('../consensus/gas');
const { createVM } = require('@ethereumjs/vm');
const { Common, Hardfork, Mainnet } = require('@ethereumjs/common');
const { createLegacyTx } = require('@ethereumjs/tx');
const { Block } = require('@ethereumjs/block');
const { bytesToHex, hexToBytes, generateAddress, createZeroAddress, toChecksumAddress, Address, Account, setLengthLeft, bigIntToBytes, bytesToUnprefixedHex } = require('@ethereumjs/util');
const BN = require('bn.js');

function patchLevelWsDoubleClose() {
  try {
    const { WriteStream } = require('level-ws');
    if (!WriteStream || WriteStream.prototype.__ccPatched) return;
    WriteStream.prototype.__ccPatched = true;
    const originalEmit = WriteStream.prototype.emit;
    WriteStream.prototype.emit = function (eventName, ...args) {
      if (eventName === 'close') {
        if (this.__ccCloseFired) return this;
        this.__ccCloseFired = true;
      }
      return originalEmit.call(this, eventName, ...args);
    };
  } catch (e) {
    
  }
}

patchLevelWsDoubleClose();

const initialSmartContractGasLimit = GAS_PARAMS.initialSmartContractGasLimit;
const initialSmartContractGasPrice = GAS_PARAMS.initialSmartContractGasPrice;

const InitialSmartContractGasPriceHumanReadable = (initialSmartContractGasPrice / 10 ** 9).toString() + ' Gwei';

const MAX_CONTRACT_CODE_SIZE = 24576; 

let db = null;


class LRUCache {
  constructor(maxSize = 100) {
    this.maxSize = maxSize;
    this.map = new Map();
  }

  get(key) {
    if (!this.map.has(key)) return undefined;
    const value = this.map.get(key);
    
    this.map.delete(key);
    this.map.set(key, value);
    return value;
  }

  set(key, value) {
    if (this.map.has(key)) {
      this.map.delete(key);
    } else if (this.map.size >= this.maxSize) {
      
      const oldestKey = this.map.keys().next().value;
      this.map.delete(oldestKey);
    }
    this.map.set(key, value);
  }

  has(key) {
    return this.map.has(key);
  }

  clear() {
    this.map.clear();
  }

  get size() {
    return this.map.size;
  }
}

const vmCache = new LRUCache(100);
const knownSlots = new Map();

function setDatabase(database) {
  db = database;
}

function clearVmCache() {
  vmCache.clear();
  knownSlots.clear();
}

function assertPersistentExecutionAllowed(beforeWrite) {
  if (db && !beforeWrite && db.prepare('SELECT 1 FROM pending_contract_blocks LIMIT 1').get()) {
    throw new Error('block contract execution is pending; independent state writes are blocked');
  }
}

async function getVm(contractAddress, fresh = false) {
  const key = normalizeHex(contractAddress);
  if (fresh || !vmCache.has(key)) {
    const common = new Common({ chain: Mainnet, hardfork: Hardfork.Shanghai });
    const vm = await createVM({ common });
    vmCache.set(key, vm);
  }
  if (!knownSlots.has(key)) {
    knownSlots.set(key, new Set());
  }
  return vmCache.get(key);
}

async function restoreContractBalance(vm, evmAddr, contractAddress) {
  const row = db.prepare('SELECT balance FROM smart_contract_accounts WHERE lower(address) = lower(?)').get(contractAddress);
  const account = (await vm.stateManager.getAccount(evmAddr)) || new Account();
  account.balance = BigInt(row ? row.balance : 0);
  const nonce = db.prepare('SELECT nonce FROM smart_contract_nonces WHERE lower(address) = lower(?)').get(contractAddress);
  account.nonce = BigInt(nonce ? nonce.nonce : 0);
  await vm.stateManager.putAccount(evmAddr, account);
}

async function flushContractBalance(vm, contractAddress, beforeWrite) {
  if (!db) return;
  const evmAddr = toEvmAddress(contractAddress);
  const account = (await vm.stateManager.getAccount(evmAddr)) || new Account();
  const balance = BigInt(account.balance);
  const previous = db.prepare('SELECT balance FROM smart_contract_accounts WHERE lower(address) = lower(?)').get(contractAddress);
  const previousNonce = db.prepare('SELECT nonce FROM smart_contract_nonces WHERE lower(address) = lower(?)').get(contractAddress);
  const nonceChanged = account.nonce === 0n ? !!previousNonce : !previousNonce || previousNonce.nonce !== account.nonce.toString();
  if (beforeWrite && ((balance === 0n ? !!previous : !previous || previous.balance !== balance.toString()) || nonceChanged)) {
    beforeWrite(contractAddress);
  }
  if (balance === 0n) {
    db.prepare('DELETE FROM smart_contract_accounts WHERE lower(address) = lower(?)').run(contractAddress);
  } else {
    db.prepare('INSERT OR REPLACE INTO smart_contract_accounts (address, balance) VALUES (?, ?)').run(contractAddress.toLowerCase(), balance.toString());
  }
  if (account.nonce === 0n) db.prepare('DELETE FROM smart_contract_nonces WHERE lower(address) = lower(?)').run(contractAddress);
  else db.prepare('INSERT OR REPLACE INTO smart_contract_nonces VALUES (?,?)').run(contractAddress.toLowerCase(), account.nonce.toString());
}

async function loadContractStorage(vm, contractAddress) {
  if (!db) return;
  const cacheKey = normalizeHex(contractAddress);
  const rows = db.prepare(
    'SELECT slot, value FROM smart_contract_storage WHERE lower(contract_address) = lower(?)'
  ).all(contractAddress);
  const evmAddr = toEvmAddress(contractAddress);
  if (!(await vm.stateManager.getAccount(evmAddr))) {
    await vm.stateManager.putAccount(evmAddr, new Account());
  }
  const hashedAddr = vm.stateManager.keccakFunction(evmAddr.bytes);
  const addressHex = bytesToUnprefixedHex(hashedAddr);
  if (vm.stateManager._storageTries && vm.stateManager._storageTries[addressHex]) {
    delete vm.stateManager._storageTries[addressHex];
  }
  const slots = knownSlots.get(cacheKey) || new Set();
  for (const row of rows) {
    await vm.stateManager.putStorage(evmAddr, hexToBytes('0x' + normalizeHex(row.slot)), hexToBytes('0x' + normalizeHex(row.value)));
    slots.add(row.slot);
  }
  knownSlots.set(cacheKey, slots);
  await restoreContractBalance(vm, evmAddr, contractAddress);
}

async function saveContractStorage(vm, contractAddress, writtenSlots) {
  if (!db) return;
  const evmAddr = toEvmAddress(contractAddress);
  const del = db.prepare('DELETE FROM smart_contract_storage WHERE lower(contract_address) = lower(?) AND slot = ?');
  const upsert = db.prepare(`INSERT OR REPLACE INTO smart_contract_storage (contract_address, slot, value) VALUES (?, ?, ?)`);
  const slots = knownSlots.get(normalizeHex(contractAddress)) || new Set();
  for (const rawSlot of writtenSlots) {
    const slotBuf = setLengthLeft(
      rawSlot instanceof Uint8Array ? rawSlot : (typeof rawSlot === 'bigint' ? bigIntToBytes(rawSlot) : hexToBytes('0x' + rawSlot)),
      32
    );
    const slotHex = bytesToHex(slotBuf);
    slots.add(slotHex);
    const value = await vm.stateManager.getStorage(evmAddr, slotBuf);
    const valueHex = value && value.length ? bytesToHex(value) : '';
    if (valueHex === '' || /^0*$/.test(valueHex)) {
      del.run(contractAddress, slotHex);
    } else {
      upsert.run(contractAddress, slotHex, valueHex);
    }
  }
  knownSlots.set(normalizeHex(contractAddress), slots);
}

async function SaveSmartContractState(contractAddress) {
  assertPersistentExecutionAllowed();
  if (!db) return { saved: 0 };
  const key = normalizeHex(contractAddress);
  const vm = vmCache.get(key);
  if (!vm) return { saved: 0 };
  const evmAddr = toEvmAddress(contractAddress);
  const slots = knownSlots.get(key) || new Set();
  const del = db.prepare('DELETE FROM smart_contract_storage WHERE lower(contract_address) = lower(?) AND slot = ?');
  const upsert = db.prepare(`INSERT OR REPLACE INTO smart_contract_storage (contract_address, slot, value) VALUES (?, ?, ?)`);
  let saved = 0;
  for (const slotHex of slots) {
    const value = await vm.stateManager.getStorage(evmAddr, hexToBytes('0x' + slotHex));
    const valueHex = value && value.length ? bytesToHex(value) : '';
    if (valueHex === '' || /^0*$/.test(valueHex)) {
      del.run(contractAddress, slotHex);
    } else {
      upsert.run(contractAddress, slotHex, valueHex);
      saved++;
    }
  }
  db.prepare('UPDATE smart_contracts SET updated_at = ? WHERE lower(address) = lower(?)')
    .run(Math.floor(Date.now() / 1000), contractAddress);
  await flushContractBalance(vm, contractAddress);
  return { saved };
}

async function loadContractCodes(vm) {
  if (!db) return;
  const rows = db.prepare('SELECT address, code FROM smart_contracts').all();
  for (const row of rows) {
    const code = hexToBytes('0x' + row.code);
    if (!code.length) continue;
    const evmAddr = toEvmAddress(row.address);
    if (!(await vm.stateManager.getAccount(evmAddr))) {
      await vm.stateManager.putAccount(evmAddr, new Account());
    }
    await vm.stateManager.putCode(evmAddr, code);
  }
}

async function loadAllContractState(vm) {
  if (!db) return;
  const rows = db.prepare('SELECT address FROM smart_contracts').all();
  for (const row of rows) {
    await loadContractStorage(vm, row.address);
  }
  await loadContractCodes(vm);
}

async function flushAllContractBalances(vm, beforeWrite) {
  if (!db) return;
  const rows = db.prepare('SELECT address FROM smart_contracts').all();
  for (const row of rows) {
    await flushContractBalance(vm, row.address, beforeWrite);
  }
}

async function runWithStorage(vm, contractAddress, params, persist = false, beforeWrite) {
  const stateManager = vm.stateManager;
  const canCheckpoint = stateManager && typeof stateManager.checkpoint === 'function' && typeof stateManager.revert === 'function';
  await loadAllContractState(vm);
  if (params.caller && db) {
    const callerAddress = fromEvmAddress(params.caller).toLowerCase();
    const user = db.prepare('SELECT balance FROM users WHERE lower(address) = lower(?)').get(callerAddress);
    const callerAccount = (await stateManager.getAccount(params.caller)) || new Account();
    callerAccount.balance = BigInt(user ? user.balance : 0);
    await stateManager.putAccount(params.caller, callerAccount);
  }
  if (canCheckpoint) await stateManager.checkpoint();
  const contractOwners = new Set(db ? db.prepare('SELECT address FROM smart_contracts').all().map(r => r.address.toLowerCase()) : []);
  const writtenBy = new Map();
  const evmThis = toEvmAddress(contractAddress);
  const frames = [evmThis];
  const onStep = (info) => {
    if (info.opcode && info.opcode.name === 'SSTORE') {
      const owner = fromEvmAddress(info.address || frames[frames.length - 1]).toLowerCase();
      if (!writtenBy.has(owner)) writtenBy.set(owner, new Set());
      writtenBy.get(owner).add(info.stack[info.stack.length - 1]);
    }
    if (info.opcode && info.opcode.name === 'SELFDESTRUCT') {
      const beneficiary = '0x' + info.stack[info.stack.length - 1].toString(16).padStart(40, '0').slice(-40);
      const owner = fromEvmAddress(info.address).toLowerCase();
      if (owner !== beneficiary && msgStack.length) msgStack[msgStack.length - 1].transfers.push({
        to: beneficiary, value: info.account.balance.toString(), selfdestruct: true,
      });
    }
  };

  const payouts = [];
  const msgStack = [];
  const creations = new Map();
  const onNewContract = (event) => {
    const creator = msgStack.length ? fromEvmAddress(msgStack[msgStack.length - 1].caller).toLowerCase() : contractAddress;
    creations.set(fromEvmAddress(event.address).toLowerCase(), creator);
    contractOwners.add(fromEvmAddress(event.address).toLowerCase());
  };
  const onBeforeMessage = (message) => {
    if (process.env.DBG_CALL2) console.error("DBG CALL2 to=" + bytesToHex(message.to) + " caller=" + bytesToHex(message.caller) + " data=" + (message.data||new Uint8Array(0)).toString("hex"));
    msgStack.push({
      to: message.to,
      caller: message.caller,
      value: BigInt(message.value || 0),
      delegatecall: !!message.delegatecall,
      transfers: [],
    });
    
    
    frames.push(message.to || evmThis);
  };
  const onAfterMessage = (result) => {
    const info = msgStack.pop();
    if (!info) return;
    frames.pop();
    if (result && result.execResult && !result.execResult.exceptionError) {
      if (!info.delegatecall && info.value > 0n && info.to && info.caller && !info.to.equals(info.caller)) {
        info.transfers.push({ to: fromEvmAddress(info.to), value: info.value.toString() });
      }
      if (msgStack.length) msgStack[msgStack.length - 1].transfers.push(...info.transfers);
      else payouts.push(...info.transfers);
    }
  };
  const evmEvents = vm.evm ? vm.evm.events : null;
  const events = evmEvents || vm.events;
  events.on('step', onStep);
  events.on('beforeMessage', onBeforeMessage);
  events.on('afterMessage', onAfterMessage);
  events.on('newContract', onNewContract);
  try {
    const block = params.block instanceof Object && params.block.header ? params.block : undefined;
    const result = await vm.evm.runCall({
      caller: params.caller,
      to: params.to,
      data: params.data || params.code,
      value: params.value || 0n,
      gasLimit: params.gasLimit,
      gasPrice: params.gasPrice,
      block,

    });
    const execResult = result && result.execResult ? result.execResult : result;
    const normalized = {
      execResult,
      returnValue: execResult.returnValue,
      gasUsed: execResult.executionGasUsed !== undefined ? execResult.executionGasUsed : execResult.gasUsed,
      gasRefund: execResult.gasRefund || 0n,
      logs: execResult.logs || [],
      _ccPayouts: payouts,
      createdAddress: result && result.createdAddress,
    };
    if (persist && !execResult.exceptionError) {
      try {
        const destroyed = new Set();
        for (const [address] of execResult.selfdestruct || []) {
          if (!vm.common.isActivatedEIP(6780) || execResult.createdAddresses?.has(address)) {
            destroyed.add(address.toLowerCase());
          }
        }
        for (const [address, creator] of creations) {
          if (destroyed.has(address) || (result.createdAddress && address === fromEvmAddress(result.createdAddress).toLowerCase())) continue;
          const evmAddress = toEvmAddress(address);
          const account = await stateManager.getAccount(evmAddress);
          
          if (!account || account.nonce === 0n) continue;
          if (beforeWrite) beforeWrite(address);
          const runtime = bytesToHex(await stateManager.getCode(evmAddress)).slice(2);
          db.prepare('INSERT OR REPLACE INTO smart_contracts VALUES (?,?,?,?,?)')
            .run(address, creator, runtime, 0, 0);
        }
        for (const [owner, slots] of writtenBy.entries()) {
          if (destroyed.has(owner)) continue;
          if (beforeWrite) beforeWrite(owner);
          await saveContractStorage(vm, owner, slots);
        }
        await flushAllContractBalances(vm, beforeWrite);
        if (result.createdAddress && !destroyed.has(fromEvmAddress(result.createdAddress).toLowerCase())) {
          await flushContractBalance(vm, fromEvmAddress(result.createdAddress), beforeWrite);
        }
        for (const address of destroyed) {
          if (beforeWrite) beforeWrite(address);
          for (const table of ['smart_contracts', 'smart_contract_accounts', 'smart_contract_nonces']) {
            db.prepare(`DELETE FROM ${table} WHERE lower(address) = ?`).run(address);
          }
          db.prepare('DELETE FROM smart_contract_storage WHERE lower(contract_address) = ?').run(address);
          await stateManager.deleteAccount(toEvmAddress(address));
        }
        
        
        normalized._ccPayouts = payouts.filter(p => BigInt(p.value) > 0n && !contractOwners.has(p.to.toLowerCase()))
          .map(({ to, value }) => ({ to, value }));
      } catch (err) {
        console.error('Failed to persist smart contract state', err);
        throw err;
      }
    }
    if (canCheckpoint) {
      if (persist && !execResult.exceptionError && typeof stateManager.commit === 'function') await stateManager.commit();
      else await stateManager.revert();
    }
    return normalized;
  } catch (err) {
    if (canCheckpoint) {
      try { await stateManager.revert(); } catch {}
    }
    throw err;
  } finally {
    events.off('step', onStep);
    events.off('beforeMessage', onBeforeMessage);
    events.off('afterMessage', onAfterMessage);
    events.off('newContract', onNewContract);
  }
}

function normalizeHex(input) {
  if (input instanceof Uint8Array) return bytesToHex(input);
  if (typeof input !== 'string') throw new TypeError('expected hex string or Uint8Array');
  return input.replace(/^0x/i, '').toLowerCase();
}

function toEvmAddress(systemAddress) {
  return new Address(hexToBytes('0x' + normalizeHex(systemAddress)));
}

function nonceToBytes(nonce) {
  const n = BigInt(nonce || 0);
  if (n === 0n) return Uint8Array.from([]);
  let hex = n.toString(16);
  if (hex.length % 2) hex = '0' + hex;
  return hexToBytes('0x' + hex);
}

function fromEvmAddress(evmBuf) {
  const bytes = evmBuf instanceof Uint8Array ? evmBuf : evmBuf.bytes;
  return bytesToHex(bytes);
}

function assertValidAddress(address, label) {
  if (typeof address !== 'string' || !/^0x[0-9a-fA-F]{40}$/.test(address)) {
    throw new TypeError(`${label} must be a valid EVM address (0x + 40 hex), got: ${address}`);
  }
}

function assertValidCode(code) {
  if (typeof code !== 'string' || !/^0x[0-9a-fA-F]*$/.test(code)) {
    throw new TypeError('code must be a hex string prefixed with 0x');
  }
  if (normalizeHex(code).length === 0) {
    throw new TypeError('code must not be empty');
  }
  if (normalizeHex(code).length / 2 > MAX_CONTRACT_CODE_SIZE) {
    throw new RangeError(`code exceeds max size of ${MAX_CONTRACT_CODE_SIZE} bytes`);
  }
}

function deriveContractAddress(senderAddress, nonce) {
  assertValidAddress(senderAddress, 'senderAddress');
  const senderBuf = Buffer.from(normalizeHex(senderAddress), 'hex');
  const contractBuf = generateAddress(senderBuf, nonceToBytes(nonce));
  return '0x' + bytesToHex(contractBuf).replace(/^0x/i, '');
}

function decodeRevertReason(returnValue) {
  try {
    const buf = returnValue instanceof Uint8Array ? returnValue : hexToBytes('0x' + normalizeHex(returnValue || ''));
    if (buf.length < 4) return null;
    const selector = bytesToHex(buf.slice(0, 4));
    if (buf.length >= 68 && selector === '0x08c379a0') {
      const length = Number(BigInt(bytesToHex(buf.slice(36, 68))));
      const start = 68;
      const end = start + length;
      if (end > buf.length) return null;
      return new TextDecoder().decode(buf.slice(start, end));
    }
    if (buf.length >= 36 && selector === '0x4e487b71') {
      const code = Number(BigInt(bytesToHex(buf.slice(4, 36))));
      const panicNames = { 0: 'GenericPanic', 1: 'Assert', 17: 'ArithmeticOverflow', 18: 'DivideByZero', 33: 'EnumConversion', 34: 'InvalidStorageAccess', 49: 'PopEmptyArray', 50: 'ArrayOutOfBounds', 65: 'MemoryAllocation', 81: 'InternalFunctionCall' };
      return `Panic(${code}): ${panicNames[code] || 'Unknown'}`;
    }
    return null;
  } catch (e) {
    return null;
  }
}

function parseResult(result) {
  if (result.execResult.exceptionError) {
    const rv = result.returnValue ? bytesToHex(result.returnValue) : '0x';
    if (process.env.DBG_POOL) console.error("DBG exceptionError:", JSON.stringify(result.execResult.exceptionError), "returnValue:", rv);

    const reason = decodeRevertReason(result.returnValue);
    if (!reason && rv !== '0x') {
      console.error(`[REVERT] raw returnValue=${rv} selector=${rv.slice(0, 10)}`);
    }
    const err = new Error(
      reason
        ? `contract reverted: ${reason}`
        : `contract reverted: ${result.execResult.exceptionError.error || result.execResult.exceptionError}`
    );
    err.code = 'VM_REVERT';
    err.gasUsed = String(result.gasUsed == null ? 0 : result.gasUsed);
    err.gasRefund = String(result.gasRefund == null ? 0 : result.gasRefund);
    if (reason) err.reason = reason;
    if (rv && rv !== '0x') err.revertData = rv;
    throw err;
  }
  return {
    returnValue: bytesToHex(result.returnValue),
    gasUsed: result.gasUsed.toString(),
    gasRefund: String(result.gasRefund || 0),
    logs: result.logs || [],
    payouts: result._ccPayouts || [],
  };
}

async function creditContractValue(vm, contractAddress, senderAddress, value) {
  const amount = BigInt(value || 0);
  if (amount === 0n) return;
  const evmAddr = toEvmAddress(contractAddress);
  const account = (await vm.stateManager.getAccount(evmAddr)) || new Account();
  account.balance += amount;
  await vm.stateManager.putAccount(evmAddr, account);
}

async function creditContractBalance(contractAddress, value) {
  assertPersistentExecutionAllowed();
  assertValidAddress(contractAddress, 'contractAddress');
  const amount = BigInt(value || 0);
  if (amount === 0n) return { credited: 0 };
  const vm = await getVm(contractAddress);
  await loadContractStorage(vm, contractAddress);
  await creditContractValue(vm, contractAddress, null, amount);
  await flushContractBalance(vm, contractAddress);
  return { credited: 1 };
}

async function CreateSmartContract(code, context, senderAddress, nonce, value = 0, gasLimit, gasPrice, persist = true, beforeWrite) {
  if (persist) assertPersistentExecutionAllowed(beforeWrite);
  assertValidAddress(senderAddress, 'senderAddress');
  assertValidCode(code);
  if (!Number.isInteger(nonce) || nonce < 0) throw new TypeError('nonce must be a non-negative integer');

  const contractAddress = deriveContractAddress(senderAddress, nonce);

  if (db) {
    const existing = db.prepare('SELECT address FROM smart_contracts WHERE lower(address) = lower(?)').get(contractAddress);
    if (existing) {
      const err = new Error(`contract already exists at ${contractAddress}`);
      err.code = 'CONTRACT_EXISTS';
      throw err;
    }
  }

  const vm = await getVm(contractAddress, true);
  if (persist) {
    if (beforeWrite) beforeWrite(contractAddress);
  }
  const senderEvm = toEvmAddress(senderAddress);
  const senderAccount = (await vm.stateManager.getAccount(senderEvm)) || new Account();
  senderAccount.nonce = BigInt(nonce);
  await vm.stateManager.putAccount(senderEvm, senderAccount);
  const blockCtx = (context && typeof context === 'object' && 'block' in context) ? context.block : context;
  const result = await runWithStorage(vm, contractAddress, {
    to: undefined,
    data: hexToBytes('0x' + normalizeHex(code)),
    gasLimit: BigInt(gasLimit == null ? initialSmartContractGasLimit : gasLimit),
    gasPrice: BigInt(gasPrice || initialSmartContractGasPrice),
    caller: senderEvm,
    value: BigInt(value || 0),
    ...(context && typeof context === 'object' && 'block' in context ? context : {}),
    block: blockCtx,
  }, persist, beforeWrite);

  const parsed = parseResult(result);
  const runtimeCode = normalizeHex(bytesToHex(result.returnValue));
  const destroyed = !!result.execResult.selfdestruct?.has(contractAddress)
    && (!vm.common.isActivatedEIP(6780) || !!result.execResult.createdAddresses?.has(contractAddress));
  if (runtimeCode.length / 2 > MAX_CONTRACT_CODE_SIZE) {
    throw new RangeError(`runtime code exceeds max size of ${MAX_CONTRACT_CODE_SIZE} bytes`);
  }

  if (db && persist && !destroyed) {
    const now = Math.floor(Date.now() / 1000);
    db.prepare(`
      INSERT INTO smart_contracts (address, creator, code, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?)
    `).run(contractAddress, senderAddress.toLowerCase(), runtimeCode, now, now);
  }

  return { ...parsed, contractAddress, runtimeCode: '0x' + runtimeCode, destroyed };
}

async function runSmartContract(contractAddress, senderAddress, data = '', value = 0, gasLimit, gasPrice, block, persist = false, beforeWrite) {
  if (persist) assertPersistentExecutionAllowed(beforeWrite);
  assertValidAddress(contractAddress, 'contractAddress');
  assertValidAddress(senderAddress, 'senderAddress');
  if (typeof data !== 'string' || !/^0x[0-9a-fA-F]*$/.test(data)) {
    throw new TypeError('data must be a hex string prefixed with 0x');
  }

  const contract = db
    ? db.prepare('SELECT code FROM smart_contracts WHERE lower(address) = lower(?)').get(contractAddress)
    : null;
  if (!contract) {
    const err = new Error(`contract not found at ${contractAddress}`);
    err.code = 'CONTRACT_NOT_FOUND';
    throw err;
  }

  const vm = await getVm(contractAddress, true);
  const params = {
    to: toEvmAddress(contractAddress),
    data: data ? hexToBytes('0x' + normalizeHex(data)) : new Uint8Array(0),
    gasLimit: BigInt(gasLimit == null ? initialSmartContractGasLimit : gasLimit),
    gasPrice: BigInt(gasPrice || initialSmartContractGasPrice),
    caller: toEvmAddress(senderAddress),
    value: BigInt(value || 0),
  };
  if (block) params.block = block;
  const result = await runWithStorage(vm, contractAddress, params, persist, beforeWrite);

  return parseResult(result);
}

function getSmartContract(contractAddress) {
  assertValidAddress(contractAddress, 'contractAddress');
  if (!db) return null;
  const row = db.prepare('SELECT * FROM smart_contracts WHERE lower(address) = lower(?)').get(contractAddress);
  return row || null;
}

function listSmartContracts() {
  if (!db) return [];
  return db.prepare('SELECT * FROM smart_contracts ORDER BY created_at DESC').all();
}

async function getAccountBalance(address, inVmOfContract) {
  assertValidAddress(address, 'address');
  const vm = inVmOfContract ? await getVm(inVmOfContract) : await getVm(address);
  const evmAddr = toEvmAddress(address);
  const account = (await vm.stateManager.getAccount(evmAddr)) || new Account();
  return account.balance;
}

module.exports = {
  setDatabase, clearVmCache, CreateSmartContract, runSmartContract, getSmartContract, listSmartContracts,
  getVm, loadAllContractState, saveContractStorage, loadContractStorage,
  SaveSmartContractState, InitialSmartContractGasPriceHumanReadable, deriveContractAddress,
  toChecksumAddress, toEvmAddress, fromEvmAddress, MAX_CONTRACT_CODE_SIZE, getAccountBalance,
  creditContractBalance,
};
