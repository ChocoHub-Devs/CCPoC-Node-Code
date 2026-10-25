'use strict';

const { Transaction } = require('ethers');
const { hashTransaction } = require('../crypto-utils/crypto');

function toWireTransaction(row, { stored = false } = {}) {
  let source = row;
  if (stored && row.wire_json) {
    const saved = JSON.parse(row.wire_json);
    if (!saved || typeof saved !== 'object' || saved.hash !== row.hash) throw new Error('stored transaction wire hash mismatch');
    source = { ...row, ...saved };
  }
  const wire = Object.fromEntries(Object.entries(source).filter(([key]) => !key.startsWith('_') && key !== 'wire_json'));
  if (stored && source.fee_cap != null && source.block_height != null) wire.fee = String(source.fee_cap);
  wire.type = Number(source.type ?? source.tx_type ?? 0);
  if (source.max_fee_per_gas && source.maxFeePerGas == null) wire.maxFeePerGas = String(source.max_fee_per_gas);
  if (wire.maxFeePerGas != null && source.maxPriorityFeePerGas == null) wire.maxPriorityFeePerGas = String(source.max_priority_fee_per_gas || '0');
  if (stored && !wire.raw && /^[0-9a-fA-F]{64}$/.test(wire.hash || '') && hashTransaction(wire) !== wire.hash) {
    for (const nonce of [wire.nonce, String(wire.nonce)]) {
      for (const gas_limit of [wire.gas_limit, String(wire.gas_limit)]) {
        const candidate = { ...wire, nonce, gas_limit };
        if (hashTransaction(candidate) === wire.hash) {
          wire.nonce = nonce;
          wire.gas_limit = gas_limit;
        }
      }
    }
  }
  if (!wire.raw && wire.type === 0 && wire.signature && /^0x[0-9a-fA-F]{64}$/.test(wire.hash || '')) {
    try {
      const sig = wire.signature.startsWith('0x') ? Buffer.from(wire.signature.slice(2), 'hex') : Buffer.from(wire.signature, 'base64');
      if (sig.length === 65 && sig[0] <= 1) {
        const signed = Transaction.from({
          type: 0, chainId: BigInt(wire.chain_id), nonce: Number(wire.nonce),
          to: wire.to_addr || null, value: BigInt(wire.value || 0),
          gasLimit: BigInt(wire.gas_limit), gasPrice: BigInt(wire.gas_price), data: wire.data || '0x',
          signature: { r: `0x${sig.subarray(1, 33).toString('hex')}`, s: `0x${sig.subarray(33).toString('hex')}`, yParity: sig[0] },
        });
        if (signed.hash.toLowerCase() === wire.hash.toLowerCase()) wire.raw = signed.serialized;
      }
    } catch {}
  }
  if (wire.raw) wire.rpc_type = 'evm';
  return JSON.parse(JSON.stringify(wire, (_key, value) => typeof value === 'bigint' ? value.toString() : value));
}

function toWireBlock(block, { stored = false } = {}) {
  const wire = Object.fromEntries(Object.entries(block).filter(([key]) => !key.startsWith('_')));
  if (Array.isArray(block.transactions)) wire.transactions = block.transactions.map((tx) => toWireTransaction(tx, { stored }));
  return JSON.parse(JSON.stringify(wire, (_key, value) => typeof value === 'bigint' ? value.toString() : value));
}

module.exports = { toWireTransaction, toWireBlock };
