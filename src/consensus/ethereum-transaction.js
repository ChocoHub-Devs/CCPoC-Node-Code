'use strict';

const { Transaction } = require('ethers');

function decodeRawTransaction(raw) {
  if (typeof raw !== 'string' || !/^0x(?:[0-9a-fA-F]{2})+$/.test(raw)) throw new Error('invalid raw transaction hex');
  const parsed = Transaction.from(raw);
  if (parsed.type !== 0 && parsed.type !== 2) throw new Error(`unsupported transaction type ${parsed.type}`);
  if (!parsed.isSigned()) throw new Error('unsigned raw transaction');
  if (parsed.type === 2 && parsed.maxPriorityFeePerGas > parsed.maxFeePerGas) throw new Error('priority fee exceeds max fee per gas');
  if (parsed.serialized.toLowerCase() !== raw.toLowerCase()) throw new Error('noncanonical raw transaction');
  if (parsed.chainId <= 0n) throw new Error('missing protected chain id');
  if (!Number.isSafeInteger(parsed.nonce) || parsed.nonce < 0 || parsed.gasLimit > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error('unsafe nonce or gas limit');
  if (parsed.accessList?.length) throw new Error('nonempty access lists are not supported');
  const sig = parsed.signature;
  const tx = {
    hash: parsed.hash, from_addr: parsed.from.toLowerCase(), to_addr: parsed.to?.toLowerCase() || '',
    value: parsed.value.toString(), nonce: parsed.nonce, gas_limit: Number(parsed.gasLimit),
    gas_price: (parsed.gasPrice ?? 0n).toString(), chain_id: parsed.chainId.toString(), data: parsed.data,
    fee: (parsed.gasLimit * (parsed.maxFeePerGas ?? parsed.gasPrice)).toString(),
    priority_fee: (parsed.maxPriorityFeePerGas ?? 0n).toString(),
    signature: Buffer.concat([Buffer.from([sig.yParity]), Buffer.from(sig.r.slice(2) + sig.s.slice(2), 'hex')]).toString('base64'),
    raw: parsed.serialized, rpc_signature: parsed.serialized, rpc_type: 'evm', type: parsed.type,
    v: (sig.networkV ?? BigInt(sig.yParity)).toString(), r: sig.r, s: sig.s, status: 1,
  };
  if (parsed.type === 2) {
    tx.maxFeePerGas = parsed.maxFeePerGas.toString();
    tx.maxPriorityFeePerGas = parsed.maxPriorityFeePerGas.toString();
    tx.accessList = [];
  }
  return tx;
}

function validateRawTransaction(tx) {
  if (!tx.raw) {
    if (Number(tx.type ?? tx.tx_type ?? 0) !== 0 || Number(tx.tx_type ?? 0) !== 0 ||
      [tx.maxFeePerGas, tx.maxPriorityFeePerGas, tx.max_fee_per_gas, tx.max_priority_fee_per_gas].some(v => v != null && v !== '') ||
      (tx.accessList != null && (!Array.isArray(tx.accessList) || tx.accessList.length))) {
      throw new Error('typed transaction requires a signed raw envelope');
    }
    return null;
  }
  const signed = decodeRawTransaction(tx.raw);
  for (const key of ['hash', 'from_addr', 'to_addr', 'data']) {
    if (String(tx[key] ?? '').toLowerCase() !== signed[key].toLowerCase()) throw new Error(`signed transaction ${key} mismatch`);
  }
  for (const key of ['value', 'nonce', 'gas_limit', 'gas_price', 'chain_id', 'fee']) {
    if (tx[key] == null || BigInt(tx[key]) !== BigInt(signed[key])) throw new Error(`signed transaction ${key} mismatch`);
  }
  for (const [key, canonical] of [
    ['type', 'type'], ['tx_type', 'type'], ['priority_fee', 'priority_fee'],
    ['maxFeePerGas', 'maxFeePerGas'], ['max_fee_per_gas', 'maxFeePerGas'],
    ['maxPriorityFeePerGas', 'maxPriorityFeePerGas'], ['max_priority_fee_per_gas', 'maxPriorityFeePerGas'],
    ['v', 'v'], ['r', 'r'], ['s', 's'],
  ]) {
    if (tx[key] != null && tx[key] !== '' && (signed[canonical] == null || BigInt(tx[key]) !== BigInt(signed[canonical]))) throw new Error(`signed transaction ${key} mismatch`);
  }
  if (signed.type === 2 && (tx.maxFeePerGas == null || tx.maxPriorityFeePerGas == null)) throw new Error('missing signed type 2 fee fields');
  if (tx.accessList != null && (!Array.isArray(tx.accessList) || tx.accessList.length)) throw new Error('nonempty access lists are not supported');
  const signature = Buffer.isBuffer(tx.signature) ? tx.signature : Buffer.from(String(tx.signature || '').replace(/^0x/, ''), String(tx.signature).startsWith('0x') ? 'hex' : 'base64');
  if (!signature.equals(Buffer.from(signed.signature, 'base64'))) throw new Error('signed transaction signature mismatch');
  return signed;
}

module.exports = { decodeRawTransaction, validateRawTransaction };
