const GAS_PARAMS = {
  simpleTransferGas: 21000,
  gasPerByteZero: 4,
  gasPerByteNonZero: 16,
  initialBaseFee: 10 ** 9,
  blockGasLimit: 120000000,         
  targetBlockGasLimit: 60000000,       
  maxGasPerTx: 10000000,            
  initialSmartContractGasLimit: 10000000,
  initialSmartContractGasPrice: 10 ** 9,
};

function estimateIntrinsicGas(tx) {
  let gas = GAS_PARAMS.simpleTransferGas;
  let dataHex = '';
  if (tx.data) {
    dataHex = tx.data.startsWith('0x') ? tx.data.slice(2) : tx.data;
  }
  const data = dataHex ? Buffer.from(dataHex, 'hex') : Buffer.alloc(0);
  for (const byte of data) {
    gas += byte === 0 ? GAS_PARAMS.gasPerByteZero : GAS_PARAMS.gasPerByteNonZero;
  }
  return gas;
}

function capTxGasLimit(tx) {
  const intrinsic = estimateIntrinsicGas(tx);
  const requested = safeInt(tx.gas_limit, intrinsic);
  const limit = Math.min(GAS_PARAMS.maxGasPerTx, Math.max(intrinsic, requested));
  return { gasLimit: limit, capped: requested > GAS_PARAMS.maxGasPerTx };
}

function minimumFee(tx, baseFee) {
  
  
  const gasLimit = safeInt(tx && tx.gas_limit, estimateIntrinsicGas(tx || {}));
  const price = maximumGasPrice(tx, baseFee);
  return BigInt(Math.max(0, gasLimit)) * price;
}

function maximumGasPrice(tx, fallback = 1) {
  return BigInt((tx && tx.maxFeePerGas) || (tx && tx.gas_price) || fallback || 1);
}

function effectiveGasPrice(tx, baseFee = 0) {
  const base = BigInt(baseFee || 0);
  if (tx && tx.maxFeePerGas != null) {
    const cap = BigInt(tx.maxFeePerGas);
    const tip = BigInt(tx.maxPriorityFeePerGas || 0);
    const candidate = base + tip;
    return candidate < cap ? candidate : cap;
  }
  return BigInt((tx && tx.gas_price) || base || 0);
}

function totalGasUsed(tx, executionGasUsed = 0, gasRefund = 0) {
  const intrinsic = estimateIntrinsicGas(tx);
  const limit = Math.max(intrinsic, safeInt(tx && tx.gas_limit, intrinsic));
  const executionLimit = Math.max(0, limit - intrinsic);
  const execution = Math.min(executionLimit, Math.max(0, safeInt(executionGasUsed, 0)));
  
  const refund = Math.min(Math.max(0, safeInt(gasRefund, 0)), Math.floor((intrinsic + execution) / 5));
  return intrinsic + execution - refund;
}

function safeInt(v, def) { const n = Number(v); return Number.isFinite(n) ? Math.trunc(n) : def; }

function nextBaseFee(parentBaseFee, parentGasUsed, targetGas, minGasPrice) {
  if (parentGasUsed === targetGas) return parentBaseFee;
  const delta = parentGasUsed > targetGas
    ? (parentBaseFee * BigInt(parentGasUsed - targetGas)) / BigInt(targetGas) / 8n
    : -(parentBaseFee * BigInt(targetGas - parentGasUsed)) / BigInt(targetGas) / 8n;
  let next = parentBaseFee + delta;

  if (next < BigInt(minGasPrice)) next = BigInt(minGasPrice);
  return next;
}

module.exports = {
  GAS_PARAMS,
  estimateIntrinsicGas,
  nextBaseFee,
  capTxGasLimit,
  minimumFee,
  totalGasUsed,
  maximumGasPrice,
  effectiveGasPrice,
};
