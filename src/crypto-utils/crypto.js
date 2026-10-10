const crypto = require('crypto');
const { keccak256 } = require('ethers');
const { secp256k1 } = require('@noble/curves/secp256k1.js');
const rlp = require('@ethereumjs/rlp');
const ZERO_HASH = '0'.repeat(64);

const SECP_COMPRESSED_LEN = 33;
const SECP_UNCOMPRESSED_LEN = 65;

function isHexString(v) {
  if (typeof v !== 'string') return false;
  return /^0x[0-9a-fA-F]+$/.test(v) || /^[0-9a-fA-F]+$/.test(v);
}

function stripHex(v) {
  if (typeof v !== 'string') return v;
  return v.replace(/^0x/i, '');
}

function normalizeSecpPublicKey(pub) {
  if (!pub) throw new Error('Invalid public key');
  let raw = null;
  if (typeof pub === 'string') {
    if (/^[0-9a-fA-F]+$/.test(stripHex(pub)) && stripHex(pub).length >= 64) {
      const hex = stripHex(pub);
      raw = Buffer.from((hex.length % 2 ? '0' : '') + hex, 'hex');
    } else {
      try { raw = Buffer.from(pub, 'base64'); } catch { raw = null; }
    }
  } else if (Buffer.isBuffer(pub)) {
    raw = pub;
  } else if (pub instanceof Uint8Array) {
    raw = Buffer.from(pub);
  }
  if (!raw || (raw.length !== SECP_COMPRESSED_LEN && raw.length !== SECP_UNCOMPRESSED_LEN && raw.length !== 64)) {
    throw new Error('Invalid secp256k1 public key');
  }
  if (raw.length === SECP_UNCOMPRESSED_LEN) {
    return Buffer.from(secp256k1.ProjectivePoint.fromHex(raw).toRawBytes(true));
  }
  if (raw.length === 64) {
    const uncompressed = Buffer.concat([Buffer.from([0x04]), raw]);
    return Buffer.from(secp256k1.ProjectivePoint.fromHex(uncompressed).toRawBytes(true));
  }
  secp256k1.ProjectivePoint.fromHex(raw);
  return raw;
}

function secpEncodePublicKey(pub) {
  return normalizeSecpPublicKey(pub).toString('base64');
}

function decodePublicKey(pub) {
  const compressed = normalizeSecpPublicKey(pub);
  const uncompressed = secp256k1.ProjectivePoint.fromHex(compressed).toRawBytes(false);
  return Buffer.from(uncompressed.slice(1));
}

function secpPublicKeyFromPrivate(privateKeyHex) {
  const pk = Buffer.from(stripHex(String(privateKeyHex)), 'hex');
  if (pk.length !== 32) throw new Error('Invalid private key length');
  return Buffer.from(secp256k1.getPublicKey(new Uint8Array(pk), true));
}

function secpAddressFromPrivate(privateKeyHex) {
  return pubkeyToAddress(secpPublicKeyFromPrivate(privateKeyHex));
}

function signMessage(message, privateKeyHex) {
  const pk = Buffer.from(stripHex(String(privateKeyHex)), 'hex');
  if (pk.length !== 32) throw new Error('Invalid private key length');
  const msgBytes = Buffer.isBuffer(message) ? message : Buffer.from(String(message), 'utf8');
  const digest = Uint8Array.from(Buffer.from(stripHex(keccak256('0x' + msgBytes.toString('hex'))), 'hex'));
  const recovered = secp256k1.sign(digest, new Uint8Array(pk), { format: 'recovered', prehash: false });
  const bufR = Buffer.alloc(32);
  const bufS = Buffer.alloc(32);
  const bigToBuf = (b) => { const hex = b.toString(16).padStart(64, '0'); return Buffer.from(hex, 'hex'); };
  bigToBuf(recovered.r).copy(bufR);
  bigToBuf(recovered.s).copy(bufS);
  return Buffer.concat([Buffer.from([recovered.recovery]), bufR, bufS]).toString('base64');
}

function verifySignature(message, sigB64, pubB64) {
  try {
    const sig = Buffer.isBuffer(sigB64) ? sigB64 : Buffer.from(String(sigB64), 'base64');
    if (sig.length !== 65) return false;
    const pub = normalizeSecpPublicKey(pubB64);
    const msgBytes = Buffer.isBuffer(message) ? message : Buffer.from(String(message), 'utf8');
    const digest = Uint8Array.from(Buffer.from(stripHex(keccak256('0x' + msgBytes.toString('hex'))), 'hex'));
    const signature = secp256k1.Signature.fromBytes(sig.slice(1, 65));
    return secp256k1.verify(signature, digest, pub, { prehash: false });
  } catch { return false; }
}

function recoverPublicKey(message, sigB64) {
  const sig = Buffer.isBuffer(sigB64) ? sigB64 : Buffer.from(String(sigB64), 'base64');
  if (sig.length !== 65) throw new Error('Invalid signature length');
  const msgBytes = Buffer.isBuffer(message) ? message : Buffer.from(String(message), 'utf8');
  const digest = Uint8Array.from(Buffer.from(stripHex(keccak256('0x' + msgBytes.toString('hex'))), 'hex'));
  const signature = secp256k1.Signature.fromBytes(sig.slice(1, 65)).addRecoveryBit(sig[0]);
  return Buffer.from(signature.recoverPublicKey(digest).toRawBytes(false));
}

function recoverPublicKeyForAddress(message, sigB64, expectedAddress) {
  const sig = Buffer.isBuffer(sigB64) ? sigB64 : Buffer.from(String(sigB64), 'base64');
  if (sig.length !== 65) return null;
  const msgBytes = Buffer.isBuffer(message) ? message : Buffer.from(String(message), 'utf8');
  const digest = Uint8Array.from(Buffer.from(stripHex(keccak256('0x' + msgBytes.toString('hex'))), 'hex'));
  const expected = String(expectedAddress || '').toLowerCase();
  let raw;
  try { raw = secp256k1.Signature.fromBytes(sig.slice(1, 65)); } catch { return null; }
  for (let i = 0; i < 4; i++) {
    try {
      const pub = Buffer.from(raw.addRecoveryBit(i).recoverPublicKey(digest).toRawBytes(false));
      if (pubkeyToAddress(pub).toLowerCase() === expected) return pub;
    } catch { /* try next recovery bit */ }
  }
  return null;
}

function pubkeyToAddress(pub) {
  const raw = decodePublicKey(pub);
  if (raw.length !== 64) throw new Error('Invalid secp256k1 public key');
  const hash = stripHex(keccak256('0x' + raw.toString('hex')));
  return '0x' + hash.slice(-40);
}

function pubKeyToAddress(pubKey) { return pubkeyToAddress(pubKey); }

function privateKeyToAddress(privateKeyHex) {
  return pubkeyToAddress(secpPublicKeyFromPrivate(privateKeyHex));
}

function toChecksumAddress(address) {
  const lower = String(address || '').toLowerCase().replace(/^0x/i, '');
  const hash = keccak256('0x' + lower).replace(/^0x/i, '');
  let out = '0x';
  for (let i = 0; i < lower.length; i++) {
    out += parseInt(hash[i], 16) >= 8 ? lower[i].toUpperCase() : lower[i];
  }
  return out;
}

function isValidAddress(address) {
  return typeof address === 'string' && /^0x[0-9a-fA-F]{40}$/.test(address);
}


function toMinBytes(v) {
  const n = (typeof v === 'bigint') ? v : (() => { try { return BigInt(v == null || v === '' ? 0 : v); } catch { return 0n; } })();
  if (n === 0n) return Buffer.alloc(0);
  let hex = n.toString(16);
  if (hex.length % 2) hex = '0' + hex;
  return Buffer.from(hex, 'hex');
}

function hexToBuffer(hex) {
  if (hex == null) return Buffer.alloc(0);
  let h = String(hex).replace(/^0x/i, '');
  if (h.length % 2) h = '0' + h;
  return Buffer.from(h, 'hex');
}

function encodeLegacyTxPayload(tx) {
  const to = tx.to_addr ? hexToBuffer(tx.to_addr) : Buffer.alloc(0);
  const data = tx.data ? hexToBuffer(tx.data) : Buffer.alloc(0);
  return [
    toMinBytes(tx.nonce == null ? 0 : tx.nonce),
    toMinBytes(tx.gas_price),
    toMinBytes(tx.gas_limit),
    to, 
    toMinBytes(tx.value),
    data,
    toMinBytes(tx.chain_id || 0),
    Buffer.alloc(0),
    Buffer.alloc(0),
  ];
}

function evmTxDigest(tx) {
  return stripHex(keccak256('0x' + Buffer.from(rlp.encode(encodeLegacyTxPayload(tx))).toString('hex')));
}

function evmTxHash(tx) {
  return '0x' + evmTxDigest(tx);
}

function signTransactionTx(tx, privateKeyHex) {
  const pk = Buffer.from(stripHex(String(privateKeyHex)), 'hex');
  if (pk.length !== 32) throw new Error('Invalid private key length');
  const digest = Uint8Array.from(Buffer.from(evmTxDigest(tx), 'hex'));
  const recovered = secp256k1.sign(digest, new Uint8Array(pk), { format: 'recovered', prehash: false });
  const bigToBuf = (b) => Buffer.from(b.toString(16).padStart(64, '0'), 'hex');
  const r = bigToBuf(recovered.r);
  const s = bigToBuf(recovered.s);
  return Buffer.concat([Buffer.from([recovered.recovery]), r, s]).toString('base64');
}

function recoverTransactionSender(tx) {
  const sigIn = tx && (tx.signature || tx.rpc_signature);
  if (!sigIn) return null;
  let sig;
  if (Buffer.isBuffer(sigIn)) sig = sigIn;
  else {
    const str = String(sigIn);
    if (/^0x[0-9a-fA-F]+$/.test(str) || /^[0-9a-fA-F]+$/.test(str)) {
      sig = Buffer.from(str.replace(/^0x/i, ''), 'hex');
      if (sig.length !== 65 && !/^0x/.test(str)) sig = Buffer.from(str, 'base64');
    } else {
      sig = Buffer.from(str, 'base64');
    }
  }
  if (sig.length !== 65) return null;
  const digest = Uint8Array.from(Buffer.from(evmTxDigest(tx), 'hex'));
  try {
    const signature = secp256k1.Signature.fromBytes(sig.slice(1, 65)).addRecoveryBit(sig[0]);
    const pub = Buffer.from(signature.recoverPublicKey(digest).toRawBytes(false));
    return pubkeyToAddress(pub).toLowerCase();
  } catch { return null; }
}

function signatureToHex(sigB64) {
  const sig = Buffer.isBuffer(sigB64) ? sigB64 : Buffer.from(String(sigB64), 'base64');
  return '0x' + sig.toString('hex');
}

function signatureFromHex(hex) {
  return Buffer.from(stripHex(hex), 'hex').toString('base64');
}

function sha256hex(data) {
  const input = Buffer.isBuffer(data) ? data : Buffer.from(String(data), 'utf8');
  return crypto.createHash('sha256').update(input).digest('hex');
}

function sha256buf(data) {
  const input = Buffer.isBuffer(data) ? data : Buffer.from(String(data), 'utf8');
  return crypto.createHash('sha256').update(input).digest();
}

function merkleRootBuf(hashes) {
  if (!hashes.length) return Buffer.alloc(32);
  const N = hashes.length;
  const buf = Buffer.allocUnsafe(N * 32);
  for (let i = 0; i < N; i++) {
    const h = hashes[i];
    if (Buffer.isBuffer(h)) h.copy(buf, i * 32);
    else Buffer.from(h, 'hex').copy(buf, i * 32);
  }
  return merkleRootBuf2(buf, N);
}

function merkleRootBuf2(buf, N) {
  buf = Buffer.from(buf);
  let len = N;
  const pairBuf = Buffer.allocUnsafe(64);
  while (len > 1) {
    const newLen = (len + 1) >> 1;
    for (let i = 0; i < newLen; i++) {
      const li = i * 2;
      const ri = Math.min(li + 1, len - 1);
      buf.copy(pairBuf, 0, li * 32);
      buf.copy(pairBuf, 32, ri * 32);
      sha256buf(pairBuf).copy(buf, i * 32);
    }
    len = newLen;
  }
  return buf.subarray(0, 32);
}

function computeMerkleTreeNodes(leafBuf, N) {
  const buf = Buffer.allocUnsafe(N * 32);
  leafBuf.copy(buf, 0, 0, N * 32);
  const totalInternal = merkleTreeInternalNodeCount(N);
  const result = Buffer.alloc(totalInternal * 32);
  let writeOffset = 0;
  let len = N;
  const pairBuf = Buffer.allocUnsafe(64);
  while (len > 1) {
    const newLen = (len + 1) >> 1;
    for (let i = 0; i < newLen; i++) {
      const li = i * 2;
      const ri = Math.min(li + 1, len - 1);
      buf.copy(pairBuf, 0, li * 32);
      buf.copy(pairBuf, 32, ri * 32);
      const h = sha256buf(pairBuf);
      h.copy(buf, i * 32);
      h.copy(result, writeOffset + i * 32);
    }
    writeOffset += newLen * 32;
    len = newLen;
  }
  return result;
}

function computeMerkleProofBuf(leaves, leafIndex) {
  const N = leaves.length;
  const buf = Buffer.allocUnsafe(N * 32);
  for (let i = 0; i < N; i++) {
    const h = leaves[i];
    if (Buffer.isBuffer(h)) h.copy(buf, i * 32);
    else Buffer.from(h, 'hex').copy(buf, i * 32);
  }
  return computeMerkleProofBuf2(buf, N, leafIndex);
}

function computeMerkleProofBuf2(buf, N, leafIndex) {
  const proof = [];
  let idx = leafIndex;
  let len = N;
  const pairBuf = Buffer.allocUnsafe(64);

  while (len > 1) {
    const sibIdx = idx ^ 1;
    if (sibIdx < len) {
      const sib = Buffer.allocUnsafe(32);
      buf.copy(sib, 0, sibIdx * 32);
      proof.push(sib);
    }

    const newLen = (len + 1) >> 1;
    for (let i = 0; i < newLen; i++) {
      const li = i * 2;
      const ri = Math.min(li + 1, len - 1);
      buf.copy(pairBuf, 0, li * 32);
      buf.copy(pairBuf, 32, ri * 32);
      const h = sha256buf(pairBuf);
      h.copy(buf, i * 32);
    }

    len = newLen;
    idx >>= 1;
  }

  return proof;
}

function verifyMerkleProofBuf(leafHash, leafIndex, totalLeaves, proof, root) {
  let hash = Buffer.isBuffer(leafHash) ? leafHash : Buffer.from(leafHash, 'hex');
  let idx = leafIndex;
  let count = totalLeaves;
  let pIdx = 0;
  while (count > 1) {
    const isOddLast = (count % 2 === 1 && idx === count - 1);
    if (isOddLast) {
      hash = sha256buf(Buffer.concat([hash, hash]));
    } else if (idx % 2 === 0) {
      if (pIdx >= proof.length) return false;
      const sibling = Buffer.isBuffer(proof[pIdx]) ? proof[pIdx] : Buffer.from(proof[pIdx], 'hex');
      hash = sha256buf(Buffer.concat([hash, sibling]));
      pIdx++;
    } else {
      if (pIdx >= proof.length) return false;
      const sibling = Buffer.isBuffer(proof[pIdx]) ? proof[pIdx] : Buffer.from(proof[pIdx], 'hex');
      hash = sha256buf(Buffer.concat([sibling, hash]));
      pIdx++;
    }
    idx = Math.floor(idx / 2);
    count = Math.ceil(count / 2);
  }
  const rootBuf = Buffer.isBuffer(root) ? root : Buffer.from(root, 'hex');
  return hash.equals(rootBuf);
}

function safeInt(value, def = 0) {
  const n = parseInt(value, 10);
  return isNaN(n) ? def : n;
}

function safeBigInt(value, def = 0n) {
  if (typeof value === 'bigint') return value;
  try { return BigInt(value); } catch { return def; }
}

function merkleRoot(hashes) {
  if (!hashes.length) return ZERO_HASH;
  let nodes = [...hashes];
  while (nodes.length > 1) {
    const next = [];
    for (let i = 0; i < nodes.length; i += 2) {
      const left = nodes[i];
      const right = i + 1 < nodes.length ? nodes[i + 1] : left;
      next.push(sha256hex(left + right));
    }
    nodes = next;
  }
  return nodes[0];
}

function merkleRootBuffer(hashes) {
  if (!hashes.length) return Buffer.alloc(32).toString('hex');
  const bufHashes = hashes.map(h => Buffer.from(h, 'hex'));
  return merkleRootBuf(bufHashes).toString('hex');
}

function computeMerkleProof(leaves, leafIndex) {
  let nodes = [...leaves];
  let idx = leafIndex;
  const proof = [];
  while (nodes.length > 1) {
    const next = [];
    for (let i = 0; i < nodes.length; i += 2) {
      const left = nodes[i];
      const right = i + 1 < nodes.length ? nodes[i + 1] : left;
      next.push(sha256hex(left + right));
    }
    if (nodes.length % 2 === 1 && idx === nodes.length - 1) {
    } else if (idx % 2 === 0) {
      proof.push(nodes[idx + 1]);
    } else {
      proof.push(nodes[idx - 1]);
    }
    nodes = next;
    idx = Math.floor(idx / 2);
  }
  return proof;
}

function verifyMerkleProof(leafHash, leafIndex, totalLeaves, proof, root) {
  let hash = leafHash;
  let idx = leafIndex;
  let count = totalLeaves;
  let pIdx = 0;
  while (count > 1) {
    const isOddLast = (count % 2 === 1 && idx === count - 1);
    if (isOddLast) {
      hash = sha256hex(hash + hash);
    } else if (idx % 2 === 0) {
      if (pIdx >= proof.length) return false;
      hash = sha256hex(hash + proof[pIdx++]);
    } else {
      if (pIdx >= proof.length) return false;
      hash = sha256hex(proof[pIdx++] + hash);
    }
    idx = Math.floor(idx / 2);
    count = Math.ceil(count / 2);
  }
  return hash === root;
}

function canonicalTxMessage(tx) {
  return JSON.stringify({
    chain_id: String(tx.chain_id || '0'),
    data: String(tx.data || ''),
    fee: String(tx.fee || '0'),
    from_addr: tx.from_addr,
    gas_limit: tx.gas_limit || 21000,
    gas_price: String(tx.gas_price || '1'),
    nonce: tx.nonce,
    priority_fee: String(tx.priority_fee || '0'),
    to_addr: tx.to_addr || '',
    value: String(tx.value),
  }, [
    'chain_id', 'data', 'fee', 'from_addr', 'gas_limit', 'gas_price',
    'nonce', 'priority_fee', 'to_addr', 'value',
  ].sort());
}

function hashTransaction(tx) {
  const d = {
    chain_id: String(tx.chain_id || '0'),
    data: String(tx.data || ''),
    fee: String(tx.fee || '0'),
    from_addr: tx.from_addr,
    gas_limit: tx.gas_limit || 21000,
    gas_price: String(tx.gas_price || '1'),
    nonce: tx.nonce,
    priority_fee: String(tx.priority_fee || '0'),
    to_addr: tx.to_addr || '',
    value: String(tx.value),
  };
  return sha256hex(JSON.stringify(d, Object.keys(d).sort()));
}

function proofMessage(challengeId, miner, deadline, plotId) {
  return JSON.stringify({
    type: 'poc_proof',
    challenge_id: String(challengeId),
    miner: String(miner).toLowerCase(),
    deadline: String(deadline),
    plot_id: String(plotId),
  }, ['type', 'challenge_id', 'miner', 'deadline', 'plot_id'].sort());
}

function plotRegisterMessage(miner, plotId, merkleRoot, sizeGb, totalScoops) {
  return JSON.stringify({
    type: 'plot_register',
    miner: String(miner).toLowerCase(),
    plot_id: String(plotId),
    merkle_root: String(merkleRoot),
    size_gb: String(sizeGb),
    total_scoops: String(totalScoops),
  }, ['merkle_root', 'miner', 'plot_id', 'size_gb', 'total_scoops', 'type'].sort());
}

const VRF_H2C_DOMAIN = Buffer.from('CC-VRF-h2c-v2');
const VRF_SECRET_DOMAIN = Buffer.from('CC-VRF-secret-v1');
const VRF_C_DOMAIN = Buffer.from('CC-VRF-c-v1');
const POINT_AT_INFINITY = null;

function vrfHashToCurve(merkleRootHex) {
  const raw = stripHex(String(merkleRootHex));
  const input = Buffer.from(raw, 'hex');
  for (let i = 0; i < 4096; i++) {
    const x = crypto.createHash('sha256').update(Buffer.concat([VRF_H2C_DOMAIN, input, Buffer.from(String(i))])).digest();
    try {
      const pt = secp256k1.ProjectivePoint.fromHex(Buffer.concat([Buffer.from([0x02]), x]));
      if (pt.equals(secp256k1.ProjectivePoint.ZERO)) continue;
      return pt;
    } catch { /* x not a valid field element / curve point, increment */ }
  }
  throw new Error('vrfHashToCurve: failed to hash merkle_root to a curve point');
}

function vrfDerivePlotSecret(minerPrivateKeyHex, plotId, merkleRootHex) {
  const pk = Buffer.from(stripHex(String(minerPrivateKeyHex)), 'hex');
  if (pk.length !== 32) throw new Error('Invalid private key length');
  const seed = Buffer.concat([
    VRF_SECRET_DOMAIN,
    pk,
    Buffer.from(String(plotId || ''), 'utf8'),
    Buffer.from(stripHex(String(merkleRootHex)), 'hex'),
  ]);
  const digest = crypto.createHash('sha256').update(seed).digest();
  const idx = BigInt('0x' + digest.toString('hex'));
  const n = secp256k1.CURVE.n;
  let x = idx % n;
  if (x === 0n) x = 1n;
  return x;
}

function vrfProve(minerPrivateKeyHex, plotId, merkleRootHex) {
  const x = vrfDerivePlotSecret(minerPrivateKeyHex, plotId, merkleRootHex);
  const G = secp256k1.ProjectivePoint.BASE;
  const H = vrfHashToCurve(merkleRootHex);
  const n = secp256k1.CURVE.n;
  const Y = G.multiply(x);
  const gamma = H.multiply(x);
  const output = crypto.createHash('sha256').update(gamma.toRawBytes(true)).digest('hex');

  let c = 0n;
  let s = 0n;
  let U, V;
  for (let attempt = 0; attempt < 64; attempt++) {
    const k = BigInt('0x' + crypto.randomBytes(32).toString('hex')) % n;
    U = G.multiply(k);
    V = H.multiply(k);
    const challenge = crypto.createHash('sha256').update(Buffer.concat([
      VRF_C_DOMAIN, G.toRawBytes(true), Y.toRawBytes(true),
      H.toRawBytes(true), gamma.toRawBytes(true),
      U.toRawBytes(true), V.toRawBytes(true),
    ])).digest('hex');
    c = BigInt('0x' + challenge) % n;
    s = (k + c * x) % n;
    if (s !== 0n) break;
  }

  return {
    public_key: Buffer.from(Y.toRawBytes(true)).toString('base64'),
    output,
    proof: {
      gamma: Buffer.from(gamma.toRawBytes(true)).toString('base64'),
      c: c.toString(16),
      s: s.toString(16),
    },
  };
}

function vrfVerify(publicKeyB64, merkleRootHex, outputHex, proof) {
  try {
    if (!proof || typeof proof !== 'object') return false;
    const G = secp256k1.ProjectivePoint.BASE;
    const n = secp256k1.CURVE.n;
    const Y = secp256k1.ProjectivePoint.fromHex(Buffer.from(String(publicKeyB64), 'base64'));
    if (Y.equals(secp256k1.ProjectivePoint.ZERO)) return false;
    const H = vrfHashToCurve(merkleRootHex);
    const gamma = secp256k1.ProjectivePoint.fromHex(Buffer.from(String(proof.gamma), 'base64'));
    if (gamma.equals(secp256k1.ProjectivePoint.ZERO)) return false;

    const outputCheck = crypto.createHash('sha256').update(gamma.toRawBytes(true)).digest('hex');
    if (outputCheck !== stripHex(String(outputHex))) return false;

    const c = BigInt.asUintN(256, BigInt('0x' + String(proof.c)));
    const s = BigInt.asUintN(256, BigInt('0x' + String(proof.s)));
    if (c >= n || s >= n) return false;

    const U = G.multiply(s).subtract(Y.multiply(c));
    const V = H.multiply(s).subtract(gamma.multiply(c));

    const challenge = crypto.createHash('sha256').update(Buffer.concat([
      VRF_C_DOMAIN, G.toRawBytes(true), Y.toRawBytes(true),
      H.toRawBytes(true), gamma.toRawBytes(true),
      U.toRawBytes(true), V.toRawBytes(true),
    ])).digest('hex');
    const cPrime = BigInt('0x' + challenge) % n;
    return cPrime === c;
  } catch { return false; }
}

function hashBlock(bloco) {
  let rewardsStr = '';
  if (Array.isArray(bloco.rewards)) {
    const normalized = bloco.rewards.map(r => {
      const n = {};
      for (const k of Object.keys(r).sort()) n[k] = r[k];
      return n;
    });
    rewardsStr = JSON.stringify(normalized);
  }
  let winnerProofStr = '';
  if (bloco.winner_proof && typeof bloco.winner_proof === 'object') {
    const wp = {};
    for (const k of Object.keys(bloco.winner_proof).sort()) wp[k] = bloco.winner_proof[k];
    winnerProofStr = JSON.stringify(wp);
  }
  const d = {
    base_target: String(bloco.base_target || '0'),
    challenge_id: bloco.challenge_id || '',
    contract_state_root: bloco.contract_state_root || '',
    forger: bloco.forger || (bloco.miner || ''),
    generation_signature: bloco.generation_signature || ZERO_HASH,
    height: bloco.height || 0,
    miner: bloco.miner || '',
    nonce: String(bloco.nonce || '0'),
    parent_hash: bloco.parent_hash || '',
    reward_cc: String(bloco.reward_cc || '0'),
    rewards: rewardsStr,
    target: String(bloco.target || '0'),
    timestamp: bloco.timestamp || 0,
    tx_count: parseInt(bloco.tx_count || 0, 10),
    tx_root: bloco.tx_root || '',
    state_root: bloco.state_root || '',
    winner_proof: winnerProofStr,
  };
  return sha256hex(JSON.stringify(d, Object.keys(d).sort()));
}

function blockMessage(bloco) { return hashBlock(bloco); }

function computeContractStateLeaves(db) {
  const leaves = [];
  const storage = db.prepare('SELECT contract_address, slot, value FROM smart_contract_storage ORDER BY lower(contract_address), slot').all();
  for (const s of storage) leaves.push(sha256hex(`storage:${String(s.contract_address).toLowerCase()}:${s.slot}:${s.value}`));
  const accounts = db.prepare('SELECT address, balance FROM smart_contract_accounts ORDER BY lower(address)').all();
  for (const a of accounts) leaves.push(sha256hex(`account:${String(a.address).toLowerCase()}:${a.balance}`));
  const contracts = db.prepare('SELECT address, creator, code FROM smart_contracts ORDER BY lower(address)').all();
  for (const c of contracts) {
    const codeHash = crypto.createHash('sha256').update(String(c.code || '')).digest('hex');
    leaves.push(sha256hex(`code:${String(c.address).toLowerCase()}:${String(c.creator || '').toLowerCase()}:${codeHash}`));
  }
  return leaves;
}

function computeContractStateRoot(db) {
  return merkleRoot(computeContractStateLeaves(db));
}

function computeStateRoot(db) {
  const rows = db.prepare('SELECT address, balance, nonce FROM users ORDER BY address').all();
  const leaves = rows.map(r => sha256hex(`${r.address}:${r.balance}:${r.nonce}`));
  return merkleRoot([...leaves, ...computeContractStateLeaves(db)]);
}

function computeStateRootAfterTxs(db, txs, rewards) {
  const rows = db.prepare('SELECT address, balance, nonce FROM users ORDER BY address').all();
  const state = {};
  for (const r of rows) state[r.address] = { balance: safeBigInt(r.balance, 0n), nonce: safeInt(r.nonce, 0) };
  for (const tx of txs) {
    const sender = tx.from_addr || '';
    const to = tx.to_addr || '';
    const val = safeBigInt(tx.value, 0n);
    const fee = safeBigInt(tx.fee, 0n);
    if (state[sender]) {
      if (state[sender].balance < val + fee) continue;
      state[sender].balance -= val + fee;
      state[sender].nonce += 1;
    }
    if (to) { if (!state[to]) state[to] = { balance: 0n, nonce: 0 }; state[to].balance += val; }
  }
  if (rewards) {
    for (const r of rewards) {
      if (typeof r === 'object' && r.miner && safeBigInt(r.reward_cc, 0n) > 0n) {
        if (!state[r.miner]) state[r.miner] = { balance: 0n, nonce: 0 };
        state[r.miner].balance += safeBigInt(r.reward_cc, 0n);
      }
    }
  }
  const leaves = Object.entries(state).sort().map(([addr, s]) => sha256hex(`${addr}:${s.balance}:${s.nonce}`));
  return merkleRoot(leaves);
}

function calculateMiningReward(height, cfg) {
  let reward = BigInt((cfg && cfg.initialReward) || 1_650_000_000_000_000_000n);
  const halving = (cfg && cfg.halvingInterval) || 6300000;
  const halvings = Math.floor(height / halving);
  for (let i = 0; i < halvings; i++) reward = reward / 2n;
  return reward > 0n ? reward : 0n;
}

function isBetterChainCandidate(candidate, incumbent) {
  const cw = (b) => safeBigInt((b || {}).chain_work, 0n);
  const h = (b) => safeInt((b || {}).height, 0);
  if (cw(candidate) !== cw(incumbent)) return cw(candidate) > cw(incumbent);
  if (h(candidate) !== h(incumbent)) return h(candidate) > h(incumbent);
  return String((candidate || {}).hash || '') < String((incumbent || {}).hash || '');
}

const SCOOP_SIZE = 32;
const SCOOPS_PER_NONCE = 8192;
const MINING_SCOOP_MODULUS = 4096;
const PLOT_FORMAT_V3 = 3;

function merkleTreeInternalNodeCount(N) {
  let total = 0;
  while (N > 1) {
    N = Math.ceil(N / 2);
    total += N;
  }
  return total;
}

function plotScoopCount(sizeGb) { return Math.max(1, Math.floor((sizeGb * 1024 * 1024 * 1024) / SCOOP_SIZE)); }
function plotScoopCountOrig(sizeGb) { return plotScoopCount(sizeGb); }

function computeDeadline(scoopData, genSig, baseTarget) {
  if (baseTarget == null || baseTarget === '' || BigInt(baseTarget) <= 0n) {
    throw new Error('computeDeadline: baseTarget é obrigatório e deve ser > 0');
  }
  const data = typeof scoopData === 'string' ? Buffer.from(scoopData, 'hex') : Buffer.isBuffer(scoopData) ? scoopData : Buffer.from(String(scoopData));
  const sig = typeof genSig === 'string' ? genSig : (genSig && genSig.challenge_seed) || String(genSig || '');
  const quality = crypto.createHash('sha256').update(Buffer.concat([data, Buffer.from(sig)])).digest();
  const qualityInt = quality.readBigUInt64BE(0);
  const dl = Number(qualityInt / BigInt(baseTarget));
  return Math.max(1, Math.min(dl, 86400));
}

function deriveSampleIndexes(challengeSeed, totalScoops, sampleCount, round, plotId) {
  const seed = sha256hex(`${challengeSeed}:${plotId}:${round}`);
  if (sampleCount >= totalScoops) {
    const indexes = Array.from({ length: totalScoops }, (_, i) => i);
    let state = seed;
    for (let i = indexes.length - 1; i > 0; i--) {
      state = sha256hex(`${state}:${i}`);
      const j = safeInt(state.slice(0, 16), 0) % (i + 1);
      [indexes[i], indexes[j]] = [indexes[j], indexes[i]];
    }
    return indexes;
  }
  const indexes = [];
  const seen = new Set();
  let counter = 0;
  while (indexes.length < sampleCount) {
    const h = sha256hex(`${seed}:${counter++}`);
    const idx = safeInt(h.slice(0, 16), 0) % totalScoops;
    if (!seen.has(idx)) { seen.add(idx); indexes.push(idx); }
  }
  return indexes;
}

function getChainWorkForBlock(blk) {
  return safeBigInt((blk || {}).chain_work, 0n);
}

module.exports = {
  keccak256,
  ZERO_HASH, sha256hex, sha256buf, safeInt, safeBigInt,
  normalizeSecpPublicKey, secpEncodePublicKey, decodePublicKey, secpPublicKeyFromPrivate,
  secpAddressFromPrivate, privateKeyToAddress, toChecksumAddress, isValidAddress, recoverPublicKey, recoverPublicKeyForAddress,
  pubkeyToAddress, pubKeyToAddress, signMessage, verifySignature,
  evmTxDigest, evmTxHash, signTransactionTx, recoverTransactionSender, signatureToHex, signatureFromHex,
  merkleRoot, merkleRootBuffer, merkleRootBuf, merkleRootBuf2, computeMerkleProof, computeMerkleProofBuf, computeMerkleProofBuf2, computeMerkleTreeNodes, verifyMerkleProof, verifyMerkleProofBuf,
  canonicalTxMessage, hashTransaction, hashBlock, blockMessage, proofMessage, plotRegisterMessage,
  computeStateRoot, computeStateRootAfterTxs, computeContractStateRoot, calculateMiningReward, isBetterChainCandidate,
  SCOOP_SIZE, SCOOPS_PER_NONCE, MINING_SCOOP_MODULUS, PLOT_FORMAT_V3, merkleTreeInternalNodeCount, plotScoopCount, plotScoopCountOrig,
  computeDeadline, deriveSampleIndexes, getChainWorkForBlock,
  vrfHashToCurve, vrfDerivePlotSecret, vrfProve, vrfVerify,
};
