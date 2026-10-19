'use strict';

const crypto = require('crypto');

const FORMAT_VERSION = 4;
const REGISTER_OPERATION = 1;
const SCOOP_SIZE = 32;
const SCOOPS_PER_NONCE = 8192;
const NONCE_BYTES = SCOOP_SIZE * SCOOPS_PER_NONCE;
const MIN_CAPACITY_BYTES = BigInt(NONCE_BYTES);
const MAX_CAPACITY_BYTES = 10n * 1024n * 1024n * 1024n * 1024n;
const SAMPLE_COUNT = 16;
const SAMPLE_ROUND = 4;
const REGISTRATION_BYTES = 78;
const ZERO_ADDRESS = `0x${'0'.repeat(40)}`;
const NONCE_DOMAIN = Buffer.from('CCPOC:PLOT:V4:NONCE\0', 'ascii');
const LEAF_DOMAIN = Buffer.from('CCPOC:PLOT:V4:LEAF\0', 'ascii');
const CHALLENGE_DOMAIN = Buffer.from('CCPOC:CHALLENGE:V4\0', 'ascii');
const SAMPLE_DOMAIN = Buffer.from('CCPOC:SAMPLE:V4\0', 'ascii');

function sha256(data) {
  return crypto.createHash('sha256').update(data).digest();
}

function strictHex(value, bytes, label, prefix = false) {
  if (typeof value !== 'string') throw new Error(`${label} must be a hex string`);
  const raw = prefix ? value : value.replace(/^0x/, '');
  if (prefix && !raw.startsWith('0x')) throw new Error(`${label} must start with 0x`);
  const hex = prefix ? raw.slice(2) : raw;
  if (hex.length !== bytes * 2 || !/^[0-9a-fA-F]+$/.test(hex)) {
    throw new Error(`${label} must be exactly ${bytes} bytes`);
  }
  return Buffer.from(hex, 'hex');
}

function asUInt(value, bits, label) {
  if (typeof value === 'number' && !Number.isSafeInteger(value)) throw new Error(`${label} must be supplied as an exact integer`);
  let n;
  try { n = BigInt(value); } catch { throw new Error(`${label} must be an integer`); }
  if (n < 0n || n >= (1n << BigInt(bits))) throw new Error(`${label} is out of range`);
  return n;
}

function encodeRegistration({ plotId, merkleRoot, capacityBytes }) {
  const id = strictHex(plotId, 32, 'plot_id');
  const root = strictHex(merkleRoot, 32, 'merkle_root');
  if (id.every((b) => b === 0)) throw new Error('plot_id must be nonzero');
  if (root.every((b) => b === 0)) throw new Error('merkle_root must be nonzero');
  const capacity = asUInt(capacityBytes, 64, 'capacity_bytes');
  validateCapacity(capacity);
  const out = Buffer.alloc(REGISTRATION_BYTES);
  out.write('CCPC', 0, 4, 'ascii');
  out[4] = FORMAT_VERSION;
  out[5] = REGISTER_OPERATION;
  id.copy(out, 6);
  root.copy(out, 38);
  out.writeBigUInt64BE(capacity, 70);
  return `0x${out.toString('hex')}`;
}

function validateCapacity(capacityBytes) {
  if (capacityBytes < MIN_CAPACITY_BYTES || capacityBytes > MAX_CAPACITY_BYTES || capacityBytes % MIN_CAPACITY_BYTES !== 0n) {
    throw new Error('capacity_bytes must be a whole nonce from 256 KiB through 10 TiB');
  }
}

function decodeRegistration(data) {
  if (typeof data !== 'string' || !/^0x[0-9a-f]{156}$/.test(data)) {
    throw new Error('registration data must be canonical lowercase 78-byte hex');
  }
  const bytes = Buffer.from(data.slice(2), 'hex');
  if (bytes.toString('ascii', 0, 4) !== 'CCPC' || bytes[4] !== FORMAT_VERSION || bytes[5] !== REGISTER_OPERATION) {
    throw new Error('unsupported plot registration payload');
  }
  const plotIdBytes = bytes.subarray(6, 38);
  const rootBytes = bytes.subarray(38, 70);
  const capacityBytes = bytes.readBigUInt64BE(70);
  if (plotIdBytes.every((b) => b === 0)) throw new Error('plot_id must be nonzero');
  if (rootBytes.every((b) => b === 0)) throw new Error('merkle_root must be nonzero');
  validateCapacity(capacityBytes);
  return {
    format: FORMAT_VERSION,
    operation: REGISTER_OPERATION,
    plot_id: plotIdBytes.toString('hex'),
    merkle_root: rootBytes.toString('hex'),
    capacity_bytes: capacityBytes.toString(10),
    total_leaves: Number(capacityBytes / BigInt(SCOOP_SIZE)),
  };
}

function isRegistrationPayload(data) {
  return typeof data === 'string' && /^0x43435043/i.test(data);
}

function chainIdBytes(chainId) {
  const text = String(chainId);
  if (!/^(0|[1-9][0-9]*)$/.test(text)) throw new Error('chain_id must be canonical unsigned decimal');
  const bytes = Buffer.from(text, 'ascii');
  if (bytes.length > 255) throw new Error('chain_id is too long');
  return bytes;
}

function canonicalLeaf({ chainId, miner, plotId, index }) {
  if (!Number.isSafeInteger(index) || index < 0) throw new Error('leaf index must be a nonnegative safe integer');
  const chain = chainIdBytes(chainId);
  const address = strictHex(miner, 20, 'miner address', true);
  const id = strictHex(plotId, 32, 'plot_id');
  const nonceIndex = BigInt(Math.floor(index / SCOOPS_PER_NONCE));
  const slot = index % SCOOPS_PER_NONCE;
  const nonce = Buffer.alloc(8);
  nonce.writeBigUInt64BE(nonceIndex);
  const seed = sha256(Buffer.concat([
    NONCE_DOMAIN,
    Buffer.from([chain.length]), chain,
    address, id, nonce,
  ]));
  let leaf = Buffer.alloc(0);
  for (let s = 0; s <= slot; s++) {
    const slotBytes = Buffer.alloc(2);
    slotBytes.writeUInt16BE(s);
    leaf = sha256(s === 0
      ? Buffer.concat([LEAF_DOMAIN, seed, slotBytes])
      : Buffer.concat([LEAF_DOMAIN, seed, slotBytes, leaf]));
  }
  return leaf;
}

function challengeTargetSlot(challengeId) {
  const challenge = strictHex(challengeId, 32, 'challenge_id');
  const digest = sha256(Buffer.concat([CHALLENGE_DOMAIN, challenge]));
  return digest.readUInt16BE(30) & (SCOOPS_PER_NONCE - 1);
}

function deriveCapacitySampleIndexes(challengeId, totalLeaves, plotId, count = SAMPLE_COUNT, round = SAMPLE_ROUND, exclude = []) {
  if (!Number.isSafeInteger(totalLeaves) || totalLeaves < 1) throw new Error('total_leaves is out of range');
  if (!Number.isSafeInteger(count) || count < 0 || count > SAMPLE_COUNT) throw new Error('sample count is out of range');
  if (!Number.isSafeInteger(round) || round < 0 || round > 0xffffffff) throw new Error('sample round is out of range');
  const challenge = strictHex(challengeId, 32, 'challenge_id');
  const id = strictHex(plotId, 32, 'plot_id');
  const total = BigInt(totalLeaves);
  const max = 1n << 64n;
  const limit = max - (max % total);
  const excluded = new Set(exclude.map((v) => Number(v)));
  const selected = [];
  const seen = new Set(excluded);
  let counter = 0;
  while (selected.length < count) {
    if (counter > count * 1024 + excluded.size * 1024 + 1024) throw new Error('sample derivation exceeded its work bound');
    const counterBytes = Buffer.alloc(4);
    counterBytes.writeUInt32BE(counter++);
    const roundBytes = Buffer.alloc(4);
    roundBytes.writeUInt32BE(round);
    const totalBytes = Buffer.alloc(8);
    totalBytes.writeBigUInt64BE(total);
    const digest = sha256(Buffer.concat([SAMPLE_DOMAIN, challenge, id, totalBytes, roundBytes, counterBytes]));
    const value = digest.readBigUInt64BE(0);
    if (value >= limit) continue;
    const index = Number(value % total);
    if (seen.has(index)) continue;
    seen.add(index);
    selected.push(index);
  }
  return selected;
}

function expectedProofLength(index, totalLeaves) {
  if (!Number.isSafeInteger(index) || !Number.isSafeInteger(totalLeaves) || totalLeaves < 1 || index < 0 || index >= totalLeaves) {
    throw new Error('invalid Merkle proof index or leaf count');
  }
  let count = totalLeaves;
  let position = index;
  let length = 0;
  while (count > 1) {
    if (count % 2 !== 1 || position !== count - 1) length++;
    position = Math.floor(position / 2);
    count = Math.ceil(count / 2);
  }
  return length;
}

function verifyCanonicalMerkleProof(leaf, index, totalLeaves, proof, root) {
  if (!Array.isArray(proof) || proof.length !== expectedProofLength(index, totalLeaves)) return false;
  let hash;
  let expectedRoot;
  try {
    hash = Buffer.isBuffer(leaf) ? Buffer.from(leaf) : strictHex(leaf, 32, 'leaf');
    expectedRoot = strictHex(root, 32, 'merkle_root');
    if (hash.length !== 32) return false;
  } catch { return false; }
  let position = index;
  let count = totalLeaves;
  let proofIndex = 0;
  while (count > 1) {
    const duplicateLast = (count % 2 === 1 && position === count - 1);
    if (duplicateLast) {
      hash = sha256(Buffer.concat([hash, hash]));
    } else {
      let sibling;
      try { sibling = strictHex(proof[proofIndex++], 32, 'Merkle sibling'); } catch { return false; }
      hash = position % 2 === 0
        ? sha256(Buffer.concat([hash, sibling]))
        : sha256(Buffer.concat([sibling, hash]));
    }
    position = Math.floor(position / 2);
    count = Math.ceil(count / 2);
  }
  return proofIndex === proof.length && crypto.timingSafeEqual(hash, expectedRoot);
}

module.exports = {
  FORMAT_VERSION,
  REGISTER_OPERATION,
  SCOOP_SIZE,
  SCOOPS_PER_NONCE,
  NONCE_BYTES,
  MIN_CAPACITY_BYTES,
  MAX_CAPACITY_BYTES,
  SAMPLE_COUNT,
  SAMPLE_ROUND,
  REGISTRATION_BYTES,
  ZERO_ADDRESS,
  encodeRegistration,
  decodeRegistration,
  isRegistrationPayload,
  canonicalLeaf,
  challengeTargetSlot,
  deriveCapacitySampleIndexes,
  expectedProofLength,
  verifyCanonicalMerkleProof,
};
