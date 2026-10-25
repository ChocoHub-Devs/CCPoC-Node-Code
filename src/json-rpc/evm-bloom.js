const { keccak256 } = require('ethers');
const { encode } = require('@ethereumjs/rlp');

function keccakBytes(buf) {
  if (buf instanceof Uint8Array) {
    const hex = '0x' + Buffer.from(buf).toString('hex');
    return Buffer.from(keccak256(hex).replace(/^0x/i, ''), 'hex');
  }
  const hex = '0x' + Buffer.from(String(buf)).toString('hex');
  return Buffer.from(keccak256(hex).replace(/^0x/i, ''), 'hex');
}

function addToBloom(bloom, value) {
  const h = keccakBytes(value);
  for (let i = 0; i < 3; i++) {
    const m = ((h[2 * i] << 8) | h[2 * i + 1]) & 2047;
    bloom[255 - (m >> 3)] |= (1 << (m & 7));
  }
}

function logsToBloom(logs) {
  const bloom = Buffer.alloc(256, 0);
  for (const lg of logs || []) {
    const addr = lg.address && !/^0x/.test(lg.address) ? '0x' + lg.address : lg.address;
    addToBloom(bloom, Buffer.from(String(addr).replace(/^0x/i, ''), 'hex'));
    for (const topic of lg.topics || []) {
      addToBloom(bloom, Buffer.from(String(topic).replace(/^0x/i, ''), 'hex'));
    }
  }
  return '0x' + bloom.toString('hex');
}

function receiptsRoot(receiptStrings) {
  if (!receiptStrings || !receiptStrings.length) return '0x' + keccakBytes(encode(Buffer.alloc(0))).toString('hex');
  const entries = receiptStrings.map((value, index) => ({
    key: toNibbles(encode(index === 0 ? Buffer.alloc(0) : bigintBytes(BigInt(index)))),
    value: Buffer.from(value),
  }));
  return '0x' + keccakBytes(encodeTrieNode(buildTrieNode(entries, 0))).toString('hex');
}

function bigintBytes(value) {
  if (value === 0n) return Buffer.alloc(0);
  let hex = value.toString(16);
  if (hex.length % 2) hex = '0' + hex;
  return Buffer.from(hex, 'hex');
}

function toNibbles(bytes) {
  const out = [];
  for (const byte of bytes) out.push(byte >> 4, byte & 15);
  return out;
}

function compactPath(path, leaf) {
  const odd = path.length % 2;
  const prefixed = [leaf ? 2 : 0, ...path];
  if (odd) prefixed[0] += 1;
  else prefixed.splice(1, 0, 0);
  const out = Buffer.alloc(prefixed.length / 2);
  for (let i = 0; i < prefixed.length; i += 2) out[i / 2] = (prefixed[i] << 4) | prefixed[i + 1];
  return out;
}

function encodeTrieNode(node) { return Buffer.from(encode(node)); }

function trieChild(node) {
  const encoded = encodeTrieNode(node);
  return encoded.length < 32 ? node : keccakBytes(encoded);
}

function buildTrieNode(entries, depth) {
  if (entries.length === 1) return [compactPath(entries[0].key.slice(depth), true), entries[0].value];
  let common = 0;
  while (entries.every(entry => entry.key[depth + common] !== undefined
    && entry.key[depth + common] === entries[0].key[depth + common])) common++;
  if (common > 0) return [compactPath(entries[0].key.slice(depth, depth + common), false), trieChild(buildTrieNode(entries, depth + common))];
  const branch = Array.from({ length: 17 }, () => Buffer.alloc(0));
  for (let nibble = 0; nibble < 16; nibble++) {
    const group = entries.filter(entry => entry.key[depth] === nibble);
    if (group.length) branch[nibble] = trieChild(buildTrieNode(group, depth + 1));
  }
  const terminal = entries.find(entry => entry.key.length === depth);
  if (terminal) branch[16] = terminal.value;
  return branch;
}

module.exports = { logsToBloom, receiptsRoot, keccakBytes };
