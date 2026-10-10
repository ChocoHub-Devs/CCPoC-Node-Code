const { hashBlock, verifySignature, canonicalTxMessage } = require('../crypto-utils/crypto');

async function hashBlockAsync(block) {
  return hashBlock(block);
}

async function verifySignatureAsync(message, signature, pubkey) {
  return verifySignature(message, signature, pubkey);
}

async function canonicalTxMessageAsync(tx) {
  return canonicalTxMessage(tx);
}

async function hashBlocksAsync(blocks) {
  return blocks.map(b => hashBlock(b));
}

async function verifySignaturesAsync(items) {
  return items.map(i => verifySignature(i.message, i.signature, i.pubkey));
}

function terminateWorkerPool() {
}

module.exports = {
  hashBlockAsync,
  verifySignatureAsync,
  canonicalTxMessageAsync,
  hashBlocksAsync,
  verifySignaturesAsync,
  terminateWorkerPool,
};