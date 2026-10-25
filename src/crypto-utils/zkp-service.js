const zkp = require('./zkp');
const { log } = require('../../config/config');
const { safeInt } = require('./crypto');

const WINDOW_ALIGN = 8192;

function _readHeaders(db, startHeight, endHeight) {
  const rows = db.prepare(
    'SELECT height, hash, parent_hash, state_root ' +
    'FROM blocks WHERE height >= ? AND height <= ? ORDER BY height ASC',
  ).all(startHeight, endHeight);
  return rows;
}

class ZkpService {
  constructor(db, cfg = {}) {
    this.db = db;
    this.cfg = cfg || {};
    this.engine = zkp;
  }

  get enabled() {
    return this.cfg.zkpEnabled !== false;
  }

  storeProofForRange(startHeight, endHeight) {
    if (!this.enabled) return null;
    const blocks = _readHeaders(this.db, startHeight, endHeight);
    if (blocks.length === 0) return null;
    const proof = zkp.proveInterval(blocks);
    if (!zkp.assertProofSize(proof)) {
      log('warn', `[ZKP] proof for ${startHeight}..${endHeight} exceeds 3KB budget (${proof.size_bytes}B)`);
    }
    const now = Math.floor(Date.now() / 1000);
    const info = this.db.prepare(
      `INSERT INTO zkp_proofs (start_height, end_height, block_count, commitment,
                                interval_start_height, interval_end_height, proof, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    ).run(
      startHeight, endHeight, proof.interval.block_count, proof.commitment,
      proof.interval.start_height, proof.interval.end_height,
      zkp.encodeProof(proof), now,
    );
    log('info', `[ZKP] proved retired interval ${startHeight}..${endHeight} (${blocks.length} headers, ${proof.interval.block_count} blocks, proof ${proof.size_bytes}B, commit ${proof.commitment.slice(0, 16)}…)`);
    return this.getProofById(info.lastInsertRowid);
  }

  verifyProofObject(proof) {
    return zkp.verifyInterval(proof);
  }

  verifyStored(id) {
    const row = this.getProofById(id);
    if (!row) return { valid: false, reason: 'no such proof' };
    const proof = zkp.decodeProof(row.proof);
    if (!proof) return { valid: false, reason: 'corrupt stored proof' };
    const out = zkp.verifyInterval(proof);
    try {
      this.db.prepare('UPDATE zkp_proofs SET verified = ? WHERE id = ?').run(out.valid ? 1 : 0, id);
    } catch (e) {   }
    return out;
  }

  verifyLatest() {
    const row = this.getLatest();
    if (!row) return { valid: false, reason: 'no proofs yet' };
    return { ...this.verifyStored(row.id), row };
  }

  getProofById(id) {
    return this.db.prepare('SELECT * FROM zkp_proofs WHERE id = ?').get(id);
  }

  getLatest() {
    return this.db.prepare('SELECT * FROM zkp_proofs ORDER BY end_height DESC LIMIT 1').get();
  }

  getLatestByEndHeight(endHeight) {
    return this.db.prepare('SELECT * FROM zkp_proofs WHERE end_height = ? ORDER BY id DESC LIMIT 1').get(endHeight);
  }

  proveJustRetired(tip) {
    tip = safeInt(tip, 0);
    if (!this.enabled || tip < WINDOW_ALIGN) return null;
    if (tip % WINDOW_ALIGN !== 0) return null;
    const start = tip - WINDOW_ALIGN + 1;
    const end = tip;
    const existing = this.getLatestByEndHeight(end);
    if (existing) return existing;
    return this.storeProofForRange(start, end);
  }
}

module.exports = { ZkpService, _readHeaders };
