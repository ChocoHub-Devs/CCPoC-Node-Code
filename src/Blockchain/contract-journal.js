'use strict';

function ensureContractJournalSchema(db) {
  db.exec(`
    CREATE TABLE IF NOT EXISTS pending_contract_blocks (block_hash TEXT PRIMARY KEY);
    CREATE TABLE IF NOT EXISTS pending_contract_undo (
      block_hash TEXT NOT NULL, address TEXT NOT NULL, snapshot TEXT NOT NULL,
      PRIMARY KEY (block_hash, address)
    );
    CREATE TABLE IF NOT EXISTS smart_contract_nonces (
      address TEXT PRIMARY KEY, nonce TEXT NOT NULL
    );
  `);
}

// Write-ahead undo records commit before any pre-execution SQL mutation. The
// block transaction deletes them atomically with the block and its history.
// A process interruption leaves records which startup restores before loading tip.
class ContractJournal {
  constructor(db, restore) { this.db = db; this.restore = restore; }

  begin(hash) {
    this.db.transaction(() => {
      if (this.db.prepare('SELECT 1 FROM pending_contract_blocks LIMIT 1').get()) {
        throw new Error('pending contract execution requires recovery');
      }
      this.db.prepare('INSERT INTO pending_contract_blocks VALUES (?)').run(hash);
    }).immediate();
  }

  capture(hash, snapshot) {
    if (!this.db.prepare('SELECT 1 FROM pending_contract_blocks WHERE block_hash = ?').get(hash)) {
      throw new Error('cannot capture contract undo without a pending block');
    }
    this.db.prepare('INSERT OR IGNORE INTO pending_contract_undo VALUES (?,?,?)')
      .run(hash, snapshot.address, JSON.stringify(snapshot));
  }

  finish(hash) {
    if (!this.db.inTransaction) throw new Error('contract journal must finish inside the block transaction');
    this.db.prepare('DELETE FROM pending_contract_undo WHERE block_hash = ?').run(hash);
    this.db.prepare('DELETE FROM pending_contract_blocks WHERE block_hash = ?').run(hash);
  }

  rollback(hash) {
    this.db.transaction(() => {
      const snapshots = this.db.prepare('SELECT snapshot FROM pending_contract_undo WHERE block_hash = ? ORDER BY address').all(hash)
        .map(row => JSON.parse(row.snapshot));
      this.restore(snapshots);
      this.finish(hash);
    })();
  }

  recover() {
    this.db.transaction(() => {
      const pending = this.db.prepare('SELECT block_hash FROM pending_contract_blocks').all();
      if (pending.length > 1 || this.db.prepare(`SELECT 1 FROM pending_contract_undo u
        LEFT JOIN pending_contract_blocks b ON b.block_hash = u.block_hash
        WHERE b.block_hash IS NULL LIMIT 1`).get()) {
        throw new Error('ambiguous or orphaned pending contract undo records');
      }
      for (const { block_hash: hash } of pending) {
        if (this.db.prepare('SELECT 1 FROM blocks WHERE hash = ?').get(hash)) {
          throw new Error('committed block has pending contract undo records; refusing ambiguous recovery');
        }
        this.rollback(hash);
      }
    })();
  }
}

module.exports = { ContractJournal, ensureContractJournalSchema };
