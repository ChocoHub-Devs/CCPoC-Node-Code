const Database = require('better-sqlite3');

function safeBigInt(value, def) {
  if (typeof value === 'bigint') return value;
  try { return BigInt(value); } catch { return def; }
}

function initDB(dbPath, cfg) {
  cfg = cfg || {};
  const dir = require('path').dirname(dbPath);
  require('fs').mkdirSync(dir, { recursive: true });
  const db = new Database(dbPath);
  db.pragma('journal_mode = WAL');
  db.pragma('synchronous = NORMAL');
  db.pragma('cache_size = -64000');
  db.pragma('busy_timeout = 5000');
  db.pragma('foreign_keys = ON');

  db.exec(`
    CREATE TABLE IF NOT EXISTS blocks (
      height INTEGER, hash TEXT PRIMARY KEY, parent_hash TEXT, timestamp INTEGER,
      miner TEXT, challenge_id TEXT, tx_root TEXT, nonce TEXT, difficulty TEXT,
      target TEXT, reward_units TEXT, reward_cc TEXT, tx_count INTEGER,
      chain_work TEXT, signature TEXT, generation_signature TEXT,
      proof_digest TEXT, plot_id TEXT, state_root TEXT, origin TEXT,
      total_fees_units TEXT, gas_used INTEGER, gas_limit INTEGER, base_fee TEXT DEFAULT '0',
      base_target TEXT, miner_public_key TEXT DEFAULT '',
      body_pruned INTEGER DEFAULT 0
    );
    CREATE INDEX IF NOT EXISTS idx_blocks_height ON blocks(height);
    CREATE INDEX IF NOT EXISTS idx_blocks_parent ON blocks(parent_hash);
    CREATE INDEX IF NOT EXISTS idx_blocks_challenge ON blocks(challenge_id);

    CREATE TABLE IF NOT EXISTS transactions (
      hash TEXT PRIMARY KEY, from_addr TEXT, to_addr TEXT, value TEXT,
      fee TEXT, nonce INTEGER, gas_limit INTEGER, gas_price TEXT,
      signature TEXT, block_height INTEGER, timestamp INTEGER,
      block_hash TEXT DEFAULT '', chain_id TEXT DEFAULT ''
    );
    CREATE INDEX IF NOT EXISTS idx_tx_from ON transactions(from_addr);
    CREATE INDEX IF NOT EXISTS idx_tx_to ON transactions(to_addr);
    CREATE INDEX IF NOT EXISTS idx_tx_height ON transactions(block_height);
    CREATE INDEX IF NOT EXISTS idx_tx_block_hash ON transactions(block_hash);

    CREATE TABLE IF NOT EXISTS users (
      address TEXT PRIMARY KEY, public_key_secp256k1 TEXT UNIQUE,
      balance TEXT DEFAULT '0', nonce INTEGER DEFAULT 0,
      created_at INTEGER, updated_at INTEGER
    );

    CREATE TABLE IF NOT EXISTS mempool (
      hash TEXT PRIMARY KEY, raw TEXT NOT NULL, timestamp INTEGER, fee TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_mempool_fee ON mempool(fee);

    CREATE TABLE IF NOT EXISTS peers (
      url TEXT PRIMARY KEY, node_id TEXT, height INTEGER DEFAULT 0,
      first_seen INTEGER, last_seen INTEGER, health REAL DEFAULT 1.0,
      fail_count INTEGER DEFAULT 0, banned INTEGER DEFAULT 0, timeout_until INTEGER DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS nodes (
      url TEXT PRIMARY KEY, node_id TEXT, height INTEGER DEFAULT 0,
      chain_work TEXT DEFAULT '0', version TEXT DEFAULT '',
      peers INTEGER DEFAULT 0, first_seen INTEGER, last_seen INTEGER
    );

    CREATE TABLE IF NOT EXISTS mining_challenges (
      challenge_id TEXT PRIMARY KEY, challenge_seed TEXT, nonce TEXT,
      target_scoop_index INTEGER, created_at INTEGER, expires_at INTEGER,
      block_height INTEGER, winner_miner TEXT, winner_deadline INTEGER,
      winner_plot_id TEXT, forged_block_height INTEGER, finalized_at INTEGER
    );

    CREATE TABLE IF NOT EXISTS challenge_submissions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      challenge_id TEXT, miner TEXT, plot_id TEXT, size_gb REAL,
      deadline INTEGER, proof_digest TEXT, submitted_at INTEGER
    );
    CREATE INDEX IF NOT EXISTS idx_sub_challenge ON challenge_submissions(challenge_id);
    CREATE UNIQUE INDEX IF NOT EXISTS ux_sub_challenge_plot ON challenge_submissions(challenge_id, miner, plot_id, deadline);

    CREATE TABLE IF NOT EXISTS plot_commitments (
      plot_id TEXT, miner TEXT, merkle_root TEXT, size_gb REAL,
      created_at INTEGER, PRIMARY KEY(plot_id, miner)
    );

    CREATE TABLE IF NOT EXISTS peer_plot_commitments (
      plot_id TEXT, miner TEXT, size_gb REAL, node_url TEXT,
      created_at INTEGER, PRIMARY KEY(plot_id, miner, node_url)
    );

    CREATE TABLE IF NOT EXISTS block_rewards (
      block_height INTEGER, block_hash TEXT, challenge_id TEXT,
      miner TEXT, plot_id TEXT, size_gb REAL, reward_cc TEXT, 
      created_at INTEGER
    );

    CREATE TABLE IF NOT EXISTS block_payouts (
      block_hash TEXT NOT NULL,
      height INTEGER,
      to_addr TEXT NOT NULL,
      value TEXT,
      PRIMARY KEY (block_hash, to_addr)
    );
    CREATE INDEX IF NOT EXISTS idx_block_payouts_height ON block_payouts(height);
    CREATE INDEX IF NOT EXISTS idx_block_payouts_to ON block_payouts(to_addr);

    CREATE TABLE IF NOT EXISTS plot_cache (
      plot_id TEXT PRIMARY KEY, merkle_root TEXT, size_gb REAL,
      updated_at INTEGER
    );

    CREATE TABLE IF NOT EXISTS config (
      key TEXT PRIMARY KEY, value TEXT
    );

    CREATE TABLE IF NOT EXISTS smart_contracts (
      address TEXT PRIMARY KEY,
      creator TEXT,
      code TEXT,
      created_at INTEGER,
      updated_at INTEGER
    );
  `);
  try { db.prepare('ALTER TABLE peers ADD COLUMN timeout_until INTEGER DEFAULT 0').run(); } catch {}

  try {
    db.prepare(`
      CREATE TABLE IF NOT EXISTS smart_contracts (
        address TEXT PRIMARY KEY,
        creator TEXT,
        code TEXT,
        created_at INTEGER,
        updated_at INTEGER
      )
    `).run();
  } catch (e) {}

  try { db.prepare('DELETE FROM block_rewards WHERE rowid NOT IN (SELECT MIN(rowid) FROM block_rewards GROUP BY block_height, block_hash, miner, plot_id, reward_cc)').run(); } catch (e) { /* nothing to clean */ }
  try { db.prepare('CREATE UNIQUE INDEX IF NOT EXISTS ux_block_rewards ON block_rewards (block_height, block_hash, miner, plot_id, reward_cc)').run(); } catch (e) { /* duplicates present, skipped */ }

  try {
    db.prepare(`
      CREATE TABLE IF NOT EXISTS smart_contract_storage (
        contract_address TEXT NOT NULL,
        slot TEXT NOT NULL,
        value TEXT NOT NULL,
        PRIMARY KEY (contract_address, slot)
      )
    `).run();
  } catch (e) {}

  try {
    db.prepare(`
      CREATE TABLE IF NOT EXISTS smart_contract_accounts (
        address TEXT PRIMARY KEY,
        balance TEXT DEFAULT '0'
      )
    `).run();
  } catch (e) {}

  try {
    db.prepare(`
      CREATE TABLE IF NOT EXISTS smart_contract_storage_history (
        contract_address TEXT NOT NULL,
        slot TEXT NOT NULL,
        prev_value TEXT,
        new_value TEXT,
        block_height INTEGER NOT NULL,
        block_hash TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        PRIMARY KEY (contract_address, slot, block_height)
      )
    `).run();
    db.prepare('CREATE INDEX IF NOT EXISTS idx_sc_storage_history_height ON smart_contract_storage_history(block_height)').run();
    db.prepare('CREATE INDEX IF NOT EXISTS idx_sc_storage_history_hash ON smart_contract_storage_history(block_hash)').run();
  } catch (e) {}

  try { db.prepare('ALTER TABLE challenge_submissions ADD COLUMN proof_signature TEXT DEFAULT ""').run(); } catch {}
  try { db.prepare('ALTER TABLE challenge_submissions ADD COLUMN scoop_data TEXT DEFAULT ""').run(); } catch {}
  try { db.prepare('ALTER TABLE challenge_submissions ADD COLUMN scoop_index INTEGER DEFAULT 0').run(); } catch {}
  try { db.prepare('ALTER TABLE challenge_submissions ADD COLUMN total_scoops INTEGER DEFAULT 0').run(); } catch {}
  try { db.prepare('ALTER TABLE challenge_submissions ADD COLUMN merkle_proof TEXT DEFAULT ""').run(); } catch {}
  try { db.prepare('ALTER TABLE challenge_submissions ADD COLUMN merkle_root TEXT DEFAULT ""').run(); } catch {}

  try {
    db.prepare('DELETE FROM challenge_submissions WHERE id NOT IN (SELECT MIN(id) FROM challenge_submissions GROUP BY challenge_id, miner, plot_id, deadline)').run();
    db.prepare('CREATE UNIQUE INDEX IF NOT EXISTS ux_sub_challenge_plot ON challenge_submissions(challenge_id, miner, plot_id, deadline)').run();
  } catch (e) {}

  try { db.prepare('ALTER TABLE blocks ADD COLUMN winner_proof TEXT DEFAULT ""').run(); } catch {}
  try { db.prepare("ALTER TABLE blocks ADD COLUMN miner_public_key TEXT DEFAULT ''").run(); } catch {}
  try { db.prepare('ALTER TABLE mining_challenges ADD COLUMN base_target TEXT').run(); } catch {}
  try { db.prepare("ALTER TABLE blocks ADD COLUMN rewards_json TEXT DEFAULT '[]'").run(); } catch {}
  try { db.prepare('ALTER TABLE plot_commitments ADD COLUMN total_scoops INTEGER DEFAULT 0').run(); } catch {}
  try { db.prepare('ALTER TABLE plot_commitments ADD COLUMN vrf_public_key TEXT DEFAULT ""').run(); } catch {}
  try { db.prepare('ALTER TABLE plot_commitments ADD COLUMN vrf_output TEXT DEFAULT ""').run(); } catch {}
  try { db.prepare('ALTER TABLE plot_commitments ADD COLUMN vrf_proof TEXT DEFAULT ""').run(); } catch {}
  try { db.prepare('ALTER TABLE plot_commitments ADD COLUMN vrf_verified INTEGER DEFAULT 0').run(); } catch {}
  try { db.prepare('ALTER TABLE peer_plot_commitments ADD COLUMN merkle_root TEXT DEFAULT ""').run(); } catch {}
  try { db.prepare('ALTER TABLE peer_plot_commitments ADD COLUMN vrf_public_key TEXT DEFAULT ""').run(); } catch {}
  try { db.prepare('ALTER TABLE peer_plot_commitments ADD COLUMN vrf_output TEXT DEFAULT ""').run(); } catch {}
  try { db.prepare('ALTER TABLE peer_plot_commitments ADD COLUMN vrf_proof TEXT DEFAULT ""').run(); } catch {}
  try { db.prepare('ALTER TABLE peer_plot_commitments ADD COLUMN signature TEXT DEFAULT ""').run(); } catch {}
  try { db.prepare('ALTER TABLE peer_plot_commitments ADD COLUMN public_key TEXT DEFAULT ""').run(); } catch {};
  try { db.prepare("ALTER TABLE transactions ADD COLUMN chain_id TEXT DEFAULT ''").run(); } catch {}

  const chainIdDefault = String(cfg.chainId || '0');
  try {
    db.prepare("UPDATE transactions SET chain_id = ? WHERE chain_id IS NULL OR chain_id = ''").run(chainIdDefault);
  } catch (e) {}

  try {
    const rows = db.prepare('SELECT address, balance, nonce, public_key_secp256k1 FROM users WHERE address != lower(address)').all();
    for (const row of rows) {
      const lower = row.address.toLowerCase();
      const existing = db.prepare('SELECT balance, nonce FROM users WHERE address = ?').get(lower);
      if (existing) {
        const mergedBalance = BigInt(existing.balance || '0') + BigInt(row.balance || '0');
        const mergedNonce = Math.max(existing.nonce || 0, row.nonce || 0);
        const newPubkey = row.public_key_secp256k1 || existing.public_key_secp256k1 || '';
        db.prepare('UPDATE users SET balance = ?, nonce = ?, public_key_secp256k1 = ? WHERE address = ?').run(String(mergedBalance), mergedNonce, newPubkey, lower);
        db.prepare('DELETE FROM users WHERE address = ?').run(row.address);
      } else {
        db.prepare('UPDATE users SET address = ? WHERE address = ?').run(lower, row.address);
      }
    }
  } catch (e) {}

  const treasuryAddress = '0x' + '0'.repeat(40);
  const existingTreasury = db.prepare('SELECT balance FROM users WHERE address = ?').get(treasuryAddress);
  if (!existingTreasury) {
    db.prepare('INSERT OR IGNORE INTO users (address, public_key_secp256k1, balance, nonce, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)').run(treasuryAddress, '', '0', 0, cfg.genesisTimestamp || Math.floor(Date.now() / 1000), cfg.genesisTimestamp || Math.floor(Date.now() / 1000));
  }

  try {
    db.prepare(`
      CREATE TABLE IF NOT EXISTS contract_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        tx_hash TEXT NOT NULL,
        block_height INTEGER NOT NULL,
        block_hash TEXT NOT NULL,
        log_index INTEGER NOT NULL,
        address TEXT NOT NULL,
        topics TEXT NOT NULL,
        data TEXT NOT NULL
      )
    `).run();
    db.prepare('CREATE INDEX IF NOT EXISTS idx_contract_logs_block_hash ON contract_logs(block_hash)').run();
    db.prepare('CREATE INDEX IF NOT EXISTS idx_contract_logs_height ON contract_logs(block_height)').run();
    db.prepare('CREATE INDEX IF NOT EXISTS idx_contract_logs_address ON contract_logs(address)').run();
    db.prepare('CREATE INDEX IF NOT EXISTS idx_contract_logs_tx_hash ON contract_logs(tx_hash)').run();
  } catch (e) { /* table likely exists */ }

  try {
    db.exec(`
      CREATE TABLE IF NOT EXISTS zkp_proofs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        start_height INTEGER, end_height INTEGER, block_count INTEGER,
        commitment TEXT NOT NULL, interval_start_height INTEGER, interval_end_height INTEGER,
        proof TEXT NOT NULL, verified INTEGER DEFAULT 0, created_at INTEGER
      )
    `);
    db.prepare('CREATE INDEX IF NOT EXISTS idx_zkp_proofs_end ON zkp_proofs(end_height)').run();
  } catch (e) { /* table likely exists */ }
  try { db.prepare('ALTER TABLE zkp_proofs ADD COLUMN interval_start_height INTEGER').run(); } catch {}
  try { db.prepare('ALTER TABLE zkp_proofs ADD COLUMN interval_end_height INTEGER').run(); } catch {}

  try {
    db.exec(`
      CREATE TABLE IF NOT EXISTS snapshots (
        height INTEGER PRIMARY KEY,
        state_root TEXT NOT NULL,
        zkp_commitment TEXT DEFAULT '',
        digest TEXT DEFAULT '',
        block_hash TEXT DEFAULT '',
        file TEXT DEFAULT '',
        verified INTEGER DEFAULT 0,
        created_at INTEGER DEFAULT 0
      )
    `);
    db.prepare('CREATE INDEX IF NOT EXISTS idx_snapshots_state_root ON snapshots(state_root)').run();
  } catch (e) { /* table likely exists */ }

  return db;
}

module.exports = { initDB };
