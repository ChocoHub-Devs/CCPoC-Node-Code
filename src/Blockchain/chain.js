const { ZERO_HASH, sha256hex, safeInt, safeBigInt, hashBlock, hashTransaction, evmTxHash, keccak256, merkleRoot, computeStateRoot, computeStateRootAfterTxs, computeContractStateRoot, verifySignature, calculateMiningReward, isBetterChainCandidate, canonicalTxMessage, blockMessage, signMessage, proofMessage, SCOOPS_PER_NONCE, computeDeadline, pubkeyToAddress, recoverTransactionSender } = require('../crypto-utils/crypto');

const { IncrementalStateRoot } = require('./state-trie');
const { ZkpService } = require('../crypto-utils/zkp-service');
const { SnapSyncService } = require('../snap/snap-service');
const { hashBlockAsync, verifySignatureAsync } = require('../utils/worker-pool');
const { estimateIntrinsicGas, nextBaseFee, GAS_PARAMS, capTxGasLimit, minimumFee } = require('../consensus/gas');
const { log } = require('../../config/config');
const { createBlock } = require('@ethereumjs/block');
const { bytesToHex } = require('@ethereumjs/util');
const BN = require('bn.js');
const PocPlotV4 = require('../consensus/poc-plot-v4');

function normalizeAddr(a) { return typeof a === 'string' ? a.toLowerCase() : a; }

class Config {
 static Configuration = Object.freeze({
  FINALIZATION_DEPTH: 30,
  ANCHOR_WINDOW_SIZE: 8192,
  MAX_ENTRIES_PER_BLOCK: 256,
  MAX_BASE_TARGET: 2n ** 43n,
 });
}

class Chain {
  constructor(db, cfg) {
    this.db = db;
    this.cfg = cfg;
    this.height = 0;
    this.bestHash = ZERO_HASH;
    this.contracts = null;

    try { this.db.prepare('ALTER TABLE transactions ADD COLUMN block_hash TEXT DEFAULT ""').run(); } catch (e) { /* already exists */ }
    try { this.db.prepare('ALTER TABLE blocks ADD COLUMN base_target TEXT').run(); } catch (e) { /* already exists */ }
    try { this.db.prepare('ALTER TABLE blocks ADD COLUMN contract_state_root TEXT DEFAULT ""').run(); } catch (e) { /* already exists */ }
    try { this.db.prepare('ALTER TABLE blocks ADD COLUMN forger TEXT DEFAULT ""').run(); } catch (e) { /* already exists */ }
    try { this.db.prepare("ALTER TABLE blocks ADD COLUMN rewards_json TEXT DEFAULT '[]'").run(); } catch (e) { /* already exists */ }
    try { this.db.prepare('ALTER TABLE blocks ADD COLUMN body_pruned INTEGER DEFAULT 0').run(); } catch (e) { /* already exists */ }
    try { this.db.prepare('ALTER TABLE transactions ADD COLUMN data TEXT DEFAULT ""').run(); } catch (e) { /* already exists */ }
    try { this.db.prepare('ALTER TABLE challenge_submissions ADD COLUMN capacity_samples TEXT DEFAULT "[]"').run(); } catch (e) { /* already exists */ }
    try { this.db.prepare('ALTER TABLE challenge_submissions ADD COLUMN public_key TEXT DEFAULT ""').run(); } catch (e) { /* already exists */ }
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS plot_registration_events (
        block_hash TEXT NOT NULL,
        block_height INTEGER NOT NULL,
        miner TEXT NOT NULL,
        plot_id TEXT NOT NULL,
        merkle_root TEXT NOT NULL,
        capacity_bytes TEXT NOT NULL,
        tx_hash TEXT NOT NULL,
        PRIMARY KEY (block_hash, plot_id, miner),
        UNIQUE (block_hash, tx_hash),
        FOREIGN KEY (block_hash) REFERENCES blocks(hash) ON DELETE CASCADE
      );
      CREATE INDEX IF NOT EXISTS idx_plot_registration_owner ON plot_registration_events(miner, plot_id);
      CREATE INDEX IF NOT EXISTS idx_plot_registration_height ON plot_registration_events(block_height);
    `);
    this.stateTrie = new IncrementalStateRoot();
    this.diffManager = new Diff_Manager(db, cfg, this);
    this.genesisPlotRegistrations = this._normalizeGenesisPlotRegistrations();
    this._loadTip();
    if (!this.getBlock(0)) this._initGenesis();
    this._assertGenesisMatchesConfig();
    this._backfillPlotRegistrationEvents();
    this.stateTrieLoadPromise = this.stateTrie.loadFromDB(this.db).catch(e => log('warn', `State trie init: ${e.message}`));
    try { this.db.prepare('DELETE FROM block_rewards WHERE rowid NOT IN (SELECT MIN(rowid) FROM block_rewards GROUP BY block_height, block_hash, miner, plot_id, reward_cc)').run(); } catch (e) { /* nothing to clean */ }
    try { this.db.prepare('CREATE UNIQUE INDEX IF NOT EXISTS ux_block_rewards ON block_rewards (block_height, block_hash, miner, plot_id, reward_cc)').run(); } catch (e) { /* duplicates present, skipped */ }
    const repFix = (t) => { const rows = this.db.prepare(`SELECT block_height, block_hash FROM ${t}`).all(); for (const r of rows) { const blks = this.db.prepare('SELECT hash FROM blocks WHERE height = ?').all(r.block_height); if (blks.length === 1 && blks[0].hash !== r.block_hash) this.db.prepare(`UPDATE ${t} SET block_hash = ? WHERE block_height = ? AND block_hash = ?`).run(blks[0].hash, r.block_height, r.block_hash); } };
    try { repFix('block_rewards'); repFix('transactions'); } catch (e) { /* table missing */ }
    try { this.db.prepare('DELETE FROM challenge_submissions WHERE id NOT IN (SELECT MIN(id) FROM challenge_submissions GROUP BY challenge_id, miner, plot_id, deadline)').run(); } catch (e) { /* nothing to clean */ }
    try { this.db.prepare('CREATE UNIQUE INDEX IF NOT EXISTS ux_sub_challenge_plot ON challenge_submissions(challenge_id, miner, plot_id, deadline)').run(); } catch (e) { /* duplicates present, skipped */ }
    try { this.zkp = new ZkpService(this.db, this.cfg); } catch (e) { log('warn', `ZKP service init: ${e.message}`); this.zkp = null; }
    try {
      this.snapsync = new SnapSyncService(this.db, this.cfg);
      if (this.zkp) this.snapsync.setZkp(this.zkp);
    } catch (e) { log('warn', `SnapSync service init: ${e.message}`); this.snapsync = null; }
    this.mempoolManager = new MemPool_Manager(db, cfg, this);
    this.contractsManager = new contracts_Manager(db, this);
  }

  _normalizeGenesisPlotRegistrations() {
    if (safeInt(this.cfg.genesisTimestamp, -1) <= 0) throw new Error('v4 genesisTimestamp must be a fixed positive Unix timestamp');
    const configured = this.cfg.genesisPlotRegistrations || [];
    if (!Array.isArray(configured)) throw new Error('genesisPlotRegistrations must be an array');
    const plots = configured.map((plot) => {
      const miner = String(plot && plot.miner || '');
      if (!/^0x[0-9a-f]{40}$/.test(miner)) throw new Error('genesis plot miner must be a canonical lowercase address');
      const registration = PocPlotV4.decodeRegistration(PocPlotV4.encodeRegistration({
        plotId: plot.plot_id,
        merkleRoot: plot.merkle_root,
        capacityBytes: plot.capacity_bytes,
      }));
      return {
        miner,
        plot_id: registration.plot_id,
        merkle_root: registration.merkle_root,
        capacity_bytes: registration.capacity_bytes,
      };
    }).sort((a, b) => a.plot_id.localeCompare(b.plot_id));
    const seen = new Set();
    for (const plot of plots) {
      if (seen.has(plot.plot_id)) throw new Error(`duplicate genesis plot_id ${plot.plot_id}`);
      seen.add(plot.plot_id);
    }
    if (plots.length === 0) throw new Error('v4 genesis requires at least one genesisPlotRegistrations entry to mine block 1');
    return plots;
  }

  _assertGenesisMatchesConfig() {
    const genesis = this.getBlock(0);
    if (!genesis) throw new Error('v4 chain is missing its genesis block');
    const expectedTimestamp = safeInt(this.cfg.genesisTimestamp, -1);
    const expectedTarget = String(this.cfg.initialTarget || '0x00FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF');
    if (safeInt(genesis.timestamp, -1) !== expectedTimestamp || String(genesis.target) !== expectedTarget) {
      throw new Error('database genesis timestamp/target do not match the configured v4 network');
    }
    if (this.cfg.genesisBaseTarget != null && String(genesis.base_target) !== String(this.cfg.genesisBaseTarget)) {
      throw new Error('database genesis base target does not match the configured v4 network');
    }
    const expectedHash = hashBlock({ ...genesis, chain_id: this.cfg.chainId, genesis_plot_registrations: this.genesisPlotRegistrations });
    if (genesis.hash !== expectedHash) {
      throw new Error('database genesis does not match the configured v4 network; use a fresh database and identical genesisPlotRegistrations on every node');
    }
    const insertGenesisPlot = this.db.prepare(`
      INSERT OR IGNORE INTO plot_registration_events
      (block_hash, block_height, miner, plot_id, merkle_root, capacity_bytes, tx_hash)
      VALUES (?, 0, ?, ?, ?, ?, ?)
    `);
    for (const plot of this.genesisPlotRegistrations) {
      const commitmentId = sha256hex(`CCPOC:GENESIS:PLOT:V4:${plot.miner}:${plot.plot_id}:${plot.merkle_root}:${plot.capacity_bytes}`);
      insertGenesisPlot.run(genesis.hash, plot.miner, plot.plot_id, plot.merkle_root, plot.capacity_bytes, commitmentId);
    }
    const indexedGenesisPlots = this.db.prepare('SELECT miner, plot_id, merkle_root, capacity_bytes FROM plot_registration_events WHERE block_hash = ? ORDER BY plot_id').all(genesis.hash);
    if (JSON.stringify(indexedGenesisPlots) !== JSON.stringify(this.genesisPlotRegistrations)) {
      throw new Error('stored genesis plot index does not match the v4 genesis configuration');
    }
  }

  _plotRegistrationsOnAncestry(parentHash, maxHeight = Number.MAX_SAFE_INTEGER) {
    if (!parentHash) return [];
    const cutoff = Math.max(0, safeInt(maxHeight, Number.MAX_SAFE_INTEGER));
    return this.db.prepare(`
      WITH RECURSIVE ancestry(hash, parent_hash, height, depth) AS (
        SELECT hash, parent_hash, height, 0 FROM blocks WHERE hash = ?
        UNION ALL
        SELECT b.hash, b.parent_hash, b.height, a.depth + 1
        FROM blocks b JOIN ancestry a ON b.hash = a.parent_hash
        WHERE a.height > 0 AND a.depth < 1000000
      )
      SELECT e.block_hash, e.block_height, e.miner, e.plot_id, e.merkle_root,
        e.capacity_bytes, e.tx_hash
      FROM plot_registration_events e
      JOIN ancestry a ON a.hash = e.block_hash
      WHERE e.block_height <= ?
      ORDER BY e.block_height, e.tx_hash
    `).all(parentHash, cutoff);
  }

  getPlotRegistration(plotId, miner, parentHash, maxHeight = Number.MAX_SAFE_INTEGER) {
    const id = String(plotId || '').toLowerCase();
    const owner = String(miner || '').toLowerCase();
    const matches = this._plotRegistrationsOnAncestry(parentHash, Math.max(0, maxHeight)).filter((r) => r.plot_id === id);
    if (matches.length !== 1 || matches[0].miner !== owner) return null;
    return matches[0];
  }

  getPlotRegistrations(parentHash, maxHeight = Number.MAX_SAFE_INTEGER) {
    return this._plotRegistrationsOnAncestry(parentHash, maxHeight);
  }

  getMaturePlotRegistrations(parentHash, winnerHeight) {
    const matureHeight = safeInt(winnerHeight, 0) - 2;
    if (safeInt(winnerHeight, 0) <= 0) return [];
    const rows = this._plotRegistrationsOnAncestry(parentHash, Math.max(0, matureHeight))
      .filter((row) => row.block_height === 0 || row.block_height <= matureHeight);
    const ids = new Set();
    for (const row of rows) {
      if (ids.has(row.plot_id)) throw new Error(`duplicate plot_id ${row.plot_id} in parent ancestry`);
      ids.add(row.plot_id);
    }
    return rows;
  }

  verifyPocV4CapacityProof(proof, challengeId, miner, plotId, winnerHeight, parentHash) {
    try {
      const registration = this.getPlotRegistration(plotId, miner, parentHash, Math.max(0, winnerHeight - 2));
      if (!registration) return { ok: false, motivo: 'plot registration is not present and mature on the parent ancestry' };
      const totalLeaves = Number(BigInt(registration.capacity_bytes) / 32n);
      const totalScoops = safeInt(proof && proof.total_scoops, -1);
      if (totalScoops !== totalLeaves) return { ok: false, motivo: 'winner_proof total_scoops does not match registered capacity' };
      if (String(proof.merkle_root || '').toLowerCase() !== registration.merkle_root) {
        return { ok: false, motivo: 'winner_proof root does not match mature on-chain registration' };
      }
      const targetSlot = PocPlotV4.challengeTargetSlot(challengeId);
      const index = safeInt(proof.scoop_index, -1);
      if (index < 0 || index >= totalLeaves || index % SCOOPS_PER_NONCE !== targetSlot) {
        return { ok: false, motivo: 'winner_proof index is not the canonical v4 target slot' };
      }
      const targetLeaf = PocPlotV4.canonicalLeaf({
        chainId: this.cfg.chainId,
        miner,
        plotId,
        index,
      });
      if (String(proof.scoop_data || '') !== targetLeaf.toString('hex')) {
        return { ok: false, motivo: 'winner_proof target leaf is not canonical for this chain and plot' };
      }
      if (!PocPlotV4.verifyCanonicalMerkleProof(targetLeaf, index, totalLeaves, proof.merkle_proof, registration.merkle_root)) {
        return { ok: false, motivo: 'winner_proof target Merkle path is invalid' };
      }
      const expectedSamples = PocPlotV4.deriveCapacitySampleIndexes(
        challengeId, totalLeaves, plotId, PocPlotV4.SAMPLE_COUNT, PocPlotV4.SAMPLE_ROUND, [index],
      );
      if (!Array.isArray(proof.capacity_samples) || proof.capacity_samples.length !== expectedSamples.length) {
        return { ok: false, motivo: 'winner_proof must contain exactly 16 capacity samples' };
      }
      for (let i = 0; i < expectedSamples.length; i++) {
        const sample = proof.capacity_samples[i];
        const sampleIndex = safeInt(sample && sample.index, -1);
        if (sampleIndex !== expectedSamples[i]) return { ok: false, motivo: 'capacity samples are missing, duplicated, or out of canonical order' };
        const expectedLeaf = PocPlotV4.canonicalLeaf({ chainId: this.cfg.chainId, miner, plotId, index: sampleIndex });
        if (String(sample.leaf || '') !== expectedLeaf.toString('hex')) return { ok: false, motivo: `capacity sample ${i} leaf is not canonical` };
        if (!PocPlotV4.verifyCanonicalMerkleProof(expectedLeaf, sampleIndex, totalLeaves, sample.merkle_proof, registration.merkle_root)) {
          return { ok: false, motivo: `capacity sample ${i} Merkle path is invalid` };
        }
      }
      return { ok: true, registration, totalLeaves, targetSlot };
    } catch (e) {
      return { ok: false, motivo: e.message || 'invalid v4 capacity proof' };
    }
  }

  _preparePlotRegistrationEvents(txs, height, parentHash) {
    const events = [];
    const currentIds = new Set();
    const prior = this._plotRegistrationsOnAncestry(parentHash);
    const knownIds = new Set(prior.map((r) => r.plot_id));
    const maxPerBlock = Math.max(1, safeInt(this.cfg.maxPlotRegistrationsPerBlock, 4));
    const maxPerMiner = Math.max(1, safeInt(this.cfg.maxPlotRegistrationsPerMinerPerBlock, 1));
    const perMiner = new Map();
    for (const tx of txs) {
      if (!PocPlotV4.isRegistrationPayload(tx && tx.data)) continue;
      let registration;
      try { registration = PocPlotV4.decodeRegistration(tx.data); }
      catch (e) { throw new Error(`invalid v4 plot registration: ${e.message}`); }
      const sender = String(tx.from_addr || '');
      let value;
      try { value = BigInt(tx.value == null ? '0' : tx.value); } catch { value = -1n; }
      const envelopeValid = sender === sender.toLowerCase()
        && /^0x[0-9a-f]{40}$/.test(sender)
        && String(tx.to_addr || '') === PocPlotV4.ZERO_ADDRESS
        && value === 0n
        && String(tx.chain_id) === String(this.cfg.chainId);
      if (!envelopeValid) {
        throw new Error('v4 plot registration must be a canonical zero-value transaction to the zero address');
      }
      if (knownIds.has(registration.plot_id) || currentIds.has(registration.plot_id)) {
        throw new Error(`plot_id ${registration.plot_id} is already registered in this ancestry`);
      }
      if (events.length >= maxPerBlock) {
        throw new Error(`too many v4 plot registrations in one block (max ${maxPerBlock})`);
      }
      const already = perMiner.get(sender) || 0;
      if (already >= maxPerMiner) {
        throw new Error(`miner ${sender} exceeds ${maxPerMiner} v4 plot registration(s) per block`);
      }
      perMiner.set(sender, already + 1);
      currentIds.add(registration.plot_id);
      events.push({
        block_height: height,
        miner: sender,
        plot_id: registration.plot_id,
        merkle_root: registration.merkle_root,
        capacity_bytes: registration.capacity_bytes,
        tx_hash: tx.hash || hashTransaction(tx),
      });
    }
    return events;
  }

  _backfillPlotRegistrationEvents() {
    const rows = this.db.prepare(`
      SELECT t.hash, t.from_addr, t.to_addr, t.value, t.data, t.chain_id,
        b.hash AS block_hash, b.height AS block_height
      FROM transactions t JOIN blocks b ON b.hash = t.block_hash
      WHERE t.data LIKE '0x43435043%'
    `).all();
    const insert = this.db.prepare(`
      INSERT OR IGNORE INTO plot_registration_events
      (block_hash, block_height, miner, plot_id, merkle_root, capacity_bytes, tx_hash)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `);
    const save = this.db.transaction(() => {
      for (const tx of rows) {
        try {
          const reg = PocPlotV4.decodeRegistration(tx.data);
          if (String(tx.from_addr || '') !== String(tx.from_addr || '').toLowerCase()
            || !/^0x[0-9a-f]{40}$/.test(String(tx.from_addr || ''))
            || String(tx.to_addr || '').toLowerCase() !== PocPlotV4.ZERO_ADDRESS
            || BigInt(tx.value || '0') !== 0n
            || String(tx.chain_id) !== String(this.cfg.chainId)) continue;
          insert.run(tx.block_hash, tx.block_height, tx.from_addr, reg.plot_id, reg.merkle_root, reg.capacity_bytes, tx.hash);
        } catch { /* historical ordinary transactions are not registration events */ }
      }
    });
    save();
  }

  // ================== Diff Manager things ==================================
  _targetForHeight(height) { return this.diffManager._targetForHeight(height); }
  _blockWork(block) { return this.diffManager._blockWork(block); }
  _defaultBaseTarget() { return this.diffManager._defaultBaseTarget(); }
  _baseTargetCapacity() { return this.diffManager._baseTargetCapacity(); }
  _baseTargetForHeight(height) { return this.diffManager._baseTargetForHeight(height); }
  _baseFeeForHeight(height) { return this.diffManager._baseFeeForHeight(height); }

  // ================== Mempool Manager things ==================================
  _validateTxOrder(txs) { return this.mempoolManager._validateTxOrder(txs); }
  _validateTxBalances(txs) { return this.mempoolManager._validateTxBalances(txs); }
  _txRootMatches(bloco) {
    if (!bloco || !Array.isArray(bloco.transactions)) return true;
    const txs = bloco.transactions || [];
    const expected = merkleRoot(txs.map(tx => tx && tx.hash ? tx.hash : hashTransaction(tx)));
    return String(bloco.tx_root || '') === String(expected);
  }
  async validateTxForMempool(tx) { return this.mempoolManager.validateTxForMempool(tx); }
  addMempoolTx(tx) { return this.mempoolManager.addMempoolTx(tx); }
  getMempoolForBlock(maxCount = 100) { return this.mempoolManager.getMempoolForBlock(maxCount); }
  cleanMempool() { return this.mempoolManager.cleanMempool(); }

  // ================== Contracts Manager things ==================================
  _isContractCall(tx) { return this.contractsManager._isContractCall(tx); }
  _isContractOp(tx) { return this.contractsManager._isContractOp(tx); }
  async _preExecuteContracts(bloco, txs) { return this.contractsManager._preExecuteContracts(bloco, txs); }
  _recordContractStateChanges(blockHeight, blockHash, snapshots) { return this.contractsManager._recordContractStateChanges(blockHeight, blockHash, snapshots); }
  _restoreContractStateFromHistory(aboveHeight) { return this.contractsManager._restoreContractStateFromHistory(aboveHeight); }

  setContractExecutor(sc) { this.contracts = sc; }

  _initGenesis() {
    const cfg = this.cfg;
    const now = cfg.genesisTimestamp || Math.floor(Date.now() / 1000);
    const target = cfg.initialTarget || '0x00FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF';
    const reward = calculateMiningReward(0, cfg);
    const state_root = computeStateRoot(this.db);
    const genesis = {
      height: 0, chain_id: this.cfg.chainId, parent_hash: ZERO_HASH, timestamp: now,
      miner: 'genesis', challenge_id: '', tx_root: ZERO_HASH,
      nonce: '0', difficulty: '0', target: String(target),
      reward_units: '0', reward_cc: String(reward), tx_count: 0,
      signature: '', generation_signature: ZERO_HASH,
      proof_digest: '', plot_id: '', state_root,
      origin: 'genesis', total_fees_units: '0', gas_used: 0, gas_limit: GAS_PARAMS.blockGasLimit, base_target: String(this.cfg.genesisBaseTarget ?? this._defaultBaseTarget()),
      transactions: [], rewards: [], genesis_plot_registrations: this.genesisPlotRegistrations,
    };
    genesis.hash = hashBlock(genesis);
    try {
      const work = this._blockWork(genesis);
      const totalFees = 0n;
      const gasUsed = 0;
      this.db.prepare(`INSERT INTO blocks (height, hash, parent_hash, timestamp, miner, challenge_id, tx_root, nonce, difficulty, target,
        reward_units, reward_cc, tx_count, chain_work, signature, generation_signature, proof_digest, plot_id, state_root, origin,
        total_fees_units, gas_used, gas_limit, base_target, base_fee, contract_state_root, forger, rewards_json) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).run(
        0, genesis.hash, ZERO_HASH, now, 'genesis', '', ZERO_HASH, '0', '0', String(target),
        '0', String(reward), 0, String(work), '', ZERO_HASH, '', '', state_root, 'genesis',
        String(totalFees), gasUsed, GAS_PARAMS.blockGasLimit, genesis.base_target, String(GAS_PARAMS.initialBaseFee),
        genesis.contract_state_root || '', genesis.forger || '', '[]'
      );
      const insertGenesisPlot = this.db.prepare(`
        INSERT INTO plot_registration_events
        (block_hash, block_height, miner, plot_id, merkle_root, capacity_bytes, tx_hash)
        VALUES (?, 0, ?, ?, ?, ?, ?)
      `);
      for (const plot of this.genesisPlotRegistrations) {
        const commitmentId = sha256hex(`CCPOC:GENESIS:PLOT:V4:${plot.miner}:${plot.plot_id}:${plot.merkle_root}:${plot.capacity_bytes}`);
        insertGenesisPlot.run(genesis.hash, plot.miner, plot.plot_id, plot.merkle_root, plot.capacity_bytes, commitmentId);
      }
      this.height = 0;
      this.bestHash = genesis.hash;
      log('info', `Genesis block created — hash: ${genesis.hash.slice(0, 16)}`);
    } catch (e) {
      log('warn', `Genesis creation skipped (${e.message})`);
    }
  }

  _loadTip() {
    const row = this.db.prepare('SELECT height, hash FROM blocks ORDER BY LENGTH(chain_work) DESC, chain_work DESC, hash ASC LIMIT 1').get();
    if (row) { this.height = row.height; this.bestHash = row.hash; }
  }

  _validateRewardDistribution(bloco) {
    if (safeInt(bloco.height, 0) <= 0) return { ok: true };
    const rewardsData = bloco.rewards || [];
    if (!Array.isArray(rewardsData)) return { ok: false, motivo: 'invalid reward distribution' };
    const totalReward = calculateMiningReward(bloco.height, this.cfg);
    const maxSupply = safeBigInt(this.cfg.maxSupply, 0n);
    if (maxSupply > 0n) {
      const emitted = this.db.prepare('SELECT reward_cc FROM blocks WHERE height > 0').all().reduce((sum, row) => sum + safeBigInt(row.reward_cc, 0n), 0n);
      if (safeBigInt(emitted, 0n) + totalReward > maxSupply) return { ok: false, motivo: 'max supply exceeded' };
    }
    let subKeys = null;
    if (bloco.challenge_id) {
      const hasSubs = this.db.prepare('SELECT 1 FROM challenge_submissions WHERE challenge_id = ? LIMIT 1').get(bloco.challenge_id);
      if (hasSubs) {
        const subs = this.db.prepare('SELECT miner, plot_id, deadline FROM challenge_submissions WHERE challenge_id = ?').all(bloco.challenge_id);
        subKeys = new Set(subs.map(s => `${normalizeAddr(s.miner)}:${s.plot_id || ''}:${s.deadline}`));
      }
    }
    if (rewardsData.length < 1 || rewardsData.length > MAX_REWARD_ENTRIES) return { ok: false, motivo: `reward entries must be between 1 and ${MAX_REWARD_ENTRIES} (got ${rewardsData.length})` };
    const wp = bloco.winner_proof && typeof bloco.winner_proof === 'object' ? bloco.winner_proof : null;
    if (!wp) {
      if (rewardsData.length !== 1) return { ok: false, motivo: `winner-takes-all expects exactly one reward entry (got ${rewardsData.length})` };
      const r = rewardsData[0];
      if (typeof r !== 'object' || r === null || !r.miner) return { ok: false, motivo: 'reward entry missing miner' };
      const miner = normalizeAddr(r.miner);
      if (miner !== normalizeAddr(bloco.miner || '')) return { ok: false, motivo: 'reward miner does not match block miner' };
      const plot = r.plot_id || '';
      const deadline = safeInt(r.deadline, -1);
      if (deadline < 0) return { ok: false, motivo: 'reward entry has invalid deadline' };
      const key = `${miner}:${plot}:${deadline}`;
      if (subKeys && !subKeys.has(key)) {
        log('warn', `reward entry for ${miner} has no matching submission in challenge ${(bloco.challenge_id || '').slice(0, 12)}`);
        return { ok: false, motivo: `reward for ${miner} has no matching proof submission` };
      }
      let reward;
      try { reward = BigInt(r.reward_cc || '0'); } catch { reward = 0n; }
      if (reward < 0n) return { ok: false, motivo: 'reward entry has negative reward_cc' };
      if (reward !== totalReward) return { ok: false, motivo: 'reward entry must equal the block reward' };
      return { ok: true };
    }
    const wpMiner = normalizeAddr(wp.miner || '');
    const wpPlot = String(wp.plot_id || '');
    const wpDeadline = safeInt(wp.deadline, -1);
    let sum = 0n;
    let winnerCovered = false;
    for (const r of rewardsData) {
      if (typeof r !== 'object' || r === null || !r.miner) return { ok: false, motivo: 'reward entry missing miner' };
      const miner = normalizeAddr(r.miner);
      const deadline = safeInt(r.deadline, -1);
      if (deadline < 0) return { ok: false, motivo: 'reward entry has invalid deadline' };
      let amount;
      try { amount = BigInt(r.reward_cc || '0'); } catch { amount = 0n; }
      if (amount < 0n) return { ok: false, motivo: 'reward entry has negative reward_cc' };
      if (amount === 0n && totalReward > 0n) return { ok: false, motivo: 'reward entry must be positive' };
      sum += amount;
      if (miner === wpMiner && String(r.plot_id || '') === wpPlot && deadline === wpDeadline) winnerCovered = true;
    }
    if (sum !== totalReward) return { ok: false, motivo: 'reward entries must sum to the block reward' };
    if (!winnerCovered) return { ok: false, motivo: 'no reward entry matches the winning proof' };
    return { ok: true };
  }

  _attachTransactions(bloco) {
    if (bloco && !Array.isArray(bloco.transactions)) {
      bloco.transactions = this.db.prepare('SELECT * FROM transactions WHERE block_hash = ? ORDER BY rowid').all(bloco.hash);
    }
    if (bloco) {
      if (!Array.isArray(bloco.rewards)) {
        try { bloco.rewards = bloco.rewards_json ? JSON.parse(bloco.rewards_json) : []; } catch { bloco.rewards = []; }
        if (!Array.isArray(bloco.rewards)) bloco.rewards = [];
      }
      delete bloco.rewards_json;
      if (typeof bloco.winner_proof === 'string' && bloco.winner_proof.startsWith('{')) {
        try { bloco.winner_proof = JSON.parse(bloco.winner_proof); } catch { /* keep raw string */ }
      } else if (bloco.winner_proof == null) {
        bloco.winner_proof = null;
      }
    }
    return bloco;
  }

  getBlock(heightOrHash) {
    let row;
    if (typeof heightOrHash === 'number' || /^\d+$/.test(String(heightOrHash))) {
      row = this.db.prepare('SELECT * FROM blocks WHERE height = ? ORDER BY LENGTH(chain_work) DESC, chain_work DESC, hash ASC LIMIT 1').get(Number(heightOrHash));
    } else {
      row = this.db.prepare('SELECT * FROM blocks WHERE hash = ?').get(heightOrHash);
    }
    return this._attachTransactions(row);
  }

  getBlockByHash(hash) { return this._attachTransactions(this.db.prepare('SELECT * FROM blocks WHERE hash = ?').get(hash)); }

  getStats() {
    const tip = this.getBlock(this.height);
    const totalTxs = this.db.prepare('SELECT COUNT(*) as c FROM transactions').get().c;
    const wallets = this.db.prepare('SELECT COUNT(*) as c FROM users').get().c;
    const mempoolCount = this.db.prepare('SELECT COUNT(*) as c FROM mempool').get().c;
    let plotsCount;
    let capacityGb;
    const registrations = tip ? this.getMaturePlotRegistrations(tip.hash, this.height + 1) : [];
    plotsCount = registrations.length;
    capacityGb = Number(registrations.reduce((sum, r) => sum + BigInt(r.capacity_bytes), 0n)) / (1024 ** 3);
    const totalBlocks = this.db.prepare('SELECT COUNT(*) as c FROM blocks').get().c;
    const supply = this.db.prepare("SELECT balance FROM users").all().reduce((s, r) => s + safeBigInt(r.balance, 0n), 0n).toString();
    return {
      height: this.height, hash: this.bestHash, blocks: totalBlocks,
      users: wallets, total_txs: totalTxs, mempool: mempoolCount,
      plots_count: plotsCount, capacity_gb: Number(capacityGb.toFixed(2)),
      chain_work: (tip && tip.chain_work) || '0',
      supply: String(supply), max_deadline: this.computeMaxDeadline(),
      base_target: (tip && tip.base_target) || String(BigInt(2) ** BigInt(64) / BigInt(5898240)),
    };
  }

  async addBlock(bloco, opts = {}) {
    const {
      forceSync = false,
      allowEqualWork = false,
      allowVotedTie = false,
      allowIntermediateEqualWork = false,
    } = opts;
    const isLocalForge = !!bloco._from_local_forge;
    const blockOrigin = isLocalForge ? 'local' : 'network';
    delete bloco._from_local_forge;
    let plotRegistrationEvents = [];
    const height = bloco.height;
    const parent = height > 0
      ? this.db.prepare('SELECT height, timestamp, hash, chain_work, generation_signature FROM blocks WHERE hash = ?').get(bloco.parent_hash)
      : null;
    if (typeof height !== 'number') return { ok: false, motivo: 'height missing' };
    if (!bloco.hash || !bloco.parent_hash) return { ok: false, motivo: 'hash or parent_hash missing' };
    if (this.db.prepare('SELECT 1 FROM blocks WHERE hash = ?').get(bloco.hash)) return { ok: true, motivo: 'already known' };
    {
        const computedHash = await hashBlockAsync(bloco);
        if (computedHash !== bloco.hash) return { ok: false, motivo: 'block hash mismatch' };
      }
    if (bloco.miner) bloco.miner = normalizeAddr(bloco.miner);
    if (Array.isArray(bloco.rewards)) bloco.rewards.forEach(r => { if (r.miner) r.miner = normalizeAddr(r.miner); });
    if (height > 0) {
      if (!parent) return { ok: false, motivo: 'parent not found' };
      if (parent.height !== height - 1) return { ok: false, motivo: 'height sequence error' };
      const medianTimes = this.db.prepare('SELECT timestamp FROM blocks WHERE height <= ? ORDER BY height DESC LIMIT 11').all(parent.height).map(r => safeInt(r.timestamp, 0)).sort((a, b) => a - b);
      const medianTime = medianTimes.length ? medianTimes[Math.floor(medianTimes.length / 2)] : safeInt(parent.timestamp, 0);
      const expectedGenerationSignature = sha256hex(`${this.db.prepare('SELECT generation_signature FROM blocks WHERE hash = ?').get(bloco.parent_hash)?.generation_signature || ZERO_HASH}${bloco.parent_hash}`);
      if (String(bloco.generation_signature || '') !== expectedGenerationSignature) return { ok: false, motivo: 'invalid generation_signature' };
      if (safeInt(bloco.timestamp, -1) <= safeInt(parent.timestamp, -1)) return { ok: false, motivo: 'timestamp <= parent' };
      if (safeInt(bloco.timestamp, -1) <= medianTime) return { ok: false, motivo: 'timestamp not greater than median-time-past' };
      if (safeInt(bloco.timestamp, 0) > Date.now() / 1000 + this.cfg.maxFutureBlockSec) return { ok: false, motivo: 'timestamp too far in future' };
      if (isLocalForge && bloco.challenge_id && bloco.nonce) {
        const ch = this.db.prepare('SELECT created_at, winner_deadline FROM mining_challenges WHERE challenge_id = ?').get(bloco.challenge_id);
        if (ch && ch.winner_deadline) {
          const earliestForge = (ch.created_at || 0) + ch.winner_deadline;
          if (safeInt(bloco.timestamp, 0) < earliestForge) {
            return { ok: false, motivo: `block forged too early: timestamp ${bloco.timestamp} < earliest ${earliestForge} (deadline ${ch.winner_deadline}s)` };
          }
        }
      }
      const expectedTarget = this._targetForHeight(height);
      let blockTarget;
      try { blockTarget = BigInt(bloco.target || '0'); } catch { blockTarget = 0n; }
      if (blockTarget === 0n) try { blockTarget = BigInt(this.cfg.initialTarget); } catch { blockTarget = 0n; }
      if (blockTarget !== expectedTarget) return { ok: false, motivo: `incorrect target: got ${blockTarget}, expected ${expectedTarget}` };
      const expectedBaseTarget = BigInt(this._baseTargetForHeight(height));
      if (!bloco.base_target) bloco.base_target = String(expectedBaseTarget);
      let blockBaseTarget;
      try { blockBaseTarget = BigInt(bloco.base_target); } catch { return { ok: false, motivo: 'invalid base_target format' }; }
      if (expectedBaseTarget > 0n && blockBaseTarget > 0n) {
        const ratio = blockBaseTarget > expectedBaseTarget
          ? blockBaseTarget / expectedBaseTarget
          : expectedBaseTarget / blockBaseTarget;
        const maxRatio = BigInt(Math.max(1, safeInt(this.cfg.btDriftTolerance, 2)));
        if (ratio > maxRatio) {
          log('warn', `base_target drift at #${height}: got ${blockBaseTarget}, expected ${expectedBaseTarget} (${Number(ratio)}x > ${maxRatio}x)`);
          return { ok: false, motivo: `incorrect base_target: got ${blockBaseTarget}, expected ${expectedBaseTarget}` };
        }
      }
    }
    const txs = bloco.transactions || [];
    const [balanceOk, balanceMotivo] = this._validateTxBalances(txs);
    if (!balanceOk) return { ok: false, motivo: balanceMotivo };
    {
      let blockBaseFee;
      try { blockBaseFee = BigInt(this._baseFeeForHeight(height)); } catch { return { ok: false, motivo: 'invalid base_fee' }; }
      for (const tx of txs) {
        const intrinsic = estimateIntrinsicGas(tx);
        const gasLimit = safeInt(tx.gas_limit, 0);
        if (gasLimit < intrinsic || gasLimit > GAS_PARAMS.maxGasPerTx) return { ok: false, motivo: 'invalid transaction gas_limit' };
        // v4 plot registrations are zero-fee protocol declarations: they must be
        // canonical zero-value txs to the zero address and are exempt from the
        // gas_price/fee minimums (anti-spam is handled by per-block caps).
        if (PocPlotV4.isRegistrationPayload(tx.data)) continue;
        if (safeBigInt(tx.gas_price, 0n) < blockBaseFee) return { ok: false, motivo: 'transaction gas_price below base fee' };
        if (safeBigInt(tx.fee, 0n) < minimumFee(tx, blockBaseFee)) return { ok: false, motivo: 'transaction fee below minimum' };
      }
      const [ok, motivo] = this._validateTxOrder(txs);
      if (!ok) return { ok: false, motivo };
      if (!this._txRootMatches(bloco)) return { ok: false, motivo: 'tx_root mismatch' };
      if (safeInt(bloco.tx_count, txs.length) !== txs.length) return { ok: false, motivo: 'tx_count mismatch' };
      try {
        plotRegistrationEvents = this._preparePlotRegistrationEvents(txs, height, parent.hash);
      } catch (e) {
        return { ok: false, motivo: e.message || 'invalid plot registration transaction' };
      }
    }
    if (height > 0) {
      if (!bloco.signature) return { ok: false, motivo: 'block not signed' };
      let signerPubKey = null;
      if (bloco.miner_public_key) {
        try { pubkeyToAddress(bloco.miner_public_key); } catch { return { ok: false, motivo: 'invalid miner_public_key encoding' }; }
        signerPubKey = bloco.miner_public_key;
      }
      const expectedSigner = String(bloco.forger || bloco.miner || '').toLowerCase();
      if (!signerPubKey) {
        const pkRow = this.db.prepare('SELECT public_key_secp256k1 FROM user_keys WHERE address = ?').get(expectedSigner)
          || this.db.prepare('SELECT public_key_secp256k1 FROM users WHERE address = ?').get(expectedSigner);
        if (pkRow && pkRow.public_key_secp256k1) signerPubKey = pkRow.public_key_secp256k1;
      }
      if (!signerPubKey) return { ok: false, motivo: 'forger not registered or no key' };
      try {
        if (pubkeyToAddress(signerPubKey).toLowerCase() !== expectedSigner) return { ok: false, motivo: 'block signer does not match forger' };
      } catch { return { ok: false, motivo: 'invalid block signer key' }; }
      if (!verifySignature(blockMessage(bloco), bloco.signature, signerPubKey)) return { ok: false, motivo: 'invalid block signature' };

      if (height > 0) {
        if (!bloco.challenge_id) return { ok: false, motivo: 'block missing challenge_id' };
        const winnerProof = bloco.winner_proof && typeof bloco.winner_proof === 'object' ? bloco.winner_proof : {};
        const storedChallenge = this.db.prepare('SELECT * FROM mining_challenges WHERE challenge_id = ?').get(bloco.challenge_id);
        const storedFinalized = !!(storedChallenge && storedChallenge.finalized_at &&
          storedChallenge.winner_miner && safeInt(storedChallenge.winner_deadline, -1) >= 0);
        const challenge = storedFinalized ? storedChallenge : {
          challenge_id: bloco.challenge_id,
          challenge_seed: String(winnerProof.challenge_seed || ''),
          block_height: height - 1,
          winner_miner: bloco.miner,
          winner_deadline: safeInt(winnerProof.deadline, -1),
          created_at: safeInt(bloco.challenge_created_at, safeInt(parent.timestamp, 0)),
          finalized_at: 1,
        };
        if (!challenge.finalized_at || !challenge.winner_miner || safeInt(challenge.winner_deadline, -1) < 0) return { ok: false, motivo: 'challenge has no finalized winner' };
        const expectedChallengeId = sha256hex(`${String(challenge.challenge_seed || '')}:${String(parent.hash)}`);
        if (String(bloco.challenge_id) !== expectedChallengeId) return { ok: false, motivo: 'challenge is not bound to parent' };
        if (safeInt(challenge.block_height, -1) !== parent.height) return { ok: false, motivo: 'challenge height does not match parent' };
        const wp = bloco.winner_proof;
        if (!wp || typeof wp !== 'object') {
          return { ok: false, motivo: 'block missing winner_proof for challenge' };
        }
        const wpMiner = normalizeAddr(wp.miner || '');
        const wpDeadline = safeInt(wp.deadline, -1);
        const wpPlotId = String(wp.plot_id || '');
        if (wpMiner !== bloco.miner) {
          return { ok: false, motivo: 'winner_proof.miner does not match block.miner' };
        }
        if (wpDeadline < 0) {
          return { ok: false, motivo: 'winner_proof has no deadline' };
        }
        if (safeInt(bloco.timestamp, 0) < safeInt(parent.timestamp, 0) + wpDeadline) return { ok: false, motivo: 'block timestamp precedes winning deadline' };
        if (!wp.proof_signature) {
          return { ok: false, motivo: 'winner_proof not signed' };
        }
        const wpPk = String(wp.public_key || '');
        if (!wpPk) {
          return { ok: false, motivo: 'winner_proof miner has no public key' };
        }
        try {
          if (pubkeyToAddress(wpPk).toLowerCase() !== wpMiner) return { ok: false, motivo: 'winner_proof public key does not match miner' };
        } catch { return { ok: false, motivo: 'winner_proof miner public key is invalid' }; }
        const wpMsg = proofMessage(bloco.challenge_id, wpMiner, wpDeadline, wpPlotId);
        const wpSigValid = await verifySignatureAsync(wpMsg, wp.proof_signature, wpPk);
        if (!wpSigValid) {
          return { ok: false, motivo: 'invalid winner_proof signature — miner did not submit this proof' };
        }

        const scoopData = String(wp.scoop_data || '');
        if (!/^[0-9a-fA-F]+$/.test(scoopData) || scoopData.length !== 64) {
          return { ok: false, motivo: 'winner_proof missing 32-byte scoop_data' };
        }
        const scoopIndex = safeInt(wp.scoop_index, -1);
        const totalScoops = safeInt(wp.total_scoops, 0);
        if (totalScoops < 1 || scoopIndex < 0 || scoopIndex >= totalScoops) {
          return { ok: false, motivo: `winner_proof invalid scoop_index ${scoopIndex} for ${totalScoops} scoops` };
        }
        const merkleRootClaim = String(wp.merkle_root || '');
        if (!/^[0-9a-fA-F]{64}$/.test(merkleRootClaim)) {
          return { ok: false, motivo: 'winner_proof missing merkle_root' };
        }
        const registration = this.getPlotRegistration(wpPlotId, wpMiner, parent.hash, Math.max(0, height - 2));
        if (!registration || (registration.block_height !== 0 && registration.block_height > height - 2)) {
          return { ok: false, motivo: 'winner plot has no mature registration on the parent ancestry' };
        }
        const v4Proof = this.verifyPocV4CapacityProof(wp, bloco.challenge_id, wpMiner, wpPlotId, height, parent.hash);
        if (!v4Proof.ok) return { ok: false, motivo: v4Proof.motivo };
        const genSig = String(wp.challenge_seed || '');
        if (!genSig) {
          return { ok: false, motivo: 'winner_proof missing challenge_seed' };
        }
        if (genSig !== String(challenge.challenge_seed || '')) return { ok: false, motivo: 'winner_proof challenge_seed mismatch' };
        if (safeInt(challenge.block_height, -1) !== height - 1) return { ok: false, motivo: 'challenge does not belong to parent height' };
        const challengeBt = String(challenge.base_target || this._baseTargetForHeight(challenge.block_height || height - 1));
        const wpBaseTarget = safeBigInt(wp.base_target, 0n);
        if (wpBaseTarget > 0n && /^\d+$/.test(challengeBt)) {
          const expectedChallengeBt = BigInt(challengeBt);
          if (expectedChallengeBt > 0n) {
            const ratio = wpBaseTarget > expectedChallengeBt ? wpBaseTarget / expectedChallengeBt : expectedChallengeBt / wpBaseTarget;
            const maxRatio = BigInt(Math.max(1, safeInt(this.cfg.btDriftTolerance, 2)));
            if (ratio > maxRatio) {
              return { ok: false, motivo: `winner_proof base_target drift (${Number(ratio)}x > ${maxRatio}x)` };
            }
          }
        }
        const recomputed = computeDeadline(scoopData, genSig, /^\d+$/.test(challengeBt) && BigInt(challengeBt) > 0n ? challengeBt : String(wpBaseTarget));
        if (recomputed !== wpDeadline) {
          return { ok: false, motivo: `PoC verification failed: computed deadline ${recomputed}s, claimed ${wpDeadline}s` };
        }
      }
    }
    const rewardCheck = this._validateRewardDistribution(bloco);
    if (!rewardCheck.ok) return { ok: false, motivo: rewardCheck.motivo };
    const now = Math.floor(Date.now() / 1000);
    const rewardsData = bloco.rewards || [];
    const reward = calculateMiningReward(height, this.cfg);
    const rewardStr = String(reward);
    const totalTxFees = txs.reduce((s, t) => s + safeBigInt(t.fee, 0n), 0n);
    const gasUsed = txs.reduce((s, t) => s + estimateIntrinsicGas(t), 0);
    if (gasUsed > GAS_PARAMS.blockGasLimit) {
      return { ok: false, motivo: `block gas ${gasUsed} exceeds max block gas limit ${GAS_PARAMS.blockGasLimit}` };
    }
    const parentWork = height > 0 ? (() => { const p = this.db.prepare('SELECT chain_work FROM blocks WHERE hash = ?').get(bloco.parent_hash); return p ? safeBigInt(p.chain_work, 0n) : 0n; })() : 0n;
    const newWork = parentWork + this._blockWork(bloco);
    bloco.chain_work = String(newWork);
    if (!bloco.hash) bloco.hash = await hashBlockAsync(bloco);
    const existingAtHeight = this.db.prepare('SELECT hash, chain_work FROM blocks WHERE height = ?').get(height);
    if (existingAtHeight && existingAtHeight.hash !== bloco.hash) {
      if (forceSync) {
        if (height <= this.height - FINALIZATION_DEPTH) return { ok: false, motivo: 'cannot replace finalized block during sync' };
        const incumbent = this.getBlockByHash(existingAtHeight.hash);
        const incumbentWork = safeBigInt(existingAtHeight.chain_work, 0n);
        const equalWorkTie = newWork === incumbentWork && (
          allowIntermediateEqualWork
          || (allowEqualWork && (allowVotedTie || isBetterChainCandidate(bloco, incumbent)))
        );
        if (newWork < incumbentWork) return { ok: false, motivo: 'forced candidate does not have more chain work' };
        if (newWork === incumbentWork && !equalWorkTie) {
          return { ok: false, motivo: 'forced candidate does not have more chain work or a valid tie-break' };
        }
        log('debug', `addBlock forceSync h=${height} local=${existingAtHeight.hash.slice(0, 10)} remote=${bloco.hash.slice(0, 10)}`);
        const doomed = this.getBlockByHash(existingAtHeight.hash);
        if (doomed) this._rollbackRewardsForBlock(doomed.hash);
        if (doomed) this._rollbackPayoutsForBlock(doomed.hash);
        // Desfaz também o que as transações do bloco incumbente aplicaram em
        // users (débito do sender, crédito do recipient, taxa do forger). Sem
        // isso o estado fica com o efeito do bloco descartado E do bloco novo,
        // e todo bloco seguinte falha com state_root mismatch para sempre.
        this._rollbackTxsForBlock(existingAtHeight.hash);
        this.db.prepare('DELETE FROM contract_logs WHERE block_hash = ?').run(existingAtHeight.hash);
        this.db.prepare('DELETE FROM transactions WHERE block_hash = ?').run(existingAtHeight.hash);
        this.db.prepare('DELETE FROM blocks WHERE hash = ?').run(existingAtHeight.hash);
        log('debug', `addBlock forceSync: replaced incumbent ${existingAtHeight.hash.slice(0, 10)} at h=${height}`);
      } else if (isBetterChainCandidate(bloco, this.getBlockByHash(existingAtHeight.hash))
        || (allowVotedTie && newWork === safeBigInt(existingAtHeight.chain_work, 0n))) {
        log('debug', `addBlock better candidate h=${height} local=${existingAtHeight.hash.slice(0, 10)} remote=${bloco.hash.slice(0, 10)}`);
        const reorgResult = await this.reorganize(bloco, false, allowVotedTie);
        if (!reorgResult.ok) return { ok: false, motivo: `reorg failed: ${reorgResult.motivo}` };
        return { ok: true, motivo: 'reorganized to better tip', height: this.height, hash: this.bestHash };
      } else {
        return { ok: false, motivo: 'competing block not better than incumbent' };
      }
    }

    let contractExec = null;
    const contractTxs = txs.filter(t => this._isContractOp(t));
    if (contractTxs.length) {
      if (!this.contracts) return { ok: false, motivo: 'block contains contract txs but smart contracts are disabled' };
      contractExec = await this._preExecuteContracts(bloco, txs);
      if (!contractExec.ok) {
        contractExec.rollback();
        return { ok: false, motivo: contractExec.motivo };
      }
    }

    if (this.stateTrieLoadPromise) await this.stateTrieLoadPromise;

    try {
      this.db.transaction(() => {
        for (const d of rewardsData) {
          if (typeof d !== 'object' || !d.miner) continue;
          const rewardCc = safeBigInt(d.reward_cc, 0n);
          if (rewardCc > 0n) {
            const cur = this.db.prepare('SELECT balance FROM users WHERE address = ?').get(d.miner);
            const curBalance = safeBigInt(cur ? cur.balance : 0n, 0n);
            const newBalance = curBalance + rewardCc;
            if (cur) this.db.prepare('UPDATE users SET balance = ?, updated_at = ? WHERE address = ?').run(String(newBalance), now, d.miner);
            else this.db.prepare('INSERT OR IGNORE INTO users (address, balance, nonce, created_at, updated_at) VALUES (?,?,?,?,?)').run(d.miner, String(rewardCc), 0, now, now);
          }
          this.db.prepare('INSERT OR IGNORE INTO block_rewards (block_height, block_hash, challenge_id, miner, plot_id, size_gb, reward_cc, created_at) VALUES (?,?,?,?,?,?,?,?)').run(height, bloco.hash, bloco.challenge_id || '', d.miner, d.plot_id || '', d.size_gb || 0, String(rewardCc), now);
        }
        for (const tx of txs) {
          const txHash = tx.hash || hashTransaction(tx);
          this.db.prepare('INSERT OR REPLACE INTO transactions (hash, from_addr, to_addr, value, fee, nonce, gas_limit, gas_price, signature, block_height, timestamp, block_hash, data, chain_id) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)').run(txHash, tx.from_addr, tx.to_addr || '', String(tx.value || 0), String(tx.fee || 0), safeInt(tx.nonce, 0), safeInt(tx.gas_limit, 21000), String(tx.gas_price || '1'), tx.signature || '', height, tx.timestamp || now, bloco.hash, String(tx.data || ''), String(tx.chain_id || bloco.chain_id || this.cfg.chainId || '0'));
          if (tx.from_addr) {
            const cur = this.db.prepare('SELECT balance, nonce FROM users WHERE address = ?').get(tx.from_addr);
            if (cur) {
              const curBalance = safeBigInt(cur.balance, 0n);
              const newBalance = curBalance - safeBigInt(tx.value, 0n) - safeBigInt(tx.fee, 0n);
              this.db.prepare('UPDATE users SET balance = ?, nonce = ?, updated_at = ? WHERE address = ?').run(String(newBalance), Math.max(safeInt(cur.nonce, 0) + 1, safeInt(tx.nonce, 0) + 1), now, tx.from_addr);
            }
          }
          const isContractRecipient = this._isContractCall(tx);
          if (tx.to_addr && !isContractRecipient) {
            const cur = this.db.prepare('SELECT balance FROM users WHERE address = ?').get(tx.to_addr);
            const curBalance = safeBigInt(cur ? cur.balance : 0n, 0n);
            const newBalance = curBalance + safeBigInt(tx.value, 0n);
            if (cur) this.db.prepare('UPDATE users SET balance = ?, updated_at = ? WHERE address = ?').run(String(newBalance), now, tx.to_addr);
            else this.db.prepare('INSERT OR IGNORE INTO users (address, balance, nonce, created_at, updated_at) VALUES (?,?,?,?,?)').run(tx.to_addr, String(safeBigInt(tx.value, 0n)), 0, now, now);
          }
          this.db.prepare('DELETE FROM mempool WHERE hash = ?').run(txHash);
        }
        if (contractExec && contractExec.logs && contractExec.logs.length) {
          for (const lg of contractExec.logs) {
            this.db.prepare('INSERT INTO contract_logs (tx_hash, block_height, block_hash, log_index, address, topics, data) VALUES (?,?,?,?,?,?,?)')
              .run(lg.tx_hash, height, bloco.hash, safeInt(lg._idx, 0), lg.address, lg.topics, lg.data);
          }
        }
        if (contractExec && contractExec.payouts && contractExec.payouts.length) {
          const payoutsByUser = new Map();
          for (const p of contractExec.payouts) {
            const to = String(p.to || '').toLowerCase();
            const v = safeBigInt(p.value, 0n);
            if (!to || v <= 0n) continue;
            if (this.db.prepare('SELECT 1 FROM smart_contracts WHERE lower(address) = ?').get(to)) {
              const cur = this.db.prepare('SELECT balance FROM smart_contract_accounts WHERE lower(address) = ?').get(to);
              const nv = safeBigInt(cur ? cur.balance : 0n, 0n) + v;
              this.db.prepare('INSERT OR REPLACE INTO smart_contract_accounts (address, balance) VALUES (?, ?)').run(to, String(nv));
            } else {
              payoutsByUser.set(to, (payoutsByUser.get(to) || 0n) + v);
            }
          }
          for (const [to, v] of payoutsByUser) {
            const cur = this.db.prepare('SELECT balance FROM users WHERE address = ?').get(to);
            if (cur) {
              this.db.prepare('UPDATE users SET balance = ?, updated_at = ? WHERE address = ?').run(String(safeBigInt(cur.balance, 0n) + v), now, to);
            } else {
              this.db.prepare('INSERT OR IGNORE INTO users (address, balance, nonce, created_at, updated_at) VALUES (?,?,?,?,?)').run(to, String(v), 0, now, now);
            }
            this.db.prepare('INSERT OR REPLACE INTO block_payouts (block_hash, height, to_addr, value) VALUES (?,?,?,?)').run(bloco.hash, height, to, String(v));
          }
        }
        if (totalTxFees > 0n) {
          const forgerAddr = String(bloco.forger || bloco.miner || '').toLowerCase();
          if (forgerAddr && forgerAddr !== 'genesis') {
            const cur = this.db.prepare('SELECT balance FROM users WHERE address = ?').get(forgerAddr);
            if (cur) this.db.prepare('UPDATE users SET balance = ?, updated_at = ? WHERE address = ?').run(String(safeBigInt(cur.balance, 0n) + totalTxFees), now, forgerAddr);
            else this.db.prepare('INSERT OR IGNORE INTO users (address, balance, nonce, created_at, updated_at) VALUES (?,?,?,?,?)').run(forgerAddr, String(totalTxFees), 0, now, now);
            this.db.prepare('INSERT OR REPLACE INTO block_payouts (block_hash, height, to_addr, value) VALUES (?,?,?,?)').run(bloco.hash, height, forgerAddr, String(totalTxFees));
            log('info', `[FEES] Block #${height} fees ${totalTxFees} -> forger ${forgerAddr.slice(0, 10)}… (${txs.length} tx, total_fees_units=${totalTxFees})`);
          }
        }
        if (isLocalForge) {
          bloco.contract_state_root = computeContractStateRoot(this.db);
          bloco.state_root = computeStateRoot(this.db);
          const preStateHash = bloco.hash;
          bloco.hash = hashBlock(bloco);
          if (preStateHash !== bloco.hash) {
            this.db.prepare('UPDATE block_rewards SET block_hash = ? WHERE block_height = ? AND block_hash = ?').run(bloco.hash, height, preStateHash);
            this.db.prepare('UPDATE transactions SET block_hash = ? WHERE block_height = ? AND block_hash = ?').run(bloco.hash, height, preStateHash);
            this.db.prepare('UPDATE block_payouts SET block_hash = ? WHERE height = ? AND block_hash = ?').run(bloco.hash, height, preStateHash);
            this.db.prepare('UPDATE contract_logs SET block_hash = ? WHERE block_height = ? AND block_hash = ?').run(bloco.hash, height, preStateHash);
          }
          if (this.cfg.minerPrivateKey) {
            try { bloco.signature = signMessage(blockMessage(bloco), this.cfg.minerPrivateKey); } catch {}
          }
        }

        this._updateStateTrie(txs, rewardsData, bloco.hash, height, (bloco.forger || bloco.miner || '').toLowerCase(), totalTxFees);
        this.db.prepare(`INSERT INTO blocks (height, hash, parent_hash, timestamp, miner, challenge_id, tx_root, nonce, difficulty, target,
          reward_units, reward_cc, tx_count, chain_work, signature, generation_signature, proof_digest, plot_id, state_root, origin,
          total_fees_units, gas_used, gas_limit, base_target, base_fee, contract_state_root, forger, miner_public_key, rewards_json, winner_proof) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).run(
          height, bloco.hash, bloco.parent_hash, bloco.timestamp, bloco.miner || '',
          bloco.challenge_id || '', bloco.tx_root || '', String(bloco.nonce || '0'),
          bloco.difficulty || '0', String(bloco.target || '0'), bloco.reward_units || '0',
          rewardStr, txs.length, String(newWork), bloco.signature || '',
          bloco.generation_signature || ZERO_HASH, bloco.proof_digest || '',
          bloco.plot_id || '', bloco.state_root || '', blockOrigin,
          String(totalTxFees), gasUsed, bloco.gas_limit || GAS_PARAMS.blockGasLimit, bloco.base_target || String(BigInt(2) ** BigInt(64) / BigInt(5898240)),
          bloco.base_fee || String(this._baseFeeForHeight(height)),
          bloco.contract_state_root || '',
          bloco.forger || '',
          bloco.miner_public_key || '',
          JSON.stringify(Array.isArray(bloco.rewards) ? bloco.rewards : []),
          bloco.winner_proof && typeof bloco.winner_proof === 'object' ? JSON.stringify(bloco.winner_proof) : '',
        );
        if (plotRegistrationEvents.length) {
          const insertRegistration = this.db.prepare(`
            INSERT INTO plot_registration_events
            (block_hash, block_height, miner, plot_id, merkle_root, capacity_bytes, tx_hash)
            VALUES (?, ?, ?, ?, ?, ?, ?)
          `);
          for (const event of plotRegistrationEvents) {
            insertRegistration.run(bloco.hash, event.block_height, event.miner, event.plot_id,
              event.merkle_root, event.capacity_bytes, event.tx_hash);
          }
        }
        {
          const actualStateRoot = computeStateRoot(this.db);
          const claimedStateRoot = bloco.state_root || '';
          if (claimedStateRoot && claimedStateRoot !== actualStateRoot) {
            log('warn', `state_root mismatch at #${height}`);
            throw new Error('state_root mismatch');
          }
        }
        if (this.contracts && bloco.contract_state_root) {
          const actualCsr = computeContractStateRoot(this.db);
          if (actualCsr !== bloco.contract_state_root) {
            log('warn', `contract_state_root mismatch at #${height}: local=${actualCsr.slice(0, 16)} claimed=${bloco.contract_state_root.slice(0, 16)}`);
            throw new Error('contract_state_root mismatch');
          }
        }
        if (contractExec && contractExec.backup && contractExec.backup.length) this._recordContractStateChanges(height, bloco.hash, contractExec.backup);
        this._selectTip();
      })();
      if (height > 0) log('info', `Block #${height} accepted [${bloco.hash.slice(0, 10)}] from ${blockOrigin} (miner: ${(bloco.miner || '').slice(0, 10)}…)`);
      return { ok: true, motivo: 'block added', height, hash: bloco.hash };
    } catch (e) {
      if (contractExec) { try { contractExec.rollback(); } catch {} }
      const msg = e.message || 'database error';
      // Autocorreção: "state_root mismatch" quase sempre significa que o NOSSO
      // estado no tip divergiu (bug de reorg/rollback), não que o bloco seja
      // inválido. Reconstrói a partir da cadeia e tenta de novo UMA vez. O
      // guard _stateRepaired evita loop quando o bloco é mesmo de outro fork.
      if (!opts._stateRepaired && /state_root mismatch|contract_state_root mismatch/.test(msg)) {
        const rep = this.verifyStateIntegrity();
        if (rep.repaired && rep.ok) {
          log('warn', `estado divergiu no tip; reconstruído da cadeia (${rep.motivo}); retentando #${height}`);
          return this.addBlock(bloco, { ...opts, _stateRepaired: true });
        }
      }
      return { ok: false, motivo: msg };
    }
  }


  _blockContext(bloco) {
    try {
      return createBlock({
        header: {
          timestamp: BigInt(safeInt(bloco.timestamp, 0)),
          number: BigInt(safeInt(bloco.height, 0)),
        },
      });
    } catch (e) { return undefined; }
  }

  _snapshotContractState(address) {
    return {
      address,
      storage: this.db.prepare('SELECT * FROM smart_contract_storage WHERE lower(contract_address) = lower(?)').all(address),
      account: this.db.prepare('SELECT * FROM smart_contract_accounts WHERE lower(address) = lower(?)').get(address) || null,
      contract: this.db.prepare('SELECT * FROM smart_contracts WHERE lower(address) = lower(?)').get(address) || null,
    };
  }

  _restoreContractState(snaps) {
    for (const s of snaps) {
      this.db.prepare('DELETE FROM smart_contract_storage WHERE lower(contract_address) = lower(?)').run(s.address);
      this.db.prepare('DELETE FROM smart_contract_accounts WHERE lower(address) = lower(?)').run(s.address);
      this.db.prepare('DELETE FROM smart_contracts WHERE lower(address) = lower(?)').run(s.address);
      for (const row of s.storage) this.db.prepare('INSERT OR REPLACE INTO smart_contract_storage (contract_address, slot, value) VALUES (?,?,?)').run(row.contract_address, row.slot, row.value);
      if (s.account) this.db.prepare('INSERT OR REPLACE INTO smart_contract_accounts (address, balance) VALUES (?,?)').run(s.account.address, s.account.balance);
      if (s.contract) this.db.prepare('INSERT OR REPLACE INTO smart_contracts (address, creator, code, created_at, updated_at) VALUES (?,?,?,?,?)').run(s.contract.address, s.contract.creator, s.contract.code, s.contract.created_at, s.contract.updated_at);
    }
    if (this.contracts && this.contracts.clearVmCache) this.contracts.clearVmCache();
  }

  _recordContractStateChanges(blockHeight, blockHash, snapshots) {
    const now = Math.floor(Date.now() / 1000);
    for (const snap of snapshots || []) {
      const addr = String(snap.address || '').toLowerCase();
      if (!addr) continue;
      const currentStorageRows = this.db.prepare('SELECT * FROM smart_contract_storage WHERE lower(contract_address) = lower(?)').all(addr);
      const prevStorage = new Map((snap.storage || []).map(r => [String(r.slot), (r.value == null ? '' : String(r.value))]));
      const nextStorage = new Map(currentStorageRows.map(r => [String(r.slot), (r.value == null ? '' : String(r.value))]));
      const slots = new Set([...prevStorage.keys(), ...nextStorage.keys()]);
      for (const slot of slots) {
        const prevValue = prevStorage.has(slot) ? prevStorage.get(slot) : '';
        const newValue = nextStorage.has(slot) ? nextStorage.get(slot) : '';
        this.db.prepare(`
          INSERT OR REPLACE INTO smart_contract_storage_history (contract_address, slot, prev_value, new_value, block_height, block_hash, created_at)
          VALUES (?,?,?,?,?,?,?)
        `).run(addr, slot, prevValue, newValue, blockHeight, blockHash, now);
      }

      const prevAccount = snap.account ? (snap.account.balance == null ? '' : String(snap.account.balance)) : '';
      const nextAccountRow = this.db.prepare('SELECT * FROM smart_contract_accounts WHERE lower(address) = lower(?)').get(addr);
      const nextAccount = nextAccountRow ? (nextAccountRow.balance == null ? '' : String(nextAccountRow.balance)) : '';
      this.db.prepare(`
        INSERT OR REPLACE INTO smart_contract_storage_history (contract_address, slot, prev_value, new_value, block_height, block_hash, created_at)
        VALUES (?,?,?,?,?,?,?)
      `).run(addr, '__balance__', prevAccount, nextAccount, blockHeight, blockHash, now);

      const prevContract = snap.contract ? JSON.stringify(snap.contract) : '';
      const nextContractRow = this.db.prepare('SELECT * FROM smart_contracts WHERE lower(address) = lower(?)').get(addr);
      const nextContract = nextContractRow ? JSON.stringify(nextContractRow) : '';
      this.db.prepare(`
        INSERT OR REPLACE INTO smart_contract_storage_history (contract_address, slot, prev_value, new_value, block_height, block_hash, created_at)
        VALUES (?,?,?,?,?,?,?)
      `).run(addr, '__contract__', prevContract, nextContract, blockHeight, blockHash, now);
    }
  }

  _restoreContractStateFromHistory(aboveHeight) {
    const changes = this.db.prepare('SELECT * FROM smart_contract_storage_history WHERE block_height > ? ORDER BY block_height DESC').all(aboveHeight);
    const byContract = new Map();
    for (const c of changes) {
      if (!byContract.has(c.contract_address)) byContract.set(c.contract_address, []);
      byContract.get(c.contract_address).push(c);
    }
    for (const [addr, chgs] of byContract) {
      const seen = new Set();
      for (const c of chgs) {
        const key = c.slot;
        if (seen.has(key)) continue;
        seen.add(key);
        if (c.slot === '__contract__') {
          if (c.prev_value === null || c.prev_value === '') {
            this.db.prepare('DELETE FROM smart_contracts WHERE lower(address) = lower(?)').run(addr);
          } else {
            try {
              const prev = JSON.parse(c.prev_value);
              this.db.prepare('INSERT OR REPLACE INTO smart_contracts (address, creator, code, created_at, updated_at) VALUES (?,?,?,?,?)').run(prev.address, prev.creator, prev.code, prev.created_at, prev.updated_at);
            } catch {
              this.db.prepare('DELETE FROM smart_contracts WHERE lower(address) = lower(?)').run(addr);
            }
          }
        } else if (c.slot === '__balance__') {
          if (c.prev_value === null || c.prev_value === '') {
            this.db.prepare('DELETE FROM smart_contract_accounts WHERE lower(address) = lower(?)').run(addr);
          } else {
            this.db.prepare('INSERT OR REPLACE INTO smart_contract_accounts (address, balance) VALUES (?,?)').run(addr, c.prev_value);
          }
        } else if (c.prev_value === null || c.prev_value === '') {
          this.db.prepare('DELETE FROM smart_contract_storage WHERE lower(contract_address) = lower(?) AND slot = ?').run(addr, c.slot);
        } else {
          this.db.prepare('INSERT OR REPLACE INTO smart_contract_storage (contract_address, slot, value) VALUES (?,?,?)').run(addr, c.slot, c.prev_value);
        }
      }
    }
    this.db.prepare('DELETE FROM smart_contract_storage_history WHERE block_height > ?').run(aboveHeight);
    if (this.contracts && this.contracts.clearVmCache) this.contracts.clearVmCache();

    this.stateTrie.loadFromDB(this.db).catch(e => log('warn', `State trie reload: ${e.message}`));
  }

  _updateStateTrie(txs, rewards, blockHash, height, forger = '', feePayout = 0n) {
    const now = Math.floor(Date.now() / 1000);
    const userUpdateMap = new Map();
    const contractUpdateMap = new Map();
    try {
      for (const d of rewards) {
        if (!d.miner) continue;
        const cur = this.db.prepare('SELECT balance, nonce FROM users WHERE address = ?').get(d.miner);
        if (cur) {
          const newBalance = safeBigInt(cur.balance, 0n) + safeBigInt(d.reward_cc, 0n);
          userUpdateMap.set(d.miner, { address: d.miner, balance: newBalance.toString(), nonce: cur.nonce || 0 });
        }
      }
      for (const tx of txs) {
        if (tx.from_addr) {
          const cur = this.db.prepare('SELECT balance, nonce FROM users WHERE address = ?').get(tx.from_addr);
          if (cur) {
            const newBalance = safeBigInt(cur.balance, 0n) - safeBigInt(tx.value, 0n) - safeBigInt(tx.fee, 0n);
            const newNonce = Math.max(safeInt(cur.nonce, 0), safeInt(tx.nonce, 0)) + 1;
            userUpdateMap.set(tx.from_addr, { address: tx.from_addr, balance: newBalance.toString(), nonce: newNonce });
          }
        }
        const isContractCall = this._isContractCall(tx);
        if (tx.to_addr && !isContractCall) {
          const cur = this.db.prepare('SELECT balance, nonce FROM users WHERE address = ?').get(tx.to_addr);
          if (cur) {
            const newBalance = safeBigInt(cur.balance, 0n) + safeBigInt(tx.value, 0n);
            userUpdateMap.set(tx.to_addr, { address: tx.to_addr, balance: newBalance.toString(), nonce: cur.nonce || 0 });
          }
        }
        if (isContractCall && tx.to_addr) {
          const cur = this.db.prepare('SELECT balance FROM smart_contract_accounts WHERE lower(address) = lower(?)').get(tx.to_addr);
          if (cur) {
            contractUpdateMap.set(tx.to_addr, { address: tx.to_addr, balance: cur.balance });
          }
        }
      }
      if (userUpdateMap.size) this.stateTrie.batchUpdateUsers([...userUpdateMap.values()]);
      if (contractUpdateMap.size) this.stateTrie.batchUpdateContracts([...contractUpdateMap.values()]);
      if (forger && feePayout > 0n) {
        const cur = this.db.prepare('SELECT balance, nonce FROM users WHERE address = ?').get(forger);
        if (cur) {
          const newBalance = safeBigInt(cur.balance, 0n) + feePayout;
          userUpdateMap.set(forger, { address: forger, balance: newBalance.toString(), nonce: cur.nonce || 0 });
          this.stateTrie.batchUpdateUsers([{ address: forger, balance: newBalance.toString(), nonce: cur.nonce || 0 }]);
        }
      }
    } catch (e) {
      log('warn', `State trie update: ${e.message}`);
    }
  }

  computeMaxDeadline() {
    const tip = this.getBlock(this.height);
    let bytes = 0n;
    if (tip) {
      for (const plot of this.getMaturePlotRegistrations(tip.hash, this.height + 1)) bytes += BigInt(plot.capacity_bytes);
    }
    const capacity = Number(bytes) / (1024 ** 3);
    const expected = this.cfg.expectedTimePerBlock || 60;
    if (capacity <= 0) return 21600;
    return Math.max(600, Math.min(86400, Math.floor(expected * 36000 / Math.max(capacity, 1))));
  }

  async reorganize(targetOrHash, forceSync = false, allowVotedTie = false) {
    const target = typeof targetOrHash === 'string' ? this.getBlockByHash(targetOrHash) : targetOrHash;
    if (!target) return { ok: false, motivo: 'target block not found' };
    if (target.height >= this.height && this.getBlock(target.height) && this.getBlock(target.height).hash === target.hash) {
      return { ok: true, motivo: 'already at tip', height: this.height, hash: this.bestHash };
    }
    const depth = this.height - target.height;
    if (!forceSync && depth > FINALIZATION_DEPTH) return { ok: false, motivo: `reorg exceeds finalization depth (${depth} > ${FINALIZATION_DEPTH})` };
    const forkPoint = this.getBlockByHash(target.parent_hash);
    if (!forkPoint) return { ok: false, motivo: 'fork point not found' };
    const oldTip = this.getBlock(this.height);
    if (!oldTip) return { ok: false, motivo: 'old tip not found' };
    const hashes = [];
    let current = target;
    while (current && current.height > forkPoint.height) {
      hashes.push(current.hash);
      current = this.getBlock(current.parent_hash);
    }
    hashes.reverse();
    for (const h of hashes) {
      let blk = this.getBlockByHash(h);
      if (!blk) {
        if (h === target.hash) blk = target;
        else return { ok: false, motivo: `block ${h} not in DB` };
      }
      const res = await this.addBlock(blk, { forceSync: true, allowEqualWork: true, allowVotedTie });
      if (!res.ok) return { ok: false, motivo: res.motivo };
    }
    const finalizeReorg = this.db.transaction(() => {
      this._selectTip();
      this._purgeOrphanedDescendants(forkPoint.height, target.height);
      this._purgeOrphanedBlocks();
      this._restoreContractStateFromHistory(forkPoint.height);
      this._recomputeBalances();
      this._selectTip();
    });
    finalizeReorg();
    log('info', `Reorg to #${this.height} ${this.bestHash.slice(0, 10)} (depth ${depth})`);
    return { ok: true, motivo: 'reorganized', height: this.height, hash: this.bestHash };
  }

  _rollbackRewardsForBlock(blockHash) {
    const rows = this.db.prepare('SELECT miner, reward_cc FROM block_rewards WHERE block_hash = ?').all(blockHash);
    const now = Math.floor(Date.now() / 1000);
    for (const r of rows) {
      if (!r.miner || r.miner === 'genesis') continue;
      const reward = BigInt(r.reward_cc || '0');
      if (reward <= 0n) continue;
      const cur = this.db.prepare('SELECT balance FROM users WHERE address = ?').get(r.miner);
      if (cur) this.db.prepare('UPDATE users SET balance = ?, updated_at = ? WHERE address = ?').run(String(BigInt(cur.balance || 0) - reward), now, r.miner);
    }
    // Apaga as linhas também, igual a _rollbackPayoutsForBlock. Sem isso o
    // bloco órfão continua em block_rewards e aparece na API de rewards,
    // além de sobreviver ao dedupe por (block_height, block_hash, ...).
    this.db.prepare('DELETE FROM block_rewards WHERE block_hash = ?').run(blockHash);
  }

  _rollbackPayoutsForBlock(hash) {
    const rows = this.db.prepare('SELECT to_addr, value FROM block_payouts WHERE block_hash = ?').all(hash);
    if (!rows.length) return;
    const now = Math.floor(Date.now() / 1000);
    for (const p of rows) {
      const cur = this.db.prepare('SELECT balance FROM users WHERE address = ?').get(p.to_addr);
      if (cur) this.db.prepare('UPDATE users SET balance = ?, updated_at = ? WHERE address = ?').run(String(safeBigInt(cur.balance, 0n) - safeBigInt(p.value, 0n)), now, p.to_addr);
    }
    this.db.prepare('DELETE FROM block_payouts WHERE block_hash = ?').run(hash);
  }

  // Desfaz o efeito das transações de um bloco descartado. Os saldos já são
  // reconstruídos por _recomputeBalances no fim do reorg, mas o forceSync
  // acontece antes disso e precisa deixar um estado coerente; o nonce depende
  // desta reversão porque o recompute só mexe em users presentes na cadeia.
  _rollbackTxsForBlock(hash) {
    const rows = this.db.prepare('SELECT from_addr, to_addr, value, fee, data, nonce FROM transactions WHERE block_hash = ?').all(hash);
    if (!rows.length) return;
    const now = Math.floor(Date.now() / 1000);
    for (const tx of rows) {
      const from = tx.from_addr ? String(tx.from_addr).toLowerCase() : '';
      const to = tx.to_addr ? String(tx.to_addr).toLowerCase() : '';
      if (from) {
        const cur = this.db.prepare('SELECT balance FROM users WHERE address = ?').get(from);
        // Devolve valor + taxa ao remetente, espelhando a subtração de addBlock.
        if (cur) this.db.prepare('UPDATE users SET balance = ?, updated_at = ? WHERE address = ?')
          .run(String(safeBigInt(cur.balance, 0n) + safeBigInt(tx.value, 0n) + safeBigInt(tx.fee, 0n)), now, from);
      }
      // Mesmo critério de creditRecipient em addBlock: não credita em chamada de contrato.
      if (to && !this._isContractCall(tx)) {
        const cur = this.db.prepare('SELECT balance FROM users WHERE address = ?').get(to);
        if (cur) this.db.prepare('UPDATE users SET balance = ?, updated_at = ? WHERE address = ?')
          .run(String(safeBigInt(cur.balance, 0n) - safeBigInt(tx.value, 0n)), now, to);
      }
      // Rebaixa o nonce do remetente para o valor que a assinatura exigia.
      if (from) {
        const cur = this.db.prepare('SELECT nonce FROM users WHERE address = ?').get(from);
        if (cur && safeInt(cur.nonce, 0) > safeInt(tx.nonce, 0)) {
          this.db.prepare('UPDATE users SET nonce = ?, updated_at = ? WHERE address = ?').run(safeInt(tx.nonce, 0), now, from);
        }
      }
    }
  }

  _purgeOrphanedDescendants(fromHeight, retainThroughHeight = -1) {
    const maxH = this.db.prepare('SELECT MAX(height) as m FROM blocks').get().m || 0;
    if (maxH <= fromHeight) return;
    const doRollback = (doomed) => {
      for (const d of doomed) {
        if (d.height > retainThroughHeight) {
          this._rollbackRewardsForBlock(d.hash);
          this._rollbackPayoutsForBlock(d.hash);
        }
      }
    };
    for (let h = fromHeight + 1; h <= maxH; h++) {
      const bestParent = this.db.prepare('SELECT hash FROM blocks WHERE height = ? ORDER BY LENGTH(chain_work) DESC, chain_work DESC, hash ASC LIMIT 1').get(h - 1);
      if (!bestParent) {
        const doomed = this.db.prepare('SELECT height, miner, reward_cc, hash FROM blocks WHERE height >= ?').all(h);
        doRollback(doomed);
        this.db.prepare('DELETE FROM blocks WHERE height >= ?').run(h);
        break;
      }
      const doomed = this.db.prepare('SELECT height, miner, reward_cc, hash FROM blocks WHERE height = ? AND parent_hash != ?').all(h, bestParent.hash);
      doRollback(doomed);
      this.db.prepare('DELETE FROM blocks WHERE height = ? AND parent_hash != ?').run(h, bestParent.hash);
      const remaining = this.db.prepare('SELECT 1 FROM blocks WHERE height = ? LIMIT 1').get(h);
      if (!remaining) {
        const doomed2 = this.db.prepare('SELECT height, miner, reward_cc, hash FROM blocks WHERE height > ?').all(h);
        doRollback(doomed2);
        this.db.prepare('DELETE FROM blocks WHERE height > ?').run(h);
        break;
      }
    }
    this._selectTip();
  }

  // Replay FIEL da cadeia canônica. O estado é função pura dos blocos, então
  // reconstruir = aplicar genesis->tip com as MESMAS regras do addBlock:
  //   1) rewards  -> credita; se a conta não existe, cria com nonce 0
  //   2) txs      -> debita/avança nonce SÓ se o remetente JÁ existe; crédito ao
  //                  destinatário cria a conta com nonce 0
  //   3) payouts  -> payout de contrato + taxas ao forger, idem (cria se não existe)
  // A versão anterior acumulava mapas fora de ordem e sem a semântica de
  // "conta existe", o que inflava nonces — ex.: contas de registro de plot, cujas
  // txs têm to=0x0/value=0 e não devem avançar nonce. Isso mudava computeStateRoot
  // a cada reorg e travava o node com "state_root mismatch" para sempre.
  _recomputeBalances() {
    const hashes = [];
    let h = this.db.prepare('SELECT hash, parent_hash, height FROM blocks WHERE hash = ?').get(this.bestHash);
    while (h) { hashes.push(h); if (h.height === 0) break; h = this.db.prepare('SELECT hash, parent_hash, height FROM blocks WHERE hash = ?').get(h.parent_hash); }
    hashes.reverse(); // genesis -> tip, a mesma ordem em que o estado foi construído
    const state = new Map(); // address -> { balance: BigInt, nonce: number }
    const get = (a) => state.get(a);
    for (const b of hashes) {
      // (1) rewards
      for (const r of this.db.prepare('SELECT miner, reward_cc FROM block_rewards WHERE block_height = ? AND block_hash = ?').all(b.height, b.hash)) {
        const reward = BigInt(r.reward_cc || '0');
        const m = r.miner ? String(r.miner) : '';
        if (reward <= 0n || !m || m === 'genesis') continue;
        const s = get(m);
        if (s) s.balance += reward;
        else state.set(m, { balance: reward, nonce: 0 });
      }
      // (2) transactions (ordem de inserção = ordem em que foram aplicadas)
      for (const tx of this.db.prepare('SELECT from_addr, to_addr, value, fee, nonce, data FROM transactions WHERE block_hash = ? ORDER BY rowid').all(b.hash)) {
        const from = tx.from_addr ? String(tx.from_addr) : '';
        const to = tx.to_addr ? String(tx.to_addr) : '';
        if (from) {
          const s = get(from);
          if (s) {
            s.balance -= BigInt(tx.value || 0) + BigInt(tx.fee || 0);
            s.nonce = Math.max(s.nonce + 1, safeInt(tx.nonce, 0) + 1);
          }
        }
        if (to && !this._isContractCall(tx)) {
          const s = get(to);
          if (s) s.balance += BigInt(tx.value || 0);
          else state.set(to, { balance: BigInt(tx.value || 0), nonce: 0 });
        }
      }
      // (3) payouts (contrato + taxas ao forger)
      for (const p of this.db.prepare('SELECT to_addr, value FROM block_payouts WHERE block_hash = ?').all(b.hash)) {
        const to = p.to_addr ? String(p.to_addr) : '';
        if (!to) continue;
        const s = get(to);
        if (s) s.balance += BigInt(p.value || 0);
        else state.set(to, { balance: BigInt(p.value || 0), nonce: 0 });
      }
    }
    const now = Math.floor(Date.now() / 1000);
    const updBal = this.db.prepare('UPDATE users SET balance = ?, updated_at = ? WHERE address = ?');
    const updNonce = this.db.prepare('UPDATE users SET nonce = ?, updated_at = ? WHERE address = ?');
    for (const u of this.db.prepare('SELECT address, balance, nonce FROM users').all()) {
      const s = get(String(u.address));
      // Sem atividade na cadeia canônica: não mexe (não apaga saldo de snapshot).
      if (!s) continue;
      if (String(s.balance) !== u.balance) updBal.run(String(s.balance), now, u.address);
      if (safeInt(u.nonce, 0) !== s.nonce) updNonce.run(s.nonce, now, u.address);
    }
    for (const [addr, s] of state) {
      if (!this.db.prepare('SELECT 1 FROM users WHERE address = ?').get(addr)) {
        this.db.prepare('INSERT OR IGNORE INTO users (address, balance, nonce, created_at, updated_at) VALUES (?,?,?,?,?)').run(addr, String(s.balance), s.nonce, now, now);
      }
    }
  }

  // O estado (users + contratos) é função pura da cadeia canônica: dado o
  // mesmo conjunto de blocos, todo node chega ao mesmo state_root. Portanto,
  // se o root materializado não bate com o root comprometido no bloco do tip,
  // o estado divergiu por bug de reorg/rollback — e reconstruir é seguro,
  // determinístico e idempotente. Sem isto o node fica travado para sempre:
  // nenhum bloco novo valida e nada volta a derivar o estado da cadeia.
  verifyStateIntegrity() {
    const tip = this.getBlock(this.height);
    if (!tip) return { ok: true, repaired: false, motivo: 'sem tip' };
    const before = computeStateRoot(this.db);
    const claimed = tip.state_root || '';
    if (!claimed || before === claimed) return { ok: true, repaired: false, motivo: 'estado consistente' };
    this.db.transaction(() => { this._recomputeBalances(); })();
    const after = computeStateRoot(this.db);
    return {
      ok: after === claimed,
      repaired: before !== after,
      motivo: `#${tip.height} ${before.slice(0, 12)}… -> ${after.slice(0, 12)}… (esperado ${claimed.slice(0, 12)}…)`,
    };
  }

  async _insertBlockDirect(blk) {
    const parentWork = blk.height > 0 ? (() => { const p = this.db.prepare('SELECT chain_work FROM blocks WHERE hash = ?').get(blk.parent_hash); return p ? safeBigInt(p.chain_work, 0n) : 0n; })() : 0n;
    const work = blk.chain_work || String(parentWork + this._blockWork(blk));
    const now = Math.floor(Date.now() / 1000);
    const txs = blk.transactions || [];
    const contractTxs = txs.filter(t => this._isContractOp(t));
    let contractExec = null;
    if (contractTxs.length) {
      if (!this.contracts) return { ok: false, motivo: 'contract txs but smart contracts disabled' };
      contractExec = await this._preExecuteContracts(blk, txs);
      if (!contractExec.ok) {
        contractExec.rollback();
        return { ok: false, motivo: contractExec.motivo };
      }
    }
    try {
      this.db.transaction(() => {
          this.db.prepare(`INSERT OR REPLACE INTO blocks (height, hash, parent_hash, timestamp, miner, challenge_id, tx_root, nonce, difficulty, target,
          reward_units, reward_cc, tx_count, chain_work, signature, generation_signature, proof_digest, plot_id, state_root, origin,
          total_fees_units, gas_used, gas_limit, base_target, base_fee, contract_state_root, forger, miner_public_key, rewards_json, winner_proof) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).run(
          blk.height, blk.hash, blk.parent_hash || '', blk.timestamp || now, blk.miner || '',
          blk.challenge_id || '', blk.tx_root || '', String(blk.nonce || '0'), blk.difficulty || '0',
          String(blk.target || '0'), blk.reward_units || '0', blk.reward_cc || '0', blk.tx_count || 0,
          String(work), blk.signature || '', blk.generation_signature || ZERO_HASH, blk.proof_digest || '',
          blk.plot_id || '', blk.state_root || '', blk.origin || 'reorg',
          blk.total_fees_units || '0', blk.gas_used || 0, blk.gas_limit || GAS_PARAMS.blockGasLimit, blk.base_target || String(BigInt(2) ** BigInt(64) / BigInt(5898240)),
          blk.base_fee || '0',
          blk.contract_state_root || '',
          blk.forger || '',
          blk.miner_public_key || '',
          JSON.stringify(Array.isArray(blk.rewards) ? blk.rewards : []),
          blk.winner_proof && typeof blk.winner_proof === 'object' ? JSON.stringify(blk.winner_proof) : '',
        );
        for (const tx of txs) {
          const txHash = tx.hash || hashTransaction(tx);
          this.db.prepare('INSERT OR REPLACE INTO transactions (hash, from_addr, to_addr, value, fee, nonce, gas_limit, gas_price, signature, block_height, timestamp, block_hash, data, chain_id) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)').run(txHash, tx.from_addr, tx.to_addr || '', String(tx.value || 0), String(tx.fee || 0), safeInt(tx.nonce, 0), safeInt(tx.gas_limit, 21000), String(tx.gas_price || '1'), tx.signature || '', blk.height, tx.timestamp || now, blk.hash, String(tx.data || ''), String(tx.chain_id || blk.chain_id || this.cfg.chainId || '0'));
        }
        const entries = Array.isArray(blk.rewards) && blk.rewards.length ? blk.rewards : [{ miner: blk.miner, reward_cc: blk.reward_cc }];
        for (const e of entries) {
          const m = e && e.miner ? String(e.miner).toLowerCase() : '';
          if (!m || m === 'genesis' || blk.height <= 0) continue;
          const reward = BigInt((e && e.reward_cc) || '0');
          if (reward <= 0n) continue;
          const cur = this.db.prepare('SELECT balance FROM users WHERE address = ?').get(m);
          if (cur) this.db.prepare('UPDATE users SET balance = ?, updated_at = ? WHERE address = ?').run(String(BigInt(cur.balance || 0) + reward), now, m);
          else this.db.prepare('INSERT OR IGNORE INTO users (address, balance, nonce, created_at, updated_at) VALUES (?,?,?,?,?)').run(m, String(reward), 0, now, now);
          this.db.prepare('INSERT OR IGNORE INTO block_rewards (block_height, block_hash, challenge_id, miner, plot_id, size_gb, reward_cc, created_at) VALUES (?,?,?,?,?,?,?,?)')
            .run(blk.height, blk.hash, blk.challenge_id || '', m, (e && e.plot_id) || '', Number((e && e.size_gb) || 0), String(reward), now);
        }
        if (contractExec && contractExec.backup && contractExec.backup.length) {
          this._recordContractStateChanges(blk.height, blk.hash, contractExec.backup);
        }
      })();
      return { ok: true };
    } catch (e) {
      if (contractExec) { try { contractExec.rollback(); } catch {} }
      return { ok: false, motivo: e.message || 'database error' };
    }
  }

  _selectTip() {
    const row = this.db.prepare('SELECT height, hash FROM blocks ORDER BY LENGTH(chain_work) DESC, chain_work DESC, hash ASC LIMIT 1').get();
    if (row) { this.height = row.height; this.bestHash = row.hash; }
  }

  _purgeOrphanedBlocks() {
    const activeChain = new Set();
    let cur = this.db.prepare('SELECT hash, parent_hash, height FROM blocks WHERE hash = ?').get(this.bestHash);
    while (cur) {
      activeChain.add(`${cur.height}:${cur.hash}`);
      if (cur.height === 0) break;
      cur = this.db.prepare('SELECT hash, parent_hash, height FROM blocks WHERE hash = ?').get(cur.parent_hash);
    }
    const maxH = this.db.prepare('SELECT MAX(height) as m FROM blocks').get().m || 0;
    let purged = 0;
    for (let h = 0; h <= maxH; h++) {
      const rows = this.db.prepare('SELECT hash, miner, reward_cc FROM blocks WHERE height = ?').all(h);
      for (const r of rows) {
        if (!activeChain.has(`${h}:${r.hash}`)) {
          if (r.miner && r.miner !== 'genesis' && h > 0) {
            const reward = BigInt(r.reward_cc || '0');
            if (reward > 0n) {
              const curBal = this.db.prepare('SELECT balance FROM users WHERE address = ?').get(r.miner);
              if (curBal) this.db.prepare('UPDATE users SET balance = ?, updated_at = ? WHERE address = ?').run(String(BigInt(curBal.balance || 0) - reward), Math.floor(Date.now() / 1000), r.miner);
            }
          }
          this._rollbackPayoutsForBlock(r.hash);
          this.db.prepare('DELETE FROM contract_logs WHERE block_hash = ?').run(r.hash);
          this.db.prepare('DELETE FROM blocks WHERE hash = ?').run(r.hash);
          purged++;
        }
      }
    }
    if (purged > 0) {
      log('info', `Purged ${purged} orphaned blocks, chain now height=${this.height} tip=${this.bestHash.slice(0, 10)}`);
    }
    return purged;
  }

  retireOldBlocks() {
    if (this.cfg.pruningEnabled === false) return 0;
    const window = safeInt(this.cfg.anchorWindowSize, Config.Configuration.ANCHOR_WINDOW_SIZE);
    const tip = this.db.prepare('SELECT MAX(height) AS m FROM blocks').get().m || 0;
    const cutoff = tip - window;
    if (cutoff < 0) return 0;
    const pruned = this.db.prepare(
      "UPDATE blocks SET body_pruned = 1 WHERE height <= ? AND body_pruned = 0",
    ).run(cutoff).changes;
    this.db.prepare('DELETE FROM transactions WHERE block_height <= ?').run(cutoff);
    if (pruned > 0) {
      log('info', `[ANCHOR] Retired ${pruned} blocks past the ${window}-block anchor window (tip=${tip}); bodies execution-pruned, headers preserved`);
    }
    let zkpProof = null;
    let snapshot = null;
    if (this.zkp) {
      try { zkpProof = this.zkp.proveJustRetired(tip); } catch (e) { log('warn', `[ZKP] boundary proof generation failed: ${e.message}`); }
    }
    if (this.snapsync) {
      try { snapshot = this.snapsync.generateAtBoundary(tip); } catch (e) { log('warn', `[SnapSync] boundary snapshot generation failed: ${e.message}`); }
    }
    const out = { pruned };
    if (zkpProof) out.zkp = { id: zkpProof.id, start: zkpProof.start_height, end: zkpProof.end_height, commitment: zkpProof.commitment };
    if (snapshot) out.snapshot = { height: snapshot.height, state_root: snapshot.state_root, zkp_commitment: snapshot.zkp_commitment };
    return Object.keys(out).length > 1 ? out : pruned;
  }

  prune() {
    if (this.cfg.pruningEnabled === false) return 0;
    return this.retireOldBlocks();
  }
}

class Diff_Manager {
  constructor(db, cfg, chain) {
    this.db = db;
    this.cfg = cfg;
    this.chain = chain;
  }

  getBlock(heightOrHash) {
    return this.chain ? this.chain.getBlock(heightOrHash) : null;
  }

  getMaturePlotRegistrations(parentHash, winnerHeight) {
    return this.chain ? this.chain.getMaturePlotRegistrations(parentHash, winnerHeight) : [];
  }

  get height() {
    return this.chain ? this.chain.height : 0;
  }

  _targetForHeight(height) {
    if (height === 0) {
      try { return BigInt(this.cfg.initialTarget); } catch { return BigInt('0x00FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF'); }
    }
    const interval = this.cfg.difficultyAdjustBlocks || 8192;
    const expected = this.cfg.expectedTimePerBlock || 60;
    if (height % interval !== 0) {
      const prev = this.db.prepare('SELECT target FROM blocks WHERE height = ?').get(height - 1);
      if (prev) try { return BigInt(prev.target); } catch {}
      try { return BigInt(this.cfg.initialTarget); } catch { return 0n; }
    }
    const prevInterval = this.db.prepare('SELECT timestamp FROM blocks WHERE height = ?').get(Math.max(0, height - interval));
    const latest = this.db.prepare('SELECT timestamp FROM blocks WHERE height = ?').get(height - 1);
    if (prevInterval && latest) {
      const actual = latest.timestamp - prevInterval.timestamp;
      // actual is the timespan of (interval) blocks, not a single block
      const expectedSpan = expected * interval;
      const target = BigInt(this._targetForHeight(height - 1));
      if (actual < expectedSpan / 2) return target * 2n;
      if (actual > expectedSpan * 2) return target / 2n;
      const ratio = BigInt(Math.floor((expectedSpan * 1000) / Math.max(1, actual)));
      return (target * ratio) / 1000n;
    }
    try { return BigInt(this.cfg.initialTarget); } catch { return 0n; }
  }

  _blockWork(block) {
    try {
      const baseTarget = BigInt(block.base_target ||  this.cfg.initialTarget);
      if (baseTarget <= 0n) return 1n;
      return (2n ** 64n / baseTarget);
    } catch { return 1n; }
  }

  _defaultBaseTarget() {
    const blockTime = Math.max(1, this.cfg.expectedTimePerBlock || 60);
    let candidates = 0n;
    const tip = this.getBlock(this.height);
    if (tip) {
      for (const plot of this.getMaturePlotRegistrations(tip.hash, this.height + 1)) {
        candidates += BigInt(BigInt(plot.capacity_bytes) / BigInt(PocPlotV4.NONCE_BYTES));
      }
    }
    if (candidates < 1n) candidates = 1n;
    const bt = (BigInt(2) ** BigInt(64)) / (candidates * BigInt(blockTime));
    const MAX_BT = BigInt('1000000000000000000');
    return String(bt < 1n ? 1n : bt > MAX_BT ? MAX_BT : bt);
  }

  _baseTargetCapacity() {
    const blockTime = Math.max(1, this.cfg.expectedTimePerBlock || 60);
    let candidates = 0n;
    const tip = this.getBlock(this.height);
    if (tip) {
      for (const plot of this.getMaturePlotRegistrations(tip.hash, this.height + 1)) {
        candidates += BigInt(BigInt(plot.capacity_bytes) / BigInt(PocPlotV4.NONCE_BYTES));
      }
    }
    if (candidates < 1n) candidates = 1n;
    return (BigInt(2) ** BigInt(64)) / (candidates * BigInt(blockTime));
  }

  // Capacity-derived reference base target for a block at `height`: the value
  // that makes the expected best deadline of every mature registration match
  // `expectedTimePerBlock`. Pure function of the chain up to `height - 1`
  // (explicit parent lookup, not this.height), so all nodes agree.
  _baseTargetIdealFor(height) {
    const expectedTime = Math.max(1, this.cfg.expectedTimePerBlock || 60);
    let candidates = 0n;
    const parent = this.db.prepare('SELECT hash FROM blocks WHERE height = ?').get(height - 1);
    if (parent) {
      for (const plot of this.getMaturePlotRegistrations(parent.hash, height)) {
        candidates += BigInt(BigInt(plot.capacity_bytes) / BigInt(PocPlotV4.NONCE_BYTES));
      }
    }
    if (candidates < 1n) return null;
    return (BigInt(2) ** BigInt(64)) / (candidates * BigInt(expectedTime));
  }

  // Clamp a candidate base target: keep it within a generous, scale-free factor
  // of the capacity-derived reference, then inside [baseTargetMin, baseTargetMax].
  _clampBaseTarget(value, ideal) {
    let t = value;
    if (ideal && ideal > 0n) {
      const anchor = BigInt(Math.max(2, safeInt(this.cfg.baseTargetAnchorFactor, 16)));
      const lo = ideal / anchor;
      const hi = ideal * anchor;
      if (t < lo) t = lo;
      if (t > hi) t = hi;
    }
    const minB = safeBigInt(this.cfg.baseTargetMin, 2n ** 32n);
    const maxB = safeBigInt(this.cfg.baseTargetMax, 2n ** 56n);
    if (t < minB) t = minB;
    if (t > maxB) t = maxB;
    if (t < 1n) t = 1n;
    return t;
  }

  _baseTargetForHeight(height) {
    const expectedTime = Math.max(1, this.cfg.expectedTimePerBlock || 60);
    if (height === 0) return String(this.cfg.genesisBaseTarget ?? this._defaultBaseTarget());
    const prev = this.db.prepare('SELECT base_target, timestamp FROM blocks WHERE height = ?').get(height - 1);
    if (!prev) return this._defaultBaseTarget();
    const prevTarget = BigInt((prev && prev.base_target) || this._defaultBaseTarget());
    const ideal = this._baseTargetIdealFor(height);

    // Re-evaluate at most once per window; between windows the base target is
    // frozen. The old code applied a +/-30% step to *every* block, which
    // compounded into an exponential runaway and drove the base target down to
    // an un-mineable floor whenever the miner was faster than the target.
    const window = Math.max(8, safeInt(this.cfg.baseTargetWindow, 128));

    // Bootstrap: until one full measurement window exists, follow the
    // capacity-derived reference directly instead of the fixed genesis value.
    // `genesisBaseTarget` assumes a large network; on a small one it is several
    // times too low and each block then takes minutes, so the first window
    // would be hours away. Tracking the reference self-sizes the network
    // immediately, and the feedback step below refines it afterwards.
    if (height < window) {
      const seed = ideal && ideal > 0n ? ideal : prevTarget;
      return String(this._clampBaseTarget(seed, ideal));
    }

    if (height % window !== 0) return String(prevTarget);

    const oldest = this.db.prepare('SELECT timestamp FROM blocks WHERE height = ?').get(Math.max(0, height - window));
    if (!oldest) return String(prevTarget);
    const actualDuration = prev.timestamp - oldest.timestamp;
    if (actualDuration <= 0) return String(prevTarget);

    // Proportional step: deadline scales as 1/baseTarget, so measured/expected
    // drives the base target straight to the target block time. Bounded per
    // window to avoid overshoot from a noisy measurement, then clamped against
    // the capacity reference so a noisy measurement cannot run it away.
    const meanSeconds = actualDuration / window;
    const maxMove = Math.min(0.9, Math.max(0.01, Number(this.cfg.baseTargetMaxMove ?? 0.5)));
    const ratio = meanSeconds / expectedTime;
    const factor = Math.min(1 + maxMove, Math.max(1 - maxMove, ratio));
    const t = (prevTarget * BigInt(Math.round(factor * 1000000))) / 1000000n;

    return String(this._clampBaseTarget(t, ideal));
  }

  _baseFeeForHeight(height) {
    if (height === 0) return GAS_PARAMS.initialBaseFee;
    const parent = this.db.prepare('SELECT base_fee, gas_used FROM blocks WHERE height = ?').get(height - 1);
    if (!parent) return GAS_PARAMS.initialBaseFee;
    const parentBaseFee = parent.base_fee != null && parent.base_fee !== '' ? BigInt(parent.base_fee) : BigInt(GAS_PARAMS.initialBaseFee);
    const mempoolPendingCount = this.db.prepare('SELECT COUNT(*) as c FROM mempool').get().c;
    return String(nextBaseFee(
      parentBaseFee,
      parent.gas_used || 0,
      GAS_PARAMS.blockGasLimit / 2,
      this.cfg.minGasPrice,
      mempoolPendingCount
    ));
  }
}

class MemPool_Manager {
  constructor(db, cfg, chain) {
    this.db = db;
    this.cfg = cfg;
    this.chain = chain;
  }

  _validateTxOrder(txs) {
    const projectedNonce = {}, projectedBalance = {};
    for (const tx of txs) {
      if (tx.chain_id == null) tx.chain_id = String(this.cfg.chainId || '0');
      const sender = tx.from_addr;
      if (!sender) return [false, 'invalid tx sender'];
      if (String(tx.chain_id) !== String(this.cfg.chainId || '')) return [false, 'wrong chain_id'];
      if (tx.hash) {
        const expectedHash = tx.rpc_type === 'evm' && tx.raw
          ? keccak256(tx.raw)
          : (String(tx.hash).startsWith('0x') ? evmTxHash(tx) : hashTransaction(tx));
        if (String(tx.hash).toLowerCase() !== String(expectedHash).toLowerCase() && String(tx.hash).toLowerCase() !== hashTransaction(tx).toLowerCase() && String(tx.hash).toLowerCase() !== evmTxHash(tx).toLowerCase()) return [false, 'transaction hash mismatch'];
      }
      if (!(sender in projectedNonce)) {
        const user = this.db.prepare('SELECT nonce, balance FROM users WHERE address = ?').get(sender);
        projectedNonce[sender] = user ? safeInt(user.nonce, 0) : 0;
        projectedBalance[sender] = user ? safeBigInt(user.balance, 0n) : 0n;
      }
      if (safeInt(tx.nonce, -1) < 0 || safeInt(tx.value, -1) < 0) return [false, `invalid tx values for ${sender}`];
      if (safeInt(tx.nonce, 0) !== projectedNonce[sender]) return [false, 'transactions not ordered by nonce'];
      if (projectedBalance[sender] < safeBigInt(tx.value, 0n) + safeBigInt(tx.fee, 0n)) return [false, `insufficient balance for ${sender}`];
      const sig = tx.signature || '';
      if (!sig) return [false, `missing signature from ${sender}`];
      const recovered = recoverTransactionSender(tx);
      if (!recovered) return [false, `invalid signature from ${sender}`];
      if (recovered !== sender.toLowerCase()) return [false, `recovered sender ${recovered} does not match ${sender}`];
      const msg = canonicalTxMessage(tx);
      void msg;
      projectedBalance[sender] -= safeBigInt(tx.value, 0n) + safeBigInt(tx.fee, 0n);
      projectedNonce[sender] = Math.max(projectedNonce[sender] + 1, safeInt(tx.nonce, 0) + 1);
    }
    return [true, ''];
  }

  _validateTxBalances(txs) {
    const projectedBalance = {};
    for (const tx of txs) {
      const sender = tx.from_addr;
      if (!sender) return [false, 'invalid tx sender'];
      if (safeInt(tx.value, -1) < 0 || safeInt(tx.fee, -1) < 0) return [false, `invalid tx values for ${sender}`];
      if (!(sender in projectedBalance)) {
        const user = this.db.prepare('SELECT balance FROM users WHERE address = ?').get(sender);
        projectedBalance[sender] = user ? safeBigInt(user.balance, 0n) : 0n;
      }
      if (projectedBalance[sender] < safeBigInt(tx.value, 0n) + safeBigInt(tx.fee, 0n)) {
        return [false, `insufficient balance for ${sender}`];
      }
      projectedBalance[sender] -= safeBigInt(tx.value, 0n) + safeBigInt(tx.fee, 0n);
    }
    return [true, ''];
  }

  async validateTxForMempool(tx) {
    if (tx.from_addr) tx.from_addr = normalizeAddr(tx.from_addr);
    if (tx.to_addr) tx.to_addr = normalizeAddr(tx.to_addr);
    if (tx.chain_id == null) tx.chain_id = String(this.cfg.chainId || '0');
    if (String(tx.chain_id) !== String(this.cfg.chainId || '')) return { ok: false, motivo: 'wrong chain_id' };
    const sender = tx.from_addr;
    if (!sender) return { ok: false, motivo: 'missing from_addr' };
    if (!tx.to_addr && !tx.data) return { ok: false, motivo: 'missing to_addr (or data for contract creation)' };
    if (tx.to_addr && !/^0x[0-9a-fA-F]{40}$/.test(tx.to_addr)) return { ok: false, motivo: 'invalid to_addr' };
    if (tx.data && !/^0x[0-9a-fA-F]*$/.test(tx.data)) return { ok: false, motivo: 'invalid data' };
    if (safeInt(tx.nonce, -1) < 0 || safeInt(tx.value, -1) < 0) return { ok: false, motivo: 'invalid nonce/value' };
    const sig = tx.signature || '';
    if (!sig) return { ok: false, motivo: `missing signature from ${sender}` };
    const recovered = recoverTransactionSender(tx);
    if (!recovered) return { ok: false, motivo: `invalid signature from ${sender}` };
    if (recovered !== sender.toLowerCase()) return { ok: false, motivo: `recovered sender ${recovered} does not match from_addr` };
    const user = this.db.prepare('SELECT balance, nonce FROM users WHERE lower(address) = lower(?)').get(sender);
    const curNonce = user ? safeInt(user.nonce, 0) : 0;
    const curBalance = user ? safeBigInt(user.balance, 0n) : 0n;
    // Accept the confirmed nonce or any near-future nonce: a client preparing
    // several txs back to back (e.g. auto-registering multiple plots) hands out
    // consecutive nonces, and nonce-gapped txs simply stay queued until their
    // predecessors are mined. This matches the forger's sequential selection
    // (which only drops nonces below the projected value).
    const txNonce = safeInt(tx.nonce, 0);
    if (txNonce < curNonce) return { ok: false, motivo: `stale nonce (tx=${txNonce}, account=${curNonce})` };
    const maxFutureNonce = curNonce + Math.max(1, safeInt(this.cfg.maxFutureNonce, 64));
    if (txNonce > maxFutureNonce) return { ok: false, motivo: `nonce too far in future (tx=${txNonce}, account=${curNonce})` };
    if (curBalance < safeBigInt(tx.value, 0n) + safeBigInt(tx.fee, 0n)) return { ok: false, motivo: `insufficient balance for ${sender}` };
    if (!tx.to_addr && this.chain.contracts) {
      const address = this.chain.contracts.deriveContractAddress(sender, safeInt(tx.nonce, 0));
      if (this.db.prepare('SELECT 1 FROM smart_contracts WHERE lower(address) = lower(?)').get(address)) {
        return { ok: false, motivo: `contract already exists at ${address}` };
      }
    }

    const requiredGas = estimateIntrinsicGas(tx);
    if (safeInt(tx.gas_limit, 0) < requiredGas) return { ok: false, motivo: `gas_limit too low (need ${requiredGas})` };
    if (safeInt(tx.gas_limit, 0) > GAS_PARAMS.maxGasPerTx) return { ok: false, motivo: `gas_limit exceeds max per tx (${GAS_PARAMS.maxGasPerTx})` };
    const isRegistration = PocPlotV4.isRegistrationPayload(tx.data);
    if (!isRegistration) {
      const currentBaseFee = BigInt(this.chain._baseFeeForHeight(this.chain.height + 1));
      if (safeBigInt(tx.gas_price, 0n) < currentBaseFee) return { ok: false, motivo: `gas_price below base fee (${currentBaseFee})` };
      const minFee = minimumFee(tx, currentBaseFee);
      if (safeBigInt(tx.fee, 0n) < minFee) return { ok: false, motivo: `fee too low (need ${minFee} = intrinsic ${estimateIntrinsicGas(tx)} * baseFee ${currentBaseFee})` };
    }

    if (isRegistration) {
      let events;
      try { events = this.chain._preparePlotRegistrationEvents([tx], this.chain.height + 1, this.chain.bestHash); }
      catch (e) { return { ok: false, motivo: e.message || 'invalid v4 plot registration' }; }
      if (events.length !== 1) return { ok: false, motivo: 'invalid v4 plot registration transaction' };
      const maxPerBlock = Math.max(1, safeInt(this.cfg.maxPlotRegistrationsPerBlock, 4));
      const maxPerMiner = Math.max(1, safeInt(this.cfg.maxPlotRegistrationsPerMinerPerBlock, 1));
      const senderLc = sender.toLowerCase();
      const pending = this.db.prepare('SELECT raw FROM mempool').all();
      let pendingTotal = 0, pendingForSender = 0;
      for (const row of pending) {
        try {
          const other = JSON.parse(row.raw);
          if (!PocPlotV4.isRegistrationPayload(other.data)) continue;
          pendingTotal++;
          if (String(other.from_addr || '').toLowerCase() === senderLc) pendingForSender++;
          const registration = PocPlotV4.decodeRegistration(other.data);
          if (registration.plot_id === events[0].plot_id) return { ok: false, motivo: 'plot_id already has a pending registration' };
        } catch { /* malformed unrelated mempool entry */ }
      }
      if (pendingTotal >= maxPerBlock) return { ok: false, motivo: `too many pending plot registrations (max ${maxPerBlock})` };
      if (pendingForSender >= maxPerMiner) return { ok: false, motivo: `miner already has a pending plot registration (max ${maxPerMiner})` };
    }

    return { ok: true, motivo: 'valid' };
  }

  addMempoolTx(tx) {
    const txHash = tx.hash || hashTransaction(tx);
    const existing = this.db.prepare('SELECT 1 FROM mempool WHERE hash = ?').get(txHash);
    if (existing) return { ok: true, motivo: 'Tx already in mempool' };
    const inBlock = this.db.prepare('SELECT 1 FROM transactions WHERE hash = ?').get(txHash);
    if (inBlock) return { ok: false, motivo: 'Tx already in chain' };
    const maxMempool = this.cfg.maxMempoolSize || 5000;
    const count = this.db.prepare('SELECT COUNT(*) as c FROM mempool').get().c;
    if (count >= maxMempool) return { ok: false, motivo: 'mempool full' };
    const ttl = this.cfg.mempoolTxTtlSec || 3600;
    this.db.prepare('DELETE FROM mempool WHERE timestamp < ?').run(Math.floor(Date.now() / 1000) - ttl);
    try {
      const raw = JSON.stringify(tx);
      this.db.prepare('INSERT INTO mempool (hash, raw, timestamp, fee) VALUES (?, ?, ?, ?)').run(txHash, raw, Math.floor(Date.now() / 1000), String(tx.fee || 0));
      return { ok: true, motivo: 'added', hash: txHash };
    } catch (e) { return { ok: false, motivo: e.message || 'insert error' }; }
  }

  getMempoolForBlock(maxCount = 100) {
    const raw = this.db.prepare('SELECT * FROM mempool ORDER BY CAST(fee AS INTEGER) DESC, timestamp ASC LIMIT ?').all(maxCount);
    if (raw.length) log('info', `[TX] getMempoolForBlock: ${raw.length} raw entries in mempool`);
    return raw.map(r => { try { return JSON.parse(r.raw); } catch { return null; } }).filter(Boolean);
  }

  cleanMempool() {
    const ttl = this.cfg.mempoolTxTtlSec || 3600;
    this.db.prepare('DELETE FROM mempool WHERE timestamp < ?').run(Math.floor(Date.now() / 1000) - ttl);
  }
}

class contracts_Manager {
  constructor(db, chain) {
    this.db = db;
    this.chain = chain;
  }

  _isCreateTx(tx) { return !!(tx && !tx.to_addr && tx.data); }

  _isContractCall(tx) {
    if (!tx || !tx.to_addr || !tx.data) return false;
    if (!this.chain.contracts) return false;
    return !!this.db.prepare('SELECT 1 FROM smart_contracts WHERE lower(address) = lower(?)').get(tx.to_addr);
  }

  _isContractOp(tx) { return this._isCreateTx(tx) || this._isContractCall(tx); }

  _blockContext(bloco) { return this.chain._blockContext(bloco); }
  _snapshotContractState(address) { return this.chain._snapshotContractState(address); }
  _restoreContractState(snaps) { return this.chain._restoreContractState(snaps); }
  _recordContractStateChanges(blockHeight, blockHash, snapshots) { return this.chain._recordContractStateChanges(blockHeight, blockHash, snapshots); }
  _restoreContractStateFromHistory(aboveHeight) { return this.chain._restoreContractStateFromHistory(aboveHeight); }

  async _preExecuteContracts(bloco, txs) {
    const backup = [];
    const payouts = [];
    const logs = [];
    const blkCtx = this._blockContext(bloco);
    const appendLogs = (tx, res) => {
      if (!res || !Array.isArray(res.logs)) return;
      let idx = 0;
      for (const raw of res.logs) {
        if (!raw) continue;
        let address = raw.address;
        if (address && typeof address === 'object' && address.bytes) address = bytesToHex(address.bytes);
        address = String(address || '').toLowerCase();
        const topics = (raw.topics || []).map(t => (t && typeof t === 'object' && t instanceof Uint8Array) ? bytesToHex(t) : String(t || ''));
        let data = raw.data;
        if (data && data instanceof Uint8Array) data = bytesToHex(data);
        else if (data != null && !/^0x/.test(String(data))) data = '0x' + String(data);
        logs.push({ tx_hash: (tx.hash || hashTransaction(tx)), address, topics: JSON.stringify(topics), data: String(data || '0x'), _idx: idx++ });
      }
    };
    try {
      for (const tx of txs) {
        const txHash = tx.hash || hashTransaction(tx);
        if (this.db.prepare('SELECT 1 FROM transactions WHERE hash = ?').get(txHash)) {
          tx._ccApplied = true;
          continue;
        }
        if (this._isCreateTx(tx)) {
          const nonce = safeInt(tx.nonce, 0);
          const address = this.chain.contracts.deriveContractAddress(tx.from_addr, nonce);
          backup.push(this._snapshotContractState(address));
          try {
            const res = await this.chain.contracts.CreateSmartContract(
              tx.data,
              blkCtx,
              tx.from_addr,
              nonce,
              safeBigInt(tx.value, 0n).toString(),
              tx.gas_limit,
              tx.gas_price
            );
            tx._ccApplied = true;
            tx._ccContractAddress = res && res.contractAddress ? String(res.contractAddress).toLowerCase() : address;
            if (res && Array.isArray(res.payouts)) payouts.push(...res.payouts);
            appendLogs(tx, res);
          } catch (e) {
            tx._ccError = e.message || String(e);
            tx._ccApplied = false;
          }
        } else if (this._isContractCall(tx)) {
          const to = tx.to_addr;
          backup.push(this._snapshotContractState(to));
          try {
            const res = await this.chain.contracts.runSmartContract(to, tx.from_addr, tx.data || '0x', safeBigInt(tx.value, 0n).toString(), tx.gas_limit, tx.gas_price, blkCtx, true);
            if (safeBigInt(tx.value, 0n) > 0n) {
              await this.chain.contracts.creditContractBalance(to, safeBigInt(tx.value, 0n).toString());
            }
            tx._ccApplied = true;
            log('info', `[SMART CONTRACTS] Block contract call OK: to=${to} from=${tx.from_addr} gasUsed=${res ? res.gasUsed : '?'} data=${(tx.data || '0x').slice(0, 10)}`);
            if (res && Array.isArray(res.payouts)) payouts.push(...res.payouts);
            appendLogs(tx, res);
          } catch (e) {
            tx._ccError = e.message || String(e);
            tx._ccApplied = false;
            log('error', `[SMART CONTRACTS] Block contract call REVERTED: to=${to} from=${tx.from_addr} data=${(tx.data || '0x').slice(0, 42)} reason=${e.reason || 'none'} error=${e.message}`);
          }
        }
      }
      return { ok: true, rollback: () => this._restoreContractState(backup), payouts, backup, logs };
    } catch (e) {
      this._restoreContractState(backup);
      return { ok: false, motivo: e.message || 'contract execution error', rollback: () => {}, payouts: [], logs: [] };
    }
  }
}

const FINALIZATION_DEPTH = Config.Configuration.FINALIZATION_DEPTH;
const MAX_REWARD_ENTRIES = 256;

module.exports = { Chain, Config, Diff_Manager, MemPool_Manager, contracts_Manager, FINALIZATION_DEPTH, MAX_REWARD_ENTRIES };
