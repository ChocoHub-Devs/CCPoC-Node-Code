const { ZERO_HASH, sha256hex, safeInt, safeBigInt, hashBlock, hashTransaction, evmTxHash, keccak256, merkleRoot, computeStateRoot, computeStateRootAfterTxs, computeContractStateRoot, verifySignature, calculateMiningReward, isBetterChainCandidate, canonicalTxMessage, blockMessage, signMessage, proofMessage, SCOOPS_PER_NONCE, computeDeadline, pubkeyToAddress, recoverTransactionSender } = require('../crypto-utils/crypto');

const { IncrementalStateRoot } = require('./state-trie');
const { ZkpService } = require('../crypto-utils/zkp-service');
const { SnapSyncService } = require('../snap/snap-service');
const { hashBlockAsync, verifySignatureAsync } = require('../utils/worker-pool');
const { estimateIntrinsicGas, totalGasUsed, maximumGasPrice, effectiveGasPrice, nextBaseFee, GAS_PARAMS, capTxGasLimit, minimumFee } = require('../consensus/gas');
const { log } = require('../../config/config');
const { createBlock } = require('@ethereumjs/block');
const { bytesToHex } = require('@ethereumjs/util');
const BN = require('bn.js');
const PocPlotV4 = require('../consensus/poc-plot-v4');
const { CONSENSUS_VERSION } = require('../consensus/protocol');
const { normalizeMaxSupply } = require('../consensus/config-values');
const { ContractJournal } = require('./contract-journal');

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
    cfg.maxSupply = normalizeMaxSupply(cfg.maxSupply);
    this.db = db;
    this.cfg = cfg;
    if (cfg.smartContractsEnabled === false) {
      throw new Error('consensus v6 requires deterministic EVM execution on every validator');
    }
    this.height = 0;
    this.bestHash = ZERO_HASH;
    this.contracts = null;
    this._blockMutationTail = Promise.resolve();
    this._stateTransitionPending = false;
    this._stableStateReaders = 0;
    this._stableStateDrainWaiters = [];
    this.contractJournal = new ContractJournal(db, snapshots => this._restoreContractState(snapshots));
    this.contractJournal.recover();

    try { this.db.prepare('ALTER TABLE transactions ADD COLUMN block_hash TEXT DEFAULT ""').run(); } catch (e) {   }
    try { this.db.prepare('ALTER TABLE blocks ADD COLUMN base_target TEXT').run(); } catch (e) {   }
    try { this.db.prepare('ALTER TABLE blocks ADD COLUMN contract_state_root TEXT DEFAULT ""').run(); } catch (e) {   }
    try { this.db.prepare('ALTER TABLE blocks ADD COLUMN forger TEXT DEFAULT ""').run(); } catch (e) {   }
    try { this.db.prepare("ALTER TABLE blocks ADD COLUMN rewards_json TEXT DEFAULT '[]'").run(); } catch (e) {   }
    try { this.db.prepare('ALTER TABLE blocks ADD COLUMN body_pruned INTEGER DEFAULT 0').run(); } catch (e) {   }
    try { this.db.prepare("ALTER TABLE blocks ADD COLUMN chain_id TEXT DEFAULT ''").run(); } catch (e) {   }
    try { this.db.prepare('ALTER TABLE transactions ADD COLUMN data TEXT DEFAULT ""').run(); } catch (e) {   }
    try { this.db.prepare('ALTER TABLE challenge_submissions ADD COLUMN capacity_samples TEXT DEFAULT "[]"').run(); } catch (e) {   }
    try { this.db.prepare('ALTER TABLE challenge_submissions ADD COLUMN public_key TEXT DEFAULT ""').run(); } catch (e) {   }
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
    try { this.db.prepare('DELETE FROM block_rewards WHERE rowid NOT IN (SELECT MIN(rowid) FROM block_rewards GROUP BY block_height, block_hash, miner, plot_id, reward_cc)').run(); } catch (e) {   }
    try { this.db.prepare('CREATE UNIQUE INDEX IF NOT EXISTS ux_block_rewards ON block_rewards (block_height, block_hash, miner, plot_id, reward_cc)').run(); } catch (e) {   }
    const repFix = (t) => { const rows = this.db.prepare(`SELECT block_height, block_hash FROM ${t}`).all(); for (const r of rows) { const blks = this.db.prepare('SELECT hash FROM blocks WHERE height = ?').all(r.block_height); if (blks.length === 1 && blks[0].hash !== r.block_hash) this.db.prepare(`UPDATE ${t} SET block_hash = ? WHERE block_height = ? AND block_hash = ?`).run(blks[0].hash, r.block_height, r.block_hash); } };
    try { repFix('block_rewards'); repFix('transactions'); } catch (e) {   }
    try { this.db.prepare('DELETE FROM challenge_submissions WHERE id NOT IN (SELECT MIN(id) FROM challenge_submissions GROUP BY challenge_id, miner, plot_id, deadline)').run(); } catch (e) {   }
    try { this.db.prepare('CREATE UNIQUE INDEX IF NOT EXISTS ux_sub_challenge_plot ON challenge_submissions(challenge_id, miner, plot_id, deadline)').run(); } catch (e) {   }
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

  _consensusParameters() {
    return {
      initial_target: String(this.cfg.initialTarget || '0x00FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF'),
      genesis_base_target: String(this.cfg.genesisBaseTarget),
      initial_reward: String(this.cfg.initialReward),
      halving_interval: safeInt(this.cfg.halvingInterval, 0),
      max_supply: normalizeMaxSupply(this.cfg.maxSupply),
      difficulty_adjust_blocks: safeInt(this.cfg.difficultyAdjustBlocks, 0),
      expected_time_per_block: safeInt(this.cfg.expectedTimePerBlock, 0),
      base_target_window: safeInt(this.cfg.baseTargetWindow, 0),
      base_target_max_move: Number(this.cfg.baseTargetMaxMove),
      base_target_anchor_factor: safeInt(this.cfg.baseTargetAnchorFactor, 0),
      base_target_min: String(this.cfg.baseTargetMin),
      base_target_max: String(this.cfg.baseTargetMax),
      min_gas_price: String(this.cfg.minGasPrice),
      block_gas_limit: GAS_PARAMS.blockGasLimit,
      target_block_gas_limit: GAS_PARAMS.targetBlockGasLimit,
      max_transaction_gas: GAS_PARAMS.maxGasPerTx,
      gas_accounting: 'intrinsic-plus-evm-execution-v1',
      gas_refund_quotient: 5,
      fee_model: 'signed-gas-limit-cap-settle-actual-v1',
      simple_transfer_gas: GAS_PARAMS.simpleTransferGas,
      gas_per_zero_byte: GAS_PARAMS.gasPerByteZero,
      gas_per_nonzero_byte: GAS_PARAMS.gasPerByteNonZero,
      initial_base_fee: GAS_PARAMS.initialBaseFee,
      max_plot_registrations_per_block: safeInt(this.cfg.maxPlotRegistrationsPerBlock, 0),
      max_plot_registrations_per_miner_per_block: safeInt(this.cfg.maxPlotRegistrationsPerMinerPerBlock, 0),
      max_future_block_sec: safeInt(this.cfg.maxFutureBlockSec, 0),
      smart_contract_hardfork: 'Shanghai',
      contract_state_model: 'state-root-v2-nonce-journal',
    };
  }

  _assertGenesisMatchesConfig() {
    const genesis = this.getBlock(0);
    if (!genesis) throw new Error('consensus v6 chain is missing its genesis block');
    if (String(genesis.chain_id) !== String(this.cfg.chainId)) throw new Error('database genesis chain_id does not match the configured network');
    const expectedTimestamp = safeInt(this.cfg.genesisTimestamp, -1);
    const expectedTarget = String(this.cfg.initialTarget || '0x00FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF');
    if (safeInt(genesis.timestamp, -1) !== expectedTimestamp || String(genesis.target) !== expectedTarget) {
      throw new Error('database genesis timestamp/target do not match the configured v6 network');
    }
    if (this.cfg.genesisBaseTarget != null && String(genesis.base_target) !== String(this.cfg.genesisBaseTarget)) {
      throw new Error('database genesis base target does not match the configured v4 network');
    }
    const expectedHash = hashBlock({ ...genesis, chain_id: this.cfg.chainId, consensus_version: CONSENSUS_VERSION,
      consensus_params: this._consensusParameters(), genesis_plot_registrations: this.genesisPlotRegistrations });
    if (genesis.hash !== expectedHash) {
      throw new Error('database genesis does not match consensus v6 configuration; use a fresh database and identical genesis parameters on every node');
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
        } catch {   }
      }
    });
    save();
  }

  
  _targetForHeight(height, parentHash) { return this.diffManager._targetForHeight(height, parentHash); }
  _blockWork(block) { return this.diffManager._blockWork(block); }
  _defaultBaseTarget() { return this.diffManager._defaultBaseTarget(); }
  _baseTargetCapacity() { return this.diffManager._baseTargetCapacity(); }
  _baseTargetForHeight(height, parentHash) { return this.diffManager._baseTargetForHeight(height, parentHash); }
  _baseFeeForHeight(height, parentHash) { return this.diffManager._baseFeeForHeight(height, parentHash); }

  
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

  
  _isContractCall(tx) { return this.contractsManager._isContractCall(tx); }
  _isContractOp(tx) { return this.contractsManager._isContractOp(tx); }
  async _preExecuteContracts(bloco, txs, beforeWrite) { return this.contractsManager._preExecuteContracts(bloco, txs, beforeWrite); }
  _recordContractStateChanges(blockHeight, blockHash, snapshots) { return this.contractsManager._recordContractStateChanges(blockHeight, blockHash, snapshots); }
  _restoreContractStateFromHistory(aboveHeight) { return this.contractsManager._restoreContractStateFromHistory(aboveHeight); }

  setContractExecutor(sc) { this.contracts = sc; }

  _initGenesis() {
    const cfg = this.cfg;
    const now = cfg.genesisTimestamp || Math.floor(Date.now() / 1000);
    const target = cfg.initialTarget || '0x00FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF';
    const reward = calculateMiningReward(0, cfg);
    const state_root = computeStateRoot(this.db);
    const contract_state_root = computeContractStateRoot(this.db);
    const genesis = {
      height: 0, chain_id: this.cfg.chainId, consensus_version: CONSENSUS_VERSION, consensus_params: this._consensusParameters(), parent_hash: ZERO_HASH, timestamp: now,
      miner: 'genesis', challenge_id: '', tx_root: ZERO_HASH,
      nonce: '0', difficulty: '0', target: String(target),
      reward_units: '0', reward_cc: String(reward), tx_count: 0,
      signature: '', generation_signature: ZERO_HASH,
      proof_digest: '', plot_id: '', state_root, contract_state_root,
      origin: 'genesis', total_fees_units: '0', gas_used: 0, gas_limit: GAS_PARAMS.blockGasLimit,
      base_fee: String(GAS_PARAMS.initialBaseFee), base_target: String(this.cfg.genesisBaseTarget ?? this._defaultBaseTarget()),
      transactions: [], rewards: [], genesis_plot_registrations: this.genesisPlotRegistrations,
    };
    genesis.hash = hashBlock(genesis);
    try {
      const work = this._blockWork(genesis);
      const totalFees = 0n;
      const gasUsed = 0;
      this.db.prepare(`INSERT INTO blocks (height, hash, parent_hash, timestamp, miner, challenge_id, tx_root, nonce, difficulty, target,
        reward_units, reward_cc, tx_count, chain_work, signature, generation_signature, proof_digest, plot_id, state_root, origin,
        total_fees_units, gas_used, gas_limit, base_target, base_fee, contract_state_root, forger, rewards_json, chain_id) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).run(
        0, genesis.hash, ZERO_HASH, now, 'genesis', '', ZERO_HASH, '0', '0', String(target),
        '0', String(reward), 0, String(work), '', ZERO_HASH, '', '', state_root, 'genesis',
        String(totalFees), gasUsed, GAS_PARAMS.blockGasLimit, genesis.base_target, String(GAS_PARAMS.initialBaseFee),
        genesis.contract_state_root || '', genesis.forger || '', '[]', String(this.cfg.chainId)
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

  _validateRewardDistribution(bloco, parentHash) {
    if (safeInt(bloco.height, 0) <= 0) return { ok: true };
    const rewardsData = bloco.rewards || [];
    if (!Array.isArray(rewardsData)) return { ok: false, motivo: 'invalid reward distribution' };
    const totalReward = calculateMiningReward(bloco.height, this.cfg);
    const maxSupply = BigInt(normalizeMaxSupply(this.cfg.maxSupply));
    if (maxSupply > 0n) {
      parentHash ||= this.db.prepare('SELECT parent_hash FROM blocks WHERE hash = ?').get(bloco.hash)?.parent_hash || this.bestHash;
      const ancestryRewards = this.db.prepare(`
        WITH RECURSIVE ancestry(hash, parent_hash, height, depth) AS (
          SELECT hash, parent_hash, height, 0 FROM blocks WHERE hash = ?
          UNION ALL
          SELECT b.hash, b.parent_hash, b.height, a.depth + 1
          FROM blocks b JOIN ancestry a ON b.hash = a.parent_hash
          WHERE a.height > 0 AND a.depth < 1000000
        )
        SELECT b.reward_cc FROM ancestry a JOIN blocks b ON b.hash = a.hash WHERE a.height > 0
      `).all(parentHash);
      const emitted = ancestryRewards.reduce((sum, row) => sum + safeBigInt(row.reward_cc, 0n), 0n);
      if (safeBigInt(emitted, 0n) + totalReward > maxSupply) return { ok: false, motivo: 'max supply exceeded' };
    }
    if (rewardsData.length !== 1) return { ok: false, motivo: `consensus v6 requires exactly one winner reward (got ${rewardsData.length})` };
    const wp = bloco.winner_proof && typeof bloco.winner_proof === 'object' ? bloco.winner_proof : null;
    if (!wp) return { ok: false, motivo: 'winner proof is required for the consensus reward' };
    const r = rewardsData[0];
    if (typeof r !== 'object' || r === null || !r.miner) return { ok: false, motivo: 'reward entry missing miner' };
    if (normalizeAddr(r.miner) !== normalizeAddr(wp.miner || '')
      || normalizeAddr(r.miner) !== normalizeAddr(bloco.miner || '')
      || String(r.plot_id || '') !== String(wp.plot_id || '')
      || safeInt(r.deadline, -1) !== safeInt(wp.deadline, -2)) {
      return { ok: false, motivo: 'the sole reward must match the block winner proof' };
    }
    if (safeBigInt(r.reward_cc, -1n) !== totalReward) return { ok: false, motivo: 'winner reward must equal the full block reward' };
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
        try { bloco.winner_proof = JSON.parse(bloco.winner_proof); } catch {   }
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
    if (opts._reorgInternal) return this._addBlockUnsafe(bloco, opts);
    const previousMutation = this._blockMutationTail;
    let releaseMutation;
    this._blockMutationTail = new Promise((resolve) => { releaseMutation = resolve; });
    await previousMutation;
    try {
      return await this._addBlockUnsafe(bloco, opts);
    } finally {
      releaseMutation();
    }
  }

  tryAcquireStableRead() {
    if (this._stateTransitionPending) return null;
    this._stableStateReaders++;
    let released = false;
    return () => {
      if (released) return;
      released = true;
      this._stableStateReaders = Math.max(0, this._stableStateReaders - 1);
      if (this._stableStateReaders === 0) {
        for (const resolve of this._stableStateDrainWaiters.splice(0)) resolve();
      }
    };
  }

  async _beginStateTransition() {
    if (this._stateTransitionPending) throw new Error('another canonical state transition is already active');
    this._stateTransitionPending = true;
    if (this._stableStateReaders > 0) {
      await new Promise(resolve => this._stableStateDrainWaiters.push(resolve));
    }
    let released = false;
    return () => {
      if (released) return;
      released = true;
      this._stateTransitionPending = false;
    };
  }

  async _addBlockUnsafe(bloco, opts = {}) {
    if (this._stateRecoveryRequired) return { ok: false, motivo: 'contract state recovery required; restart node' };
    const isLocalForge = !!(bloco && bloco._from_local_forge);
    if (!bloco || String(bloco.chain_id) !== String(this.cfg.chainId)) return { ok: false, motivo: 'wrong or missing block chain_id' };
    if (!isLocalForge && !/^[0-9a-f]{64}$/i.test(String(bloco.state_root || ''))) return { ok: false, motivo: 'missing or invalid state_root' };
    if (!isLocalForge && !/^[0-9a-f]{64}$/i.test(String(bloco.contract_state_root || ''))) return { ok: false, motivo: 'missing or invalid contract_state_root' };
    if (safeInt(bloco.gas_limit, -1) !== GAS_PARAMS.blockGasLimit) return { ok: false, motivo: 'invalid block gas_limit' };
    if (!/^\d+$/.test(String(bloco.base_fee ?? ''))) return { ok: false, motivo: 'missing or invalid base_fee' };
    const { allowVotedTie = false } = opts;
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
    const incumbentAtHeight = this.db.prepare('SELECT hash FROM blocks WHERE height = ?').get(height);
    if (incumbentAtHeight && incumbentAtHeight.hash !== bloco.hash && !opts._reorgInternal && !isLocalForge) {
      
      
      
      const reorgResult = await this.reorganize(bloco, false, opts.allowVotedTie, [bloco], true);
      if (reorgResult.ok) return { ...reorgResult, motivo: 'reorganized to better tip' };
      return { ok: false, motivo: `competing block rejected: ${reorgResult.motivo}` };
    }
    if (height > 0) {
      if (!parent) return { ok: false, motivo: 'parent not found' };
      if (parent.height !== height - 1) return { ok: false, motivo: 'height sequence error' };
      const medianTimes = this.db.prepare(`
        WITH RECURSIVE ancestry(hash, parent_hash, height, depth) AS (
          SELECT hash, parent_hash, height, 0 FROM blocks WHERE hash = ?
          UNION ALL
          SELECT b.hash, b.parent_hash, b.height, a.depth + 1
          FROM blocks b JOIN ancestry a ON b.hash = a.parent_hash
          WHERE a.height > 0 AND a.depth < 11
        )
        SELECT b.timestamp FROM ancestry a JOIN blocks b ON b.hash = a.hash
        ORDER BY a.depth LIMIT 11
      `).all(parent.hash).map(r => safeInt(r.timestamp, 0)).sort((a, b) => a - b);
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
      const expectedTarget = this._targetForHeight(height, parent.hash);
      let blockTarget;
      try { blockTarget = BigInt(bloco.target || '0'); } catch { blockTarget = 0n; }
      if (blockTarget === 0n) try { blockTarget = BigInt(this.cfg.initialTarget); } catch { blockTarget = 0n; }
      if (blockTarget !== expectedTarget) return { ok: false, motivo: `incorrect target: got ${blockTarget}, expected ${expectedTarget}` };
      const expectedBaseTarget = BigInt(this._baseTargetForHeight(height, parent.hash));
      let blockBaseTarget;
      try { blockBaseTarget = BigInt(bloco.base_target); } catch { return { ok: false, motivo: 'invalid base_target format' }; }
      if (blockBaseTarget !== expectedBaseTarget) {
        log('warn', `base_target mismatch at #${height}: got ${blockBaseTarget}, expected ${expectedBaseTarget}`);
        return { ok: false, motivo: `incorrect base_target: got ${blockBaseTarget}, expected ${expectedBaseTarget}` };
      }
    }
    const txs = bloco.transactions || [];
    const [balanceOk, balanceMotivo] = this._validateTxBalances(txs);
    if (!balanceOk) return { ok: false, motivo: balanceMotivo };
    {
      let blockBaseFee;
      try { blockBaseFee = BigInt(this._baseFeeForHeight(height, parent.hash)); } catch { return { ok: false, motivo: 'invalid base_fee' }; }
      if (BigInt(bloco.base_fee) !== blockBaseFee) return { ok: false, motivo: 'incorrect base_fee' };
      for (const tx of txs) {
        if (tx.chain_id == null || String(tx.chain_id) !== String(this.cfg.chainId)) return { ok: false, motivo: 'wrong or missing transaction chain_id' };
        const intrinsic = estimateIntrinsicGas(tx);
        const gasLimit = safeInt(tx.gas_limit, 0);
        if (gasLimit < intrinsic || gasLimit > GAS_PARAMS.maxGasPerTx) return { ok: false, motivo: 'invalid transaction gas_limit' };
        
        
        
        if (PocPlotV4.isRegistrationPayload(tx.data)) continue;
        if (maximumGasPrice(tx, 0n) < blockBaseFee) return { ok: false, motivo: 'transaction gas price cap below base fee' };
      if (safeBigInt(tx.fee, 0n) < minimumFee(tx, blockBaseFee)) return { ok: false, motivo: 'transaction fee cap below gas_limit * gas_price' };
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
        const challenge = {
          challenge_id: sha256hex(`${String(parent.generation_signature || ZERO_HASH)}:${String(parent.hash)}`),
          challenge_seed: String(parent.generation_signature || ZERO_HASH),
          block_height: parent.height,
          winner_miner: bloco.miner,
          winner_deadline: safeInt(winnerProof.deadline, -1),
          base_target: String(this._baseTargetForHeight(height, parent.hash)),
          finalized_at: 1,
        };
        const expectedChallengeId = challenge.challenge_id;
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
        const challengeBt = String(challenge.base_target);
        const wpBaseTarget = safeBigInt(wp.base_target, 0n);
        if (!/^\d+$/.test(challengeBt)) return { ok: false, motivo: 'challenge has invalid base_target' };
        const expectedChallengeBt = BigInt(challengeBt);
        if (wpBaseTarget !== expectedChallengeBt) return { ok: false, motivo: 'winner_proof base_target does not match candidate-parent consensus value' };
        const recomputed = computeDeadline(scoopData, genSig, challengeBt);
        if (recomputed !== wpDeadline) {
          return { ok: false, motivo: `PoC verification failed: computed deadline ${recomputed}s, claimed ${wpDeadline}s` };
        }
      }
    }
    const rewardCheck = this._validateRewardDistribution(bloco, parent && parent.hash);
    if (!rewardCheck.ok) return { ok: false, motivo: rewardCheck.motivo };
    const now = Math.floor(Date.now() / 1000);
    const rewardsData = bloco.rewards || [];
    const reward = calculateMiningReward(height, this.cfg);
    const rewardStr = String(reward);
    let totalTxFees = 0n;
    let gasUsed = 0;
    const expectedReward = height > 0 ? calculateMiningReward(height, this.cfg) : 0n;
    if (safeBigInt(bloco.reward_cc, -1n) !== expectedReward) return { ok: false, motivo: 'incorrect reward_cc' };
    const parentWork = height > 0 ? (() => { const p = this.db.prepare('SELECT chain_work FROM blocks WHERE hash = ?').get(bloco.parent_hash); return p ? safeBigInt(p.chain_work, 0n) : 0n; })() : 0n;
    const newWork = parentWork + this._blockWork(bloco);
    bloco.chain_work = String(newWork);
    if (!bloco.hash) bloco.hash = await hashBlockAsync(bloco);
    const existingAtHeight = this.db.prepare('SELECT hash, chain_work FROM blocks WHERE height = ?').get(height);
    if (existingAtHeight && existingAtHeight.hash !== bloco.hash) {
      if (isBetterChainCandidate(bloco, this.getBlockByHash(existingAtHeight.hash))
        || (allowVotedTie && newWork === safeBigInt(existingAtHeight.chain_work, 0n))) {
        log('debug', `addBlock better local candidate h=${height} local=${existingAtHeight.hash.slice(0, 10)} remote=${bloco.hash.slice(0, 10)}`);
        const reorgResult = await this.reorganize(bloco, false, allowVotedTie, [bloco], true);
        if (!reorgResult.ok) return { ok: false, motivo: `reorg failed: ${reorgResult.motivo}` };
        return { ok: true, motivo: 'reorganized to better tip', height: this.height, hash: this.bestHash };
      } else {
        return { ok: false, motivo: 'competing block not better than incumbent' };
      }
    }

    let contractExec = null;
    let journalHash = null;
    let trieBefore = null;
    const oldHeight = this.height;
    const oldBestHash = this.bestHash;
    const contractTxs = txs.filter(t => this._isContractOp(t));
    let releaseBlockState = null;
    try {
      if (!opts._reorgInternal) releaseBlockState = await this._beginStateTransition();
      if (this.stateTrieLoadPromise) await this.stateTrieLoadPromise;
      trieBefore = this.stateTrie.snapshot();
      if (contractTxs.length) {
        if (!this.contracts) throw new Error('block contains contract txs but smart contracts are disabled');
        this.contractJournal ||= new ContractJournal(this.db, snapshots => this._restoreContractState(snapshots));
        this.contractJournal.begin(bloco.hash);
        journalHash = bloco.hash;
        for (const tx of txs) tx._effectiveGasPrice = effectiveGasPrice(tx, BigInt(bloco.base_fee));
        contractExec = await this._preExecuteContracts(bloco, txs, snap => this.contractJournal.capture(journalHash, snap));
        if (!contractExec.ok) throw new Error(contractExec.motivo);
      }
      let cumulativeGasUsed = 0;
      for (const tx of txs) {
        const intrinsic = estimateIntrinsicGas(tx);
        const executionGas = safeInt(tx._executionGasUsed, 0);
        const refund = safeInt(tx._gasRefund, 0);
        tx._gasUsed = this._isContractOp(tx) ? totalGasUsed(tx, executionGas, refund) : intrinsic;
        tx._receiptStatus = tx._executionStatus === 0 ? 0 : 1;
        const blockBaseFee = BigInt(bloco.base_fee);
        tx._effectiveGasPrice = effectiveGasPrice(tx, blockBaseFee);
        tx._actualFee = PocPlotV4.isRegistrationPayload(tx.data) ? 0n : BigInt(tx._gasUsed) * tx._effectiveGasPrice;
        if (tx._actualFee > safeBigInt(tx.fee, 0n)) throw new Error(`transaction fee cap below actual gas charge for ${tx.hash || hashTransaction(tx)}`);
        cumulativeGasUsed += tx._gasUsed;
        tx._cumulativeGasUsed = cumulativeGasUsed;
      }
      gasUsed = cumulativeGasUsed;
      if (gasUsed > GAS_PARAMS.blockGasLimit) throw new Error(`block gas ${gasUsed} exceeds max block gas limit ${GAS_PARAMS.blockGasLimit}`);
      if (!isLocalForge && safeInt(bloco.gas_used, -1) !== gasUsed) throw new Error('incorrect gas_used');
      if (isLocalForge) bloco.gas_used = gasUsed;
      totalTxFees = txs.reduce((s, t) => s + (t._actualFee || 0n), 0n);
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
          this.db.prepare('INSERT OR REPLACE INTO transactions (hash, from_addr, to_addr, value, fee, nonce, gas_limit, gas_price, signature, block_height, timestamp, block_hash, data, chain_id, fee_cap, receipt_status, gas_used, cumulative_gas_used, tx_type, max_fee_per_gas, max_priority_fee_per_gas) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)').run(txHash, tx.from_addr, tx.to_addr || '', String(tx.value || 0), String(tx._actualFee || 0n), safeInt(tx.nonce, 0), safeInt(tx.gas_limit, 21000), String(tx.gas_price || '1'), tx.signature || '', height, tx.timestamp || now, bloco.hash, String(tx.data || ''), String(tx.chain_id || bloco.chain_id || this.cfg.chainId || '0'), String(tx.fee || 0), tx._receiptStatus, tx._gasUsed, tx._cumulativeGasUsed, safeInt(tx.type, 0), String(tx.maxFeePerGas || ''), String(tx.maxPriorityFeePerGas || ''));
          if (tx.from_addr) {
            const cur = this.db.prepare('SELECT balance, nonce FROM users WHERE address = ?').get(tx.from_addr);
            if (cur) {
              const curBalance = safeBigInt(cur.balance, 0n);
              const revertedContractValue = this._isContractOp(tx) && tx._receiptStatus === 0;
              const chargedValue = revertedContractValue ? 0n : safeBigInt(tx.value, 0n);
              const newBalance = curBalance - chargedValue - (tx._actualFee || 0n);
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
          total_fees_units, gas_used, gas_limit, base_target, base_fee, contract_state_root, forger, miner_public_key, rewards_json, winner_proof, chain_id) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).run(
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
          String(bloco.chain_id),
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
          if (claimedStateRoot !== actualStateRoot) {
            log('warn', `state_root mismatch at #${height}`);
            throw new Error('state_root mismatch');
          }
        }
        {
          const actualCsr = computeContractStateRoot(this.db);
          if (actualCsr !== bloco.contract_state_root) {
            log('warn', `contract_state_root mismatch at #${height}: local=${actualCsr.slice(0, 16)} claimed=${bloco.contract_state_root.slice(0, 16)}`);
            throw new Error('contract_state_root mismatch');
          }
        }
        if (contractExec && contractExec.backup && contractExec.backup.length) this._recordContractStateChanges(height, bloco.hash, contractExec.backup);
        if (journalHash !== null) this.contractJournal.finish(journalHash);
        this.stateTrie.reloadFromDB(this.db);
        this._selectTip();
      })();
      if (height > 0) log('info', `Block #${height} accepted [${bloco.hash.slice(0, 10)}] from ${blockOrigin} (miner: ${(bloco.miner || '').slice(0, 10)}…)`);
      return { ok: true, motivo: 'block added', height, hash: bloco.hash };
    } catch (e) {
      if (journalHash !== null) {
        try { this.contractJournal.rollback(journalHash); }
        catch (recoveryError) {
          this._stateRecoveryRequired = true;
          e = new Error(`${e.message}; contract recovery failed: ${recoveryError.message}`);
        }
      }
      this.height = oldHeight;
      this.bestHash = oldBestHash;
      if (trieBefore) this.stateTrie.restore(trieBefore);
      if (this.contracts && this.contracts.clearVmCache) this.contracts.clearVmCache();
      const msg = e.message || 'database error';
      return { ok: false, motivo: msg };
    } finally {
      if (releaseBlockState) releaseBlockState();
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
      nonce: this.db.prepare('SELECT * FROM smart_contract_nonces WHERE lower(address) = lower(?)').get(address) || null,
      contract: this.db.prepare('SELECT * FROM smart_contracts WHERE lower(address) = lower(?)').get(address) || null,
    };
  }

  _restoreContractState(snaps) {
    for (const s of snaps) {
      this.db.prepare('DELETE FROM smart_contract_storage WHERE lower(contract_address) = lower(?)').run(s.address);
      this.db.prepare('DELETE FROM smart_contract_accounts WHERE lower(address) = lower(?)').run(s.address);
      this.db.prepare('DELETE FROM smart_contract_nonces WHERE lower(address) = lower(?)').run(s.address);
      this.db.prepare('DELETE FROM smart_contracts WHERE lower(address) = lower(?)').run(s.address);
      for (const row of s.storage) this.db.prepare('INSERT OR REPLACE INTO smart_contract_storage (contract_address, slot, value) VALUES (?,?,?)').run(row.contract_address, row.slot, row.value);
      if (s.account) this.db.prepare('INSERT OR REPLACE INTO smart_contract_accounts (address, balance) VALUES (?,?)').run(s.account.address, s.account.balance);
      if (s.nonce) this.db.prepare('INSERT OR REPLACE INTO smart_contract_nonces (address, nonce) VALUES (?,?)').run(s.nonce.address, s.nonce.nonce);
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
          INSERT INTO smart_contract_storage_history (contract_address, slot, prev_value, new_value, block_height, block_hash, created_at)
          VALUES (?,?,?,?,?,?,?)
          ON CONFLICT (contract_address, slot, block_height) DO UPDATE SET
            new_value = excluded.new_value, created_at = excluded.created_at
        `).run(addr, slot, prevValue, newValue, blockHeight, blockHash, now);
      }

      const prevAccount = snap.account ? (snap.account.balance == null ? '' : String(snap.account.balance)) : '';
      const nextAccountRow = this.db.prepare('SELECT * FROM smart_contract_accounts WHERE lower(address) = lower(?)').get(addr);
      const nextAccount = nextAccountRow ? (nextAccountRow.balance == null ? '' : String(nextAccountRow.balance)) : '';
      this.db.prepare(`
        INSERT INTO smart_contract_storage_history (contract_address, slot, prev_value, new_value, block_height, block_hash, created_at)
        VALUES (?,?,?,?,?,?,?)
        ON CONFLICT (contract_address, slot, block_height) DO UPDATE SET
          new_value = excluded.new_value, created_at = excluded.created_at
      `).run(addr, '__balance__', prevAccount, nextAccount, blockHeight, blockHash, now);

      const prevNonce = snap.nonce ? String(snap.nonce.nonce) : '';
      const nonceRow = this.db.prepare('SELECT nonce FROM smart_contract_nonces WHERE lower(address) = lower(?)').get(addr);
      this.db.prepare(`INSERT INTO smart_contract_storage_history
        (contract_address, slot, prev_value, new_value, block_height, block_hash, created_at)
        VALUES (?,?,?,?,?,?,?) ON CONFLICT (contract_address, slot, block_height)
        DO UPDATE SET new_value = excluded.new_value, created_at = excluded.created_at`)
        .run(addr, '__nonce__', prevNonce, nonceRow ? String(nonceRow.nonce) : '', blockHeight, blockHash, now);

      const prevContract = snap.contract ? JSON.stringify(snap.contract) : '';
      const nextContractRow = this.db.prepare('SELECT * FROM smart_contracts WHERE lower(address) = lower(?)').get(addr);
      const nextContract = nextContractRow ? JSON.stringify(nextContractRow) : '';
      this.db.prepare(`
        INSERT INTO smart_contract_storage_history (contract_address, slot, prev_value, new_value, block_height, block_hash, created_at)
        VALUES (?,?,?,?,?,?,?)
        ON CONFLICT (contract_address, slot, block_height) DO UPDATE SET
          new_value = excluded.new_value, created_at = excluded.created_at
      `).run(addr, '__contract__', prevContract, nextContract, blockHeight, blockHash, now);
    }
  }

  _restoreContractStateFromHistory(aboveHeight) {
    this.db.transaction(() => {
      const changes = this.db.prepare('SELECT * FROM smart_contract_storage_history WHERE block_height > ? ORDER BY block_height DESC').all(aboveHeight);
      const byContract = new Map();
      for (const c of changes) {
        if (!byContract.has(c.contract_address)) byContract.set(c.contract_address, []);
        byContract.get(c.contract_address).push(c);
      }
      for (const [addr, chgs] of byContract) {
        
        
        for (const c of chgs) {
          if (c.slot === '__contract__') {
            if (c.prev_value === null || c.prev_value === '') {
              this.db.prepare('DELETE FROM smart_contracts WHERE lower(address) = lower(?)').run(addr);
            } else {
              const prev = JSON.parse(c.prev_value);
              if (!prev || String(prev.address).toLowerCase() !== String(addr).toLowerCase() || typeof prev.code !== 'string') {
                throw new Error('corrupt contract undo history');
              }
              this.db.prepare('INSERT OR REPLACE INTO smart_contracts (address, creator, code, created_at, updated_at) VALUES (?,?,?,?,?)').run(prev.address, prev.creator, prev.code, prev.created_at, prev.updated_at);
            }
          } else if (c.slot === '__nonce__') {
            if (c.prev_value === null || c.prev_value === '') {
              this.db.prepare('DELETE FROM smart_contract_nonces WHERE lower(address) = lower(?)').run(addr);
            } else {
              this.db.prepare('INSERT OR REPLACE INTO smart_contract_nonces (address, nonce) VALUES (?,?)').run(addr, c.prev_value);
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
    })();
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
            const revertedContractValue = this._isContractOp(tx) && tx._receiptStatus === 0;
            const chargedValue = revertedContractValue ? 0n : safeBigInt(tx.value, 0n);
            const newBalance = safeBigInt(cur.balance, 0n) - chargedValue - (tx._actualFee || safeBigInt(tx.fee, 0n));
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

  async reorganize(targetOrHash, forceSync = false, allowVotedTie = false, candidateBlocks = null, alreadySerialized = false) {
    if (this._stateRecoveryRequired) return { ok: false, motivo: 'contract state recovery required; restart node' };
    let releaseMutation = null;
    let releaseStateTransition = null;
    if (!alreadySerialized) {
      const previousMutation = this._blockMutationTail;
      this._blockMutationTail = new Promise((resolve) => { releaseMutation = resolve; });
      await previousMutation;
    }
    try {
      const target = typeof targetOrHash === 'string' ? this.getBlockByHash(targetOrHash) : targetOrHash;
      if (!target || !target.hash) return { ok: false, motivo: 'target block not found' };
      const oldTip = this.getBlockByHash(this.bestHash) || this.getBlock(this.height);
      if (!oldTip) return { ok: false, motivo: 'old tip not found' };
      if (target.hash === oldTip.hash) return { ok: true, motivo: 'already at tip', height: this.height, hash: this.bestHash };

      
      
      
      const activeByHash = new Map();
      let ancestor = oldTip;
      while (ancestor) {
        activeByHash.set(ancestor.hash, ancestor);
        if (ancestor.height === 0) break;
        ancestor = this.getBlockByHash(ancestor.parent_hash);
      }

      let branch;
      if (Array.isArray(candidateBlocks)) {
        branch = candidateBlocks.map((block) => ({ ...block }));
        if (!branch.length || branch[branch.length - 1].hash !== target.hash) {
          if (branch.some((block) => block.hash === target.hash)) {
            branch = branch.slice(0, branch.findIndex((block) => block.hash === target.hash) + 1);
          } else {
            branch.push({ ...target });
          }
        }
      } else {
        branch = [];
        let current = target;
        while (current && !activeByHash.has(current.hash)) {
          branch.unshift(current);
          current = this.getBlockByHash(current.parent_hash);
        }
        if (!current) return { ok: false, motivo: 'candidate branch has no common ancestor with active chain' };
      }

      while (branch.length && activeByHash.has(branch[0].hash)) branch.shift();
      if (!branch.length) return { ok: true, motivo: 'candidate is already on active chain', height: this.height, hash: this.bestHash };
      const forkPoint = activeByHash.get(branch[0].parent_hash);
      if (!forkPoint) return { ok: false, motivo: 'candidate branch does not attach to the active chain' };
      for (let i = 0; i < branch.length; i++) {
        const block = branch[i];
        const expectedParent = i === 0 ? forkPoint.hash : branch[i - 1].hash;
        const expectedHeight = forkPoint.height + i + 1;
        if (block.parent_hash !== expectedParent || block.height !== expectedHeight || !block.hash) {
          return { ok: false, motivo: `candidate branch is discontinuous at height ${expectedHeight}` };
        }
      }
      const candidateTip = branch[branch.length - 1];
      if (candidateTip.hash !== target.hash) return { ok: false, motivo: 'candidate tip does not match requested target' };

      const depth = oldTip.height - forkPoint.height;
      if (!forceSync && depth > FINALIZATION_DEPTH) {
        return { ok: false, motivo: `reorg exceeds finalization depth (${depth} > ${FINALIZATION_DEPTH})` };
      }

      releaseStateTransition = await this._beginStateTransition();
      if (this.stateTrieLoadPromise) await this.stateTrieLoadPromise;
      const oldHeight = this.height;
      const oldBestHash = this.bestHash;
      const trieSnapshot = this.stateTrie.snapshot();
      let transactionOpen = false;
      try {
        
        
        
        this.db.exec('BEGIN IMMEDIATE');
        transactionOpen = true;

        this._restoreContractStateFromHistory(forkPoint.height);
        const retainedHashes = new Set();
        let retained = forkPoint;
        while (retained) {
          retainedHashes.add(retained.hash);
          if (retained.height === 0) break;
          retained = this.getBlockByHash(retained.parent_hash);
        }

        const rows = this.db.prepare('SELECT hash FROM blocks').all();
        const orphanAddresses = new Set();
        const orphanChallenges = [];
        const orphanBlockMeta = this.db.prepare('SELECT height, challenge_id FROM blocks WHERE hash = ?');
        const orphanRewards = this.db.prepare('SELECT miner FROM block_rewards WHERE block_hash = ?');
        const orphanTransactions = this.db.prepare('SELECT from_addr, to_addr FROM transactions WHERE block_hash = ?');
        const orphanPayouts = this.db.prepare('SELECT to_addr FROM block_payouts WHERE block_hash = ?');
        const deleteBlock = this.db.prepare('DELETE FROM blocks WHERE hash = ?');
        for (const row of rows) {
          if (retainedHashes.has(row.hash)) continue;
          const meta = orphanBlockMeta.get(row.hash);
          if (meta && meta.challenge_id) orphanChallenges.push(meta);
          for (const reward of orphanRewards.all(row.hash)) if (reward.miner) orphanAddresses.add(String(reward.miner).toLowerCase());
          for (const tx of orphanTransactions.all(row.hash)) {
            if (tx.from_addr) orphanAddresses.add(String(tx.from_addr).toLowerCase());
            if (tx.to_addr) orphanAddresses.add(String(tx.to_addr).toLowerCase());
          }
          for (const payout of orphanPayouts.all(row.hash)) if (payout.to_addr) orphanAddresses.add(String(payout.to_addr).toLowerCase());
          this.db.prepare('DELETE FROM contract_logs WHERE block_hash = ?').run(row.hash);
          this.db.prepare('DELETE FROM block_payouts WHERE block_hash = ?').run(row.hash);
          this.db.prepare('DELETE FROM block_rewards WHERE block_hash = ?').run(row.hash);
          this.db.prepare('DELETE FROM transactions WHERE block_hash = ?').run(row.hash);
          this.db.prepare('DELETE FROM plot_registration_events WHERE block_hash = ?').run(row.hash);
          deleteBlock.run(row.hash);
        }
        for (const orphan of orphanChallenges) {
          this.db.prepare('UPDATE mining_challenges SET forged_block_height = NULL WHERE challenge_id = ? AND forged_block_height = ?')
            .run(orphan.challenge_id, orphan.height);
        }

        this._selectTip();
        if (this.bestHash !== forkPoint.hash) throw new Error('failed to restore common ancestor as active tip');
        this._recomputeBalances();
        const hasAncestorActivity = this.db.prepare(`
          SELECT 1 FROM transactions WHERE lower(from_addr) = ? OR lower(to_addr) = ?
          UNION ALL SELECT 1 FROM block_rewards WHERE lower(miner) = ?
          UNION ALL SELECT 1 FROM block_payouts WHERE lower(to_addr) = ?
          LIMIT 1
        `);
        for (const address of orphanAddresses) {
          if (!hasAncestorActivity.get(address, address, address, address)) {
            this.db.prepare('DELETE FROM users WHERE lower(address) = ?').run(address);
          }
        }
        if (!/^[0-9a-f]{64}$/i.test(String(forkPoint.state_root || ''))
          || computeStateRoot(this.db) !== forkPoint.state_root) {
          throw new Error(`state root mismatch after rollback to common ancestor #${forkPoint.height}`);
        }
        if (!/^[0-9a-f]{64}$/i.test(String(forkPoint.contract_state_root || ''))
          || computeContractStateRoot(this.db) !== forkPoint.contract_state_root) {
          throw new Error(`contract state root mismatch after rollback to common ancestor #${forkPoint.height}`);
        }
        await this.stateTrie.loadFromDB(this.db);

        for (const block of branch) {
          const result = await this.addBlock(block, { _reorgInternal: true, allowVotedTie });
          if (!result.ok) throw new Error(`candidate block #${block.height} rejected: ${result.motivo}`);
        }

        const appliedTip = this.getBlockByHash(candidateTip.hash);
        if (!appliedTip) throw new Error('candidate tip disappeared during reorganization');
        const equalWorkAllowed = allowVotedTie
          && safeBigInt(appliedTip.chain_work, 0n) === safeBigInt(oldTip.chain_work, 0n);
        if (!isBetterChainCandidate(appliedTip, oldTip) && !equalWorkAllowed) {
          throw new Error('candidate chain does not outrank the previous active tip');
        }
        if (this.bestHash !== candidateTip.hash) throw new Error('candidate tip did not become the active tip');

        this.db.exec('COMMIT');
        transactionOpen = false;
        this._selectTip();
        log('info', `Reorg to #${this.height} ${this.bestHash.slice(0, 10)} (common ancestor #${forkPoint.height}, depth ${depth})`);
        return { ok: true, motivo: 'reorganized', height: this.height, hash: this.bestHash };
      } catch (e) {
        if (transactionOpen) {
          try { this.db.exec('ROLLBACK'); } catch {}
        }
        this.height = oldHeight;
        this.bestHash = oldBestHash;
        this.stateTrie.restore(trieSnapshot);
        if (this.contracts && this.contracts.clearVmCache) this.contracts.clearVmCache();
        return { ok: false, motivo: e.message || 'reorganization failed' };
      }
    } finally {
      if (releaseStateTransition) releaseStateTransition();
      if (releaseMutation) releaseMutation();
    }
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

  
  
  
  
  
  
  
  
  
  
  _recomputeBalances() {
    const hashes = [];
    let h = this.db.prepare('SELECT hash, parent_hash, height FROM blocks WHERE hash = ?').get(this.bestHash);
    while (h) { hashes.push(h); if (h.height === 0) break; h = this.db.prepare('SELECT hash, parent_hash, height FROM blocks WHERE hash = ?').get(h.parent_hash); }
    hashes.reverse(); 
    const state = new Map(); 
    const get = (a) => state.get(a);
    for (const b of hashes) {
      
      for (const r of this.db.prepare('SELECT miner, reward_cc FROM block_rewards WHERE block_height = ? AND block_hash = ?').all(b.height, b.hash)) {
        const reward = BigInt(r.reward_cc || '0');
        const m = r.miner ? String(r.miner) : '';
        if (reward <= 0n || !m || m === 'genesis') continue;
        const s = get(m);
        if (s) s.balance += reward;
        else state.set(m, { balance: reward, nonce: 0 });
      }
      
      for (const tx of this.db.prepare('SELECT from_addr, to_addr, value, fee, nonce, data, receipt_status FROM transactions WHERE block_hash = ? ORDER BY rowid').all(b.hash)) {
        const from = tx.from_addr ? String(tx.from_addr) : '';
        const to = tx.to_addr ? String(tx.to_addr) : '';
        if (from) {
          const s = get(from);
          if (s) {
            const revertedContractValue = this._isContractOp(tx) && tx.receipt_status === 0;
            s.balance -= (revertedContractValue ? 0n : BigInt(tx.value || 0)) + BigInt(tx.fee || 0);
            s.nonce = Math.max(s.nonce + 1, safeInt(tx.nonce, 0) + 1);
          }
        }
        if (to && !this._isContractCall(tx)) {
          const s = get(to);
          if (s) s.balance += BigInt(tx.value || 0);
          else state.set(to, { balance: BigInt(tx.value || 0), nonce: 0 });
        }
      }
      
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

  
  
  
  
  
  
  verifyStateIntegrity() {
    if (this._stateTransitionPending || this._stateRecoveryRequired || this.db.inTransaction || this.db.prepare('SELECT 1 FROM pending_contract_blocks LIMIT 1').get()) {
      return { ok: false, repaired: false, motivo: 'state transition pending' };
    }
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
    
    return this.addBlock(blk);
  }

  _selectTip() {
    const row = this.db.prepare('SELECT height, hash FROM blocks ORDER BY LENGTH(chain_work) DESC, chain_work DESC, hash ASC LIMIT 1').get();
    if (row) { this.height = row.height; this.bestHash = row.hash; }
  }

  _purgeOrphanedBlocks() {
    if (this._stateTransitionPending || this._stateRecoveryRequired || this.db.inTransaction || this.db.prepare('SELECT 1 FROM pending_contract_blocks LIMIT 1').get()) return 0;
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
    if (this._stateTransitionPending || this._stateRecoveryRequired || this.db.inTransaction || this.db.prepare('SELECT 1 FROM pending_contract_blocks LIMIT 1').get()) return 0;
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

  _ancestorAt(parentHash, height) {
    if (!parentHash || height < 0) return null;
    return this.db.prepare(`
      WITH RECURSIVE ancestry(hash, parent_hash, height, depth) AS (
        SELECT hash, parent_hash, height, 0 FROM blocks WHERE hash = ?
        UNION ALL
        SELECT b.hash, b.parent_hash, b.height, a.depth + 1
        FROM blocks b JOIN ancestry a ON b.hash = a.parent_hash
        WHERE a.height > 0 AND a.depth < 1000000
      )
      SELECT b.* FROM blocks b JOIN ancestry a ON a.hash = b.hash WHERE a.height = ? LIMIT 1
    `).get(parentHash, height) || null;
  }

  get height() {
    return this.chain ? this.chain.height : 0;
  }

  _targetForHeight(height, parentHash) {
    if (height === 0) {
      try { return BigInt(this.cfg.initialTarget); } catch { return BigInt('0x00FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF'); }
    }
    parentHash ||= this.chain?.bestHash;
    const interval = this.cfg.difficultyAdjustBlocks || 8192;
    const expected = this.cfg.expectedTimePerBlock || 60;
    const latest = this._ancestorAt(parentHash, height - 1);
    if (!latest) throw new Error(`missing candidate ancestor at height ${height - 1}`);
    if (height % interval !== 0) {
      const prev = this.db.prepare('SELECT target FROM blocks WHERE hash = ?').get(latest.hash);
      if (prev) try { return BigInt(prev.target); } catch {}
      try { return BigInt(this.cfg.initialTarget); } catch { return 0n; }
    }
    const prevInterval = this._ancestorAt(parentHash, Math.max(0, height - interval));
    if (prevInterval && latest) {
      const actual = latest.timestamp - prevInterval.timestamp;
      
      const expectedSpan = expected * interval;
      const target = BigInt(latest.target || this.cfg.initialTarget);
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

  
  
  
  
  _baseTargetIdealFor(height, parentHash) {
    const expectedTime = Math.max(1, this.cfg.expectedTimePerBlock || 60);
    let candidates = 0n;
    parentHash ||= this.chain?.bestHash;
    const parent = this._ancestorAt(parentHash, height - 1);
    if (parent) {
      for (const plot of this.getMaturePlotRegistrations(parent.hash, height)) {
        candidates += BigInt(BigInt(plot.capacity_bytes) / BigInt(PocPlotV4.NONCE_BYTES));
      }
    }
    if (candidates < 1n) return null;
    return (BigInt(2) ** BigInt(64)) / (candidates * BigInt(expectedTime));
  }

  
  
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

  _baseTargetForHeight(height, parentHash) {
    const expectedTime = Math.max(1, this.cfg.expectedTimePerBlock || 60);
    if (height === 0) return String(this.cfg.genesisBaseTarget ?? this._defaultBaseTarget());
    parentHash ||= this.chain?.bestHash;
    const prev = this._ancestorAt(parentHash, height - 1);
    if (!prev) return this._defaultBaseTarget();
    const parentRow = this.db.prepare('SELECT base_target FROM blocks WHERE hash = ?').get(prev.hash);
    const prevTarget = BigInt((parentRow && parentRow.base_target) || this._defaultBaseTarget());
    const ideal = this._baseTargetIdealFor(height, parentHash);

    
    
    
    
    const window = Math.max(8, safeInt(this.cfg.baseTargetWindow, 128));

    
    
    
    
    
    
    if (height < window) {
      const seed = ideal && ideal > 0n ? ideal : prevTarget;
      return String(this._clampBaseTarget(seed, ideal));
    }

    if (height % window !== 0) return String(prevTarget);

    const oldest = this._ancestorAt(parentHash, Math.max(0, height - window));
    if (!oldest) return String(prevTarget);
    const actualDuration = prev.timestamp - oldest.timestamp;
    if (actualDuration <= 0) return String(prevTarget);

    
    
    
    
    const meanSeconds = actualDuration / window;
    const maxMove = Math.min(0.9, Math.max(0.01, Number(this.cfg.baseTargetMaxMove ?? 0.5)));
    const ratio = meanSeconds / expectedTime;
    const factor = Math.min(1 + maxMove, Math.max(1 - maxMove, ratio));
    const t = (prevTarget * BigInt(Math.round(factor * 1000000))) / 1000000n;

    return String(this._clampBaseTarget(t, ideal));
  }

  _baseFeeForHeight(height, parentHash) {
    if (height === 0) return GAS_PARAMS.initialBaseFee;
    parentHash ||= this.chain?.bestHash;
    const parentAncestor = this._ancestorAt(parentHash, height - 1);
    const parent = parentAncestor && this.db.prepare('SELECT base_fee, gas_used FROM blocks WHERE hash = ?').get(parentAncestor.hash);
    if (!parent) return GAS_PARAMS.initialBaseFee;
    const parentBaseFee = parent.base_fee != null && parent.base_fee !== '' ? BigInt(parent.base_fee) : BigInt(GAS_PARAMS.initialBaseFee);
    return String(nextBaseFee(
      parentBaseFee,
      parent.gas_used || 0,
      GAS_PARAMS.targetBlockGasLimit,
      this.cfg.minGasPrice
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
      const sender = tx.from_addr;
      if (!sender) return [false, 'invalid tx sender'];
      if (tx.chain_id == null || String(tx.chain_id) !== String(this.cfg.chainId || '')) return [false, 'wrong or missing chain_id'];
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
    if (tx.chain_id == null || String(tx.chain_id) !== String(this.cfg.chainId || '')) return { ok: false, motivo: 'wrong or missing chain_id' };
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
      if (maximumGasPrice(tx, 0n) < currentBaseFee) return { ok: false, motivo: `gas price cap below base fee (${currentBaseFee})` };
      const minFee = minimumFee(tx, currentBaseFee);
      if (safeBigInt(tx.fee, 0n) < minFee) return { ok: false, motivo: `fee cap too low (need at least ${minFee} = gas_limit * gas_price)` };
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
        } catch {   }
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

  async _preExecuteContracts(bloco, txs, beforeWrite) {
    const backup = [];
    const captured = new Set();
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
        const transactionBackup = new Map();
        const capture = (address) => {
          const addr = String(address).toLowerCase();
          if (!transactionBackup.has(addr)) transactionBackup.set(addr, this._snapshotContractState(addr));
          if (!captured.has(addr)) {
            captured.add(addr);
            backup.push(transactionBackup.get(addr));
            if (beforeWrite) beforeWrite(transactionBackup.get(addr));
          }
        };
        const txHash = tx.hash || hashTransaction(tx);
        if (this._isCreateTx(tx)) {
          const nonce = safeInt(tx.nonce, 0);
          const address = this.chain.contracts.deriveContractAddress(tx.from_addr, nonce);
          capture(address);
          try {
            const intrinsic = estimateIntrinsicGas(tx);
            const executionLimit = Math.max(0, safeInt(tx.gas_limit, intrinsic) - intrinsic);
            const res = await this.chain.contracts.CreateSmartContract(
              tx.data,
              blkCtx,
              tx.from_addr,
              nonce,
              safeBigInt(tx.value, 0n).toString(),
              executionLimit,
              tx._effectiveGasPrice || tx.gas_price,
              true,
              capture
            );
            tx._executionGasUsed = safeInt(res && res.gasUsed, 0);
            tx._gasRefund = safeInt(res && res.gasRefund, 0);
            tx._executionStatus = 1;
            tx._ccApplied = true;
            tx._ccContractAddress = res && res.contractAddress ? String(res.contractAddress).toLowerCase() : address;
            if (res && Array.isArray(res.payouts)) payouts.push(...res.payouts);
            appendLogs(tx, res);
          } catch (e) {
            this._restoreContractState([...transactionBackup.values()]);
            tx._executionGasUsed = e.gasUsed == null ? Math.max(0, safeInt(tx.gas_limit, 0) - estimateIntrinsicGas(tx)) : safeInt(e.gasUsed, 0);
            tx._gasRefund = 0;
            tx._executionStatus = 0;
            tx._ccError = e.message || String(e);
            tx._ccApplied = false;
          }
        } else if (this._isContractCall(tx)) {
          const to = tx.to_addr;
          capture(to);
          try {
            const intrinsic = estimateIntrinsicGas(tx);
            const executionLimit = Math.max(0, safeInt(tx.gas_limit, intrinsic) - intrinsic);
            const res = await this.chain.contracts.runSmartContract(to, tx.from_addr, tx.data || '0x', safeBigInt(tx.value, 0n).toString(), executionLimit, tx._effectiveGasPrice || tx.gas_price, blkCtx, true, capture);
            tx._executionGasUsed = safeInt(res && res.gasUsed, 0);
            tx._gasRefund = safeInt(res && res.gasRefund, 0);
            tx._executionStatus = 1;
            tx._ccApplied = true;
            log('info', `[SMART CONTRACTS] Block contract call OK: to=${to} from=${tx.from_addr} gasUsed=${res ? res.gasUsed : '?'} data=${(tx.data || '0x').slice(0, 10)}`);
            if (res && Array.isArray(res.payouts)) payouts.push(...res.payouts);
            appendLogs(tx, res);
          } catch (e) {
            this._restoreContractState([...transactionBackup.values()]);
            tx._executionGasUsed = e.gasUsed == null ? Math.max(0, safeInt(tx.gas_limit, 0) - estimateIntrinsicGas(tx)) : safeInt(e.gasUsed, 0);
            tx._gasRefund = 0;
            tx._executionStatus = 0;
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
