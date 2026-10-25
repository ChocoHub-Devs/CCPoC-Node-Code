const crypto = require('crypto');
const { ZERO_HASH, sha256hex, sha256buf, safeInt, safeBigInt, hashBlock, hashTransaction, merkleRoot, computeStateRootAfterTxs, calculateMiningReward, computeDeadline, verifySignature, pubkeyToAddress, canonicalTxMessage, proofMessage, recoverTransactionSender } = require('../crypto-utils/crypto');
const { log } = require('../../config/config');
const PocPlotV4 = require('../consensus/poc-plot-v4');
const { estimateIntrinsicGas, GAS_PARAMS } = require('../consensus/gas');


class ChallengeManager {
  constructor(db, chain, cfg) {
    this.db = db;
    this.cfg = cfg || {};
    this.chain = chain;

    this._forging = new Set();
  }

  getOrCreate() {
    const now = Math.floor(Date.now() / 1000);
    const tip = this.chain.getBlock(this.chain.height);
    const genSig = (tip && tip.generation_signature) || ZERO_HASH;
    const tipHash = tip ? tip.hash : ZERO_HASH;
    const challengeId = sha256hex(`${genSig}:${tipHash}`);
    const targetIdx = PocPlotV4.challengeTargetSlot(challengeId);
    const challengeGrace = Math.max(15, Math.floor((this.cfg.expectedTimePerBlock || 60) / 2));
    const challengeExpiredGraceSec = Math.max(this.cfg.challengeExpiredGraceSec || 300, (this.cfg.expectedTimePerBlock || 60) * 2);
    const baseTarget = this.chain._baseTargetForHeight(this.chain.height + 1, tip && tip.hash);
    const withBt = (r) => (r ? {
      ...r,
      target_scoop_index: targetIdx,
      base_target: (r && r.base_target) || String(baseTarget),
    } : r);

    const pendingWinner = this.db.prepare(`SELECT * FROM mining_challenges WHERE challenge_id = ? AND forged_block_height IS NULL
      AND winner_miner IS NOT NULL AND winner_deadline IS NOT NULL AND finalized_at IS NOT NULL
      AND (finalized_at + winner_deadline) > ?`).get(challengeId, now);
    if (pendingWinner) return withBt(pendingWinner);

    const existing = this.db.prepare('SELECT * FROM mining_challenges WHERE challenge_id = ? AND forged_block_height IS NULL AND expires_at > ?').get(challengeId, now);
    if (existing) return withBt(existing);

    const expired = this.db.prepare('SELECT * FROM mining_challenges WHERE challenge_id = ? AND forged_block_height IS NULL AND expires_at <= ? AND challenge_id IN (SELECT DISTINCT challenge_id FROM challenge_submissions)').get(challengeId, now);
    if (expired && (now - expired.expires_at) <= challengeExpiredGraceSec) {
      return withBt(expired);
    }

    const minTtl = Math.max(this.cfg.challengeTtlSec || 300, this.cfg.challengeMinTtlSec || (this.cfg.expectedTimePerBlock || 60) * 5);
    const ttl = Math.min(Math.max(minTtl, 60), 86400);
    this.db.prepare('DELETE FROM mining_challenges WHERE forged_block_height IS NULL AND (challenge_id != ? OR expires_at + ? < ?) AND challenge_id NOT IN (SELECT DISTINCT challenge_id FROM challenge_submissions)').run(challengeId, challengeGrace, now);
    this.db.prepare('DELETE FROM mining_challenges WHERE challenge_id = ? AND (forged_block_height IS NOT NULL OR expires_at < ?)').run(challengeId, now - challengeGrace);
    const nonce = crypto.randomBytes(4).toString('hex');
    try {
      this.db.prepare('INSERT INTO mining_challenges (challenge_id, challenge_seed, nonce, target_scoop_index, created_at, expires_at, block_height, base_target) VALUES (?,?,?,?,?,?,?,?)').run(challengeId, genSig, nonce, targetIdx, now, now + ttl, this.chain.height, String(baseTarget));
      log('info', `New challenge ${challengeId.slice(0, 12)}  scoop=${targetIdx}  expires in ${ttl}s`);
    } catch (e) {
      log('error', `[CHALLENGE] Failed to create challenge ${challengeId.slice(0, 12)}: ${e.message}`);
      const r = this.db.prepare('SELECT * FROM mining_challenges WHERE challenge_id = ?').get(challengeId);
      return r || null;
    }
    const row = this.db.prepare('SELECT * FROM mining_challenges WHERE challenge_id = ?').get(challengeId);
    return { ...row, base_target: (row && row.base_target) || String(baseTarget) };
  }


  submitProof(chain, challengeId, miner, plotId, deadline, proofPacket = null) {
    const now = Math.floor(Date.now() / 1000);
    const submitGrace = Math.max(15, Math.floor((this.cfg.expectedTimePerBlock || 60) / 2));
    const ch = this.db.prepare('SELECT * FROM mining_challenges WHERE challenge_id = ? AND forged_block_height IS NULL AND expires_at + ? >= ?').get(challengeId, submitGrace, now);
    if (!ch) return { ok: false, motivo: 'challenge not found or expired' };
    if (ch.forged_block_height != null) return { ok: false, motivo: 'challenge already finalized' };
    const maxDl = chain.computeMaxDeadline();
    deadline = safeInt(deadline, -1);
    if (deadline < 0 || deadline > maxDl) return { ok: false, motivo: `invalid deadline (must be 0–${maxDl}s)` };
    const challengeHeight = safeInt(ch.block_height, this.chain.height);
    const parent = this.chain.getBlock(challengeHeight);
    const commitment = parent && this.chain.getPlotRegistration(plotId, miner, parent.hash, Math.max(0, challengeHeight - 1));
    if (!commitment) return { ok: false, motivo: 'plot has no mature consensus registration for this challenge' };
    const sizeGb = Number(BigInt(commitment.capacity_bytes)) / (1024 ** 3);
    const committedRoot = commitment.merkle_root;
    if (!proofPacket || !proofPacket.scoop_data) return { ok: false, motivo: 'proof_packet with scoop_data required for PoC verification' };
    if (!committedRoot) return { ok: false, motivo: 'plot has no merkle_root commitment' };
    const genSig = ch.challenge_seed || ZERO_HASH;
    const networkBaseTarget = ch.base_target || chain._baseTargetForHeight(ch.block_height || chain.height);
    const computedDeadline = computeDeadline(proofPacket.scoop_data, genSig, networkBaseTarget);
    if (computedDeadline > maxDl) return { ok: false, motivo: `computed deadline exceeds network limit (${computedDeadline} > ${maxDl}s)` };
    if (computedDeadline !== deadline) return { ok: false, motivo: `PoC verification failed: computed ${computedDeadline}s, submitted ${deadline}s` };
    const expectedDigest = sha256hex(Buffer.concat([Buffer.from(proofPacket.scoop_data, 'hex'), Buffer.from(String(computedDeadline))]));
    if (proofPacket.proof_digest && proofPacket.proof_digest !== expectedDigest) return { ok: false, motivo: 'proof digest mismatch' };
    const totalScoops = safeInt(proofPacket.total_scoops, 0);
    const scoopIndex = safeInt(proofPacket.scoop_index, -1);
    if (scoopIndex < 0 || scoopIndex >= totalScoops) return { ok: false, motivo: `invalid scoop_index ${scoopIndex} for ${totalScoops} scoops` };
    const merkleProof = proofPacket.merkle_proof || [];
    const checked = this.chain.verifyPocV4CapacityProof(
      { ...proofPacket, total_scoops: totalScoops }, challengeId, miner, plotId,
      challengeHeight + 1, parent.hash,
    );
    if (!checked.ok) return { ok: false, motivo: checked.motivo };

    const proofSig = (proofPacket && proofPacket.proof_signature) || '';
    if (!proofSig) return { ok: false, motivo: 'proof_signature required' };
    const proofPublicKey = String(proofPacket.public_key || '');
    if (!proofPublicKey) return { ok: false, motivo: 'miner public key is required' };
    try {
      if (pubkeyToAddress(proofPublicKey).toLowerCase() !== String(miner).toLowerCase()) return { ok: false, motivo: 'proof public key does not match miner address' };
    } catch { return { ok: false, motivo: 'invalid proof public key' }; }
    const msg = proofMessage(challengeId, miner, deadline, plotId);
    if (!verifySignature(msg, proofSig, proofPublicKey)) {
      return { ok: false, motivo: 'proof signature does not match miner address' };
    }

    const insertRes = this.db.prepare('INSERT OR IGNORE INTO challenge_submissions (challenge_id, miner, plot_id, size_gb, deadline, proof_digest, proof_signature, submitted_at) VALUES (?,?,?,?,?,?,?,?)').run(challengeId, miner, plotId, sizeGb, deadline, expectedDigest, proofSig, now);
    if (insertRes.changes > 0 && /^[0-9a-fA-F]{64}$/.test(proofPacket.scoop_data)) {
      this.db.prepare('UPDATE challenge_submissions SET scoop_data = ?, scoop_index = ?, total_scoops = ?, merkle_proof = ?, merkle_root = ?, capacity_samples = ?, public_key = ? WHERE challenge_id = ? AND miner = ? AND plot_id = ? AND deadline = ?')
        .run(String(proofPacket.scoop_data), safeInt(proofPacket.scoop_index, 0), totalScoops, JSON.stringify(merkleProof || []), String(committedRoot || ''), JSON.stringify(proofPacket.capacity_samples || []), proofPublicKey, challengeId, miner, plotId, deadline);
    }
    const updated = this.db.prepare('UPDATE mining_challenges SET winner_miner = ?, winner_deadline = ?, winner_plot_id = ?, finalized_at = ? WHERE challenge_id = ? AND (winner_deadline IS NULL OR ? < winner_deadline)').run(miner, deadline, plotId, now, challengeId, deadline);
    const subCount = this.db.prepare('SELECT COUNT(*) as cnt FROM challenge_submissions WHERE challenge_id = ?').get(challengeId).cnt;
    const result = { ok: true, submitted: true, challenge_id: challengeId, total_submissions: subCount };
    log('info', `PoC proof from ${(miner || '').slice(0, 10)}… d=${deadline}s plot=${(plotId || '').slice(0, 10)}… for challenge ${challengeId.slice(0, 12)}`);
    if (updated.changes > 0) {
      log('info', `Best deadline updated! d=${deadline}s for challenge ${challengeId.slice(0, 12)}`);
      const waitSec = deadline;
      log('info', `Waiting ${waitSec}s for deadline to elapse on challenge ${challengeId.slice(0, 12)}`);
    }
    return result;
  }

  _selectValidMempoolTxs(chain, maxCount) {
    const candidates = chain.getMempoolForBlock(maxCount);
    candidates.sort((a, b) => {
      const sa = String(a.from_addr || '').toLowerCase();
      const sb = String(b.from_addr || '').toLowerCase();
      if (sa !== sb) return sa < sb ? -1 : 1;
      return safeInt(a.nonce, 0) - safeInt(b.nonce, 0);
    });
    log('info', `[TX] mempool candidates: ${candidates.length}`);
    const good = [];
    const projectedNonce = {};
    const projectedBalance = {};
    for (const tx of candidates) {
      const sender = tx.from_addr;
      let reason = null;
      if (!sender) reason = 'invalid tx sender';
      if (!reason) {
        if (!(sender in projectedNonce)) {
          const user = this.db.prepare('SELECT nonce, balance FROM users WHERE address = ?').get(sender);
          projectedNonce[sender] = user ? safeInt(user.nonce, 0) : 0;
          projectedBalance[sender] = user ? safeBigInt(user.balance, 0n) : 0n;
        }
        if (safeInt(tx.nonce, -1) < 0 || safeInt(tx.value, -1) < 0) reason = `invalid tx values for ${sender}`;
        else if (safeInt(tx.nonce, 0) < projectedNonce[sender]) reason = `stale nonce (tx=${tx.nonce}, expected>=${projectedNonce[sender]})`;
        else if (projectedBalance[sender] < safeBigInt(tx.value, 0n) + safeBigInt(tx.fee, 0n)) reason = `insufficient balance for ${sender}`;
        else {
          const sig = tx.signature || '';
          if (!sig) reason = `missing signature from ${sender}`;
          else {
            const recovered = recoverTransactionSender(tx);
            if (!recovered) reason = `invalid tx signature from ${sender}`;
            else if (recovered !== sender.toLowerCase()) reason = `recovered sender ${recovered} does not match ${sender}`;
          }
        }
      }
      if (reason) {
        log('warn', `[TX] Dropping mempool tx ${(tx.hash || '').slice(0, 12)}: ${reason}`);
        this.db.prepare('DELETE FROM mempool WHERE hash = ?').run(tx.hash || hashTransaction(tx));
        continue;
      }
      log('info', `[TX] Accepting tx ${(tx.hash || '').slice(0, 12)} from ${sender.slice(0, 14)}... nonce=${tx.nonce}`);
      projectedBalance[sender] -= safeBigInt(tx.value, 0n) + safeBigInt(tx.fee, 0n);
      projectedNonce[sender] = Math.max(projectedNonce[sender] + 1, safeInt(tx.nonce, 0) + 1);
      good.push(tx);
    }
    // Enforce the per-block v4 plot-registration caps so the forged block stays
    // valid; surplus registrations are left in the mempool for a later block.
    const maxReg = Math.max(1, safeInt(this.cfg.maxPlotRegistrationsPerBlock, 4));
    const maxRegMiner = Math.max(1, safeInt(this.cfg.maxPlotRegistrationsPerMinerPerBlock, 1));
    const regPerMiner = new Map();
    let regTotal = 0;
    const capped = [];
    for (const tx of good) {
      if (PocPlotV4.isRegistrationPayload(tx && tx.data)) {
        const sender = String(tx.from_addr || '').toLowerCase();
        const used = regPerMiner.get(sender) || 0;
        if (regTotal >= maxReg || used >= maxRegMiner) {
          log('info', `[TX] deferring plot registration ${(tx.hash || '').slice(0, 12)} to a later block (registration cap)`);
          continue;
        }
        regPerMiner.set(sender, used + 1);
        regTotal++;
      }
      capped.push(tx);
    }
    log('info', `[TX] selected ${capped.length} txs for block`);
    return capped;
  }

  async _forgeBlock(chain, challenge, miner, deadline, rewardDistribution = [], plotId = '', proofDigest = '', winnerProof = null) {
    try {
      miner = typeof miner === 'string' ? miner.toLowerCase() : miner;
      const newHeight = chain.height + 1;
      let now = Math.floor(Date.now() / 1000);
      const parent = chain.getBlock(chain.height);
      if (parent && now <= parent.timestamp) now = parent.timestamp + 1;
      log('info', `[TX] _forgeBlock called for height ${newHeight}, chain.height=${chain.height}`);
      const mempoolTxs = this._selectValidMempoolTxs(chain, 100);
      log('info', `[TX] _forgeBlock: ${mempoolTxs.length} txs selected for block #${newHeight}`);
      const txHashes = mempoolTxs.map(t => t.hash || hashTransaction(t));
      const txRoot = merkleRoot(txHashes);
      const totalReward = calculateMiningReward(newHeight, this.cfg);
      const rewardCc = String(totalReward);
      const targetValue = chain._targetForHeight(newHeight, parent && parent.hash);
      const genSig = parent ? sha256hex((parent.generation_signature || ZERO_HASH) + parent.hash) : ZERO_HASH;
      const block = {
        height: newHeight, chain_id: this.cfg.chainId, parent_hash: parent ? parent.hash : ZERO_HASH, generation_signature: genSig,
        timestamp: now, miner, tx_count: mempoolTxs.length, tx_root: txRoot,
        challenge_id: challenge.challenge_id, nonce: String(Math.floor(deadline)),
        difficulty: '0', target: String(targetValue), reward_units: '0', reward_cc: String(rewardCc),
        proof_digest: proofDigest, plot_id: plotId, base_target: chain._baseTargetForHeight(newHeight, parent && parent.hash),
        state_root: computeStateRootAfterTxs(this.db, mempoolTxs, rewardDistribution),
        transactions: mempoolTxs, signature: '',
        gas_used: mempoolTxs.reduce((sum, tx) => sum + estimateIntrinsicGas(tx), 0),
        gas_limit: GAS_PARAMS.blockGasLimit,
        base_fee: String(chain._baseFeeForHeight(newHeight, parent && parent.hash)),
        miner_public_key: this.cfg.minerPublicKey || '',
        forger: String(this.cfg.minerAddress || '').toLowerCase(),
        _from_local_forge: true, rewards: rewardDistribution,
        winner_proof: winnerProof || null,
      };
      if (this.cfg.minerPrivateKey) {
        const { signMessage, blockMessage } = require('../crypto-utils/crypto');
        block.signature = signMessage(blockMessage(block), this.cfg.minerPrivateKey);
      }
      block.hash = hashBlock(block);
      log('debug', `[FORGE] block #${newHeight} built, hash=${String(block.hash).slice(0,10)}, state_root=${String(block.state_root).slice(0,10)}`);
      return block;
    } catch (e) { log('error', `forge block error: ${e.message}`); return null; }
  }

  async finalizeExpiredChallenges(chain, syncEngine) {
    if (chain && chain._stateTransitionPending) return;
    if (!this.db || this.db.open === false) return;
    const now = Math.floor(Date.now() / 1000);
    const nextHeight = chain.height + 1;
    const existingBlock = this.db.prepare('SELECT hash, challenge_id FROM blocks WHERE height = ? ORDER BY LENGTH(chain_work) DESC, chain_work DESC LIMIT 1').get(nextHeight);

    const stale = this.db.prepare(`SELECT challenge_id, block_height FROM mining_challenges
      WHERE forged_block_height IS NULL AND winner_deadline IS NOT NULL AND winner_miner IS NOT NULL
      AND (finalized_at + winner_deadline) <= ? AND block_height < ?`).all(now, chain.height);
    for (const s of stale) {
      log('warn', `Abandoning stale challenge ${s.challenge_id.slice(0, 12)} (created at height ${s.block_height}, chain now at ${chain.height})`);
      this.db.prepare('UPDATE mining_challenges SET forged_block_height = ? WHERE challenge_id = ? AND forged_block_height IS NULL').run(-1, s.challenge_id);
    }

    const canForge = Boolean(this.cfg.minerPrivateKey && String(this.cfg.minerAddress || ''));
    if (!canForge) {
      const pendingWinner = this.db.prepare(`SELECT 1 FROM mining_challenges WHERE forged_block_height IS NULL
        AND winner_miner IS NOT NULL AND winner_deadline IS NOT NULL
        AND (finalized_at + winner_deadline) <= ? LIMIT 1`).get(now);
      if (pendingWinner) {
        log('warn', `[FORGE] Block NOT forged: winner deadline elapsed but this node has no minerPrivateKey/minerAddress configured (set MINER_PRIVATE_KEY to forge)`);
      }
      return;
    }
    const readyToForge = this.db.prepare(`SELECT * FROM mining_challenges WHERE forged_block_height IS NULL
      AND winner_deadline IS NOT NULL AND winner_miner IS NOT NULL
      AND (finalized_at + winner_deadline) <= ? AND block_height >= ?
      ORDER BY created_at ASC LIMIT 1`).get(now, chain.height);
    if (readyToForge) {
      const ch = readyToForge;
      const blockUsesThisChallenge = existingBlock && String(existingBlock.challenge_id || '') === String(ch.challenge_id);
      if (blockUsesThisChallenge) {
        this.db.prepare('UPDATE mining_challenges SET forged_block_height = ? WHERE challenge_id = ? AND forged_block_height IS NULL').run(nextHeight, ch.challenge_id);
      } else if (chain.height >= nextHeight) {
        const usedInBlock = this.db.prepare('SELECT 1 FROM blocks WHERE challenge_id = ? AND height >= ? LIMIT 1').get(ch.challenge_id, ch.block_height);
        if (usedInBlock) {
          this.db.prepare('UPDATE mining_challenges SET forged_block_height = ? WHERE challenge_id = ? AND forged_block_height IS NULL').run(chain.height, ch.challenge_id);
        } else {
          log('info', `Deadline elapsed — forging block for challenge ${ch.challenge_id.slice(0, 12)} (d=${ch.winner_deadline}s)`);
          await this._forgeBlockForChallenge(chain, syncEngine, ch);
          return;
        }
      } else {
        log('info', `Deadline elapsed — forging block for challenge ${ch.challenge_id.slice(0, 12)} (d=${ch.winner_deadline}s)`);
        await this._forgeBlockForChallenge(chain, syncEngine, ch);
        return;
      }
    }

    const expired = this.db.prepare(`SELECT * FROM mining_challenges WHERE forged_block_height IS NULL
      AND winner_deadline IS NOT NULL AND winner_miner IS NOT NULL
      AND (finalized_at + winner_deadline) <= ? AND block_height >= ?
      AND challenge_id NOT IN (SELECT DISTINCT challenge_id FROM blocks WHERE blocks.challenge_id = mining_challenges.challenge_id AND blocks.challenge_id != '')
      AND challenge_id IN (SELECT DISTINCT challenge_id FROM challenge_submissions)
      ORDER BY created_at ASC LIMIT 1`).get(now, chain.height);
    if (expired) {
      const ch = expired;
      const chId = ch.challenge_id;
      const blockUsesThisChallenge2 = existingBlock && String(existingBlock.challenge_id || '') === String(chId);
      if (blockUsesThisChallenge2) {
        this.db.prepare('UPDATE mining_challenges SET forged_block_height = ? WHERE challenge_id = ? AND forged_block_height IS NULL').run(nextHeight, chId);
      } else if (chain.height >= nextHeight) {
        const usedInBlock2 = this.db.prepare('SELECT 1 FROM blocks WHERE challenge_id = ? AND height >= ? LIMIT 1').get(chId, ch.block_height);
        if (usedInBlock2) {
          this.db.prepare('UPDATE mining_challenges SET forged_block_height = ? WHERE challenge_id = ? AND forged_block_height IS NULL').run(chain.height, chId);
        } else {
          await this._forgeBlockForChallenge(chain, syncEngine, ch);
        }
      } else {
        await this._forgeBlockForChallenge(chain, syncEngine, ch);
      }
    }
  }

  async _forgeBlockForChallenge(chain, syncEngine, challenge) {
    const chId = challenge && challenge.challenge_id;
    if (!chId || this._forging.has(chId)) return null;
    this._forging.add(chId);
    try {
      return await this._forgeBlockForChallengeUnsafe(chain, syncEngine, challenge);
    } finally {
      this._forging.delete(chId);
    }
  }

  async _forgeBlockForChallengeUnsafe(chain, syncEngine, challenge) {
    try {
      const nextHeight = chain.height + 1;
      const existing = this.db.prepare('SELECT hash, challenge_id FROM blocks WHERE height = ? LIMIT 1').get(nextHeight);
      if (existing) { log('info', `[FORGE] Skipping forge for challenge ${challenge.challenge_id.slice(0, 12)}: block already exists at height ${nextHeight} (${existing.hash ? existing.hash.slice(0, 12) : ''})`); return null; }
      const submissions = this.db.prepare('SELECT * FROM challenge_submissions WHERE challenge_id = ?').all(challenge.challenge_id);
      if (!submissions.length) { log('warn', `[FORGE] Cannot forge challenge ${challenge.challenge_id.slice(0, 12)}: no PoC submissions recorded`); return null; }
      const maxDl = chain.computeMaxDeadline();
      const seenSub = new Set();
      const validSubs = submissions
        .filter(s => safeInt(s.deadline, maxDl + 1) <= maxDl)
        .filter(s => {
          const k = `${(s.miner || '').toLowerCase()}:${s.plot_id || ''}:${safeInt(s.deadline, -1)}`;
          if (seenSub.has(k)) return false;
          seenSub.add(k);
          return true;
        })
        .sort((a, b) => {
          const da = safeInt(a.deadline, Number.MAX_SAFE_INTEGER);
          const dbd = safeInt(b.deadline, Number.MAX_SAFE_INTEGER);
          if (da !== dbd) return da - dbd;
          const ma = String(a.miner || '').toLowerCase();
          const mb = String(b.miner || '').toLowerCase();
          if (ma !== mb) return ma < mb ? -1 : 1;
          const pa = String(a.plot_id || '');
          const pb = String(b.plot_id || '');
          if (pa !== pb) return pa < pb ? -1 : 1;
          const sa = String(a.proof_digest || '');
          const sb = String(b.proof_digest || '');
          return sa < sb ? -1 : sa > sb ? 1 : 0;
        });
      if (!validSubs.length) { log('warn', `[FORGE] Cannot forge challenge ${challenge.challenge_id.slice(0, 12)}: ${submissions.length} submissions but none valid (deadline > ${chain.computeMaxDeadline()}s or duplicates)`); return null; }
      const winner = validSubs[0];
      if (!this.cfg.minerPrivateKey || !String(this.cfg.minerAddress || '')) {
      log('error', `[FORGE] Cannot forge challenge ${challenge.challenge_id.slice(0, 12)}: winner d=${winner.deadline}s from ${(winner.miner || '').slice(0, 10)}… but this node has no minerPrivateKey/minerAddress configured`);
      return null;
    }
    const totalReward = calculateMiningReward(chain.height + 1, this.cfg);
    const distribution = [{
      miner: (winner.miner || '').toLowerCase(),
      plot_id: winner.plot_id || '',
      size_gb: winner.size_gb,
      deadline: winner.deadline,
      reward_cc: String(totalReward),
      type: 'poc',
    }];
    let winnerMerkleProof = [];
    try { winnerMerkleProof = JSON.parse(String(winner.merkle_proof || '[]')); if (!Array.isArray(winnerMerkleProof)) winnerMerkleProof = []; } catch { winnerMerkleProof = []; }
    if (!winner.scoop_data || !winner.merkle_root) {
      log('warn', `[FORGE] winner submission for challenge ${challenge.challenge_id.slice(0, 12)} predates PoC packet recordkeeping; skipping forge`);
      return null;
    }
    const winnerPkRow = this.db.prepare('SELECT public_key_secp256k1 FROM user_keys WHERE lower(address) = lower(?)').get(winner.miner)
      || this.db.prepare('SELECT public_key_secp256k1 FROM users WHERE lower(address) = lower(?)').get(winner.miner);
    const winnerProof = {
      miner: (winner.miner || '').toLowerCase(),
      public_key: winner.public_key || (winnerPkRow && winnerPkRow.public_key_secp256k1) || '',
      deadline: winner.deadline,
      plot_id: winner.plot_id || '',
      proof_signature: winner.proof_signature || '',
      merkle_proof: winnerMerkleProof,
      scoop_data: winner.scoop_data || '',
      scoop_index: safeInt(winner.scoop_index, 0),
      total_scoops: safeInt(winner.total_scoops, 0),
      merkle_root: winner.merkle_root || '',
      capacity_samples: (() => { try { return JSON.parse(String(winner.capacity_samples || '[]')); } catch { return []; } })(),
      challenge_seed: challenge.challenge_seed || '',
      base_target: String(challenge.base_target || this.chain._baseTargetForHeight(safeInt(challenge.block_height, this.chain.height))),
    };
    const block = await this._forgeBlock(chain, challenge, winner.miner, winner.deadline, distribution, winner.plot_id || '', winner.proof_digest || '', winnerProof);
    if (!block) { log('error', `[FORGE] _forgeBlock returned no block for challenge ${challenge.challenge_id.slice(0, 12)} (winner ${(winner.miner || '').slice(0, 10)}… d=${winner.deadline}s)`); return null; }
    const result = await chain.addBlock(block);
    if (!result.ok) {
      log('error', `Block forge rejected for challenge ${challenge.challenge_id.slice(0, 12)}: ${result.motivo}`);
      return null;
    }
      this.db.prepare('UPDATE mining_challenges SET forged_block_height = ? WHERE challenge_id = ? AND forged_block_height IS NULL').run(block.height, challenge.challenge_id);
      log('info', `Block #${block.height} forged — challenge ${challenge.challenge_id.slice(0, 12)} (winner ${winner.miner.slice(0, 10)}…, reward ${totalReward} CC)`);
      if (syncEngine) setImmediate(() => { syncEngine.broadcastBlock(block); });
      return block;
    } catch (e) { log('error', `forge error: ${e.message}`); return null; } 
  }
}

module.exports = { ChallengeManager };
