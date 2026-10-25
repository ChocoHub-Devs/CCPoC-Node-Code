const path = require('path');
const { safeInt, safeBigInt, hashTransaction, pubkeyToAddress, calculateMiningReward, evmTxHash, recoverTransactionSender } = require('../crypto-utils/crypto');
const { log, getLogBuffer } = require('../../config/config');
const { estimateIntrinsicGas, minimumFee } = require('../consensus/gas');
const PocPlotV4 = require('../consensus/poc-plot-v4');
const { CONSENSUS_VERSION } = require('../consensus/protocol');

const CC_SCALE = 10n ** 18n;
function parseCcAmount(value) {
  const text = String(value ?? '').trim();
  const match = /^(\d+)(?:\.(\d{1,18}))?$/.exec(text);
  if (!match) return null;
  const fraction = (match[2] || '').padEnd(18, '0');
  return BigInt(match[1]) * CC_SCALE + BigInt(fraction || '0');
}

function formatCcAmount(units) {
  const value = safeBigInt(units, 0n);
  const whole = value / CC_SCALE;
  const fraction = (value % CC_SCALE).toString().padStart(18, '0').replace(/0+$/, '');
  return fraction ? `${whole}.${fraction}` : String(whole);
}

const rateLimitStore = new Map();
function rateLimit(options = {}) {
  const { windowMs = 600000, max = 100, keyPrefix = 'rl', message = 'Too many requests', skip } = options;
  return (req, res, next) => {
    if (skip && skip(req)) return next();
    const ip = req.ip || req.connection?.remoteAddress || 'unknown';
    const key = `${keyPrefix}:${ip}`;
    const now = Date.now();
    const record = rateLimitStore.get(key) || { count: 0, resetTime: now + windowMs };
    if (now > record.resetTime) {
      record.count = 0;
      record.resetTime = now + windowMs;
    }
    record.count++;
    rateLimitStore.set(key, record);
    res.setHeader('X-RateLimit-Limit', max);
    res.setHeader('X-RateLimit-Remaining', Math.max(0, max - record.count));
    res.setHeader('X-RateLimit-Reset', Math.ceil(record.resetTime / 1000));
    if (record.count > max) {
      return res.status(429).json({ error: message, retryAfter: Math.ceil((record.resetTime - now) / 1000) });
    }
    next();
  };
}

function cleanupRateLimit() {
  const now = Date.now();
  for (const [key, record] of rateLimitStore.entries()) {
    if (now > record.resetTime) rateLimitStore.delete(key);
  }
}
setInterval(cleanupRateLimit, 60000);

class Server {
  constructor(cfg, db, chain, peers, sync, challengeMgr, registry, NODE_ID, smartContracts = null, p2pWsServer = null) {
    this.cfg = cfg;
    this.db = db;
    this.chain = chain;
    this.peers = peers;
    this.sync = sync;
    this.challengeMgr = challengeMgr;
    this.registry = registry;
    this.NODE_ID = NODE_ID;
    this.smartContracts = smartContracts;
    this.p2pWsServer = p2pWsServer;
    this.app = null;
    this.server = null;
    this.discoveryServer = null;
    this._peerStorageCache = { peers: [], local: { plots_count: 0, capacidade_gb: 0 }, fetched_at: 0 };
  }

  relayTx(tx) {
    if (!tx) return;
    const maxRelayHops = Math.max(1, safeInt(this.cfg.txRelayHops, 6));
    if (safeInt(tx.relay_hops, 0) >= maxRelayHops) return;
    const next = { ...tx, relay_hops: safeInt(tx.relay_hops, 0) + 1 };
    setImmediate(() => {
      try { this.sync.broadcastTx(next); } catch {}
      if (this.p2pWsServer) { try { this.p2pWsServer.broadcastTx(next); } catch {} }
    });
  }

  async _fetchPeerStorage() {
    try {
      const gossip = this.peers.gossipPeers(50);
      const results = [];
      const fetches = gossip.map(async (p) => {
        const controller = new AbortController();
          const timer = setTimeout(() => controller.abort(), 4000);
          try {
            const res = await fetch(p.url + '/api/stats', { signal: controller.signal });
            if (!res.ok) return null;
            const d = await res.json();
            return { url: p.url, node_id: p.node_id, plots_count: d.plots_count || 0, capacity_gb: Number(d.capacity_gb) || 0, height: d.height || 0 };
          } catch { return null; }
          finally { clearTimeout(timer); }
      });
      const settled = await Promise.allSettled(fetches);
      for (const r of settled) {
        if (r.status === 'fulfilled' && r.value) results.push(r.value);
      }
      const st = this.chain.getStats();
      this._peerStorageCache = {
        peers: results,
        local: { plots_count: st.plots_count || 0, capacity_gb: Number(st.capacity_gb) || 0 },
        fetched_at: Date.now(),
      };
    } catch (e) {   }
  }

  start() {
    const express = require('express');
    const helmet = require('helmet');
    const app = express();
    this.app = app;

    const PUBLIC_DIR = path.join(__dirname, 'public');

    app.use(helmet({ contentSecurityPolicy: false, crossOriginEmbedderPolicy: false }));
    app.use(express.json({ limit: '2mb' }));

    const allowedOrigins = this.cfg.corsOrigins || (this.cfg.nodeUrl ? [this.cfg.nodeUrl] : []);
    app.use((req, res, next) => {
      const origin = req.headers.origin;
      if (origin && allowedOrigins.includes(origin)) {
        res.header('Access-Control-Allow-Origin', origin);
      }
      res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Admin-Token');
      res.header('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS');
      if (req.method === 'OPTIONS') return res.sendStatus(200);
      next();
    });

    app.use(express.static(PUBLIC_DIR, { maxAge: 0 }));

    
    
    
    app.use((req, res, next) => {
      if ((req.method === 'POST' && (req.path === '/api/node/broadcast/block' || req.path === '/api/node/forge'))
        || req.path === '/health' || req.path === '/health/liveness' || req.path === '/health/readiness') {
        return next();
      }
      const release = this.chain.tryAcquireStableRead();
      if (!release) {
        res.setHeader('Retry-After', '1');
        return res.status(503).json({ error: 'canonical chain transition in progress', retry_after: 1 });
      }
      let done = false;
      const finish = () => {
        if (done) return;
        done = true;
        release();
      };
      res.once('finish', finish);
      res.once('close', finish);
      next();
    });

    const isSyncTraffic = (req) => {
      const path = req.path || '';
      if (req.method === 'GET' && (
        path === '/api/stats' || path === '/api/blocks' || path === '/peers'
        || path === '/api/snapshot/latest' || path === '/api/zkp/latest'
        || /^\/api\/block\/[^/]+$/.test(path)
      )) return true;
      return req.method === 'POST' && path === '/api/node/broadcast/block';
    };
    const apiLimiter = rateLimit({ windowMs: 60000, max: 120, keyPrefix: 'api', message: 'Too many API requests', skip: isSyncTraffic });
    const syncLimiter = rateLimit({ windowMs: 60000, max: 300, keyPrefix: 'sync', message: 'Too many sync requests' });
    const mutationLimiter = rateLimit({ windowMs: 60000, max: 30, keyPrefix: 'mut', message: 'Too many mutation requests' });
    const walletLimiter = rateLimit({ windowMs: 60000, max: 10, keyPrefix: 'wlt', message: 'Too many wallet requests' });
    const p2pLimiter = rateLimit({ windowMs: 60000, max: 60, keyPrefix: 'p2p', message: 'Too many P2P requests' });

    const requireAdmin = (req, res, next) => {
      const token = req.headers['x-admin-token'] || (req.headers.authorization || '').replace(/^Bearer\s+/i, '');
      if (token === this.cfg.adminToken) return next();
      res.status(401).json({ error: 'unauthorized' });
    };

    app.use(apiLimiter);

    app.get('/', (req, res) => res.redirect('/api/stats'));

    app.get('/api/stats', syncLimiter, (req, res) => {
      const stats = this.chain.getStats();
      res.json({
        ...stats, chain_id: this.cfg.chainId, chain_name: this.cfg.chainName,
        consensus_version: CONSENSUS_VERSION, genesis_hash: this.chain.getBlock(0)?.hash || null,
        symbol: this.cfg.symbol, current_reward: calculateMiningReward(this.chain.height + 1, this.cfg).toString(),
        current_reward_cc: Number(calculateMiningReward(this.chain.height + 1, this.cfg)) / 1e18,
        blocks_to_halving: this.cfg.halvingInterval - (this.chain.height % this.cfg.halvingInterval),
        halving_interval: this.cfg.halvingInterval, max_supply: this.cfg.maxSupply,
        seed_version: this.cfg.version, node_url: this.cfg.nodeUrl,
        node_id: this.NODE_ID, peers: { total: this.peers.count(), active: this.peers.active().length, banned: this.peers.banned().length, avg_health: 0 },
        version: this.cfg.version,
      });
    });

app.get('/api/state', (req, res) => {
  const running = !!this.chain;
  const config = this.cfg;
  const wallets = this.db.prepare('SELECT address, balance, nonce FROM users ORDER BY address').all();
  const node = running ? this.chain.getStats() : null;
  res.json({
    running,
    config: {
      port: config.port,
      chainId: config.chainId,
      chainName: config.chainName,
      symbol: config.symbol
    },
    wallets: wallets.map(w => ({
      address: w.address,
      balance: w.balance,
      nonce: w.nonce
    })),
    node: node ? {
      height: node.height,
      hash: node.hash,
      peers: node.blocks ? node.blocks.length : 0
    } : null,
    network_storage: {
      local: { plots_count: node ? node.plots_count : 0, capacity_gb: node ? Number(node.capacity_gb || 0) : 0 },
      peers: []
    },
    data_dir: config.dataDir
  });
});

    app.get('/api/blocks', syncLimiter, (req, res) => {
      const from = parseInt(req.query.from) || 0;
      const limit = Math.min(parseInt(req.query.limit) || 50, 200);
      let blocks;
      if (req.query.hash) {
        const b = this.chain.getBlock(req.query.hash);
        blocks = b ? [b] : [];
      } else {
        blocks = [];
        for (let h = from; h < from + limit; h++) {
          const b = this.chain.getBlock(h);
          if (b) blocks.push(b); else break;
        }
      }
      res.json({ blocks, total: this.chain.height + 1 });
    });

    app.get('/api/block/:heightOrHash', syncLimiter, (req, res) => {
      const b = this.chain.getBlock(req.params.heightOrHash);
      if (!b) return res.status(404).json({ error: 'block not found' });
      res.json(b);
    });

    app.get('/api/zkp/proofs', (req, res) => {
      const rows = this.db.prepare('SELECT id, start_height, end_height, block_count, commitment, verified, created_at FROM zkp_proofs ORDER BY end_height DESC').all();
      res.json({ proofs: rows });
    });
    app.get('/api/zkp/proof/:id', (req, res) => {
      const row = this.db.prepare('SELECT * FROM zkp_proofs WHERE id = ?').get(parseInt(req.params.id, 10) || -1);
      if (!row) return res.status(404).json({ error: 'proof not found' });
      let proof = null;
      try { proof = require('../crypto-utils/zkp').decodeProof(row.proof); } catch (e) { proof = null; }
      res.json({ id: row.id, start: row.start_height, end: row.end_height, commitment: row.commitment, proof });
    });
    app.get('/api/zkp/latest', syncLimiter, (req, res) => {
      if (!this.chain.zkp) return res.status(404).json({ error: 'zkp disabled' });
      const row = this.chain.zkp.getLatest();
      if (!row) return res.status(404).json({ error: 'no proofs yet' });
      let proof = null;
      try { proof = require('../crypto-utils/zkp').decodeProof(row.proof); } catch (e) { proof = null; }
      res.json({ id: row.id, start: row.start_height, end: row.end_height, commitment: row.commitment, proof });
    });

    app.get('/api/snapshot', (req, res) => {
      if (!this.chain.snapsync) return res.status(404).json({ error: 'snapsync disabled' });
      res.json({ snapshots: this.chain.snapsync.listMeta() });
    });
    app.get('/api/snapshot/latest', syncLimiter, (req, res) => {
      if (!this.chain.snapsync) return res.status(404).json({ error: 'snapsync disabled' });
      const snapObj = this.chain.snapsync.loadLatestSnapshot();
      if (!snapObj) return res.status(404).json({ error: 'no snapshots yet' });
      res.json(snapObj);
    });
    app.get('/api/snapshot/:height', (req, res) => {
      if (!this.chain.snapsync) return res.status(404).json({ error: 'snapsync disabled' });
      const height = parseInt(req.params.height, 10) || 0;
      const meta = this.chain.snapsync.getMeta(height);
      if (!meta) return res.status(404).json({ error: 'snapshot not found' });
      const full = (req.query.full === '1' || req.query.full === 'true');
      if (full) {
        const snapObj = this.chain.snapsync.loadSnapshot(height);
        if (!snapObj) return res.status(404).json({ error: 'snapshot data missing on disk' });
        return res.json(snapObj);
      }
      res.json(meta);
    });
    app.post('/api/snapshot/generate', requireAdmin, (req, res) => {
      if (!this.chain.snapsync) return res.status(404).json({ error: 'snapsync disabled' });
      const height = parseInt((req.body && req.body.height) || this.chain.height, 10) || 0;
      const meta = this.chain.snapsync.generateAtBoundary(height);
      if (!meta) return res.status(400).json({ error: 'height is not a clean 8,192 boundary or snapshot exists' });
      res.json(meta);
    });

    app.get('/api/plots', (req, res) => {
      const tip = this.chain.getBlock(this.chain.height);
      const plots = tip ? this.chain.getMaturePlotRegistrations(tip.hash, this.chain.height + 1).map((p) => ({
        ...p,
        size_gb: Number(BigInt(p.capacity_bytes)) / (1024 ** 3),
        created_at: p.block_height,
      })) : [];
      res.json({ plots });
    });

    app.get('/api/challenge', (req, res) => {
      const ch = this.challengeMgr.getOrCreate();
      if (!ch) return res.status(404).json({ error: 'no active challenge' });
      const now = Math.floor(Date.now() / 1000);
      const deadline = ch.expires_at ? Math.max(0, ch.expires_at - now) : 0;
      const tip = this.chain.getBlock(this.chain.height);
      const registered = tip ? this.chain.getMaturePlotRegistrations(tip.hash, this.chain.height + 1) : [];
      const capacityGb = Number(registered.reduce((sum, p) => sum + BigInt(p.capacity_bytes), 0n)) / (1024 ** 3);
      const plotsCount = registered.length;
      res.json({
        challenge_id: ch.challenge_id,
        block_height: ch.block_height,
        challenge_seed: ch.challenge_seed,
        target_scoop_index: ch.target_scoop_index,
        created_at: ch.created_at,
        expires_at: ch.expires_at,
        deadline,
        base_target: ch.base_target,
        plots: plotsCount,
        capacity_gb: Number(capacityGb.toFixed(2)),
        difficulty: this.chain.height > 0 ? '~' + this.chain.height + ' blocks' : 'genesis',
      });
    });

    app.get('/api/mempool', (req, res) => {
      const txs = this.db.prepare('SELECT * FROM mempool ORDER BY CAST(fee AS INTEGER) DESC LIMIT 200').all().map(r => { try { return JSON.parse(r.raw); } catch { return null; } }).filter(Boolean);
      res.json({ transactions: txs, count: txs.length });
    });

    app.post('/api/mempool', mutationLimiter, async (req, res) => {
      const tx = req.body;
      if (!tx || !tx.from_addr || (!tx.to_addr && !tx.data)) return res.status(400).json({ error: 'invalid transaction' });
      const validation = await this.chain.validateTxForMempool(tx);
      if (!validation.ok) return res.status(400).json({ ok: false, error: validation.motivo });
      if (!tx.hash) tx.hash = hashTransaction(tx);
      const result = this.chain.addMempoolTx(tx);
      if (result.ok) this.relayTx(tx);
      res.json(result);
    });

    app.post('/api/wallet/prepare-tx', walletLimiter, async (req, res) => {
      try {
        const { from_addr, to_addr, amount, data, gas_limit, gas_price, chain_id, priority_fee } = req.body;
        if (!from_addr || (!to_addr && !data)) return res.status(400).json({ error: 'from_addr and to_addr (or data for contract creation) required' });
        
        const normalizedFrom = from_addr.toLowerCase();
        const user = this.db.prepare('SELECT balance, nonce FROM users WHERE lower(address) = lower(?)').get(normalizedFrom);
        
        const hasData = !!(data && /^0x[0-9a-fA-F]*$/.test(String(data)));
        const amountNum = amount === undefined || amount === null ? 0 : Number(amount);
        if (isNaN(amountNum) || amountNum < 0) return res.status(400).json({ error: 'invalid amount' });
        const valueWei = String(Math.round(amountNum * 1e18));
        
        
        
        
        
        
        const confirmedNonce = user ? (user.nonce || 0) : 0;
        let nonce = confirmedNonce;
        try {
          const pending = this.db.prepare('SELECT raw FROM mempool').all();
          const used = new Set();
          for (const row of pending) {
            try {
              const t = JSON.parse(row.raw);
              if (String(t.from_addr || '').toLowerCase() !== normalizedFrom) continue;
              const n = Number(t.nonce);
              if (Number.isInteger(n) && n >= confirmedNonce) used.add(n);
            } catch {   }
          }
          while (used.has(nonce)) nonce++;
        } catch {   }
        const gasPrice = gas_price || this.chain._baseFeeForHeight(this.chain.height + 1);
        const defaultGas = hasData ? 3000000 : 21000;
        const gasLimit = gas_limit || defaultGas;
        const tx = {
          from_addr: normalizedFrom,
          to_addr: to_addr || '',
          value: valueWei,
          nonce,
          fee: '',
          gas_limit: gasLimit,
          gas_price: String(gasPrice),
          chain_id: chain_id || this.cfg.chainId || '0',
          priority_fee: priority_fee || '0'
        };
        if (hasData) tx.data = String(data);
        const intrinsic = estimateIntrinsicGas(tx);
        if (gasLimit < intrinsic) tx.gas_limit = intrinsic;
        const estimatedFee = minimumFee(tx, this.chain._baseFeeForHeight(this.chain.height + 1));
        tx.fee = String(estimatedFee);
        
        const txHash = evmTxHash(tx);
        
        const currentBaseFee = BigInt(this.chain._baseFeeForHeight(this.chain.height + 1));
        
        res.json({
          ok: true,
          transaction: tx,
          sign_message: '0x' + (require('../crypto-utils/crypto').evmTxDigest ? require('../crypto-utils/crypto').evmTxDigest(tx) : ''),
          tx_hash: txHash,
          estimated_gas: intrinsic,
          estimated_fee: String(estimatedFee),
          gas_price: String(currentBaseFee),
          balance: user ? user.balance : '0',
          nonce
        });
      } catch (e) { res.status(400).json({ error: e.message }); }
    });

    app.get('/api/wallets', (req, res) => {
      const wallets = this.db.prepare('SELECT address, balance, nonce, created_at, updated_at FROM users ORDER BY CAST(balance AS INTEGER) DESC LIMIT 200').all();
      res.json({ wallets, count: wallets.length });
    });
    app.get('/api/accounts', (req, res) => {
      const address = req.query.address;
      if (!address) return res.status(400).json({ error: 'address query param required' });
      const u = this.db.prepare('SELECT address, balance, nonce, created_at, updated_at FROM users WHERE lower(address) = lower(?)').get(address);
      if (!u) return res.json({ address, balance: '0', nonce: 0 });
      res.json(u);
    });
    app.get('/api/gas/price', (req, res) => {
      const dynamicPrice = this.chain._baseFeeForHeight(this.chain.height + 1);
      res.json({ gas_price: String(dynamicPrice), unit: 'wei' });
    });
    app.get('/api/users/:address', (req, res) => {
      const u = this.db.prepare('SELECT * FROM users WHERE lower(address) = lower(?)').get(req.params.address);
      if (!u) return res.status(404).json({ error: 'user not found' });
      res.json(u);
    });

    app.post('/api/wallet/import', requireAdmin, walletLimiter, (req, res) => {
      const { address, public_key } = req.body;
      if (!address || !public_key) return res.status(400).json({ error: 'address and public_key required (private keys never sent to node)' });
      const normalizedAddress = address.toLowerCase();
      try { if (pubkeyToAddress(public_key).toLowerCase() !== normalizedAddress) return res.status(400).json({ error: 'address does not match public key' }); } catch { return res.status(400).json({ error: 'Invalid public key' }); }
      const now = Math.floor(Date.now() / 1000);
      this.db.prepare('INSERT INTO user_keys (address, public_key_secp256k1, created_at, updated_at) VALUES (?, ?, ?, ?) ON CONFLICT(address) DO UPDATE SET public_key_secp256k1 = excluded.public_key_secp256k1, updated_at = excluded.updated_at').run(normalizedAddress, public_key, now, now);
      log('info', `Imported wallet: address=${normalizedAddress}, public_key=${public_key}`);
      res.json({ ok: true, address: normalizedAddress });
    });

    app.post('/api/wallet/register', walletLimiter, (req, res) => {
      const { address, public_key } = req.body;
      if (!address || !public_key) return res.status(400).json({ error: 'address and public_key required' });
      const normalizedAddress = address.toLowerCase();
      try { if (pubkeyToAddress(public_key).toLowerCase() !== normalizedAddress) return res.status(400).json({ error: 'address does not match public key' }); } catch { return res.status(400).json({ error: 'Invalid public key' }); }
      const now = Math.floor(Date.now() / 1000);
      const existing = this.db.prepare('SELECT address, public_key_secp256k1 FROM user_keys WHERE lower(address) = lower(?)').get(normalizedAddress);
      if (existing && existing.public_key_secp256k1) {
        return res.status(409).json({ ok: false, error: 'public key already registered', address: normalizedAddress });
      }
      if (existing) {
        this.db.prepare('UPDATE user_keys SET public_key_secp256k1 = ?, updated_at = ? WHERE lower(address) = lower(?)').run(public_key, now, normalizedAddress);
      } else {
        this.db.prepare('INSERT INTO user_keys (address, public_key_secp256k1, created_at, updated_at) VALUES (?, ?, ?, ?)').run(normalizedAddress, public_key, now, now);
      }
      log('info', `Registered wallet: address=${normalizedAddress}, public_key=${public_key}`);
      res.json({ ok: true, address: normalizedAddress, public_key });
    });

    app.get('/api/node/info', (req, res) => {
      const ns = this.registry.getStats();
      res.json({ ...this.chain.getStats(), chain_id: this.cfg.chainId, chain_name: this.cfg.chainName,
        consensus_version: CONSENSUS_VERSION, genesis_hash: this.chain.getBlock(0)?.hash || null,
        symbol: this.cfg.symbol, node_url: this.cfg.nodeUrl, node_id: this.NODE_ID, version: this.cfg.version, peers: this.peers.gossipPeers(20) });
    });
    app.get('/api/node/status', (req, res) => res.json({
      height: this.chain.height, hash: this.chain.bestHash,
      chain_work: (this.chain.getBlock(this.chain.height) || {}).chain_work || '0',
      peer_count: this.peers.count(), mining_active: false,
      node_url: this.cfg.nodeUrl,
    }));
    app.get('/api/node/peers', (req, res) => res.json({ peers: this.peers.all(100) }));
    app.get('/api/node/peers/gossip', (req, res) => res.json({ peers: this.peers.gossipPeers(50) }));

    app.get('/api/peers', (req, res) => res.json({ peers: this.peers.all(100) }));
    app.post('/api/peers/add', p2pLimiter, (req, res) => {
      const url = require('../../config/config').normalizeUrl(req.body.url);
      if (!url) return res.status(400).json({ error: 'invalid url' });
      this.peers.add(url);
      res.json({ ok: true, url });
    });

    app.get('/api/mining/challenge', (req, res) => {
      const ch = this.challengeMgr.getOrCreate();
      if (!ch) return res.status(404).json({ error: 'no challenge available' });
      res.json(ch);
    });

    app.post('/api/mining/submit-proof', mutationLimiter, async (req, res) => {
      const { challenge_id, miner, plot_id, deadline, proof_packet, proof_signature } = req.body;
      if (!challenge_id || !miner || !plot_id || deadline == null) return res.status(400).json({ error: 'challenge_id, miner, plot_id, deadline required' });
      const packet = proof_packet || {};
      if (proof_signature && !packet.proof_signature) packet.proof_signature = proof_signature;
      const result = this.challengeMgr.submitProof(this.chain, challenge_id, miner, plot_id, safeInt(deadline, -1), packet);
      if (!result.ok) return res.status(400).json({ error: result.motivo });
      log('info', `[MINERS] Proof submit: miner=${miner}, plot_id=${plot_id}, deadline=${deadline}, result=${result.ok ? 'accepted' : 'rejected'}, reason=${result.motivo}`);
      if (result.bloco && this.sync) {
        const block = result.bloco;
        setImmediate(() => { this.sync.broadcastBlock(block); });
        if (this.p2pWsServer) this.p2pWsServer.broadcastBlock(block);
      }
      res.json(result);
    });

    app.get('/api/poc/plots/:miner', (req, res) => {
      const normalizedAddress = String(req.params.miner || '').toLowerCase();
      const tip = this.chain.getBlock(this.chain.height);
      const plots = tip ? this.chain.getMaturePlotRegistrations(tip.hash, this.chain.height + 1).filter((p) => p.miner === normalizedAddress) : [];
      res.json({ plots });
    });

    app.post('/api/poc/commitment/encode', mutationLimiter, (req, res) => {
      try {
        const data = PocPlotV4.encodeRegistration(req.body || {});
        res.json({
          ok: true,
          data,
          to_addr: PocPlotV4.ZERO_ADDRESS,
          value: '0',
          chain_id: String(this.cfg.chainId),
          note: 'Sign and broadcast as a normal transaction; wait for inclusion and two-block maturity.',
        });
      } catch (e) {
        res.status(400).json({ error: e.message || 'invalid plot registration' });
      }
    });

    const removedPlotRegistration = (req, res) => res.status(410).json({ error: 'off-chain plot registration was removed; use genesisPlotRegistrations for the new network bootstrap or submit an on-chain v4 commitment transaction' });
    app.post('/api/poc/register_plot', requireAdmin, removedPlotRegistration);
    app.post('/api/poc/register_plot_public', mutationLimiter, removedPlotRegistration);
    app.post('/api/poc/verify_plot', mutationLimiter, removedPlotRegistration);
    app.get('/api/plots/announced', removedPlotRegistration);

    const contractsEnabled = () => !!this.cfg.smartContractsEnabled && this.smartContracts;
    const contractsDisabled = (res) => res.status(503).json({ error: 'smart contracts disabled on this node', enabled: false });

    app.get('/api/contracts', (req, res) => {
      if (!contractsEnabled()) return contractsDisabled(res);
      res.json({ contracts: this.smartContracts.listSmartContracts() });
    });

    app.get('/api/contracts/:address', (req, res) => {
      if (!contractsEnabled()) return contractsDisabled(res);
      const addr = String(req.params.address || '').toLowerCase();
      if (!/^0x[0-9a-f]{40}$/.test(addr)) return res.status(400).json({ error: 'invalid contract address' });
      const c = this.smartContracts.getSmartContract(addr);
      if (!c) return res.status(404).json({ error: 'contract not found' });
      res.json({ contract: c });
    });

    app.post('/api/contracts/deploy', mutationLimiter, async (req, res) => {
      if (!contractsEnabled()) return contractsDisabled(res);
      if (Object.prototype.hasOwnProperty.call(req.body || {}, 'private_key')) {
        return res.status(400).json({ error: 'private_key is not accepted; sign the transaction locally and send signature' });
      }
      const { code, sender, signature, nonce, value, gas_limit, gas_price, fee } = req.body || {};
      if (!code || !sender || !signature) {
        return res.status(400).json({ error: 'code, sender, and signature required; private keys are never accepted' });
      }
      try {
        const from_addr = String(sender).toLowerCase();
        const user = this.db.prepare('SELECT balance, nonce FROM users WHERE lower(address) = lower(?)').get(from_addr);
        const txNonce = safeInt(req.body.nonce, user ? (user.nonce || 0) : 0);
        const gasLimit = safeInt(gas_limit, 3000000);
        const dataHex = /^0x/i.test(String(code)) ? String(code) : '0x' + String(code);
        const txNoSig = { from_addr, to_addr: '', value: '', nonce: txNonce, gas_limit: gasLimit, gas_price: String(gas_price || this.chain._baseFeeForHeight(this.chain.height + 1)), data: dataHex };
        const defaultFee = fee || String(minimumFee(txNoSig, this.chain._baseFeeForHeight(this.chain.height + 1)));
        const tx = { from_addr, to_addr: '', value: String(Math.round(Number(value) || 0) * 1e18 || 0), nonce: txNonce, fee: defaultFee, gas_limit: gasLimit, gas_price: String(gas_price || this.chain._baseFeeForHeight(this.chain.height + 1)), chain_id: this.cfg.chainId || '0', priority_fee: req.body.priority_fee || '0', data: dataHex };
        tx.signature = signature;
        const recoveredSender = recoverTransactionSender(tx);
        if (!recoveredSender || recoveredSender !== from_addr) {
          return res.status(401).json({ ok: false, error: 'signature does not match sender' });
        }
        tx.hash = evmTxHash(tx);
        tx.status = 1;
        const validation = await this.chain.validateTxForMempool(tx);
        if (!validation.ok) return res.status(400).json({ ok: false, error: validation.motivo });
        const result = this.chain.addMempoolTx(tx);
        if (!result.ok) return res.status(400).json({ ok: false, error: result.motivo || 'failed to add transaction' });
        setImmediate(() => this.sync.broadcastTx(tx));
        if (this.p2pWsServer) this.p2pWsServer.broadcastTx(tx);
        const contractAddress = this.smartContracts && typeof this.smartContracts.deriveContractAddress === 'function'
          ? this.smartContracts.deriveContractAddress(from_addr, txNonce)
          : null;
        res.json({ ok: true, mode: 'tx', txHash: tx.hash, hash: tx.hash, from: from_addr, contractAddress, contract_address: contractAddress });
        log('info', `[SMART CONTRACTS] Deploy tx broadcast: sender=${from_addr}, estimated address=${contractAddress}, tx=${tx.hash}`);
      } catch (e) {
        res.status(400).json({ error: e.code || 'CREATE_FAILED', message: e.message });
      }
    });

    app.post('/api/contracts/:address/snapshot', requireAdmin, async (req, res) => {
      if (!contractsEnabled()) return contractsDisabled(res);
      try {
        const result = await this.smartContracts.SaveSmartContractState(req.params.address);
        res.json({ ok: true, ...result });
        log('info', `[SMART CONTRACTS] Saved snapshot for contract: address=${req.params.address}`);
      } catch (e) {
        res.status(400).json({ error: e.code || 'SNAPSHOT_FAILED', message: e.message });
      }
    });

    app.post('/api/contracts/call', mutationLimiter, async (req, res) => {
      if (!contractsEnabled()) return contractsDisabled(res);
      const { address, sender, data, value } = req.body || {};
      if (!address || !sender) return res.status(400).json({ error: 'address and sender required' });
      try {
        const result = await this.smartContracts.runSmartContract(address, sender, data || '0x', Number(value) || 0);
        res.json({ ok: true, returnValue: result.returnValue, gasUsed: result.gasUsed });
        log('info', `[SMART CONTRACTS] Called contract: address=${address}, sender=${sender}, gasUsed=${result.gasUsed}`);
      } catch (e) {
        log('error', `[SMART CONTRACTS] Failed to call contract: address=${address}, sender=${sender}, error=${e.message}`);
        res.status(400).json({ error: e.code || 'CALL_FAILED', message: e.message });
      }
    });

    app.post('/api/contracts/call-batch', mutationLimiter, async (req, res) => {
      if (!contractsEnabled()) return contractsDisabled(res);
      const { address, sender, calls } = req.body || {};
      if (!address || !sender || !Array.isArray(calls)) return res.status(400).json({ error: 'address, sender, and calls[] required' });
      const results = [];
      for (const call of calls) {
        try {
          const result = await this.smartContracts.runSmartContract(address, sender, call.data || '0x', Number(call.value) || 0);
          results.push({ ok: true, returnValue: result.returnValue, gasUsed: result.gasUsed });
        } catch (e) {
          results.push({ ok: false, error: e.message });
        }
      }
      res.json({ ok: true, results });
    });

    app.post('/api/contracts/execute', mutationLimiter, async (req, res) => {
      if (!contractsEnabled()) return contractsDisabled(res);
      try {
        if (Object.prototype.hasOwnProperty.call(req.body || {}, 'private_key')) {
          return res.status(400).json({ error: 'private_key is not accepted; sign the transaction locally and send signature' });
        }
        const { address, sender, data, value, signature } = req.body || {};
        if (!address) return res.status(400).json({ error: 'address required' });
        const calldata = data || '0x';
        if (!signature) {
          const execSender = sender || this.cfg.minerAddress;
          const result = await this.smartContracts.runSmartContract(address, execSender, calldata, Number(value) || 0);
          return res.json({ ok: true, mode: 'read', returnValue: result.returnValue, gasUsed: result.gasUsed });
        }
        if (!sender) return res.status(400).json({ error: 'sender required for signed execution' });
        const from_addr = String(sender).toLowerCase();
        const user = this.db.prepare('SELECT balance, nonce FROM users WHERE lower(address) = lower(?)').get(from_addr);
        const nonce = user ? (user.nonce || 0) : 0;
        const gasPrice = req.body.gas_price || this.chain._baseFeeForHeight(this.chain.height + 1);
        const gasLimit = req.body.gas_limit || 3000000;
        const txNoSig = { from_addr, to_addr: address, value: String(Math.round(Number(value) || 0) * 1e18 || 0), nonce, gas_limit: gasLimit, gas_price: String(gasPrice), data: calldata };
        const defaultFee = minimumFee(txNoSig, this.chain._baseFeeForHeight(this.chain.height + 1));
        const tx = { from_addr, to_addr: address, value: String(Math.round(Number(value) || 0) * 1e18 || 0), nonce, fee: req.body.fee || String(defaultFee), gas_limit: gasLimit, gas_price: String(gasPrice), chain_id: this.cfg.chainId || '0', priority_fee: req.body.priority_fee || '0', data: calldata };
        tx.signature = signature;
        const recoveredSender = recoverTransactionSender(tx);
        if (!recoveredSender || recoveredSender !== from_addr) {
          return res.status(401).json({ ok: false, error: 'signature does not match sender' });
        }
        tx.hash = evmTxHash(tx);
        tx.status = 1;
const validation = await this.chain.validateTxForMempool(tx);
        if (!validation.ok) return res.status(400).json({ ok: false, error: validation.motivo });
        const result = this.chain.addMempoolTx(tx);
        if (!result.ok) return res.status(400).json({ ok: false, error: result.motivo || 'failed to add transaction' });
        setImmediate(() => this.sync.broadcastTx(tx));
        if (this.p2pWsServer) this.p2pWsServer.broadcastTx(tx);
        res.json({ ok: true, mode: 'tx', hash: tx.hash, from: from_addr });
        log('info', `[SMART CONTRACTS] Executed contract tx: address=${address}, sender=${from_addr}, tx=${tx.hash}`);
      } catch (e) {
        res.status(400).json({ error: e.code || 'EXECUTE_FAILED', message: e.message });
      }
    });

    app.post('/api/node/settings', requireAdmin, (req, res) => {
      const updates = req.body;
      if (!updates || typeof updates !== 'object') return res.status(400).json({ error: 'settings object required' });
      const unsafe = ['adminToken', 'minerPrivateKey', 'minerPublicKey', 'dbPath', 'dataDir', 'plotsDir', 'port', 'p2pWsPort', 'discoveryPort', 'discoveryUrl', 'seedPeers', 'nodeUrl'];
      const sanitized = {};
      let changed = false;
      for (const [k, v] of Object.entries(updates)) {
        if (unsafe.includes(k)) continue;
        this.cfg[k] = v;
        sanitized[k] = v;
        changed = true;
      }
      if (changed) require('../../config/config').saveConfig(this.cfg);
      res.json({ ok: true, config: sanitized });
    });

    app.get('/api/logs', requireAdmin, (req, res) => res.json({ logs: getLogBuffer() }));

    app.post('/api/node/broadcast/block', syncLimiter, async (req, res) => {
      const block = req.body.block;
      if (!block) return res.status(400).json({ error: 'block required' });
      const startedAt = Date.now();
      const transferBytes = Buffer.byteLength(JSON.stringify(block));
      log('debug', `[P2P] received HTTP block height=${block.height} hash=${String(block.hash || '').slice(0, 12)} txs=${Array.isArray(block.transactions) ? block.transactions.length : 0} bytes=${transferBytes}`);
      let result = await this.chain.addBlock(block);
      log('debug', `[P2P] HTTP block result=${result.ok ? 'accepted' : 'rejected'} height=${block.height} hash=${String(block.hash || '').slice(0, 12)} reason=${result.motivo || 'ok'} local_height=${this.chain.height} duration_ms=${Date.now() - startedAt}`);
      res.json(result);
    });

    app.post('/api/node/broadcast/tx', p2pLimiter, async (req, res) => {
      const tx = req.body.tx;
      if (!tx) return res.status(400).json({ error: 'tx required' });
      const validation = await this.chain.validateTxForMempool(tx);
      if (!validation.ok) return res.status(400).json({ ok: false, error: validation.motivo });
      const result = this.chain.addMempoolTx(tx);
      log('info', `[TX] Mempool tx: hash=${tx.hash ? tx.hash.slice(0,10) : 'unknown'}, from=${tx.from_addr}, nonce=${tx.nonce}, result=${result.ok ? 'accepted' : 'rejected'}, reason=${result.motivo}`);
      if (result.ok && result.motivo !== 'Tx already in mempool') this.relayTx(tx);
      res.json(result);
    });

    app.post('/api/node/announce', p2pLimiter, (req, res) => {
      const url = require('../../config/config').normalizeUrl(req.body.url);
      if (!url) return res.status(400).json({ error: 'url required' });
      this.peers.add(url);
      this.peers.seen(url, safeInt(req.body.height, 0), req.body.node_id);
      log('debug', `[P2P] Node announce: url=${url}, height=${req.body.height}, node_id=${req.body.node_id}`);
      res.json({ ok: true, our_height: this.chain.height, node_id: this.NODE_ID, peers: this.peers.gossipPeers(10) });
    });

    app.get('/peers', syncLimiter, (req, res) => res.json({ peers: this.peers.gossipPeers(50), count: this.peers.count() }));
    app.post('/register', p2pLimiter, (req, res) => {
      const url = require('../../config/config').normalizeUrl(req.body.url);
      if (!url || !req.body.node_id) return res.status(400).json({ error: 'url and node_id required' });
      this.peers.add(url);
      log('debug', `[P2P] Registering peer: url=${url}, height=${req.body.height}, node_id=${req.body.node_id}`);
      this.peers.seen(url, safeInt(req.body.height, 0), req.body.node_id);
      this.registry.registerNode(url, req.body.node_id, { height: safeInt(req.body.height, 0), chain_work: req.body.chain_work, version: req.body.version, peers: safeInt(req.body.peers, 0) });
      res.json({ ok: true, peers: this.peers.gossipPeers(20), stats: this.registry.getStats(), chain_id: this.cfg.chainId });
    });

    app.post('/api/challenge/submit', mutationLimiter, async (req, res) => {
      const { challenge_id, miner, plot_id, deadline, proof_packet, proof_signature } = req.body;
      if (!challenge_id || !miner || !plot_id || deadline == null) return res.status(400).json({ error: 'challenge_id, miner, plot_id, deadline required' });
      const packet = proof_packet || {};
      if (proof_signature && !packet.proof_signature) packet.proof_signature = proof_signature;
      const result = this.challengeMgr.submitProof(this.chain, challenge_id, miner, plot_id, safeInt(deadline, -1), packet);
      log('info', `[MINERS] Challenge submit: miner=${miner}, plot_id=${plot_id}, deadline=${deadline}, result=${result.ok ? 'accepted' : 'rejected'}, reason=${result.motivo}`);
      res.json(result);
    });

    app.post('/api/node/forge', requireAdmin, async (req, res) => {
      const challenge = this.challengeMgr.getOrCreate();
      if (!challenge) return res.status(400).json({ error: 'no challenge' });
      await this.challengeMgr._forgeBlockForChallenge(this.chain, this.sync, challenge);
      log('info', `[P2P] Forge block request: challenge_id=${challenge.challenge_id}, height=${this.chain.height}`);
      res.json({ ok: true });
    });

    app.get('/api/admin/wallets', requireAdmin, (req, res) => {
      res.json({ wallets: this.db.prepare('SELECT address, balance, nonce, created_at, updated_at FROM users ORDER BY CAST(balance AS INTEGER) DESC LIMIT 200').all() });
    });

    app.get('/api/rewards/:address', (req, res) => {
      const rewards = this.db.prepare('SELECT * FROM block_rewards WHERE miner = ? ORDER BY block_height DESC LIMIT 100').all(req.params.address);
      res.json({ rewards });
    });

    app.get('/api/transactions', (req, res) => {
      const address = req.query.address;
      const limit = Math.min(parseInt(req.query.limit) || 50, 200);
      let rows;
      if (address) rows = this.db.prepare('SELECT * FROM transactions WHERE from_addr = ? OR to_addr = ? ORDER BY block_height DESC LIMIT ?').all(address, address, limit);
      else rows = this.db.prepare('SELECT * FROM transactions ORDER BY block_height DESC LIMIT ?').all(limit);
      res.json({ transactions: rows });
    });

    app.get('/api/transaction/:hash', (req, res) => {
      const tx = this.db.prepare('SELECT * FROM transactions WHERE hash = ?').get(req.params.hash);
      if (!tx) return res.status(404).json({ error: 'not found' });
      res.json(tx);
    });

    app.get('/api/nodes', (req, res) => res.json({ nodes: this.registry.all() }));

    app.get('/api/health', (req, res) => res.json({
      ok: true, status: 'ok', height: this.chain.height, hash: this.chain.bestHash,
      peers: this.peers.count(), mempool: this.db.prepare('SELECT COUNT(*) as c FROM mempool').get().c,
      mining: false, uptime: Math.floor((Date.now() - this._startTime) / 1000),
    }));

    app.get('/health', (req, res) => res.json({ ok: true }));
    app.get('/health/liveness', (req, res) => res.json({ ok: true }));
    app.get('/health/readiness', (req, res) => res.json({ ok: true }));

    let port = this.cfg.port;

    
    
    try {
      const { EthereumRPC } = require('../json-rpc/ethereum-rpc');
      this.ethRpc = new EthereumRPC(this.cfg, this.db, this.chain, this.sync, this.peers, this.smartContracts, this.NODE_ID);
      const rpcRouter = this.ethRpc.router();
      app.post('/', rpcRouter);
      app.use('/rpc', rpcRouter);
      log('info', `Ethereum JSON-RPC enabled on ${port} (routes: /, /rpc)`);
    } catch (e) {
      log('warn', `Ethereum JSON-RPC failed to initialize: ${e.message}`);
    }

    this.server = require('http').createServer(app);
    try {
      if (this.ethRpc && typeof this.ethRpc.attachWSServer === 'function') {
        const wss = new (require('ws').Server)({ server: this.server, path: '/ws' });
        this.ethRpc.attachWSServer(wss);
        log('info', `Ethereum WebSocket subscriptions enabled on ${port} (path: /ws)`);
      }
    } catch (e) {
      log('warn', `Ethereum WebSocket failed to initialize: ${e.message}`);
    }
    this.server.listen(port, '0.0.0.0', () => {
      log('info', `HTTP server listening on port ${port}`);
    });
    this.server.on('error', (err) => {
      if (err.code === 'EADDRINUSE') {
        port++;
        this.cfg.port = port;
        this.server.listen(port);
        log('info', `Port busy, using ${port}`);
      } else {
        log('error', `Server error: ${err.message}`);
        process.exit(1);
      }
    });
    this._startTime = Date.now();
    this._fetchPeerStorage();
    this._peerStorageTimer = setInterval(() => this._fetchPeerStorage(), 30000);
  }

  stop() {
    if (this._peerStorageTimer) { clearInterval(this._peerStorageTimer); this._peerStorageTimer = null; }
    if (this.server) try { this.server.close(); } catch {}
    try { require('../utils/worker-pool').terminateWorkerPool(); } catch {}
  }
}

module.exports = { Server};
