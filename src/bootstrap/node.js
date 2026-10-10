process.on('uncaughtException', (e) => { console.error('UNCAUGHT:', e.stack || e); });
process.on('unhandledRejection', (e) => { console.error('UNHANDLED REJECTION:', e && e.stack ? e.stack : e); });

const crypto = require('crypto');
const path = require('path');
const fs = require('fs');
const { loadConfig, saveConfig, log, setLogLevel } = require('../../config/config');
const { initDB } = require('../Blockchain/db');
const { Chain } = require('../Blockchain/chain');
const { ChallengeManager } = require('../Blockchain/challenge');
const { PeerManager } = require('../P2P/peers');
const { SyncEngine } = require('../P2P/sync');
const { Server } = require('../api/server');
const { P2PWebSocketServer } = require('../P2P/p2p-ws');

class NodeRegistry {
  constructor(db) {
    this.db = db;
  }
  getStats() {
    const total = this.db.prepare('SELECT COUNT(*) as c FROM nodes').get().c;
    return { total_nodes: total, active_nodes: total, seed_version: '3.6.0-js' };
  }
  registerNode(url, nodeId, opts = {}) {
    const now = Math.floor(Date.now() / 1000);
    this.db.prepare('INSERT OR REPLACE INTO nodes (url, node_id, height, chain_work, version, peers, first_seen, last_seen) VALUES (?,?,?,?,?,?,COALESCE((SELECT first_seen FROM nodes WHERE url = ?), ?),?)').run(url, nodeId, opts.height || 0, opts.chain_work || '0', opts.version || '', opts.peers || 0, url, now, now);
  }
  all() { return this.db.prepare('SELECT * FROM nodes ORDER BY last_seen DESC').all(); }
}

class ChocoNode {
  constructor(cfg) {
    this.cfg = cfg;
    this.NODE_ID = crypto.randomBytes(16).toString('hex');
    this.db = null;
    this.chain = null;
    this.peers = null;
    this.challengeMgr = null;
    this.sync = null;
    this.server = null;
    this.p2pWsServer = null;
    this._stopDiscovery = null;
  }

  async start() {
    const cfg = this.cfg;
    setLogLevel(cfg.logLevel);

    for (const d of [cfg.dataDir, path.dirname(cfg.dbPath), cfg.plotsDir]) {
      try { fs.mkdirSync(d, { recursive: true }); } catch {}
    }

    if (!cfg.adminToken || cfg.adminToken.length < 16) {
      cfg.adminToken = crypto.randomBytes(16).toString('hex');
      try { fs.writeFileSync(path.join(cfg.dataDir, 'admin_token.txt'), cfg.adminToken); } catch {}
      log('info', `Admin token: ${cfg.adminToken}`);
    }

    this._configPath = require('../../config/config').CONFIG_PATH;

    this._printBanner();

    this.db = initDB(cfg.dbPath, cfg);
    this.smartContracts = null;
    if (cfg.smartContractsEnabled) {
      try {
        const SC = require('../vm/smartcontracts');
        this.smartContracts = SC;
        this.smartContracts.setDatabase(this.db);
        log('info', `Smart contracts (EVM) enabled`);
      } catch (e) {
        log('warn', `Smart contracts enabled but VM unavailable: ${e.message}`);
        this.smartContracts = null;
      }
    } else {
      log('info', `Smart contracts (EVM) disabled`);
    }

    this.chain = new Chain(this.db, cfg);
    if (this.smartContracts) this.chain.setContractExecutor(this.smartContracts);
    this.peers = new PeerManager(this.db, cfg);
    for (const seed of (cfg.seedPeers || [])) this.peers.add(seed);
    this.challengeMgr = new ChallengeManager(this.db, this.chain, cfg);
    if (!cfg.minerPrivateKey || !String(cfg.minerAddress || '')) {
      log('warn', `[FORGE] No minerPrivateKey/minerAddress configured — this node will NOT forge blocks (set MINER_PRIVATE_KEY to enable)`);
    }
    this.registry = new NodeRegistry(this.db);
    this.sync = new SyncEngine(this.db, cfg, this.chain, this.peers, this.challengeMgr, this.NODE_ID);

    this.server = new Server(cfg, this.db, this.chain, this.peers, this.sync, this.challengeMgr, this.registry, this.NODE_ID, this.smartContracts, this.p2pWsServer);
    this.server.start();

    if (cfg.p2pWsPort && cfg.p2pWsPort > 0) {
      this.p2pWsServer = new P2PWebSocketServer(cfg.p2pWsPort, this.chain, this.sync, this.peers);
      await this.p2pWsServer.start();
      log('info', `[P2P-WS] WebSocket P2P server started on port ${cfg.p2pWsPort}`);
      this.server.p2pWsServer = this.p2pWsServer;
    }

    this._intervals = [
      setInterval(() => { try { this.peers.decayHealth(); } catch {} }, 300000),
      setInterval(() => { try { this.chain.cleanMempool(); } catch {} }, 60000),
      setInterval(() => { try { this.chain.retireOldBlocks(); } catch {} }, 600000),
      setInterval(() => { try { if (!this.db || this.db.open === false) return; this.challengeMgr.finalizeExpiredChallenges(this.chain, this.sync).catch(e => log('error', `Finalize error: ${e.message}`)); } catch {} }, 5000),
      setInterval(() => { this.sync.loopSync().catch(() => {}); }, cfg.syncIntervalMs || 10000),
      setInterval(() => { this.sync.heartbeat().catch(() => {}); }, cfg.heartbeatMs || 20000),
      setInterval(() => { this.sync.plotsGossip().catch(() => {}); }, Math.max(30000, (cfg.heartbeatMs || 20000) * 3)),
      setInterval(() => { this.sync.discoverPeers().catch(() => {}); }, cfg.discoveryMs || 30000),
    ];

    setTimeout(async () => {
      log('info', 'Initial sync...');
      for (let i = 0; i < 3; i++) { try { await this.sync.loopSync(); } catch {} if (this.chain.height > 0) break; }
      try { await this.sync.mempoolSync(); } catch {}
      if (cfg.nodeUrl) {
        await this.sync.announce();
        await this.sync.announce();
      }
    }, 2000);

    this._setupShutdown();
  }

  _printBanner() {
    const cfg = this.cfg;
    console.log('');
    console.log('\x1b[32m\x1b[1m' +
      ' ██████╗ ██████╗██████╗  ██████╗  ██████╗    ███╗   ██╗ ██████╗ ██████╗ ███████╗\n' +
      '██║     ██║     ██████╔╝██║   ██║██║         ██╔██╗ ██║██║   ██║██║  ██║██╔════╝\n' +
      '██║     ██║     ██╔═══╝ ██║   ██║██║         ██║╚██╗██║██║   ██║██║  ██║█████╗  \n' +
      '██║     ██║     ██║     ██║   ██║██║         ██║ ╚████║██║   ██║██║  ██║██╔══╝  \n' +
      '╚██████╗╚██████╗██║     ╚██████╔╝╚██████╗    ██║  ╚███║╚██████╔╝██████╔╝███████╗\n' +
      ' ╚═════╝ ╚═════╝╚═╝      ╚═════╝  ╚═════╝    ╚═╝   ╚══╝ ╚═════╝ ╚═════╝ ╚══════╝');
    console.log('');
    console.log(`  \x1b[2mPort: ${cfg.port}  |  Peers: ${cfg.seedPeers.length} seeds\x1b[0m`);
    if (cfg.discoveryPort > 0) console.log(`  \x1b[2mDiscovery: WS on port ${cfg.discoveryPort}\x1b[0m`);
    if (cfg.discoveryUrl) console.log(`  \x1b[2mDiscovery client: ${cfg.discoveryUrl}\x1b[0m`);
    console.log('');
  }

  _setupShutdown() {
    const shutdown = () => {
      if (this._stopDiscovery) this._stopDiscovery();
      log('info', 'Shutting down...');
      if (this.p2pWsServer) this.p2pWsServer.stop();
      if (this.server) this.server.stop();
      if (this._intervals) this._intervals.forEach(t => clearInterval(t));
      setTimeout(() => {
        try { this.db.close(); } catch {}
        setTimeout(() => process.exit(0), 1000);
      }, 1000);
    };
    process.on('SIGINT', shutdown);
    process.on('SIGTERM', shutdown);
  }
}

module.exports = { ChocoNode, NodeRegistry };
