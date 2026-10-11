const fs = require('fs');
const path = require('path');
const { URL } = require('url');

const BASE_DIR = __dirname + '/..';
const CONFIG_DIR = path.join(BASE_DIR, 'config');

// Load config.env if present
try {
  const envPath = path.join(CONFIG_DIR, 'config.env');
  if (fs.existsSync(envPath)) {
    for (const line of fs.readFileSync(envPath, 'utf8').split('\n')) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith('#')) continue;
      const eq = trimmed.indexOf('=');
      if (eq < 1) continue;
      const k = trimmed.slice(0, eq).trim();
      let v = trimmed.slice(eq + 1).trim();
      const hash = v.indexOf(' #');
      if (hash >= 0) v = v.slice(0, hash).trim();
      v = v.replace(/^["']|["']$/g, '');
      if (k && !process.env[k]) process.env[k] = v;
    }
  }
} catch {}

const CONFIG_PATH = process.env.CHOCOHUB_CONFIG || path.join(CONFIG_DIR, 'node_config.json');

function loadConfig() {
  const defaults = {
    port: 3001,
    nodeUrl: null,
    seedPeers: ['https://seed1.chocohub.org/'],
    dbPath: path.join(BASE_DIR, 'db', 'choco-node.db'),
    dataDir: path.join(BASE_DIR, 'node-data'),
    plotsDir: path.join(BASE_DIR, 'plots'),
    snapshotsDir: path.join(BASE_DIR, 'snapshots'),
    syncIntervalMs: 1000,
    heartbeatMs: 20000,
    discoveryMs: 30000,
    blockTimeTarget: 60,
    minerAddress: '',
    minerPrivateKey: '',
    minerPublicKey: '',
    chainId: 19971971,
    chainName: 'CCpoc',
    symbol: 'CC',
    decimals: 18,
    maxPeers: 100,
    peerTimeoutMs: 30000,
    maxBlocksPerSync: 1000,
    peerFailThreshold: 25,
    peerBanThreshold: 50,
    version: '3.6.0-js',
    genesisTimestamp: 1735689600,
    maxFutureBlockSec: 120,
    difficultyAdjustBlocks: 8192,
    expectedTimePerBlock: 120,
    genesisBaseTarget: 2 ** 40,
    btDriftTolerance: 2,
    baseTargetMin: 2 ** 32,
    baseTargetMax: 2 ** 42,
    initialTarget: '0x00FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF',
    initialReward: '1650000000000000000',
    halvingInterval: 6300000,
    maxSupply: 21000000 * (10 ** 18),
    maxMempoolSize: 5000,
    mempoolTxTtlSec: 3600,
    txRelayHops: 6,
    challengeTtlSec: 60,
    challengeMinTtlSec: 3600,
    adminToken: '',
    verifyBlockSignatures: true,
    nodeActiveTtlMs: 5 * 60 * 1000,
    nodeRetainMs: 60 * 60 * 1000,
    maxNodes: 500,
    maxNodesPerIp: 10,
    maxPeersPerIp: 5,
    logLevel: 'info',
    minGasPrice: 10 ** 9,
    targetGasPerBlock: 2100000,
    maxGasPerBlock: 10500000,
    pruningEnabled: false,
    pruneKeepBlocks: 1000,
    pruneKeepDays: 30,
    anchorWindowSize: 8192,
    zkpEnabled: true,
    snapsyncEnabled: true,
    upnpEnabled: true,
    discoveryUrl: '',
    discoveryPort: 7777,
smartContractsEnabled: true,
  corsOrigins: [],
  p2pWsPort: 0,
  };

  if (fs.existsSync(CONFIG_PATH)) {
    try {
      const saved = JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf8'));
      Object.assign(defaults, saved);
      if (saved.seedPeers) defaults.seedPeers = normalizeSeedPeers(saved.seedPeers);
      if (saved.nodeUrl) defaults.nodeUrl = normalizeUrl(saved.nodeUrl) || defaults.nodeUrl;
    } catch {}
  }

  const envInt = (key, def) => { const v = process.env[key]; return v ? parseInt(v, 10) || def : def; };
  const envFloat = (key, def) => { const v = process.env[key]; return v ? (parseFloat(v) || def) : def; };
  const envStr = (key, def) => process.env[key] || def;
  const envBool = (key, def) => { const v = process.env[key]; return v ? v.toLowerCase() === 'true' : def; };

  defaults.port = envInt('PORT', defaults.port);
  defaults.nodeUrl = normalizeUrl(envStr('NODE_URL', '')) || defaults.nodeUrl;
  const envSeedPeers = normalizeSeedPeers(envStr('SEED_PEERS', ''));
  if (envSeedPeers.length > 0) defaults.seedPeers = envSeedPeers;
  defaults.dbPath = envStr('DB_PATH', defaults.dbPath);
  defaults.dataDir = envStr('DATA_DIR', defaults.dataDir);
  defaults.plotsDir = envStr('PLOTS_DIR', defaults.plotsDir);
  defaults.syncIntervalMs = envInt('SYNC_MS', defaults.syncIntervalMs);
  defaults.heartbeatMs = envInt('HEARTBEAT_MS', defaults.heartbeatMs);
  defaults.discoveryMs = envInt('DISCOVERY_MS', defaults.discoveryMs);
  defaults.blockTimeTarget = Math.max(10, envInt('BLOCK_TIME', defaults.blockTimeTarget));
  defaults.minerAddress = envStr('MINER_ADDRESS', defaults.minerAddress);
  defaults.minerPrivateKey = envStr('MINER_PRIVATE_KEY', defaults.minerPrivateKey);
  defaults.minerPublicKey = envStr('MINER_PUBLIC_KEY', defaults.minerPublicKey);
  defaults.plotSizeGb = envFloat('PLOT_SIZE', defaults.plotSizeGb);
  defaults.logLevel = envStr('LOG_LEVEL', defaults.logLevel);
  defaults.adminToken = envStr('ADMIN_TOKEN', defaults.adminToken);
  defaults.maxBlocksPerSync = envInt('MAX_BLOCKS_PER_SYNC', defaults.maxBlocksPerSync);
  defaults.maxMempoolSize = envInt('MAX_MEMPOOL_SIZE', defaults.maxMempoolSize);
  defaults.minGasPrice = envInt('MIN_GAS_PRICE', defaults.minGasPrice);
  defaults.targetGasPerBlock = envInt('TARGET_GAS_PER_BLOCK', defaults.targetGasPerBlock);
  defaults.maxGasPerBlock = envInt('MAX_GAS_PER_BLOCK', defaults.maxGasPerBlock);
  defaults.smartContractsEnabled = envBool('SMART_CONTRACTS_ENABLED', defaults.smartContractsEnabled);
  defaults.corsOrigins = (process.env.CORS_ORIGINS || '').split(',').map(s => s.trim()).filter(Boolean);
  defaults.p2pExchangeEnabled = envBool('P2P_EXCHANGE_ENABLED', defaults.p2pExchangeEnabled);
  defaults.maxP2POffersPerUser = envInt('MAX_P2P_OFFERS_PER_USER', defaults.maxP2POffersPerUser);
  defaults.p2pOfferTtlSec = envInt('P2P_OFFER_TTL_SEC', defaults.p2pOfferTtlSec);
  defaults.p2pWsPort = envInt('P2P_WS_PORT', defaults.p2pWsPort);
  defaults.challengeTtlSec = envInt('CHALLENGE_TTL_SEC', defaults.challengeTtlSec);
  defaults.challengeMinTtlSec = envInt('CHALLENGE_MIN_TTL_SEC', defaults.challengeMinTtlSec);
  defaults.challengeExpiredGraceSec = envInt('CHALLENGE_EXPIRED_GRACE_SEC', defaults.challengeExpiredGraceSec);

  if (defaults.nodeUrl) {
    const self = defaults.nodeUrl.toLowerCase();
    const filtered = defaults.seedPeers.filter(u => u.toLowerCase() !== self);
    if (filtered.length < defaults.seedPeers.length) defaults.seedPeers = filtered;
  }

  // Derive secp256k1 miner public key / EVM miner address from the private
  // key when they are missing or still in the legacy ed25519 format. Keeps
  // block/challenge signing (signMessage/secp256k1) and proof verification
  // consistent after the ed25519 -> secp256k1 migration.
  try {
    if (defaults.minerPrivateKey && typeof defaults.minerPrivateKey === 'string' && /^[0-9a-fA-F]{64}$/.test(defaults.minerPrivateKey)) {
      const cryptoApi = require('../src/crypto-utils/crypto');
      const pub = cryptoApi.secpPublicKeyFromPrivate(defaults.minerPrivateKey);
      const derivedPub = pub.toString('base64');
      if (!defaults.minerPublicKey || !/^[A-Za-z0-9+/]{44}={0,2}$/.test(defaults.minerPublicKey)) {
        defaults.minerPublicKey = derivedPub;
      }
      if (!defaults.minerAddress || !/^0x[0-9a-fA-F]{40}$/.test(String(defaults.minerAddress))) {
        defaults.minerAddress = cryptoApi.privateKeyToAddress(defaults.minerPrivateKey);
      } else {
        defaults.minerAddress = cryptoApi.toChecksumAddress(defaults.minerAddress);
      }
    }
  } catch (e) {
    log('warn', `Could not derive secp miner keys: ${e.message}`);
  }

  return defaults;
}

function normalizeUrl(url) {
  if (!url || typeof url !== 'string') return null;
  url = url.split(' #')[0].trim();
  if (!url.startsWith('http://') && !url.startsWith('https://')) {
    if (url.includes(':')) {
      const parts = url.split(':');
      const port = parseInt(parts[parts.length - 1], 10);
      if (port >= 1 && port <= 65535) {
        const host = parts.slice(0, -1).join(':').replace(/^\[|]$/g, '');
        return `http://${host}:${port}`;
      }
    }
    return null;
  }
  try {
    const u = new URL(url);
    if (!u.hostname) return null;
    return u.port ? `${u.protocol}//${u.hostname}:${u.port}` : `${u.protocol}//${u.hostname}`;
  } catch { return null; }
}

function normalizeSeedPeers(value) {
  if (!value) return [];
  const raw = Array.isArray(value) ? value : String(value).split(',').map(s => s.trim()).filter(Boolean);
  const seen = new Set();
  return raw.map(s => normalizeUrl(s)).filter(u => { if (!u || seen.has(u)) return false; seen.add(u); return true; });
}

function saveConfig(cfg) {
  const sensitive = new Set(['minerPrivateKey', 'adminToken']);
  const safe = {};
  for (const [k, v] of Object.entries(cfg)) { if (!sensitive.has(k)) safe[k] = v; }
  try { fs.writeFileSync(CONFIG_PATH, JSON.stringify(safe, null, 2)); } catch (e) { log('warn', `Config save failed: ${e.message}`); }
}

const LOG_LEVELS = { trace: 0, debug: 1, info: 2, warn: 3, error: 4 };
let _logLevel = 2;
let _logBuffer = [];
const MAX_LOG_BUFFER = 500;

function setLogLevel(level) { _logLevel = LOG_LEVELS[level] || 2; }

function log(level, ...args) {
  if ((LOG_LEVELS[level] || 2) < _logLevel) return;
  const ts = new Date().toISOString().slice(11, 23);
  const levelColors = { trace: '\x1b[90m', debug: '\x1b[36m', info: '\x1b[32m', warn: '\x1b[33m', error: '\x1b[31m' };
  const tagColors = { P2P: '\x1b[35m', TX: '\x1b[93m', Discovery: '\x1b[96m', MINER: '\x1b[95m' };
  const lc = levelColors[level] || '\x1b[32m';
  const prefix = `${lc}${{ trace: '[TRC]', debug: '[DBG]', info: '[INF]', warn: '[WRN]', error: '[ERR]' }[level] || '[INF]'}\x1b[0m`;
  let msg = args.join(' ');
  msg = msg.replace(/\[(P2P|TX|Discovery|MINER|MINERS|Sync)\]/g, (m, tag) => `${tagColors[tag] || '\x1b[90m'}[${tag}]\x1b[0m`);
  const line = `${ts} ${prefix} ${msg}`;
  if (level === 'error' || level === 'warn') console.error(line); else console.log(line);
  _logBuffer.push({ ts: Date.now(), level, msg: args.join(' ') });
  if (_logBuffer.length > MAX_LOG_BUFFER) _logBuffer = _logBuffer.slice(-MAX_LOG_BUFFER);
}

function getLogBuffer() { return _logBuffer.slice(-200); }

module.exports = { loadConfig, saveConfig, normalizeUrl, normalizeSeedPeers, BASE_DIR, CONFIG_PATH, log, setLogLevel, getLogBuffer };
