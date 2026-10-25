const WebSocket = require('ws');
const { log } = require('../../config/config');

const { toWireBlock } = require('../Blockchain/transaction-wire');

class P2PWebSocketServer {
  constructor(port, chain, sync, peers) {
    this.port = port;
    this.chain = chain;
    this.sync = sync;
    this.peers = peers;
    this.wss = null;
    this.clients = new Map();
    this._messageHandlers = new Map();
    this._blockRateLimiter = new Map();
    this._txRateLimiter = new Map();
    this._setupHandlers();
  }

  _setupHandlers() {
    this._messageHandlers.set('subscribe', (ws, msg) => this._handleSubscribe(ws, msg));
    this._messageHandlers.set('unsubscribe', (ws, msg) => this._handleUnsubscribe(ws, msg));
    this._messageHandlers.set('get_blocks', (ws, msg) => this._handleGetBlocks(ws, msg));
    this._messageHandlers.set('get_mempool', (ws, msg) => this._handleGetMempool(ws, msg));
    this._messageHandlers.set('ping', (ws, msg) => ws.send(JSON.stringify({ type: 'pong', timestamp: Date.now() })));
    this._messageHandlers.set('new_block', (ws, msg) => this._handleNewBlock(ws, msg));
    this._messageHandlers.set('new_tx', (ws, msg) => this._handleNewTx(ws, msg));
  }

  _handleSubscribe(ws, msg) {
    const topics = msg.topics || ['blocks', 'transactions'];
    ws.subscriptions = ws.subscriptions || new Set();
    for (const t of topics) ws.subscriptions.add(t);
    ws.send(JSON.stringify({ type: 'subscribed', topics: Array.from(ws.subscriptions) }));
  }

  _handleUnsubscribe(ws, msg) {
    const topics = msg.topics || ['blocks', 'transactions'];
    ws.subscriptions = ws.subscriptions || new Set();
    for (const t of topics) ws.subscriptions.delete(t);
    ws.send(JSON.stringify({ type: 'unsubscribed', topics: Array.from(ws.subscriptions) }));
  }

  async _handleGetBlocks(ws, msg) {
    const from = msg.from || 0;
    const limit = Math.min(msg.limit || 50, 200);
    const blocks = [];
    for (let h = from; h < from + limit; h++) {
      const b = this.chain.getBlock(h);
      if (!b) break;
      blocks.push(b);
    }
    ws.send(JSON.stringify({ type: 'blocks', blocks, from, count: blocks.length }));
  }

  async _handleGetMempool(ws, msg) {
    const limit = Math.min(msg.limit || 200, 500);
    const txs = this.chain.db.prepare('SELECT * FROM mempool ORDER BY CAST(fee AS INTEGER) DESC LIMIT ?').all(limit)
      .map(r => { try { return JSON.parse(r.raw); } catch { return null; } })
      .filter(Boolean);
    ws.send(JSON.stringify({ type: 'mempool', transactions: txs, count: txs.length }));
  }

  _handleNewBlock(ws, msg) {
    if (!msg.block) return;
    const ip = ws.peerIp || 'unknown';
    const now = Date.now();
    const lastSeen = this._blockRateLimiter.get(ip) || 0;
    if (now - lastSeen < 500) return;
    this._blockRateLimiter.set(ip, now);
    this.broadcast('new_block', { block: msg.block }, ws);
  }

  _handleNewTx(ws, msg) {
    if (!msg.tx) return;
    const ip = ws.peerIp || 'unknown';
    const now = Date.now();
    const lastSeen = this._txRateLimiter.get(ip) || 0;
    if (now - lastSeen < 500) return;
    this._txRateLimiter.set(ip, now);
    this.broadcast('new_tx', { tx: msg.tx }, ws);
  }

  start() {
    return new Promise((resolve, reject) => {
      this._startTime = Date.now();
      this.wss = new WebSocket.Server({ port: this.port, maxPayload: 2 * 1024 * 1024, clientTracking: true });
      
      this.wss.on('listening', () => {
        log('info', `[P2P-WS] WebSocket server listening on port ${this.port}`);
        resolve();
      });
      
      this.wss.on('error', (err) => {
        if (err.code === 'EADDRINUSE') {
          log('warn', `[P2P-WS] Port ${this.port} in use, trying ${this.port + 1}`);
          this.port++;
          this.wss.close();
          this.start().then(resolve, reject);
        } else {
          reject(err);
        }
      });

      this.wss.on('connection', (ws, req) => {
        const ip = req.socket.remoteAddress;
        ws.peerIp = req.socket.remoteAddress;
        ws.isAlive = true;
        ws.subscriptions = new Set(['blocks', 'transactions']);
        this.clients.set(ws, { ip, connectedAt: Date.now() });
        
        log('debug', `[P2P-WS] Client connected: ${ip} (total: ${this.clients.size})`);

        ws.on('pong', () => { ws.isAlive = true; });
        
        ws.on('message', (data) => {
          try {
            const msg = JSON.parse(data.toString());
            const handler = this._messageHandlers.get(msg.type);
            if (handler) {
              Promise.resolve(handler(ws, msg)).catch((err) => {
                log('warn', `[P2P-WS] Handler error for ${msg.type}: ${err.message}`);
                try { ws.send(JSON.stringify({ type: 'error', message: err.message || 'Handler failed' })); } catch {}
              });
            } else ws.send(JSON.stringify({ type: 'error', message: `Unknown message type: ${msg.type}` }));
          } catch (e) {
            ws.send(JSON.stringify({ type: 'error', message: 'Invalid JSON' }));
          }
        });

        ws.on('close', () => {
          this.clients.delete(ws);
          log('debug', `[P2P-WS] Client disconnected: ${ip} (total: ${this.clients.size})`);
        });

        ws.on('error', (err) => {
          log('warn', `[P2P-WS] Client error: ${err.message}`);
        });

        ws.send(JSON.stringify({ 
          type: 'welcome', 
          height: this.chain.height, 
          hash: this.chain.bestHash,
          chainWork: (this.chain.getBlock(this.chain.height) || {}).chain_work || '0'
        }));
      });

      this._pingTimer = setInterval(() => {
        for (const ws of this.wss.clients) {
          if (!ws.isAlive) {
            
            
            
            this.clients.delete(ws);
            ws.terminate();
            continue;
          }
          ws.isAlive = false;
          ws.ping();
        }
      }, 30000);

      this._broadcastTimer = setInterval(() => {
        this.broadcast('heartbeat', { 
          height: this.chain.height, 
          hash: this.chain.bestHash,
          timestamp: Date.now()
        });
      }, 60000);
    });
  }

  _topicMatches(sub, type) {
    if (sub === 'all' || sub === type) return true;
    const aliases = {
      new_block: ['blocks'],
      blocks: ['new_block'],
      new_tx: ['transactions'],
      transactions: ['new_tx'],
    };
    return (aliases[type] || []).includes(sub) || (aliases[sub] || []).includes(type);
  }

  broadcast(type, data, excludeWs = null) {
    const msg = JSON.stringify({ type, data, timestamp: Date.now() });
    let queued = 0;
    for (const ws of this.wss.clients) {
      if (ws !== excludeWs && ws.readyState === WebSocket.OPEN) {
        if (!ws.subscriptions || Array.from(ws.subscriptions).some(sub => this._topicMatches(sub, type))) {
          ws.send(msg);
          queued++;
        }
      }
    }
    if (type === 'new_block' || type === 'new_tx') {
      const item = data && (data.block || data.tx);
      log('debug', `[P2P-WS] queued ${type} clients=${queued} bytes=${Buffer.byteLength(msg)}${type === 'new_block' ? ` height=${item && item.height} hash=${String(item && item.hash || '').slice(0, 12)}` : ` hash=${String(item && item.hash || '').slice(0, 12)}`}`);
    }
  }

  broadcastBlock(block) {
    const payload = { ...toWireBlock(block), chain_id: String(block.chain_id || '') };
    delete payload.rewards_json;
    delete payload.body_pruned;
    this.broadcast('new_block', { block: payload });
  }

  broadcastTx(tx) {
    this.broadcast('new_tx', { tx });
  }

  getStats() {
    const subs = new Map();
    for (const [ws, _info] of this.clients) {
      if (ws.subscriptions) {
        for (const s of ws.subscriptions) subs.set(s, (subs.get(s) || 0) + 1);
      }
    }
    return {
      connected: this.clients.size,
      subscriptions: Object.fromEntries(subs),
      uptime: Date.now() - (this._startTime || Date.now())
    };
  }

  stop() {
    clearInterval(this._pingTimer);
    clearInterval(this._broadcastTimer);
    if (this.wss) {
      for (const ws of this.wss.clients) ws.close();
      this.wss.close();
    }
  }
}

class P2PWebSocketClient {
  constructor(url, chain, sync, peers) {
    this.url = url;
    this.chain = chain;
    this.sync = sync;
    this.peers = peers;
    this.ws = null;
    this.reconnectTimer = null;
    this.connected = false;
    this._messageQueue = [];
    this._seenBlockHashes = new Set();
  }

  connect() {
    return new Promise((resolve, reject) => {
      try {
        this.ws = new WebSocket(this.url);
        
        this.ws.on('open', () => {
          this.connected = true;
          this._seenBlockHashes.clear();
          log('info', `[P2P-WS] Connected to ${this.url}`);
          this._send({ type: 'subscribe', topics: ['blocks', 'transactions'] });
          this._flushQueue();
          resolve();
        });

        this.ws.on('message', (data) => {
          try {
            const msg = JSON.parse(data.toString());
            this._handleMessage(msg);
          } catch (e) {}
        });

        this.ws.on('close', () => {
          this.connected = false;
          log('warn', `[P2P-WS] Disconnected from ${this.url}, reconnecting in 5s`);
          this.reconnectTimer = setTimeout(() => this.connect(), 5000);
        });

        this.ws.on('error', (err) => {
          if (!this.connected) reject(err);
        });
      } catch (e) {
        reject(e);
      }
    });
  }

  _send(msg) {
    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify(msg));
    } else {
      this._messageQueue.push(msg);
    }
  }

  _flushQueue() {
    while (this._messageQueue.length) this._send(this._messageQueue.shift());
  }

  _handleMessage(msg) {
    switch (msg.type) {
      case 'new_block':
        if (msg.data?.block) this._handleNewBlock(msg.data.block);
        break;
      case 'new_tx':
        if (msg.data?.tx) this._handleNewTx(msg.data.tx);
        break;
      case 'blocks':
        if (msg.data?.blocks) this._handleBlocks(msg.data.blocks);
        break;
      case 'mempool':
        if (msg.data?.transactions) this._handleMempool(msg.data.transactions);
        break;
      case 'heartbeat':
        this._handleHeartbeat(msg.data);
        break;
    }
  }

  async _handleNewBlock(block) {
    if (block.height <= this.chain.height) return;
    if (this.chain.db.prepare('SELECT 1 FROM blocks WHERE hash = ?').get(block.hash)) return;
    
    log('debug', `[P2P-WS] Received new block #${block.height} via WebSocket`);
    log('debug', `[P2P-WS] block payload height=${block.height} hash=${String(block.hash || '').slice(0, 12)} txs=${(block.transactions || []).length} bytes=${Buffer.byteLength(JSON.stringify(block))}`);
    
    block._from_local_forge = false;
    let result = await this.chain.addBlock(block);
    log('debug', `[P2P-WS] block result=${result.ok ? 'accepted' : 'rejected'} height=${block.height} hash=${String(block.hash || '').slice(0, 12)} reason=${result.motivo || 'ok'}`);
    
    if (result.ok) {
      this._send({ type: 'subscribe', topics: ['blocks', 'transactions'] });
    }
  }

  async _handleNewTx(tx) {
    const release = this.chain.tryAcquireStableRead();
    if (!release) return;
    try {
      if (this.chain.db.prepare('SELECT 1 FROM mempool WHERE hash = ?').get(tx.hash)) return;
      if (this.chain.db.prepare('SELECT 1 FROM transactions WHERE hash = ?').get(tx.hash)) return;

      log('debug', `[P2P-WS] received transaction hash=${String(tx.hash || '').slice(0, 12)} bytes=${Buffer.byteLength(JSON.stringify(tx))}`);
      const validation = await this.chain.validateTxForMempool(tx);
      if (validation.ok) {
        const result = this.chain.addMempoolTx(tx);
        log('debug', `[P2P-WS] transaction result=${result.ok ? 'accepted' : 'rejected'} hash=${String(tx.hash || '').slice(0, 12)} reason=${result.motivo || 'ok'}`);
        if (result.ok && result.motivo !== 'Tx already in mempool') {
          this.sync.broadcastTx(tx);
        }
      } else {
        log('debug', `[P2P-WS] transaction rejected hash=${String(tx.hash || '').slice(0, 12)} reason=${validation.motivo || 'invalid'}`);
      }
    } finally {
      release();
    }
  }

  async _handleBlocks(blocks) {
    for (const block of blocks) {
      if (block.height <= this.chain.height) continue;
      if (this.chain.db.prepare('SELECT 1 FROM blocks WHERE hash = ?').get(block.hash)) continue;
      
      block._from_local_forge = false;
      let result = await this.chain.addBlock(block);
    }
  }

async _handleMempool(txs) {
    const release = this.chain.tryAcquireStableRead();
    if (!release) return;
    try {
      for (const tx of txs) {
        if (this.chain.db.prepare('SELECT 1 FROM mempool WHERE hash = ?').get(tx.hash)) continue;
        if (this.chain.db.prepare('SELECT 1 FROM transactions WHERE hash = ?').get(tx.hash)) continue;

        const validation = await this.chain.validateTxForMempool(tx);
        if (validation.ok) this.chain.addMempoolTx(tx);
      }
    } finally {
      release();
    }
  }

  _handleHeartbeat(data) {
    if (this.chain._stateTransitionPending) return;
    if (data.height > this.chain.height) {
      this._send({ type: 'get_blocks', from: this.chain.height, limit: 100 });
    }
  }

  stop() {
    clearTimeout(this.reconnectTimer);
    if (this.ws) this.ws.close();
  }
}

function createP2PWebSocketServer(port, chain, sync, peers) {
  return new P2PWebSocketServer(port, chain, sync, peers);
}

function connectP2PWebSocketClient(url, chain, sync, peers) {
  return new P2PWebSocketClient(url, chain, sync, peers);
}

module.exports = { P2PWebSocketServer, P2PWebSocketClient, createP2PWebSocketServer, connectP2PWebSocketClient };
