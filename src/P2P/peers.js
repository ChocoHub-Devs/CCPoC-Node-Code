const { log, normalizeUrl } = require('../../config/config');

const TIMEOUT_MS = [0, 5 * 60_000, 15 * 60_000, 60 * 60_000, 6 * 3600_000];

function timeoutForFail(failCount) {
  const idx = Math.min(failCount, TIMEOUT_MS.length - 1);
  return TIMEOUT_MS[idx];
}

function isUnsafePeerUrl(value) {
  try {
    const u = new (require('url').URL)(value);
    if (!['http:', 'https:', 'ws:', 'wss:'].includes(u.protocol)) return true;
    const h = u.hostname.toLowerCase();
    if (h === 'localhost' || h.endsWith('.localhost') || h.endsWith('.local')) return true;
    if (/^(127\.|10\.|192\.168\.|169\.254\.)/.test(h)) return true;
    const m = h.match(/^172\.(\d+)\./);
    if (m && Number(m[1]) >= 16 && Number(m[1]) <= 31) return true;
    if (h === '::1' || h.startsWith('fc') || h.startsWith('fd') || h.startsWith('fe80:')) return true;
    return false;
  } catch { return true; }
}

class PeerManager {
  constructor(db, cfg) {
    this.db = db;
    this.cfg = cfg;
  }

  _notTimedOut() {
    const now = Date.now();
    return `banned = 0 AND (timeout_until = 0 OR timeout_until <= ${now})`;
  }

  all(limit = 100) {
    return this.db.prepare(`SELECT * FROM peers WHERE ${this._notTimedOut()} ORDER BY health DESC, last_seen DESC LIMIT ?`).all(limit);
  }

  active(limit = 50) {
    const now = Date.now();
    const ttl = this.cfg.peerTimeoutMs || 30000;
    return this.db.prepare(`SELECT * FROM peers WHERE ${this._notTimedOut()} AND ? - last_seen < ? ORDER BY health DESC, last_seen DESC LIMIT ?`).all(now, ttl, limit);
  }

  timedOut() {
    const now = Date.now();
    return this.db.prepare('SELECT * FROM peers WHERE banned = 0 AND timeout_until > 0 AND timeout_until > ?').all(now);
  }

  banned() {
    return this.db.prepare('SELECT * FROM peers WHERE banned = 1').all();
  }

  add(url) {
    if (!url) return false;
    const normalized = normalizeUrl(url);
    if (!normalized) return false;
    if (isUnsafePeerUrl(normalized)) return false;
    try { if (this.cfg.nodeUrl && new (require('url').URL)(normalized).hostname === new (require('url').URL)(this.cfg.nodeUrl).hostname) return false; } catch {}
    const existing = this.db.prepare('SELECT * FROM peers WHERE url = ?').get(normalized);
    if (existing) {
      const clears = existing.timeout_until > Date.now() ? ', fail_count = 0, timeout_until = 0' : '';
      this.db.prepare(`UPDATE peers SET last_seen = ?, health = MIN(1.0, health + 0.05)${clears} WHERE url = ?`).run(Date.now(), normalized);
      if (clears) log('info', `Peer recovered: ${normalized}`);
      return false;
    }
    this.db.prepare('INSERT OR IGNORE INTO peers (url, first_seen, last_seen, health) VALUES (?, ?, ?, ?)').run(normalized, Date.now(), Date.now(), 1.0);
    log('info', `Peer added: ${normalized}`);
    return true;
  }

  seen(url, height, nodeId) {
    if (!url) return;
    const normalized = normalizeUrl(url);
    if (!normalized) return;
    if (isUnsafePeerUrl(normalized)) return;
    const existing = this.db.prepare('SELECT * FROM peers WHERE url = ?').get(normalized);
    const wasTimedOut = existing && existing.timeout_until > Date.now();
    this.db.prepare("UPDATE peers SET last_seen = ?, height = COALESCE(?, height), node_id = COALESCE(NULLIF(?, ''), node_id), health = MIN(1.0, health + 0.02), fail_count = 0, timeout_until = 0 WHERE url = ?").run(Date.now(), height == null ? null : height, nodeId || '', normalized);
    if (wasTimedOut) log('info', `Peer recovered: ${normalized}`);
  }

  remove(url) {
    this.db.prepare('DELETE FROM peers WHERE url = ?').run(url);
  }

  fail(url) {
    if (!url) return;
    const peer = this.db.prepare('SELECT * FROM peers WHERE url = ?').get(url);
    if (!peer) return;
    const failCount = (peer.fail_count || 0) + 1;
    const threshold = this.cfg.peerBanThreshold || 50;
    const timeoutMs = timeoutForFail(failCount);
    const timeoutUntil = Date.now() + timeoutMs;
    if (failCount >= threshold) {
      this.db.prepare('UPDATE peers SET fail_count = ?, health = health - 0.1, banned = 1, timeout_until = 0 WHERE url = ?').run(failCount, url);
      log('warn', `Peer banned: ${url}`);
    } else {
      this.db.prepare('UPDATE peers SET fail_count = ?, health = MAX(0.1, health - 0.1), timeout_until = ? WHERE url = ?').run(failCount, timeoutUntil, url);
      if (timeoutMs > 0) log('warn', `Peer timed out: ${url} (${Math.round(timeoutMs / 60000)}min, fail #${failCount})`);
    }
  }

  decayHealth() {
    this.db.prepare('UPDATE peers SET health = MAX(0.1, health - 0.02) WHERE health > 0.1').run();
  }

  count() {
    return this.db.prepare(`SELECT COUNT(*) as c FROM peers WHERE ${this._notTimedOut()}`).get().c;
  }

  maxHeight() {
    const row = this.db.prepare(`SELECT MAX(height) as h FROM peers WHERE ${this._notTimedOut()}`).get();
    return row ? row.h : 0;
  }

  stats() {
    const now = Date.now();
    const total = this.db.prepare('SELECT COUNT(*) as c FROM peers').get().c;
    const active = this.db.prepare(`SELECT COUNT(*) as c FROM peers WHERE ${this._notTimedOut()}`).get().c;
    const timedOut = this.db.prepare('SELECT COUNT(*) as c FROM peers WHERE banned = 0 AND timeout_until > 0 AND timeout_until > ?').get(now).c;
    const banned = this.db.prepare('SELECT COUNT(*) as c FROM peers WHERE banned = 1').get().c;
    return { total, active, timedOut, banned };
  }

  gossipPeers(maxPeers = 20) {
    return this.active(maxPeers).map(p => ({ url: p.url, node_id: p.node_id, height: p.height }));
  }
}

module.exports = { PeerManager };
