// Fleet inventory routes for the development mock (console API, ADR-0018).
// Synthetic only: invented node names, keys derived from fixed seeds. The
// hub here, like the real one, has no route that commands a node.

import { createHash, randomBytes } from 'node:crypto';

const sha = (s) => createHash('sha256').update(s).digest('hex');
const iso = (ms) => new Date(ms).toISOString();
const STATUSES = ['online', 'stale', 'offline', 'revoked'];
const TTL_DEFAULT = 3600;

// mode: 'hub' | 'agent' | 'both' | 'none'
export function createFleet({ mode = 'hub', now = () => Date.now(), listen = '127.0.0.1:9130' } = {}) {
  const hubOn = mode === 'hub' || mode === 'both';
  const agentOn = mode === 'agent' || mode === 'both';
  const t0 = now();

  const nodes = new Map();
  const add = (name, { interval = 30, lastSeenAgo = 10, revoked = false, sensors, storage = true, drops = 0, enrolledAgo = 86400, version = '0.3.0' }) => {
    const fp = sha(`synthetic-public-key:${name}`);
    const id = fp.slice(0, 32);
    nodes.set(id, {
      id, name, interval, revoked,
      enrolled_at: iso(t0 - enrolledAgo * 1000),
      last_seen_ms: lastSeenAgo === null ? null : t0 - lastSeenAgo * 1000,
      version: { version, commit: sha(name).slice(0, 7), go: 'go1.25' },
      uptime_seconds: lastSeenAgo === null ? 0 : 3600 * 20,
      sensors: sensors ?? [{ id: 'web', kind: 'http', state: 'running' }, { id: 'mcp-tools', kind: 'mcp', state: 'running' }],
      counters: { interaction: Math.floor(sha(name).charCodeAt(0) * 37), canary_invocation: name.length % 5, correlation_signal: name.length % 3 },
      bus_dropped_events: drops,
      storage_healthy: storage,
      public_key_fingerprint: fp,
    });
  };
  add('edge-berlin-01', { lastSeenAgo: 12 });
  add('edge-berlin-02', { lastSeenAgo: 25, sensors: [{ id: 'web', kind: 'http', state: 'running' }, { id: 'ssh-decoy', kind: 'ssh', state: 'failed' }, { id: 'redis-lure', kind: 'tcp', state: 'stopped' }] });
  add('ci-runner-lure', { interval: 30, lastSeenAgo: 120, drops: 14 });
  add('lab-mcp-canary', { interval: 60, lastSeenAgo: 3600, storage: false, version: '0.2.9' });
  add('retired-dmz-07', { lastSeenAgo: 7200, revoked: true });
  add('new-node-pending', { lastSeenAgo: null, sensors: [], enrolledAgo: 60 });
  add('hub-only-node', { lastSeenAgo: 8, sensors: [] });

  const statusOf = (n) => {
    if (n.revoked) return 'revoked';
    if (n.last_seen_ms === null) return 'offline';
    const missed = (now() - n.last_seen_ms) / 1000 / n.interval;
    if (missed >= 10) return 'offline';
    if (missed >= 3) return 'stale';
    return 'online';
  };
  const view = (n) => ({
    id: n.id, name: n.name, status: statusOf(n), enrolled_at: n.enrolled_at,
    last_seen_at: n.last_seen_ms === null ? '' : iso(n.last_seen_ms),
    version: n.version, uptime_seconds: n.uptime_seconds, sensors: n.sensors, counters: n.counters,
    bus_dropped_events: n.bus_dropped_events, storage_healthy: n.storage_healthy,
    public_key_fingerprint: n.public_key_fingerprint,
  });

  const tokens = new Map(); // id → { digest, expires_ms, note }
  const outstanding = () => [...tokens.entries()].filter(([, t]) => now() < t.expires_ms);
  tokens.set('tok_0001', { digest: sha('seed-a'), expires_ms: t0 + 40 * 60e3, note: 'edge-berlin-03 rollout' });
  tokens.set('tok_0002', { digest: sha('seed-b'), expires_ms: t0 + 20 * 3600e3, note: '' });
  let tokenSeq = 2;

  const agent = agentOn
    ? { enabled: true, hub_url: 'https://hub.example.test:9130', node_id: sha('synthetic-public-key:this-node').slice(0, 32), enrolled: true, last_heartbeat_at: iso(t0 - 9000), last_error: mode === 'both' ? '' : 'hub_unreachable' }
    : { enabled: false, hub_url: '', node_id: '', enrolled: false, last_heartbeat_at: '', last_error: '' };

  // Returns true when it handled the request.
  return async function handle({ req, res, url, p, m, need, record, who, remote, send, fail, readBody }) {
    if (p !== '/fleet' && !p.startsWith('/fleet/')) return false;
    const keys = [...url.searchParams.keys()];
    const dup = keys.length !== new Set(keys).size;
    const allowedKeys = m === 'GET' && p === '/fleet/nodes' ? ['status'] : [];
    if (dup || keys.some((k) => !allowedKeys.includes(k))) { fail(res, 'invalid_argument', 'unknown or duplicate query parameter'); return true; }

    if (p === '/fleet' && m === 'GET') {
      send(res, 200, { hub: { enabled: hubOn, listen: hubOn ? listen : '', tls: false }, agent });
      return true;
    }

    const adminRoute = p.startsWith('/fleet/enrollment-tokens') || /\/revoke$/.test(p);
    if (adminRoute && !need('admin', p.includes('token') ? 'fleet.token' : 'fleet.node.revoke')) return true;

    // Contract: hub-disabled answers 503 after auth/CSRF, for every node/token route.
    const hubRoute = p === '/fleet/nodes' || p.startsWith('/fleet/nodes/') || p.startsWith('/fleet/enrollment-tokens');
    if (hubRoute && !hubOn) { fail(res, 'unavailable', 'fleet hub is disabled on this node'); return true; }

    let mm;
    if (p === '/fleet/nodes' && m === 'GET') {
      const status = url.searchParams.get('status');
      if (status !== null && !STATUSES.includes(status)) { fail(res, 'invalid_argument', 'status must be online, stale, offline or revoked'); return true; }
      const list = [...nodes.values()].map(view).filter((n) => !status || n.status === status).sort((a, b) => a.id.localeCompare(b.id));
      send(res, 200, { nodes: list });
      return true;
    }
    if ((mm = /^\/fleet\/nodes\/([0-9a-f]{32})$/.exec(p)) && m === 'GET') {
      const n = nodes.get(mm[1]);
      if (!n) fail(res, 'not_found', 'no such node'); else send(res, 200, view(n));
      return true;
    }
    if ((mm = /^\/fleet\/nodes\/([0-9a-f]{32})\/revoke$/.exec(p)) && m === 'POST') {
      const body = await readBody(req, []).catch((e) => ({ __err: e }));
      if (body.__err || Object.keys(body).length) { fail(res, 'invalid_argument', 'revoke accepts no body'); return true; }
      const n = nodes.get(mm[1]);
      if (!n) { fail(res, 'not_found', 'no such node'); return true; }
      n.revoked = true;
      record(who.name, who.role, 'fleet.node.revoke', n.id, 'ok', remote);
      send(res, 200, view(n));
      return true;
    }
    if (p === '/fleet/enrollment-tokens' && m === 'GET') {
      send(res, 200, { tokens: outstanding().map(([id, t]) => ({ id, expires_at: iso(t.expires_ms), note: t.note })).sort((a, b) => a.id.localeCompare(b.id)) });
      return true;
    }
    if (p === '/fleet/enrollment-tokens' && m === 'POST') {
      let b;
      try { b = await readBody(req, ['ttl_seconds', 'note']); } catch (e) { fail(res, 'invalid_argument', e.message); return true; }
      const ttl = b.ttl_seconds === undefined || b.ttl_seconds === 0 ? TTL_DEFAULT : b.ttl_seconds;
      if (!Number.isInteger(ttl) || ttl < 1 || ttl > 86400) { fail(res, 'invalid_argument', 'ttl_seconds must be 1..86400'); return true; }
      const note = b.note ?? '';
      if (typeof note !== 'string' || note.length > 256 || !/^[\x20-\x7e]*$/.test(note)) { fail(res, 'invalid_argument', 'note must be printable ASCII up to 256 bytes'); return true; }
      if (outstanding().length >= 100) { fail(res, 'unavailable', 'too many outstanding tokens'); return true; }
      const raw = randomBytes(32).toString('hex');
      const id = `tok_${String(++tokenSeq).padStart(4, '0')}`;
      const expires_ms = now() + ttl * 1000;
      tokens.set(id, { digest: sha(raw), expires_ms, note });
      record(who.name, who.role, 'fleet.token.create', id, 'ok', remote);
      send(res, 201, { id, token: raw, expires_at: iso(expires_ms) });
      return true;
    }
    if ((mm = /^\/fleet\/enrollment-tokens\/([A-Za-z0-9_.-]{1,128})$/.exec(p)) && m === 'DELETE') {
      const t = tokens.get(mm[1]);
      if (!t || now() >= t.expires_ms) { fail(res, 'not_found', 'no such outstanding token'); return true; }
      tokens.delete(mm[1]);
      record(who.name, who.role, 'fleet.token.delete', mm[1], 'ok', remote);
      send(res, 204, null);
      return true;
    }
    fail(res, 'not_found', 'no such endpoint');
    return true;
  };
}
