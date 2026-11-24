// Fleet inventory routes for the development mock (console API, ADR-0018).
// Synthetic only: invented node names, keys derived from fixed seeds. The
// hub here, like the real one, has no route that commands a node.

import { createHash, randomBytes } from 'node:crypto';

const sha = (s) => createHash('sha256').update(s).digest('hex');
const iso = (ms) => new Date(ms).toISOString();
const STATUSES = ['online', 'stale', 'offline', 'revoked'];
const TTL_DEFAULT = 3600;

// mode: 'hub' | 'agent' | 'both' | 'none'
// acceptEvidence: whether the hub accepts forwarded evidence (only with a hub).
// forwardedCount(id): events the mock index holds from that node, added to
// the node's synthetic forwarded total so the two stay plausible together.
// tenant: the tenant whose registry this is (FleetNode, token metadata and
// mint responses carry it). namePrefix: prepended to node names, so another
// tenant's inventory is visibly different. localAgent: this process's agent
// status belongs to the local tenant only; other tenants see it disabled.
export function createFleet({ mode = 'hub', now = () => Date.now(), listen = '127.0.0.1:9130', acceptEvidence = true, forwardedCount = () => 0, tenant = 'default', namePrefix = '', localAgent = true } = {}) {
  const hubOn = mode === 'hub' || mode === 'both';
  const agentOn = (mode === 'agent' || mode === 'both') && localAgent;
  const accepting = hubOn && acceptEvidence;
  const t0 = now();

  const nodes = new Map();
  // fwd: synthetic forwarding self-report, or null for an agent that never
  // reported one (older build). `queued`/`error` are optional fields.
  const add = (baseName, { interval = 30, lastSeenAgo = 10, revoked = false, sensors, storage = true, drops = 0, enrolledAgo = 86400, version = '0.3.0', fwd = null }) => {
    const name = namePrefix ? `${namePrefix}-${baseName}` : baseName;
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
      fwd,
    });
  };
  if (namePrefix) {
    // Another tenant's registry: a smaller, differently named inventory.
    add('edge-lisbon-01', { lastSeenAgo: 8, fwd: { enabled: true, base: 920, sentAgo: 9 } });
    add('edge-lisbon-02', { lastSeenAgo: 15, sensors: [{ id: 'ssh-decoy', kind: 'ssh', state: 'running' }], fwd: { enabled: true, base: 300, sentAgo: 16 } });
    add('lab-tcp-lure', { interval: 60, lastSeenAgo: 900, sensors: [{ id: 'redis-lure', kind: 'tcp', state: 'running' }], fwd: { enabled: false, base: 0 } });
  } else {
  add('edge-berlin-01', { lastSeenAgo: 12, fwd: { enabled: true, base: 2400, sentAgo: 14 } });
  add('edge-berlin-02', { lastSeenAgo: 25, sensors: [{ id: 'web', kind: 'http', state: 'running' }, { id: 'ssh-decoy', kind: 'ssh', state: 'failed' }, { id: 'redis-lure', kind: 'tcp', state: 'stopped' }], fwd: { enabled: true, base: 610, sentAgo: 30, queued: [12, 48213] } });
  // The one node with counted loss: queue evictions on the agent and
  // sequence gaps the hub noticed.
  add('ci-runner-lure', { interval: 30, lastSeenAgo: 120, drops: 14, fwd: { enabled: true, base: 980, sentAgo: 125, dropped: 37, gaps: 2, queued: [500, 1048576], error: 'queue_full' } });
  add('lab-mcp-canary', { interval: 60, lastSeenAgo: 3600, storage: false, version: '0.2.9', fwd: { enabled: false, base: 0 } });
  add('retired-dmz-07', { lastSeenAgo: 7200, revoked: true });
  add('new-node-pending', { lastSeenAgo: null, sensors: [], enrolledAgo: 60 });
  add('hub-only-node', { lastSeenAgo: 8, sensors: [], fwd: { enabled: false, base: 0 } });
  }

  // FleetNode.forwarding. Counters, queue and error are the agent's report;
  // last receive time and gaps are the hub's. A hub that refuses evidence
  // receives nothing, and forwarding agents report evidence_disabled.
  const forwardingView = (n) => {
    const f = n.fwd;
    if (!f) return undefined;
    const out = {
      enabled: f.enabled,
      forwarded_total: f.enabled && accepting ? f.base + forwardedCount(n.id) : f.base,
      dropped_total: f.dropped || 0,
      last_forwarded_at: f.enabled && accepting ? iso(t0 - f.sentAgo * 1000) : '',
      gaps_total: accepting ? f.gaps || 0 : 0,
    };
    if (f.queued) { out.queued_events = f.queued[0]; out.queued_bytes = f.queued[1]; }
    const error = f.enabled && !accepting ? 'evidence_disabled' : f.error;
    if (error) out.last_error = error;
    return out;
  };

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
    tenant,
    ...(n.fwd ? { forwarding: forwardingView(n) } : {}),
  });

  const tokens = new Map(); // id → { digest, expires_ms, note }
  const outstanding = () => [...tokens.entries()].filter(([, t]) => now() < t.expires_ms);
  tokens.set('tok_0001', { digest: sha(`seed-a:${tenant}`), expires_ms: t0 + 40 * 60e3, note: namePrefix ? `${namePrefix}-edge-lisbon-03 rollout` : 'edge-berlin-03 rollout' });
  tokens.set('tok_0002', { digest: sha(`seed-b:${tenant}`), expires_ms: t0 + 20 * 3600e3, note: '' });
  let tokenSeq = 2;

  // agent.forwarding is always present, even when forwarding is off.
  const agent = agentOn
    ? {
      enabled: true, hub_url: 'https://hub.example.test:9130', node_id: sha('synthetic-public-key:this-node').slice(0, 32), enrolled: true, last_heartbeat_at: iso(t0 - 9000), last_error: mode === 'both' ? '' : 'hub_unreachable',
      forwarding: mode === 'both'
        ? { enabled: true, forwarded_total: 1820, dropped_total: 0, last_forwarded_at: iso(t0 - 9000), gaps_total: 0 }
        : { enabled: true, forwarded_total: 1204, dropped_total: 5, last_forwarded_at: iso(t0 - 3600e3), gaps_total: 0, queued_events: 64, queued_bytes: 262144, last_error: 'hub_unreachable' },
    }
    : { enabled: false, hub_url: '', node_id: '', enrolled: false, last_heartbeat_at: '', last_error: '', forwarding: { enabled: false, forwarded_total: 0, dropped_total: 0, last_forwarded_at: '', gaps_total: 0 } };

  // Nodes whose forwarded evidence the mock index holds: enabled, not revoked,
  // and only when this hub accepts evidence.
  const evidenceNodes = accepting
    ? [...nodes.values()].filter((n) => n.fwd?.enabled && !n.revoked).map((n) => ({ id: n.id, name: n.name }))
    : [];

  // Returns true when it handled the request.
  async function handle({ req, res, url, p, m, need, record, who, remote, send, fail, readBody }) {
    if (p !== '/fleet' && !p.startsWith('/fleet/')) return false;
    const keys = [...url.searchParams.keys()];
    const dup = keys.length !== new Set(keys).size;
    const allowedKeys = m === 'GET' && p === '/fleet/nodes' ? ['status'] : [];
    if (dup || keys.some((k) => !allowedKeys.includes(k))) { fail(res, 'invalid_argument', 'unknown or duplicate query parameter'); return true; }

    if (p === '/fleet' && m === 'GET') {
      send(res, 200, { hub: { enabled: hubOn, listen: hubOn ? listen : '', tls: false, accept_evidence: accepting }, agent });
      return true;
    }

    const adminRoute = p.startsWith('/fleet/enrollment-tokens') || /\/revoke$/.test(p);
    if (adminRoute && !need('fleet.manage', p.includes('token') ? 'fleet.token' : 'fleet.node.revoke')) return true;

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
      send(res, 200, { tokens: outstanding().map(([id, t]) => ({ id, expires_at: iso(t.expires_ms), note: t.note, tenant })).sort((a, b) => a.id.localeCompare(b.id)) });
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
      send(res, 201, { id, token: raw, expires_at: iso(expires_ms), tenant });
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
  }
  handle.accepting = accepting;
  handle.evidenceNodes = evidenceNodes;
  return handle;
}
