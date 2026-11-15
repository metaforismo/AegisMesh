// Fleet routes of the dev mock, started on loopback twice: as a hub and with
// the hub disabled. They mirror the ADR-0018 console contract the UI uses.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const MOCK = fileURLToPath(new URL('../devserver/mock-server.mjs', import.meta.url));
const procs = [];

function start(fleet) {
  const port = 20000 + Math.floor(Math.random() * 2000);
  const proc = spawn(process.execPath, [MOCK, '--port', String(port), '--fleet', fleet], { stdio: ['ignore', 'pipe', 'inherit'] });
  procs.push(proc);
  return new Promise((resolve, reject) => {
    const t = setTimeout(() => reject(new Error('mock did not start')), 5000);
    proc.stdout.on('data', (d) => { if (String(d).includes('console mock on')) { clearTimeout(t); resolve(`http://127.0.0.1:${port}`); } });
  });
}

let HUB;
let OFF;
before(async () => { [HUB, OFF] = await Promise.all([start('hub'), start('none')]); });
after(() => { for (const p of procs) p.kill(); });

async function session(base, token) {
  const res = await fetch(`${base}/api/v1/session`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ token }) });
  const body = await res.json();
  const cookie = (res.headers.get('set-cookie') || '').split(';')[0];
  const call = (method, path, payload, { csrf = true } = {}) => fetch(`${base}/api/v1${path}`, {
    method,
    headers: { Cookie: cookie, ...(payload ? { 'Content-Type': 'application/json' } : {}), ...(csrf && method !== 'GET' ? { 'X-AegisMesh-CSRF': body.csrf_token } : {}) },
    body: payload ? JSON.stringify(payload) : undefined,
  });
  return call;
}

test('fleet status reports roles; node list covers every status and filters', async () => {
  const viewer = await session(HUB, 'dev-viewer');
  const f = await (await viewer('GET', '/fleet')).json();
  assert.equal(f.hub.enabled, true);
  assert.equal(f.agent.enabled, false);
  const all = (await (await viewer('GET', '/fleet/nodes')).json()).nodes;
  for (const s of ['online', 'stale', 'offline', 'revoked']) assert.ok(all.some((n) => n.status === s), s);
  assert.deepEqual(all.map((n) => n.id), [...all.map((n) => n.id)].sort());
  for (const n of all) {
    // `forwarding` is optional: absent for agents that never reported it.
    assert.deepEqual(Object.keys(n).filter((k) => k !== 'forwarding').sort(), ['bus_dropped_events', 'counters', 'enrolled_at', 'id', 'last_seen_at', 'name', 'public_key_fingerprint', 'sensors', 'status', 'storage_healthy', 'uptime_seconds', 'version']);
    assert.ok(n.public_key_fingerprint.startsWith(n.id));
  }
  const stale = (await (await viewer('GET', '/fleet/nodes?status=stale')).json()).nodes;
  assert.ok(stale.length > 0 && stale.every((n) => n.status === 'stale'));
  assert.equal((await viewer('GET', '/fleet/nodes?status=bogus')).status, 400);
  assert.equal((await viewer('GET', '/fleet/nodes?status=online&status=stale')).status, 400);
  assert.equal((await viewer('GET', '/fleet?x=1')).status, 400);
  assert.equal((await viewer('GET', `/fleet/nodes/${'0'.repeat(32)}`)).status, 404);
});

test('token and revoke routes are admin-only and need CSRF', async () => {
  const viewer = await session(HUB, 'dev-viewer');
  const analyst = await session(HUB, 'dev-analyst');
  const admin = await session(HUB, 'dev-admin');
  assert.equal((await viewer('GET', '/fleet/enrollment-tokens')).status, 403);
  assert.equal((await analyst('POST', '/fleet/enrollment-tokens', {})).status, 403);
  assert.equal((await admin('POST', '/fleet/enrollment-tokens', {}, { csrf: false })).status, 403);
  const node = (await (await viewer('GET', '/fleet/nodes?status=online')).json()).nodes[0];
  assert.equal((await analyst('POST', `/fleet/nodes/${node.id}/revoke`)).status, 403);
});

test('token lifecycle: create shows the raw token once, list hides it, delete removes it', async () => {
  const admin = await session(HUB, 'dev-admin');
  assert.equal((await admin('POST', '/fleet/enrollment-tokens', { ttl_seconds: 86401 })).status, 400);
  assert.equal((await admin('POST', '/fleet/enrollment-tokens', { note: 'ünïcode' })).status, 400);
  assert.equal((await admin('POST', '/fleet/enrollment-tokens', { extra: 1 })).status, 400);
  const res = await admin('POST', '/fleet/enrollment-tokens', { ttl_seconds: 900, note: 'synthetic test' });
  assert.equal(res.status, 201);
  const minted = await res.json();
  assert.match(minted.token, /^[0-9a-f]{64}$/);
  assert.ok(!Number.isNaN(Date.parse(minted.expires_at)));
  const list = await (await admin('GET', '/fleet/enrollment-tokens')).json();
  const row = list.tokens.find((t) => t.id === minted.id);
  assert.deepEqual(Object.keys(row).sort(), ['expires_at', 'id', 'note']);
  assert.ok(!JSON.stringify(list).includes(minted.token));
  assert.equal((await admin('DELETE', `/fleet/enrollment-tokens/${minted.id}`)).status, 204);
  assert.equal((await admin('DELETE', `/fleet/enrollment-tokens/${minted.id}`)).status, 404);
  const audit = await (await admin('GET', '/audit?action=fleet.token.create')).json();
  assert.ok(audit.records.some((r) => r.target === minted.id));
});

test('revoke is idempotent and permanent', async () => {
  const admin = await session(HUB, 'dev-admin');
  const node = (await (await admin('GET', '/fleet/nodes?status=online')).json()).nodes[0];
  const first = await (await admin('POST', `/fleet/nodes/${node.id}/revoke`)).json();
  assert.equal(first.status, 'revoked');
  const again = await admin('POST', `/fleet/nodes/${node.id}/revoke`);
  assert.equal(again.status, 200);
  assert.equal((await again.json()).status, 'revoked');
  assert.equal((await admin('POST', `/fleet/nodes/${'0'.repeat(32)}/revoke`)).status, 404);
});

test('hub disabled: GET /fleet works, node and token routes answer 503 unavailable', async () => {
  const admin = await session(OFF, 'dev-admin');
  const f = await (await admin('GET', '/fleet')).json();
  assert.equal(f.hub.enabled, false);
  assert.equal(f.agent.enabled, false);
  for (const [m, p] of [['GET', '/fleet/nodes'], ['GET', '/fleet/enrollment-tokens'], ['POST', '/fleet/enrollment-tokens']]) {
    const res = await admin(m, p, m === 'POST' ? {} : undefined);
    assert.equal(res.status, 503, `${m} ${p}`);
    assert.equal((await res.json()).error.code, 'unavailable');
  }
  // CSRF is still checked first.
  assert.equal((await admin('POST', '/fleet/enrollment-tokens', {}, { csrf: false })).status, 403);
});
