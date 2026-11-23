// Starts the dev mock on loopback and checks that it enforces the contract
// rules the UI relies on (headers, cookie session, CSRF, strict bodies), so
// UI work against the mock does not drift from production behavior.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const PORT = 19000 + Math.floor(Math.random() * 1000);
const BASE = `http://127.0.0.1:${PORT}`;
let proc;

before(async () => {
  proc = spawn(process.execPath, [fileURLToPath(new URL('../devserver/mock-server.mjs', import.meta.url)), '--port', String(PORT)], { stdio: ['ignore', 'pipe', 'inherit'] });
  await new Promise((resolve, reject) => {
    const t = setTimeout(() => reject(new Error('mock did not start')), 30000);
    proc.stdout.on('data', (d) => { if (String(d).includes('console mock on')) { clearTimeout(t); resolve(); } });
  });
});
after(() => proc?.kill());

async function login(token = 'dev-analyst') {
  const res = await fetch(`${BASE}/api/v1/session`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ token }) });
  const cookie = (res.headers.get('set-cookie') || '').split(';')[0];
  return { res, cookie, body: res.ok ? await res.json() : null };
}

test('static and API responses carry the production security headers', async () => {
  for (const path of ['/', '/assets/js/main.js', '/api/v1/meta']) {
    const res = await fetch(BASE + path);
    assert.equal(res.status, 200, path);
    assert.match(res.headers.get('content-security-policy'), /script-src 'self'/);
    assert.equal(res.headers.get('x-content-type-options'), 'nosniff');
    assert.equal(res.headers.get('x-frame-options'), 'DENY');
  }
  assert.equal((await fetch(`${BASE}/../../go.mod`)).status, 404);
});

test('session cookie is HttpOnly + SameSite=Strict; bad tokens are 401', async () => {
  const { res } = await login();
  assert.match(res.headers.get('set-cookie'), /HttpOnly; SameSite=Strict/);
  assert.equal((await login('nope')).res.status, 401);
  assert.equal((await fetch(`${BASE}/api/v1/overview`)).status, 401);
});

test('mutations need the CSRF header and strict bodies; roles are enforced', async () => {
  const { cookie, body } = await login('dev-analyst');
  const post = (headers, payload) => fetch(`${BASE}/api/v1/investigations`, { method: 'POST', headers: { Cookie: cookie, 'Content-Type': 'application/json', ...headers }, body: JSON.stringify(payload) });
  assert.equal((await post({}, { title: 'x' })).status, 403);
  assert.equal((await post({ 'X-AegisMesh-CSRF': body.csrf_token }, { title: 'x', extra: 1 })).status, 400);
  assert.equal((await post({ 'X-AegisMesh-CSRF': body.csrf_token }, { title: 'Synthetic case' })).status, 201);
  const viewer = await login('dev-viewer');
  const denied = await fetch(`${BASE}/api/v1/audit`, { headers: { Cookie: viewer.cookie } });
  assert.equal(denied.status, 403);
  assert.equal((await denied.json()).error.code, 'forbidden');
});

test('event filters reject unknown parameters', async () => {
  const { cookie } = await login();
  assert.equal((await fetch(`${BASE}/api/v1/events?bogus=1`, { headers: { Cookie: cookie } })).status, 400);
  const ok = await fetch(`${BASE}/api/v1/events?severity=high&limit=5`, { headers: { Cookie: cookie } });
  const data = await ok.json();
  assert.ok(data.events.length <= 5);
  assert.ok(data.events.every((e) => ['high', 'critical'].includes(e.severity)));
});
