// OIDC sign-in, tenants, per-sensor buckets and compressed static files in
// the dev mock, which mirrors the console contract (ADR-0019, ADR-0020) the
// UI is built against. Started on loopback with two tenants and both
// sign-in methods, and once with the defaults.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { gunzipSync } from 'node:zlib';

const MOCK = fileURLToPath(new URL('../devserver/mock-server.mjs', import.meta.url));
const procs = [];

function start(args) {
  const port = 22000 + Math.floor(Math.random() * 2000);
  const proc = spawn(process.execPath, [MOCK, '--port', String(port), ...args], { stdio: ['ignore', 'pipe', 'inherit'] });
  procs.push(proc);
  return new Promise((resolve, reject) => {
    const t = setTimeout(() => reject(new Error('mock did not start')), 5000);
    proc.stdout.on('data', (d) => { if (String(d).includes('console mock on')) { clearTimeout(t); resolve(`http://127.0.0.1:${port}`); } });
  });
}

let MULTI;
let PLAIN;
let OIDC_ONLY;
before(async () => {
  [MULTI, PLAIN, OIDC_ONLY] = await Promise.all([
    start(['--auth', 'both', '--tenants', 'alpha,bravo']),
    start([]),
    start(['--auth', 'oidc']),
  ]);
});
after(() => { for (const p of procs) p.kill(); });

const cookieFrom = (res, name) => {
  const all = typeof res.headers.getSetCookie === 'function' ? res.headers.getSetCookie() : [res.headers.get('set-cookie') || ''];
  const hit = all.find((c) => c.startsWith(`${name}=`));
  return hit ? hit.split(';')[0] : '';
};

async function tokenSession(base, token) {
  const res = await fetch(`${base}/api/v1/session`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ token }) });
  return { res, body: res.ok ? await res.json() : null, cookie: cookieFrom(res, 'aegismesh_session') };
}

const get = (base, path, cookie) => fetch(`${base}/api/v1${path}`, { headers: cookie ? { Cookie: cookie } : {} });
const post = (base, path, cookie, csrf, body) => fetch(`${base}/api/v1${path}`, {
  method: 'POST', headers: { Cookie: cookie, 'Content-Type': 'application/json', ...(csrf ? { 'X-AegisMesh-CSRF': csrf } : {}) }, body: JSON.stringify(body),
});

// Walk the OIDC hop like a browser: login → provider → callback.
async function oidc(base, pickCallback) {
  const login = await fetch(`${base}/api/v1/auth/oidc/login`, { redirect: 'manual' });
  assert.equal(login.status, 302);
  const pre = cookieFrom(login, 'aegismesh_oidc');
  assert.match(login.headers.get('set-cookie'), /Path=\/api\/v1\/auth\/oidc; HttpOnly; SameSite=Lax; Max-Age=120/);
  const state = new URL(login.headers.get('location'), base).searchParams.get('state');
  const cb = await fetch(`${base}/api/v1/auth/oidc/callback?${pickCallback(state)}`, { headers: { Cookie: pre }, redirect: 'manual' });
  return { cb, state, pre, location: cb.headers.get('location') };
}

test('meta advertises the configured sign-in methods', async () => {
  const both = await (await get(MULTI, '/meta')).json();
  assert.deepEqual(both.auth, { token: true, oidc: { enabled: true, display_name: 'Example IdP (mock)' } });
  assert.deepEqual((await (await get(PLAIN, '/meta')).json()).auth, { token: true, oidc: { enabled: false, display_name: 'Example IdP (mock)' } });
  assert.equal((await (await get(OIDC_ONLY, '/meta')).json()).auth.token, false);
  assert.equal((await tokenSession(OIDC_ONLY, 'dev-admin')).res.status, 401, 'token sign-in disabled');
  assert.equal((await fetch(`${PLAIN}/api/v1/auth/oidc/login`, { redirect: 'manual' })).status, 404, 'OIDC not configured');
});

test('OIDC success: session cookie, redirect to /, session shape, audit claims', async () => {
  const { cb, location } = await oidc(MULTI, (state) => `state=${state}&code=ana`);
  assert.equal(cb.status, 302);
  assert.equal(location, '/');
  const cookie = cookieFrom(cb, 'aegismesh_session');
  assert.ok(cookie);
  assert.match(cb.headers.getSetCookie().join('\n'), /aegismesh_oidc=; .*Max-Age=0/, 'pre-login cookie cleared');
  const s = await (await get(MULTI, '/session', cookie)).json();
  assert.equal(s.principal.auth_method, 'oidc');
  assert.equal(s.principal.role, 'analyst');
  assert.equal(s.tenant, 'alpha', 'first sorted membership');
  assert.deepEqual(s.tenants, ['alpha', 'bravo']);
  assert.equal(s.principal.tenant, s.tenant);

  const admin = await oidc(MULTI, (state) => `state=${state}&code=ada`);
  const ac = cookieFrom(admin.cb, 'aegismesh_session');
  const as = await (await get(MULTI, '/session', ac)).json();
  assert.deepEqual(as.tenants, ['bravo', 'alpha'], 'membership as mapped');
  assert.equal(as.tenant, 'alpha', 'initial tenant is the first in sorted order');
  const audit = await (await get(MULTI, '/audit?action=session.oidc_login', ac)).json();
  const rec = audit.records.find((r) => r.actor === 'ada@example.test');
  assert.ok(rec.issuer.endsWith('/__mock/idp'));
  assert.equal(rec.subject, '00u1ada-synthetic-7f3c');
});

test('OIDC failures redirect to a fixed code and discard provider text', async () => {
  const cases = [
    [(st) => `state=${st}&error=access_denied&error_description=${encodeURIComponent('<b>provider text</b>')}`, 'access_denied'],
    [(st) => `state=${st}&code=nobody`, 'invalid_identity'],
    [() => 'state=forged&code=ada', 'invalid_state'],
    [(st) => `state=${st}`, 'invalid_request'],
    [(st) => `state=${st}&code=ada&extra=1`, 'invalid_request'],
    [(st) => `state=${st}&code=outage`, 'unavailable'],
    [(st) => `state=${st}&code=busy`, 'rate_limited'],
  ];
  for (const [pick, code] of cases) {
    const { cb, location } = await oidc(MULTI, pick);
    assert.equal(cb.status, 302, code);
    assert.equal(location, `/#/login?error=${code}`);
    assert.equal(cookieFrom(cb, 'aegismesh_session'), '', `${code}: no session`);
  }
});

test('OIDC state is single use and bound to the pre-login cookie', async () => {
  const first = await oidc(MULTI, (st) => `state=${st}&code=ana`);
  const replay = await fetch(`${MULTI}/api/v1/auth/oidc/callback?state=${first.state}&code=ana`, { headers: { Cookie: first.pre }, redirect: 'manual' });
  assert.equal(replay.headers.get('location'), '/#/login?error=invalid_state');
  const login = await fetch(`${MULTI}/api/v1/auth/oidc/login`, { redirect: 'manual' });
  const state = new URL(login.headers.get('location'), MULTI).searchParams.get('state');
  const foreign = await fetch(`${MULTI}/api/v1/auth/oidc/callback?state=${state}&code=ana`, { headers: { Cookie: 'aegismesh_oidc=someone-else' }, redirect: 'manual' });
  assert.equal(foreign.headers.get('location'), '/#/login?error=invalid_state');
});

test('the fake provider page offers identities and every failure', async () => {
  const login = await fetch(`${MULTI}/api/v1/auth/oidc/login`, { redirect: 'manual' });
  const page = await fetch(new URL(login.headers.get('location'), MULTI));
  assert.equal(page.status, 200);
  assert.match(page.headers.get('content-security-policy'), /script-src 'self'/);
  const html = await page.text();
  assert.doesNotMatch(html, /<script/i);
  for (const word of ['code=ada', 'code=nobody', 'error=access_denied', 'state=forged-state', 'code=outage', 'code=busy']) assert.ok(html.includes(word), word);
  assert.ok(!html.includes('<b>Provider'), 'provider text in links is escaped');
});

test('tenant switch rotates session and CSRF, keeps expiry, ends the old session', async () => {
  const { body, cookie } = await tokenSession(MULTI, 'dev-admin');
  assert.equal(body.tenant, 'alpha', 'token sessions start in the first configured membership');
  assert.equal(body.principal.auth_method, 'token');
  assert.equal((await post(MULTI, '/session/tenant', cookie, '', { tenant: 'bravo' })).status, 403, 'CSRF required');
  assert.equal((await post(MULTI, '/session/tenant', cookie, body.csrf_token, { tenant: 'zulu' })).status, 404);
  const notFound = await (await post(MULTI, '/session/tenant', cookie, body.csrf_token, { tenant: 'zulu' })).json();
  assert.deepEqual(notFound, { error: { code: 'not_found', message: 'tenant not found' } });
  const res = await post(MULTI, '/session/tenant', cookie, body.csrf_token, { tenant: 'bravo' });
  assert.equal(res.status, 200);
  const next = await res.json();
  const nextCookie = cookieFrom(res, 'aegismesh_session');
  assert.equal(next.tenant, 'bravo');
  assert.equal(next.principal.tenant, 'bravo');
  assert.notEqual(next.csrf_token, body.csrf_token);
  assert.notEqual(nextCookie, cookie);
  assert.equal(next.expires_at, body.expires_at);
  assert.equal((await get(MULTI, '/session', cookie)).status, 401, 'old session invalid');
  assert.equal((await get(MULTI, '/session', nextCookie)).status, 200);
  // The departing chain records the switch without naming the target.
  const back = await post(MULTI, '/session/tenant', nextCookie, next.csrf_token, { tenant: 'alpha' });
  const backCookie = cookieFrom(back, 'aegismesh_session');
  const audit = await (await get(MULTI, '/audit?action=session.tenant_switch', backCookie)).json();
  assert.ok(audit.records.length >= 1);
  assert.ok(audit.records.every((r) => r.target === '' && !JSON.stringify(r).includes('bravo')));
});

test('a viewer with one membership cannot switch', async () => {
  const { body, cookie } = await tokenSession(MULTI, 'dev-viewer');
  assert.deepEqual(body.tenants, ['alpha']);
  assert.equal((await post(MULTI, '/session/tenant', cookie, body.csrf_token, { tenant: 'bravo' })).status, 404);
});

test('tenants hold visibly different data; local-only resources stay in the local tenant', async () => {
  const a = await tokenSession(MULTI, 'dev-admin');
  const sw = await post(MULTI, '/session/tenant', a.cookie, a.body.csrf_token, { tenant: 'bravo' });
  const b = cookieFrom(sw, 'aegismesh_session');
  const alpha = await tokenSession(MULTI, 'dev-admin');

  const [ovA, ovB] = await Promise.all([alpha.cookie, b].map(async (c) => (await get(MULTI, '/overview?window=24h', c)).json()));
  assert.notEqual(ovA.totals.events, ovB.totals.events);
  assert.equal((await (await get(MULTI, '/sensors', b)).json()).sensors.length, 0);
  assert.equal((await (await get(MULTI, '/rules', b)).json()).rules.length, 0);
  assert.equal((await get(MULTI, '/node', b)).status, 404);
  assert.equal((await get(MULTI, '/node', alpha.cookie)).status, 200);
  const evB = await (await get(MULTI, '/events?limit=200', b)).json();
  assert.ok(evB.events.every((e) => e.node), 'the other tenant holds forwarded copies only');

  const nodesA = (await (await get(MULTI, '/fleet/nodes', alpha.cookie)).json()).nodes;
  const nodesB = (await (await get(MULTI, '/fleet/nodes', b)).json()).nodes;
  assert.ok(nodesA.every((n) => n.tenant === 'alpha'));
  assert.ok(nodesB.every((n) => n.tenant === 'bravo' && n.name.startsWith('bravo-')));
  // Another tenant's objects answer exactly like absent ones.
  const foreign = await get(MULTI, `/fleet/nodes/${nodesA[0].id}`, b);
  assert.equal(foreign.status, 404);
  const invA = (await (await get(MULTI, '/investigations', alpha.cookie)).json()).investigations[0];
  assert.equal((await get(MULTI, `/investigations/${invA.id}`, b)).status, 404);
  const mint = await post(MULTI, '/fleet/enrollment-tokens', b, (await sw.clone().json()).csrf_token, { ttl_seconds: 60 });
  assert.equal(mint.status, 201);
  assert.equal((await mint.json()).tenant, 'bravo');
  // No local agent telemetry outside the local tenant.
  assert.equal((await (await get(MULTI, '/fleet', b)).json()).agent.enabled, false);
});

test('by_sensor carries buckets on the main series starts, zeros included', async () => {
  const { cookie } = await tokenSession(PLAIN, 'dev-viewer');
  for (const w of ['1h', '24h', '7d']) {
    const ov = await (await get(PLAIN, `/overview?window=${w}`, cookie)).json();
    assert.ok(ov.by_sensor.length > 0 && ov.by_sensor.length <= 64, w);
    const starts = ov.buckets.map((x) => x.start);
    for (const s of ov.by_sensor) {
      assert.deepEqual(s.buckets.map((x) => x.start), starts, `${w} ${s.sensor_id}`);
      const sum = s.buckets.reduce((n, x) => n + x.interaction + x.canary_invocation + x.correlation_signal, 0);
      assert.equal(sum, s.events, `${w} ${s.sensor_id}`);
    }
  }
});

test('default mock: one tenant named default, token sessions', async () => {
  const { body } = await tokenSession(PLAIN, 'dev-analyst');
  assert.equal(body.tenant, 'default');
  assert.deepEqual(body.tenants, ['default']);
  assert.equal(body.principal.auth_method, 'token');
});

test('static assets: gzip, strong ETag, 304, 406; index stays no-store', async () => {
  const res = await fetch(`${PLAIN}/assets/js/main.js`, { headers: { 'Accept-Encoding': 'gzip' } });
  assert.equal(res.status, 200);
  assert.equal(res.headers.get('cache-control'), 'no-cache');
  assert.equal(res.headers.get('vary'), 'Accept-Encoding');
  const etag = res.headers.get('etag');
  assert.match(etag, /^"[0-9a-f]{64}"$/);
  // fetch() decodes gzip itself; the identity representation has its own tag.
  const plain = await fetch(`${PLAIN}/assets/js/main.js`, { headers: { 'Accept-Encoding': 'identity' } });
  assert.notEqual(plain.headers.get('etag'), etag);
  assert.equal(plain.headers.get('content-encoding'), null);
  const raw = await plain.text();
  assert.ok(raw.includes('createApi'));
  for (const inm of [etag, `W/${etag}`, `"x", ${etag}`, '*']) {
    const r = await fetch(`${PLAIN}/assets/js/main.js`, { headers: { 'Accept-Encoding': 'gzip', 'If-None-Match': inm } });
    assert.equal(r.status, 304, inm);
  }
  assert.equal((await fetch(`${PLAIN}/assets/js/main.js`, { headers: { 'Accept-Encoding': 'identity;q=0' } })).status, 406);
  const index = await fetch(`${PLAIN}/`, { headers: { 'Accept-Encoding': 'gzip' } });
  assert.equal(index.headers.get('cache-control'), 'no-store');
  assert.equal(index.headers.get('etag'), null);
  assert.equal(index.headers.get('content-encoding'), null);
  assert.match(index.headers.get('content-security-policy'), /default-src 'none'/);
  // The gzip body really is gzip of the identity body.
  const http = await import('node:http');
  const port = new URL(PLAIN).port;
  const gz = await new Promise((resolve, reject) => {
    http.get({ host: '127.0.0.1', port, path: '/assets/js/main.js', headers: { 'Accept-Encoding': 'gzip' } }, (r) => {
      const chunks = [];
      r.on('data', (c) => chunks.push(c));
      r.on('end', () => resolve({ enc: r.headers['content-encoding'], body: Buffer.concat(chunks) }));
    }).on('error', reject);
  });
  assert.equal(gz.enc, 'gzip');
  assert.equal(gunzipSync(gz.body).toString('utf8'), raw);
});
