// Mock contract for round 5 (contract r5): your account, preferences,
// sessions and API keys; administration; and `--round5 off` behaving like an
// older server (404 on the new routes, API keys do not sign in).
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { clientFamily } from '../devserver/mock-accounts.mjs';

const start = (args) => new Promise((resolve, reject) => {
  const port = 23000 + Math.floor(Math.random() * 1000);
  const proc = spawn(process.execPath, [fileURLToPath(new URL('../devserver/mock-server.mjs', import.meta.url)), '--port', String(port), ...args], { stdio: ['ignore', 'pipe', 'inherit'] });
  const t = setTimeout(() => reject(new Error('mock did not start')), 30000);
  proc.stdout.on('data', (d) => { if (String(d).includes('console mock on')) { clearTimeout(t); resolve({ proc, base: `http://127.0.0.1:${port}` }); } });
});
let on;
let off;
let failing;
before(async () => { [on, off, failing] = await Promise.all([start([]), start(['--round5', 'off']), start(['--fail-prefs'])]); });
after(() => { on?.proc.kill(); off?.proc.kill(); failing?.proc.kill(); });

async function login(base, token) {
  const res = await fetch(`${base}/api/v1/session`, { method: 'POST', headers: { 'Content-Type': 'application/json', 'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/130.0 Safari/537.36' }, body: JSON.stringify({ token }) });
  const body = res.ok ? await res.json() : null;
  return { status: res.status, cookie: (res.headers.get('set-cookie') || '').split(';')[0], csrf: body?.csrf_token };
}
const call = async (base, who, method, path, body) => {
  const res = await fetch(`${base}/api/v1${path}`, { method, headers: { cookie: who.cookie, 'X-AegisMesh-CSRF': who.csrf || '', ...(body ? { 'Content-Type': 'application/json' } : {}) }, body: body ? JSON.stringify(body) : undefined });
  const text = await res.text();
  let json = null;
  try { json = JSON.parse(text); } catch { /* attachment or empty */ }
  return { status: res.status, json, text, headers: res.headers };
};

const ME_KEYS = ['auth_method', 'capabilities', 'created_at', 'id', 'kind', 'last_seen_at', 'name', 'role', 'source', 'tenant', 'tenants'].sort();
const SESSION_KEYS = ['auth_method', 'client', 'created_at', 'current', 'expires_at', 'handle', 'idle_expires_at', 'last_seen_at', 'remote', 'tenant'].sort();
const KEY_KEYS = ['created_at', 'created_by', 'expires_at', 'id', 'label', 'last_used_at', 'prefix', 'revoked_at', 'status'].sort();
const ACCOUNT_KEYS = ['active_keys', 'active_sessions', 'created_at', 'created_by', 'id', 'kind', 'last_seen_at', 'name', 'role', 'source', 'status', 'tenants'].sort();

test('client family: a fixed vocabulary, never the raw header', () => {
  assert.equal(clientFamily('Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit Chrome/130.0 Safari/537.36'), 'Chrome on macOS');
  assert.equal(clientFamily('Mozilla/5.0 (X11; Linux x86_64; rv:132.0) Gecko/20100101 Firefox/132.0'), 'Firefox on Linux');
  assert.equal(clientFamily('curl/8.7.1'), 'curl');
  assert.equal(clientFamily('<script>alert(1)</script>'), 'Unknown client');
});

test('me: contract keys; configured operators are config accounts; capabilities follow the role', async () => {
  const a = await login(on.base, 'dev-admin');
  const me = (await call(on.base, a, 'GET', '/me')).json;
  assert.deepEqual(Object.keys(me).sort(), ME_KEYS);
  assert.equal(me.id, 'cfg:ada');
  assert.equal(me.source, 'config');
  assert.deepEqual(me.capabilities, { manage_own_keys: true, administer: true });
  const v = await login(on.base, 'dev-viewer');
  assert.deepEqual((await call(on.base, v, 'GET', '/me')).json.capabilities, { manage_own_keys: false, administer: false });
});

test('preferences: defaults, strict PUT, unknown keys and values refused, --fail-prefs answers 503', async () => {
  const a = await login(on.base, 'dev-analyst');
  assert.deepEqual((await call(on.base, a, 'GET', '/me/preferences')).json, { timezone: 'utc', default_window: '24h', density: 'comfortable', theme: 'system', reduce_motion: 'system' });
  assert.equal((await call(on.base, a, 'PUT', '/me/preferences', { timezone: 'local' })).json.timezone, 'local');
  assert.equal((await call(on.base, a, 'PUT', '/me/preferences', { timezone: 'mars' })).status, 400);
  assert.equal((await call(on.base, a, 'PUT', '/me/preferences', { colour: 'red' })).status, 400);
  assert.equal((await call(on.base, a, 'GET', '/me/preferences')).json.timezone, 'local', 'persisted for the account');
  const f = await login(failing.base, 'dev-analyst');
  assert.equal((await call(failing.base, f, 'PUT', '/me/preferences', { theme: 'dark' })).status, 503);
});

test('sessions: handles are opaque, the current one is marked, the client is a family; revoking current signs out', async () => {
  const a = await login(on.base, 'dev-analyst');
  const b = await login(on.base, 'dev-analyst');
  const list = (await call(on.base, a, 'GET', '/me/sessions')).json.items;
  assert.ok(list.length >= 2);
  for (const s of list) {
    assert.deepEqual(Object.keys(s).sort(), SESSION_KEYS);
    assert.match(s.handle, /^ses_[0-9a-f]{16}$/);
    assert.ok(!s.handle.includes(a.cookie.split('=')[1]), 'never the cookie value');
  }
  assert.equal(list.filter((s) => s.current).length, 1);
  assert.equal(list.find((s) => s.current).client, 'Chrome on macOS');
  const other = (await call(on.base, b, 'GET', '/me/sessions')).json.items.find((s) => s.current);
  assert.equal((await call(on.base, a, 'DELETE', `/me/sessions/${other.handle}`)).status, 204);
  assert.equal((await call(on.base, b, 'GET', '/me')).status, 401, 'the revoked session is gone');
  const mine = list.find((s) => s.current);
  assert.equal((await call(on.base, a, 'DELETE', `/me/sessions/${mine.handle}`)).status, 204);
  assert.equal((await call(on.base, a, 'GET', '/me')).status, 401, 'revoking the current session signs out');
});

test('keys: created once with a token, listed without it, sign in, revoke; viewers refused', async () => {
  const a = await login(on.base, 'dev-analyst');
  const made = await call(on.base, a, 'POST', '/me/keys', { label: 'notebook', expires_in_days: 30 });
  assert.equal(made.status, 201);
  assert.match(made.json.token, /^amk_[A-Za-z0-9_-]{43}$/);
  assert.deepEqual(Object.keys(made.json.key).sort(), KEY_KEYS);
  assert.equal(made.json.key.prefix, made.json.token.slice(0, 8));
  const list = await call(on.base, a, 'GET', '/me/keys');
  assert.ok(!list.text.includes(made.json.token), 'the token is never listed again');
  assert.equal((await login(on.base, made.json.token)).status, 200, 'a key signs in');
  assert.equal((await call(on.base, a, 'POST', '/me/keys', { label: 'x', expires_in_days: 400 })).status, 400);
  assert.equal((await call(on.base, a, 'POST', '/me/keys', { label: '' })).status, 400);
  assert.equal((await call(on.base, a, 'DELETE', `/me/keys/${made.json.key.id}`)).status, 204);
  assert.equal((await call(on.base, a, 'GET', '/me/keys')).json.items.find((k) => k.id === made.json.key.id).status, 'revoked');
  assert.equal((await login(on.base, made.json.token)).status, 401, 'a revoked key no longer signs in');
  const v = await login(on.base, 'dev-viewer');
  assert.equal((await call(on.base, v, 'GET', '/me/keys')).status, 403);
});

test('administration: accounts, create, not_managed, disable revokes sessions; non-admins refused', async () => {
  const a = await login(on.base, 'dev-admin');
  const list = (await call(on.base, a, 'GET', '/admin/accounts')).json;
  assert.deepEqual(list.limits, { max_accounts: 200, max_keys_per_account: 10 });
  for (const acc of list.items) assert.deepEqual(Object.keys(acc).sort(), ACCOUNT_KEYS);
  assert.deepEqual([...new Set(list.items.map((x) => x.source))].sort(), ['config', 'managed', 'oidc']);
  assert.equal((await call(on.base, a, 'PATCH', '/admin/accounts/cfg%3Aada', { role: 'viewer' })).json.error.code, 'not_managed');
  const made = await call(on.base, a, 'POST', '/admin/accounts', { name: 'collector@soc.example', kind: 'service', role: 'viewer', tenants: ['default'] });
  assert.equal(made.status, 201);
  assert.match(made.json.id, /^acc_[a-z0-9]+$/);
  assert.equal((await call(on.base, a, 'POST', '/admin/accounts', { name: 'collector@soc.example', kind: 'service', role: 'viewer', tenants: ['default'] })).status, 409);
  const key = await call(on.base, a, 'POST', `/admin/accounts/${made.json.id}/keys`, { label: 'pull', expires_in_days: 90 });
  const svc = await login(on.base, key.json.token);
  assert.equal(svc.status, 200);
  assert.equal((await call(on.base, svc, 'GET', '/me')).json.source, 'managed');
  const detail = (await call(on.base, a, 'GET', `/admin/accounts/${made.json.id}`)).json;
  assert.equal(detail.sessions.length, 1);
  assert.equal(detail.keys.length, 1);
  assert.equal((await call(on.base, a, 'PATCH', `/admin/accounts/${made.json.id}`, { status: 'disabled' })).json.status, 'disabled');
  assert.equal((await call(on.base, svc, 'GET', '/me')).status, 401, 'disabling ends its sessions');
  assert.equal((await login(on.base, key.json.token)).status, 401, 'and its keys stop working');
  const all = (await call(on.base, a, 'GET', '/admin/sessions')).json.items;
  assert.ok(all.every((s) => typeof s.account_id === 'string' && typeof s.account_name === 'string'));
  const v = await login(on.base, 'dev-analyst');
  for (const p of ['/admin/accounts', '/admin/sessions', '/admin/settings', '/system']) assert.equal((await call(on.base, v, 'GET', p)).status, 403, p);
});

test('settings, audit export and system: read-only shapes, attachment, components', async () => {
  const a = await login(on.base, 'dev-admin');
  const settings = (await call(on.base, a, 'GET', '/admin/settings')).json;
  assert.deepEqual(settings.sections.map((s) => s.id), ['access', 'sso', 'tenants', 'listener', 'evidence', 'detection', 'fleet', 'exports']);
  for (const s of settings.sections) for (const it of s.items) {
    assert.equal(it.editable, false);
    assert.ok(['config', 'default', 'env'].includes(it.source));
    assert.doesNotMatch(String(it.value), /secret-value|BEGIN PRIVATE/);
  }
  const csv = await call(on.base, a, 'GET', '/admin/audit/export?format=csv');
  assert.equal(csv.status, 200);
  assert.match(csv.headers.get('content-disposition'), /attachment/);
  assert.match(csv.text.split('\n')[0], /^seq,time,actor,role,action/);
  assert.equal((await call(on.base, a, 'GET', '/admin/audit/export?format=xml')).status, 400);
  assert.equal((await call(on.base, a, 'GET', '/admin/audit/export?format=jsonl&since=yesterday')).status, 400);
  const sys = (await call(on.base, a, 'GET', '/system')).json;
  assert.equal(sys.licenses_url, '/licenses');
  assert.ok(sys.components.every((c) => ['ok', 'degraded', 'off'].includes(c.status)));
});

test('--round5 off: an older server answers 404 and API keys do not sign in', async () => {
  const a = await login(off.base, 'dev-admin');
  for (const p of ['/me', '/me/preferences', '/me/sessions', '/me/keys', '/admin/accounts', '/admin/settings', '/system']) {
    assert.equal((await call(off.base, a, 'GET', p)).status, 404, p);
  }
  assert.equal((await login(off.base, `amk_${'A'.repeat(43)}`)).status, 401);
});
