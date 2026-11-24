// Mock contract for round 6 (contract r6): the permission catalogue, custom
// roles and their refusals, permission checks that follow an account's
// current role, the editable console settings overlay with its history and
// /meta, accepted posture risk, `--settings-editing off` and `--round6 off`.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { PERMISSIONS, PERMISSION_IDS, BUILTIN, SEED_ROLE_IDS, wouldLeaveNoAdmin, checkRoleBody, formatSeconds } from '../devserver/mock-roles.mjs';

const start = (args) => new Promise((resolve, reject) => {
  const port = 24000 + Math.floor(Math.random() * 1000);
  const proc = spawn(process.execPath, [fileURLToPath(new URL('../devserver/mock-server.mjs', import.meta.url)), '--port', String(port), ...args], { stdio: ['ignore', 'pipe', 'inherit'] });
  const t = setTimeout(() => reject(new Error('mock did not start')), 30000);
  proc.stdout.on('data', (d) => { if (String(d).includes('console mock on')) { clearTimeout(t); resolve({ proc, base: `http://127.0.0.1:${port}` }); } });
});
let on;
let locked;
let old;
before(async () => { [on, locked, old] = await Promise.all([start([]), start(['--settings-editing', 'off']), start(['--round6', 'off'])]); });
after(() => { on?.proc.kill(); locked?.proc.kill(); old?.proc.kill(); });

async function login(base, token) {
  const res = await fetch(`${base}/api/v1/session`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ token }) });
  const body = res.ok ? await res.json() : null;
  return { status: res.status, cookie: (res.headers.get('set-cookie') || '').split(';')[0], csrf: body?.csrf_token, body };
}
const call = async (base, who, method, path, body) => {
  const res = await fetch(`${base}/api/v1${path}`, { method, headers: { cookie: who.cookie, 'X-AegisMesh-CSRF': who.csrf || '', ...(body ? { 'Content-Type': 'application/json' } : {}) }, body: body ? JSON.stringify(body) : undefined });
  const text = await res.text();
  let json = null;
  try { json = JSON.parse(text); } catch { /* empty */ }
  return { status: res.status, json, text };
};
const ROLE_KEYS = ['assigned', 'builtin', 'created_at', 'created_by', 'description', 'id', 'name', 'permissions', 'updated_at'].sort();
const inDays = (d) => new Date(Date.now() + d * 86400e3).toISOString().replace(/\.\d+Z$/, 'Z');

test('catalogue: 18 stable ids, groups, labels, risk; high-risk ids as the contract lists them', async () => {
  const a = await login(on.base, 'dev-viewer');
  const r = await call(on.base, a, 'GET', '/permissions');
  assert.equal(r.status, 200, 'any principal reads the catalogue');
  assert.equal(r.json.version, 1);
  assert.deepEqual(r.json.items.map((x) => x.id), PERMISSION_IDS);
  assert.equal(PERMISSION_IDS.length, 18);
  for (const x of r.json.items) {
    assert.deepEqual(Object.keys(x).sort(), ['group', 'id', 'label', 'risk']);
    assert.ok(['low', 'elevated', 'high'].includes(x.risk));
  }
  assert.deepEqual(PERMISSIONS.filter((x) => x.risk === 'high').map((x) => x.id).sort(), ['accounts.manage', 'fleet.manage', 'roles.manage', 'sessions.manage', 'settings.manage']);
});

test('built-ins: the agreed sets; /me carries sorted permissions and role_name', async () => {
  assert.deepEqual(BUILTIN.viewer, ['analysis.read', 'evidence.read', 'fleet.read', 'investigations.read', 'keys.self']);
  assert.deepEqual(BUILTIN.analyst, [...BUILTIN.viewer, 'evidence.export', 'investigations.write', 'reports.download'].sort());
  assert.deepEqual(BUILTIN.admin, [...PERMISSION_IDS].sort());
  for (const [token, role] of [['dev-viewer', 'viewer'], ['dev-analyst', 'analyst'], ['dev-admin', 'admin']]) {
    const w = await login(on.base, token);
    assert.equal(w.body.principal.role, role, '/session principal unchanged');
    assert.equal('permissions' in w.body.principal, false);
    const me = (await call(on.base, w, 'GET', '/me')).json;
    assert.deepEqual(me.permissions, BUILTIN[role]);
    assert.equal(me.role_name, role, 'built-in roles are named by their id');
  }
  const v = await login(on.base, 'dev-viewer');
  assert.deepEqual((await call(on.base, v, 'GET', '/me')).json.capabilities, { manage_own_keys: true, administer: false }, 'viewers hold keys.self');
  assert.equal((await call(on.base, v, 'GET', '/me/keys')).status, 200);
});

test('roles: list shape, live assignment counts, seeded custom roles', async () => {
  const a = await login(on.base, 'dev-admin');
  const r = (await call(on.base, a, 'GET', '/admin/roles')).json;
  assert.deepEqual(r.limits, { max_roles: 32, max_name_runes: 40, max_description_runes: 200 });
  assert.deepEqual(r.items.slice(0, 3).map((x) => x.id), ['viewer', 'analyst', 'admin']);
  for (const x of r.items) {
    assert.deepEqual(Object.keys(x).sort(), ROLE_KEYS);
    assert.match(x.id, /^(viewer|analyst|admin|role_[0-9a-f]{12})$/);
    assert.deepEqual(Object.keys(x.assigned).sort(), ['config', 'managed', 'oidc']);
  }
  const ticket = r.items.find((x) => x.id === SEED_ROLE_IDS.ticket);
  assert.equal(ticket.name, 'Ticket bridge');
  assert.equal(ticket.assigned.managed, 1);
  assert.equal(r.items.find((x) => x.id === SEED_ROLE_IDS.fleet).assigned.managed, 0);
  const accounts = (await call(on.base, a, 'GET', '/admin/accounts')).json.items;
  assert.equal(accounts.find((x) => x.name === 'auditor@soc.example').role, SEED_ROLE_IDS.auditor);
  assert.equal((await call(on.base, a, 'GET', `/admin/roles/${SEED_ROLE_IDS.auditor}`)).json.name, 'Auditor');
  assert.equal((await call(on.base, a, 'GET', '/admin/roles/role_000000000000')).status, 404);
  const an = await login(on.base, 'dev-analyst');
  assert.equal((await call(on.base, an, 'GET', '/admin/roles')).status, 403, 'needs accounts.read');
});

test('roles: create, rename, change, delete, and every refusal', async () => {
  const a = await login(on.base, 'dev-admin');
  const made = await call(on.base, a, 'POST', '/admin/roles', { name: 'Night shift', description: 'Reads and annotates.', permissions: ['evidence.read', 'investigations.read', 'investigations.write'] });
  assert.equal(made.status, 201);
  assert.match(made.json.id, /^role_[0-9a-f]{12}$/);
  assert.equal(made.json.builtin, false);
  assert.equal(made.json.created_by, 'ada');
  const id = made.json.id;
  const dup = await call(on.base, a, 'POST', '/admin/roles', { name: 'night SHIFT', permissions: ['evidence.read'] });
  assert.equal(dup.status, 409);
  assert.equal(dup.json.error.code, 'conflict', 'names are unique, case-insensitively');
  const req = await call(on.base, a, 'POST', '/admin/roles', { name: 'Settings only', permissions: ['evidence.read', 'settings.manage'] });
  assert.equal(req.status, 400);
  assert.match(req.json.error.message, /requires accounts\.manage and settings\.read/);
  assert.equal((await call(on.base, a, 'POST', '/admin/roles', { name: 'Sessions only', permissions: ['evidence.read', 'sessions.manage'] })).status, 400, 'sessions.manage needs accounts.read');
  assert.equal((await call(on.base, a, 'POST', '/admin/roles', { name: 'x', permissions: ['evidence.read', 'root.everything'] })).status, 400);
  assert.equal((await call(on.base, a, 'POST', '/admin/roles', { name: 'x', permissions: [] })).status, 400);
  assert.equal((await call(on.base, a, 'POST', '/admin/roles', { name: 'y'.repeat(41), permissions: ['evidence.read'] })).status, 400);
  assert.equal((await call(on.base, a, 'POST', '/admin/roles', { name: 'z', permissions: ['evidence.read'], colour: 'red' })).status, 400, 'strict fields');
  const patched = await call(on.base, a, 'PATCH', `/admin/roles/${id}`, { name: 'Night shift (EU)', permissions: ['evidence.read', 'investigations.read'] });
  assert.equal(patched.status, 200);
  assert.deepEqual(patched.json.permissions, ['evidence.read', 'investigations.read']);
  for (const builtin of ['viewer', 'analyst', 'admin']) {
    const r = await call(on.base, a, 'PATCH', `/admin/roles/${builtin}`, { name: 'Mine' });
    assert.equal(r.status, 409);
    assert.equal(r.json.error.code, 'builtin');
    assert.equal((await call(on.base, a, 'DELETE', `/admin/roles/${builtin}`)).json.error.code, 'builtin');
  }
  const inUse = await call(on.base, a, 'DELETE', `/admin/roles/${SEED_ROLE_IDS.ticket}`);
  assert.equal(inUse.status, 409);
  assert.equal(inUse.json.error.code, 'in_use');
  assert.match(inUse.json.error.message, /assigned to 1 account/);
  assert.equal((await call(on.base, a, 'DELETE', `/admin/roles/${id}`)).status, 204);
  assert.equal((await call(on.base, a, 'GET', `/admin/roles/${id}`)).status, 404);
  const audit = (await call(on.base, a, 'GET', '/audit?limit=200')).json.records.map((x) => x.action);
  for (const action of ['role.create', 'role.update', 'role.delete']) assert.ok(audit.includes(action), action);
  const an = await login(on.base, 'dev-analyst');
  assert.equal((await call(on.base, an, 'POST', '/admin/roles', { name: 'q', permissions: ['evidence.read'] })).status, 403);
});

test('last admin: no change may leave zero active principals holding roles.manage and accounts.manage', () => {
  const permsOf = (r) => ({ admin: BUILTIN.admin, viewer: BUILTIN.viewer, role_aaaaaaaaaaaa: ['accounts.manage', 'roles.manage', 'evidence.read'] }[r] || []);
  const people = [{ id: 'a', role: 'admin', active: true }, { id: 'b', role: 'role_aaaaaaaaaaaa', active: true }, { id: 'c', role: 'viewer', active: true }];
  assert.equal(wouldLeaveNoAdmin(people, permsOf, { principalId: 'a', role: 'viewer' }), false, 'b still holds both');
  const one = [people[1], people[2]];
  assert.equal(wouldLeaveNoAdmin(one, permsOf, { principalId: 'b', role: 'viewer' }), true);
  assert.equal(wouldLeaveNoAdmin(one, permsOf, { principalId: 'b', active: false }), true);
  assert.equal(wouldLeaveNoAdmin(one, permsOf, { roleId: 'role_aaaaaaaaaaaa', permissions: ['accounts.manage', 'evidence.read'] }), true);
  assert.equal(wouldLeaveNoAdmin(one, permsOf, { roleId: 'role_aaaaaaaaaaaa', permissions: ['accounts.manage', 'roles.manage'] }), false);
  assert.equal(checkRoleBody({ name: 'ok', permissions: ['roles.manage', 'accounts.manage', 'accounts.read'] }), null);
});

test('a custom role decides each request, and an edit applies on the next one', async () => {
  const a = await login(on.base, 'dev-admin');
  const role = (await call(on.base, a, 'POST', '/admin/roles', { name: `Reader ${Date.now()}`, permissions: ['evidence.read'] })).json;
  const acc = (await call(on.base, a, 'POST', '/admin/accounts', { name: `reader-${Date.now()}`, kind: 'service', role: role.id, tenants: ['default'] })).json;
  assert.equal(acc.role, role.id, 'managed accounts take any role id');
  assert.equal((await call(on.base, a, 'POST', '/admin/accounts', { name: 'nope', kind: 'service', role: 'role_ffffffffffff', tenants: ['default'] })).status, 400);
  const key = (await call(on.base, a, 'POST', `/admin/accounts/${acc.id}/keys`, { label: 'reader', expires_in_days: 30 })).json;
  const svc = await login(on.base, key.token);
  assert.equal(svc.status, 200);
  assert.equal(svc.body.principal.role, role.id);
  const me = (await call(on.base, svc, 'GET', '/me')).json;
  assert.deepEqual(me.permissions, ['evidence.read']);
  assert.equal(me.role_name, role.name);
  assert.deepEqual(me.capabilities, { manage_own_keys: false, administer: false });
  assert.equal((await call(on.base, svc, 'GET', '/events?limit=1')).status, 200);
  assert.equal((await call(on.base, svc, 'GET', '/investigations')).status, 403, 'no investigations.read');
  assert.equal((await call(on.base, svc, 'GET', '/posture')).status, 403, 'no analysis.read');
  assert.equal((await call(on.base, svc, 'GET', '/me/keys')).status, 403, 'no keys.self');
  await call(on.base, a, 'PATCH', `/admin/roles/${role.id}`, { permissions: ['evidence.read', 'investigations.read', 'analysis.read'] });
  assert.equal((await call(on.base, svc, 'GET', '/investigations')).status, 200, 'the same session, next request');
  assert.equal((await call(on.base, svc, 'GET', '/posture')).status, 200);
  assert.equal((await call(on.base, svc, 'POST', '/investigations', { title: 'x' })).status, 403, 'writes need investigations.write');
  // An auditor-like role reads administration without managing it.
  const audRole = (await call(on.base, a, 'POST', '/admin/roles', { name: `Reviewer ${Date.now()}`, permissions: ['evidence.read', 'accounts.read', 'settings.read', 'audit.read'] })).json;
  await call(on.base, a, 'PATCH', `/admin/accounts/${acc.id}`, { role: audRole.id });
  assert.equal((await call(on.base, svc, 'GET', '/admin/accounts')).status, 200);
  assert.equal((await call(on.base, svc, 'GET', '/admin/settings')).status, 200);
  assert.equal((await call(on.base, svc, 'GET', '/audit')).status, 200);
  assert.equal((await call(on.base, svc, 'GET', '/system')).status, 403, 'no system.read');
  assert.equal((await call(on.base, svc, 'POST', '/admin/accounts', { name: 'x', kind: 'person', role: 'viewer', tenants: ['default'] })).status, 403);
  assert.equal((await call(on.base, svc, 'PUT', '/admin/settings/console.default_window', { value: '7d', reason: 'x' })).status, 403);
  assert.equal((await call(on.base, svc, 'GET', '/me')).json.capabilities.administer, true);
  // A role manager cannot grant what its own role lacks.
  const mgr = (await call(on.base, a, 'POST', '/admin/roles', { name: `Role keeper ${Date.now()}`, permissions: ['evidence.read', 'accounts.read', 'accounts.manage', 'roles.manage'] })).json;
  await call(on.base, a, 'PATCH', `/admin/accounts/${acc.id}`, { role: mgr.id });
  const over = await call(on.base, svc, 'POST', '/admin/roles', { name: `Fleet ${Date.now()}`, permissions: ['evidence.read', 'fleet.read', 'fleet.manage'] });
  assert.equal(over.status, 403);
  assert.equal(over.json.error.code, 'exceeds_own_permissions');
  assert.equal((await call(on.base, svc, 'POST', '/admin/roles', { name: `Readers ${Date.now()}`, permissions: ['evidence.read'] })).status, 201, 'within its own permissions');
});

test('settings: editable items carry effective, file value, constraints; PUT, validation, revert, history, audit, meta', async () => {
  const a = await login(on.base, 'dev-admin');
  const body = (await call(on.base, a, 'GET', '/admin/settings')).json;
  assert.equal(body.editable, true);
  assert.equal(body.editing, 'console');
  const items = body.sections.flatMap((s) => s.items);
  for (const it of items) for (const k of ['editable', 'effective', 'file_value', 'overridden', 'constraints', 'applies']) assert.ok(k in it, `${it.key} has ${k}`);
  const ttl = items.find((x) => x.key === 'console.session_ttl_seconds');
  assert.deepEqual([ttl.editable, ttl.overridden, ttl.effective, ttl.file_value, ttl.value], [true, true, '43200', '28800', '12h']);
  assert.deepEqual(ttl.constraints, { min: 900, max: 86400, unit: 's', reason_max_len: 200 });
  assert.equal(ttl.source, 'console', 'an override reports source console');
  assert.equal(items.find((x) => x.key === 'console.listen').editable, false);
  assert.deepEqual(body.sections.find((s) => s.id === 'console').items.map((x) => x.key), ['console.organization_name', 'console.sign_in_banner', 'console.default_window', 'posture.accepted']);

  const put = (key, value, reason = 'Synthetic test change.') => call(on.base, a, 'PUT', `/admin/settings/${key}`, { value, reason });
  assert.equal((await put('console.session_ttl_seconds', 600)).status, 400, 'below the minimum');
  assert.equal((await put('console.session_ttl_seconds', 3600, '')).status, 400, 'a reason is required');
  assert.equal((await put('console.session_ttl_seconds', 3600, 'r'.repeat(201))).status, 400);
  assert.equal((await put('console.session_idle_seconds', 120)).status, 400, '0 or 300..86400');
  assert.equal((await put('console.session_idle_seconds', 0)).json.value, 'off');
  assert.equal((await put('console.default_window', '30d')).status, 400);
  assert.equal((await put('console.key_default_days', 400)).status, 400, 'at most the longest lifetime');
  assert.equal((await put('console.organization_name', 'x'.repeat(81))).status, 400);
  assert.equal((await put('console.listen', '0.0.0.0:80')).json.error.code, 'not_editable');
  assert.equal((await put('console.nope', 'x')).json.error.code, 'not_editable', 'anything outside the allowlist');
  assert.equal((await put('posture.accepted', 'x')).json.error.code, 'not_editable', 'accepted risk is changed on Posture');
  assert.equal((await call(on.base, a, 'PUT', '/admin/settings/console.default_window', { value: '7d', reason: 'x', extra: 1 })).status, 400, 'strict fields');

  const set = await put('console.key_max_days', '120', 'Shorter keys for the audit year.');
  assert.equal(set.status, 200);
  assert.deepEqual([set.json.effective, set.json.overridden, set.json.value], ['120', true, '120 days']);
  assert.deepEqual((await call(on.base, a, 'GET', '/admin/accounts')).json.limits.max_key_days, 120, 'limits follow the overlay');
  assert.equal((await call(on.base, a, 'POST', '/me/keys', { label: 'long', expires_in_days: 200 })).status, 400);
  const org = await put('console.organization_name', '<b>Blue Team</b>');
  assert.equal(org.json.effective, '<b>Blue Team</b>', 'stored as plain text');
  const meta = await (await fetch(`${on.base}/api/v1/meta`)).json();
  assert.equal(meta.organization_name, '<b>Blue Team</b>');
  assert.equal(typeof meta.sign_in_banner, 'string');
  await put('console.default_window', '7d');
  assert.equal((await call(on.base, await login(on.base, 'dev-viewer'), 'GET', '/me/preferences')).json.default_window, '7d', 'the default for accounts without a choice');

  const back = await call(on.base, a, 'DELETE', '/admin/settings/console.key_max_days');
  assert.equal(back.status, 200);
  assert.deepEqual([back.json.effective, back.json.overridden], ['365', false]);
  const hist = (await call(on.base, a, 'GET', '/admin/settings/history?key=console.key_max_days')).json.items;
  assert.deepEqual(hist.map((x) => x.action), ['revert', 'update']);
  assert.deepEqual([hist[1].from, hist[1].to, hist[1].actor_name, hist[1].reason], ['365', '120', 'ada', 'Shorter keys for the audit year.']);
  for (const x of hist) assert.deepEqual(Object.keys(x).sort(), ['action', 'actor_id', 'actor_name', 'at', 'from', 'key', 'reason', 'seq', 'to']);
  const all = (await call(on.base, a, 'GET', '/admin/settings/history')).json.items;
  assert.ok(all.length >= 5);
  assert.ok(all.every((x, i) => i === 0 || all[i - 1].seq > x.seq), 'newest first');
  assert.equal((await call(on.base, a, 'GET', '/admin/settings/history?colour=1')).status, 400);
  const audit = (await call(on.base, a, 'GET', '/audit?limit=200')).json.records;
  const upd = audit.find((x) => x.action === 'settings.update' && x.target === 'console.key_max_days');
  assert.match(upd.detail, /^from="365" to="120" seq=\d+ reason="Shorter keys for the audit year\."$/);
  assert.ok(audit.some((x) => x.action === 'settings.revert'));
  const an = await login(on.base, 'dev-analyst');
  assert.equal((await call(on.base, an, 'GET', '/admin/settings/history')).status, 403);
});

test('--settings-editing off: everything read-only, writes answer editing_disabled', async () => {
  const a = await login(locked.base, 'dev-admin');
  const body = (await call(locked.base, a, 'GET', '/admin/settings')).json;
  assert.equal(body.editable, false);
  assert.equal(body.editing, 'off');
  assert.ok(body.sections.flatMap((s) => s.items).every((x) => x.editable === false));
  const r = await call(locked.base, a, 'PUT', '/admin/settings/console.default_window', { value: '7d', reason: 'x' });
  assert.equal(r.status, 409);
  assert.equal(r.json.error.code, 'editing_disabled');
  assert.equal((await call(locked.base, a, 'DELETE', '/admin/settings/console.session_ttl_seconds')).json.error.code, 'editing_disabled');
  assert.equal((await call(locked.base, a, 'POST', '/posture/POS-003/accept', { reason: 'x', until: inDays(10) })).json.error.code, 'editing_disabled');
  assert.equal((await call(locked.base, a, 'GET', '/admin/settings/history')).status, 200, 'history stays readable');
});

test('posture: accepted risk is its own status and count, with limits and revocation', async () => {
  const a = await login(on.base, 'dev-admin');
  const p = (await call(on.base, a, 'GET', '/posture')).json;
  const count = (k) => p.checks.filter((x) => x.status === k).length;
  assert.deepEqual(p.summary, { attention: count('attention'), accepted: count('accepted'), ok: count('ok'), info: count('info') });
  assert.ok(p.summary.accepted >= 1 && p.summary.attention >= 1);
  const seeded = p.checks.find((x) => x.status === 'accepted');
  assert.deepEqual(Object.keys(seeded.accepted).sort(), ['by', 'by_name', 'reason', 'until']);
  assert.ok(p.checks.filter((x) => x.status !== 'accepted').every((x) => x.accepted === null));
  const target = p.checks.find((x) => x.status === 'attention');
  const post = (id, body, who = a) => call(on.base, who, 'POST', `/posture/${id}/accept`, body);
  assert.equal((await post(target.id, { reason: '', until: inDays(30) })).status, 400);
  assert.equal((await post(target.id, { reason: 'x', until: inDays(181) })).status, 400, 'at most 180 days');
  assert.equal((await post(target.id, { reason: 'x', until: inDays(-1) })).status, 400);
  assert.equal((await post(target.id, { reason: 'x', until: 'next week' })).status, 400);
  const ok = p.checks.find((x) => x.status === 'ok');
  assert.equal((await post(ok.id, { reason: 'x', until: inDays(30) })).json.error.code, 'conflict');
  assert.equal((await post('POS-999', { reason: 'x', until: inDays(30) })).status, 404);
  const an = await login(on.base, 'dev-analyst');
  assert.equal((await post(target.id, { reason: 'x', until: inDays(30) }, an)).status, 403, 'needs settings.manage');
  const acc = await post(target.id, { reason: 'Compensating control: the lure is behind the VPN.', until: inDays(90) });
  assert.equal(acc.status, 200);
  assert.equal(acc.json.status, 'accepted');
  assert.equal(acc.json.accepted.by_name, 'ada');
  const ph = (await call(on.base, a, 'GET', '/admin/settings/history?key=posture.accepted')).json.items;
  assert.match(ph[0].to, new RegExp(`^${target.id}: accepted until `), 'acceptances are in the settings history');
  const after1 = (await call(on.base, a, 'GET', '/posture')).json;
  assert.equal(after1.summary.accepted, p.summary.accepted + 1);
  const rev = await call(on.base, a, 'DELETE', `/posture/${target.id}/accept`);
  assert.equal(rev.status, 200);
  assert.equal(rev.json.status, 'attention');
  assert.equal(rev.json.accepted, null);
  const actions = (await call(on.base, a, 'GET', '/audit?limit=200')).json.records.map((x) => x.action);
  assert.ok(actions.includes('posture.accept') && actions.includes('posture.unaccept'));
});

test('--round6 off: a round-5 server', async () => {
  const a = await login(old.base, 'dev-admin');
  for (const [m, p] of [['GET', '/permissions'], ['GET', '/admin/roles'], ['GET', `/admin/roles/${SEED_ROLE_IDS.ticket}`], ['GET', '/admin/settings/history'], ['PUT', '/admin/settings/console.default_window'], ['DELETE', '/admin/settings/console.default_window'], ['POST', '/posture/POS-003/accept']]) {
    assert.equal((await call(old.base, a, m, p, m === 'GET' || m === 'DELETE' ? undefined : { value: '7d', reason: 'x', until: inDays(3) })).status, 404, `${m} ${p}`);
  }
  const me = (await call(old.base, a, 'GET', '/me')).json;
  assert.equal('permissions' in me, false);
  assert.equal('role_name' in me, false);
  const meta = await (await fetch(`${old.base}/api/v1/meta`)).json();
  assert.equal('organization_name' in meta, false);
  assert.equal('sign_in_banner' in meta, false);
  const settings = (await call(old.base, a, 'GET', '/admin/settings')).json;
  assert.equal(settings.sections.some((s) => s.id === 'console'), false);
  assert.ok(settings.sections.flatMap((s) => s.items).every((x) => !('effective' in x)));
  const posture = (await call(old.base, a, 'GET', '/posture')).json;
  assert.ok(posture.checks.every((x) => !('accepted' in x)));
  assert.equal('accepted' in posture.summary, false);
  const accounts = (await call(old.base, a, 'GET', '/admin/accounts')).json.items;
  assert.equal(accounts.find((x) => x.name === 'ticket-bridge').role, 'analyst');
  assert.equal(accounts.some((x) => x.name === 'auditor@soc.example'), false);
  const v = await login(old.base, 'dev-viewer');
  assert.equal((await call(old.base, v, 'GET', '/me/keys')).status, 403, 'round 5: viewers cannot manage keys in the mock');
});

test('formatSeconds: the settings display', () => {
  assert.equal(formatSeconds(28800), '8h');
  assert.equal(formatSeconds(1800), '30m');
  assert.equal(formatSeconds(0), 'off');
  assert.equal(formatSeconds(5430), '1h 30m 30s');
});
