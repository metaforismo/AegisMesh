// Settings and administration: preferences (parsing, browser copy, the
// optimistic store with rollback), the time zone and default window they
// drive, the settings rules (validation, refusals, gating, routes), the API
// client's refusal reason, and the UI kit (confirmation, one-time reveal,
// read-only settings) in the fake DOM.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createFakeDocument } from './fakedom.mjs';

globalThis.document = createFakeDocument();
const prefsLib = await import('../static/assets/js/lib/prefs.js');
const fmt = await import('../static/assets/js/lib/format.js');
const route = await import('../static/assets/js/lib/route.js');
const S = await import('../static/assets/js/lib/settings.js');
const { createApi, ApiError } = await import('../static/assets/js/lib/api.js');
const kit = await import('../static/assets/js/ui/settings-kit.js');

const { parsePreferences, cleanPatch, readLocalPrefs, writeLocalPrefs, createPrefsStore, PREF_DEFAULTS } = prefsLib;

function memoryStorage(init = {}) {
  const m = new Map(Object.entries(init));
  return { getItem: (k) => (m.has(k) ? m.get(k) : null), setItem: (k, v) => m.set(k, String(v)), dump: () => Object.fromEntries(m) };
}
const tick = () => new Promise((r) => setTimeout(r, 0));

// ---- Preferences -------------------------------------------------------------

test('preferences: closed vocabularies, unknown keys and values fall back', () => {
  assert.deepEqual(parsePreferences(null), PREF_DEFAULTS);
  assert.deepEqual(parsePreferences({ timezone: 'local', theme: 'dark', density: 'x', evil: '<b>', default_window: '7d', reduce_motion: 'on' }),
    { timezone: 'local', default_window: '7d', density: 'comfortable', theme: 'dark', reduce_motion: 'on' });
  assert.equal(cleanPatch({ theme: 'neon' }), null);
  assert.deepEqual(cleanPatch({ theme: 'light', __proto__: { x: 1 }, nope: 1 }), { theme: 'light' });
});

test('preferences: the browser copy keeps the old theme and density keys and is read back as untrusted', () => {
  const st = memoryStorage({ 'aegismesh.theme': 'dark', 'aegismesh.density': 'compact', 'aegismesh.prefs': '{"timezone":"local","default_window":"bogus"}' });
  assert.deepEqual(readLocalPrefs(st), { ...PREF_DEFAULTS, theme: 'dark', density: 'compact', timezone: 'local' });
  assert.deepEqual(readLocalPrefs(memoryStorage({ 'aegismesh.prefs': '[1,2' })), PREF_DEFAULTS);
  writeLocalPrefs(st, { ...PREF_DEFAULTS, reduce_motion: 'on' });
  assert.equal(st.dump()['aegismesh.theme'], 'system');
  assert.deepEqual(JSON.parse(st.dump()['aegismesh.prefs']), { timezone: 'utc', default_window: '24h', reduce_motion: 'on' });
  assert.deepEqual(readLocalPrefs({ getItem() { throw new Error('denied'); } }), PREF_DEFAULTS);
});

test('preferences store: the server wins on sync, a change applies at once and is saved', async () => {
  const applied = [];
  const saved = [];
  const st = memoryStorage({ 'aegismesh.theme': 'light' });
  const store = createPrefsStore({
    load: async () => ({ ...PREF_DEFAULTS, theme: 'dark', timezone: 'local' }),
    save: async (p) => { saved.push(p); return p; },
    apply: (p) => applied.push(p.theme),
    storage: st,
  });
  store.start();
  assert.deepEqual(applied, ['light'], 'browser copy first, before any request');
  await store.sync();
  assert.equal(store.source(), 'server');
  assert.equal(store.get().theme, 'dark');
  assert.equal(st.dump()['aegismesh.theme'], 'dark', 'browser copy follows the server');
  const p = store.update({ density: 'compact' });
  assert.equal(store.get().density, 'compact', 'optimistic');
  await p;
  assert.equal(saved.length, 1);
  assert.equal(saved[0].density, 'compact');
});

test('preferences store: a refused save rolls back, re-applies and rethrows', async () => {
  const applied = [];
  const store = createPrefsStore({
    load: async () => PREF_DEFAULTS,
    save: async () => { throw new ApiError(503, 'unavailable', 'read-only'); },
    apply: (p) => applied.push(p.timezone),
    storage: memoryStorage(),
  });
  await store.sync();
  await assert.rejects(store.update({ timezone: 'local' }), (e) => e.status === 503);
  assert.equal(store.get().timezone, 'utc');
  assert.deepEqual(applied.slice(-2), ['local', 'utc'], 'applied, then put back');
});

test('preferences store: an older server (404) keeps preferences in the browser; other failures surface', async () => {
  const missing = (e) => e?.status === 404;
  const st = memoryStorage();
  const store = createPrefsStore({ load: async () => { throw new ApiError(404, 'not_found', 'no'); }, save: async () => { throw new Error('must not save'); }, apply() {}, storage: st, isMissing: missing });
  await store.sync();
  assert.equal(store.source(), 'browser');
  await store.update({ theme: 'dark' });
  assert.equal(st.dump()['aegismesh.theme'], 'dark');
  const failing = createPrefsStore({ load: async () => { throw new ApiError(500, 'internal', 'x'); }, save: async () => null, apply() {}, storage: memoryStorage(), isMissing: missing });
  await assert.rejects(failing.sync());
  assert.equal(failing.source(), 'browser');
});

test('preferences store: saves are serialised and a later change is never overwritten by an earlier answer', async () => {
  const order = [];
  let release;
  const gate = new Promise((r) => { release = r; });
  const store = createPrefsStore({
    load: async () => PREF_DEFAULTS,
    save: async (p) => { order.push(p.theme); if (p.theme === 'dark') await gate; return p; },
    apply() {}, storage: memoryStorage(),
  });
  await store.sync();
  const a = store.update({ theme: 'dark' });
  const b = store.update({ theme: 'light' });
  await tick();
  assert.deepEqual(order, ['dark'], 'second save waits for the first');
  release();
  await Promise.all([a, b]);
  assert.deepEqual(order, ['dark', 'light']);
  assert.equal(store.get().theme, 'light');
});

// ---- Time zone and default window ----------------------------------------------

test('time zone: UTC by default; local time prints the offset everywhere', () => {
  assert.equal(fmt.timeZone(), 'utc');
  assert.equal(fmt.formatDateTime('2026-11-14T09:03:44Z'), '2026-11-14 09:03:44 UTC');
  fmt.setTimeZone('local');
  try {
    const d = new Date('2026-11-14T09:03:44Z');
    const pad = (n) => String(n).padStart(2, '0');
    const out = fmt.formatDateTime('2026-11-14T09:03:44Z');
    assert.ok(out.startsWith(`${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())} UTC`), out);
    assert.match(fmt.zoneLabel(d), /^UTC([+−]\d{1,2}(:\d{2})?)?$/);
    assert.equal(fmt.formatClock('2026-11-14T09:03:44Z'), `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`);
    assert.equal(fmt.zoneName(), 'local time');
  } finally {
    fmt.setTimeZone('utc');
  }
  assert.equal(fmt.setTimeZone('mars'), 'utc', 'unknown values fall back to UTC');
});

test('default window: links without a window open with the preference; explicit windows win', () => {
  assert.equal(route.normalizeWindow(undefined), '24h');
  route.setDefaultWindow('7d');
  try {
    assert.equal(route.normalizeWindow(undefined), '7d');
    assert.equal(route.normalizeWindow('1h'), '1h');
    assert.equal(route.normalizeWindow('<x>'), '7d');
  } finally {
    route.setDefaultWindow('24h');
  }
  assert.equal(route.setDefaultWindow('forever'), '24h');
});

// ---- Settings rules ---------------------------------------------------------------

test('settings routes: closed section ids and the three account id shapes', () => {
  assert.equal(route.parseHash('#/settings').name, 'settings');
  assert.deepEqual(route.parseHash('#/settings/keys').params, { section: 'keys' });
  assert.equal(route.parseHash('#/settings/evil').name, 'not_found');
  assert.equal(route.parseHash('#/settings/accounts/acc_7k2m9q4wz1').name, 'settings_account');
  assert.equal(route.parseHash('#/settings/accounts/cfg%3Aada').params.id, 'cfg:ada');
  assert.equal(route.parseHash('#/settings/accounts/oidc%3A0123456789ab').name, 'settings_account');
  for (const bad of ['acc_', 'cfg:<b>', 'oidc:xyz', '..%2F..']) assert.equal(route.parseHash(`#/settings/accounts/${bad}`).name, 'not_found', bad);
  assert.equal(route.href('settings', 'accounts', 'cfg:ada'), '#/settings/accounts/cfg%3Aada');
});

test('settings gating: administration only with capabilities.administer (a convenience; the server decides)', () => {
  assert.equal(S.visibleSections(null).admin.length, 0, 'older server');
  assert.equal(S.visibleSections({ role: 'admin', capabilities: { administer: false } }).admin.length, 0, 'admin role outside the local tenant');
  assert.equal(S.visibleSections({ capabilities: { administer: true } }).admin.length, S.ADMIN_SECTIONS.length);
  assert.ok(S.isAdminSection('accounts') && !S.isAdminSection('keys'));
  assert.equal(S.ACCOUNT_SECTIONS.length, 4);
});

test('settings validation: labels, names, tenants, typed confirmation', () => {
  assert.equal(S.validateKeyLabel('siem-pull'), '');
  assert.match(S.validateKeyLabel('  '), /label/);
  assert.match(S.validateKeyLabel('x'.repeat(65)), /64/);
  assert.match(S.validateKeyLabel('a\u0007b'), /printable/);
  assert.equal(S.validateAccountName('morgan@soc.example'), '');
  assert.match(S.validateAccountName('<script>'), /letters/);
  assert.match(S.validateTenants([], ['a']), /at least one/);
  assert.match(S.validateTenants(['b'], ['a']), /declares/);
  assert.ok(S.typedMatches(' ci smoke test ', 'ci smoke test'));
  assert.ok(!S.typedMatches('ci smoke', 'ci smoke test'));
  assert.ok(!S.typedMatches('', ''), 'an empty target never matches');
  assert.deepEqual(S.EXPIRY_PRESETS, [30, 90, 180, 365]);
});

test('settings refusals: specific words for last_admin, not_managed, 403, 404 and an unreachable server', () => {
  const e = (status, reason = '', message = 'm') => Object.assign(new ApiError(status, 'conflict', message), { reason });
  assert.match(S.refusalMessage(e(409, 'last_admin')), /no active admin/);
  assert.match(S.refusalMessage(e(409, 'not_managed')), /config file/);
  assert.match(S.refusalMessage(e(409, 'name_taken')), /already exists/);
  assert.match(S.refusalMessage(new ApiError(403, 'forbidden', 'x'), { what: 'revoking this key' }), /refused revoking this key/);
  assert.match(S.refusalMessage(new ApiError(404, 'not_found', 'x')), /no longer exists/);
  assert.match(S.refusalMessage(new ApiError(0, 'unavailable', 'x')), /Nothing was changed/);
});

test('settings sources and statuses: unknown server values never become class names or claims', () => {
  assert.equal(S.sourceMeta('config').editable, false);
  assert.equal(S.sourceMeta('managed').editable, true);
  assert.equal(S.sourceMeta('<x>').editable, false);
  assert.equal(S.keyStatusMeta('weird').label, 'Unknown');
  assert.equal(S.roleText('root').label, 'Unknown role');
  const g = S.groupSettings({ sections: [{ id: 'access', items: [] }, { id: 'future', items: [] }, null, { id: 7 }] });
  assert.ok(g.byId.has('access'));
  assert.deepEqual(g.other.map((s) => s.id), ['future']);
});

// ---- API client ---------------------------------------------------------------------

test('api: a specific refusal code is kept as a reason token, the generic code follows the status', async () => {
  const reply = (status, body) => async () => ({ ok: false, status, headers: { get: () => null }, json: async () => body });
  const run = async (body, status = 409) => {
    const api = createApi({ fetchImpl: reply(status, body) });
    try { await api.updateAccount('acc_1234', { role: 'viewer' }); } catch (e) { return e; }
    return null;
  };
  let e = await run({ error: { code: 'last_admin', message: 'would leave no admin' } });
  assert.equal(e.code, 'conflict');
  assert.equal(e.reason, 'last_admin');
  e = await run({ error: { code: 'conflict', reason: 'not_managed', message: 'x' } });
  assert.equal(e.reason, 'not_managed');
  e = await run({ error: { code: '<img src=x>', message: 'x' } });
  assert.equal(e.reason, '', 'anything but a short token is dropped');
  e = await run({ error: { code: 'forbidden', message: 'x' } }, 403);
  assert.equal(e.code, 'forbidden');
  assert.equal(e.reason, '');
});

test('api: round-5 calls use the contract paths and encode account ids', async () => {
  const seen = [];
  const api = createApi({ fetchImpl: async (url, init) => { seen.push(`${init.method} ${url}`); return { ok: true, status: 204, headers: { get: () => null } }; } });
  await api.revokeAccountKey('cfg:ada', 'key_0123456789ab');
  await api.revokeMySession('ses_0123456789abcdef');
  await api.putPreferences({ theme: 'dark' });
  assert.deepEqual(seen, [
    'DELETE /api/v1/admin/accounts/cfg%3Aada/keys/key_0123456789ab',
    'DELETE /api/v1/me/sessions/ses_0123456789abcdef',
    'PUT /api/v1/me/preferences',
  ]);
});

// ---- UI kit in the fake DOM -------------------------------------------------------------

const texts = (n) => n.textContent;
const find = (root, pred) => root.querySelectorAll(pred)[0] || null;
const byClass = (c) => (el) => (el.getAttribute('class') || '').split(' ').includes(c);

test('key reveal: shown once in one Text node; "I have stored it" empties it and removes the panel', () => {
  const token = `amk_${'A'.repeat(43)}`;
  let done = 0;
  const r = kit.keyReveal({ token, key: { label: 'ci', prefix: 'amk_AAAA', expires_at: '2027-01-01T00:00:00Z' } }, { onDone: () => { done++; } });
  document.body.appendChild(r.el);
  assert.ok(texts(r.el).includes(token));
  assert.match(texts(r.el), /You will not see this key again/);
  const value = find(r.el, byClass('reveal__value'));
  const textNode = value.childNodes[0];
  const doneBtn = find(r.el, (el) => el.tagName === 'button' && el.textContent === 'I have stored it');
  doneBtn.dispatch('click');
  assert.equal(textNode.data, '', 'the token Text node is emptied');
  assert.equal(r.el.parentNode, null, 'the panel is removed');
  assert.equal(done, 1);
  assert.ok(!texts(document.body).includes(token));
  // Leaving the page (cleanup) destroys it the same way, once.
  const r2 = kit.keyReveal({ token, key: {} });
  document.body.appendChild(r2.el);
  r2.destroy();
  r2.destroy();
  assert.ok(!texts(document.body).includes(token));
});

test('confirmation: typed match gates the action; a 204 confirms; a refusal stays in the dialog', async () => {
  const run = (onConfirm) => {
    const p = kit.confirmAction({ title: 'Revoke this API key?', consequence: 'It stops working.', targetLabel: 'Key', target: 'ci (amk_AAAA…)', typed: 'ci', confirmLabel: 'Revoke key', onConfirm });
    const dialog = document.body.childNodes[document.body.childNodes.length - 1];
    return { p, dialog };
  };
  let calls = 0;
  const { p, dialog } = run(async () => { calls++; return null; });
  assert.equal(dialog.tagName, 'dialog');
  assert.equal(dialog.open, true);
  const input = find(dialog, (el) => el.tagName === 'input');
  const submit = find(dialog, (el) => el.tagName === 'button' && el.getAttribute('type') === 'submit');
  const form = find(dialog, (el) => el.tagName === 'form');
  assert.equal(submit.disabled, true);
  assert.equal(document.activeElement, input, 'focus starts on the typed field');
  input.value = 'c';
  input.dispatch('input');
  form.dispatch('submit', { preventDefault() {} });
  await tick();
  assert.equal(calls, 0, 'no request until the name matches');
  input.value = 'ci';
  input.dispatch('input');
  assert.equal(submit.disabled, false);
  form.dispatch('submit', { preventDefault() {} });
  assert.equal(await p, true, 'a 204 (null) still confirms');
  assert.equal(calls, 1);

  const second = run(async () => { throw Object.assign(new ApiError(409, 'conflict', 'x'), { reason: 'last_admin' }); });
  const in2 = find(second.dialog, (el) => el.tagName === 'input');
  in2.value = 'ci';
  in2.dispatch('input');
  find(second.dialog, (el) => el.tagName === 'form').dispatch('submit', { preventDefault() {} });
  await tick();
  await tick();
  assert.equal(second.dialog.open, true, 'stays open');
  assert.match(texts(second.dialog), /no active admin/);
  find(second.dialog, (el) => el.tagName === 'button' && el.textContent === 'Cancel').dispatch('click');
  assert.equal(await second.p, null, 'cancel resolves null');
});

test('read-only settings renderer: values as text, closed source marks, copyable keys, no controls', () => {
  const el = kit.settingsSection({ id: 'access', items: [
    { key: 'console.session_ttl_seconds', label: 'Session lifetime', value: '8h', kind: 'duration', source: 'config', editable: false, note: 'Change in the config file and restart.' },
    { key: 'x.y', label: '<b>odd</b>', value: '<img src=x>', kind: 'text', source: 'registry', editable: true },
  ] });
  assert.match(texts(el), /Session lifetime8h/);
  assert.match(texts(el), /<img src=x>/, 'server text stays text');
  const chips = el.querySelectorAll(byClass('src-chip'));
  assert.deepEqual(chips.map((c) => c.getAttribute('class')), ['src-chip src-chip--config', 'src-chip src-chip--unknown']);
  assert.equal(el.querySelectorAll((n) => ['input', 'select', 'textarea'].includes(n.tagName)).length, 0);
  assert.equal(el.querySelectorAll(byClass('copy')).length, 2);
});

test('backend deviations: key lifetimes follow the server limits; editable and the runtime source', () => {
  assert.deepEqual(S.expiryOptions(null), { presets: [30, 90, 180, 365], def: 90 });
  assert.deepEqual(S.expiryOptions({ max_key_days: 180, default_key_days: 30 }), { presets: [30, 90, 180], def: 30 });
  assert.deepEqual(S.expiryOptions({ max_key_days: 7, default_key_days: 90 }), { presets: [7], def: 7 });
  assert.equal(S.accountEditable({ source: 'managed' }), true);
  assert.equal(S.accountEditable({ source: 'managed', editable: false }), false, 'the server can say no');
  assert.equal(S.accountEditable({ source: 'config', editable: true }), false, 'never a configured operator');
  assert.equal(S.settingSourceMeta('runtime').label, 'Measured');
  const el = kit.settingsSection({ items: [{ key: 'index.occupancy', label: 'Index occupancy', value: '1,284 events', kind: 'text', source: 'runtime' }] });
  assert.equal(el.querySelectorAll(byClass('src-chip'))[0].getAttribute('class'), 'src-chip src-chip--runtime');
});
