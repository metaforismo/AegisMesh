// Round 6 screens in the fake DOM with a stubbed API: roles (list, built-in,
// editor with live summary and dependency warning, older server, 403),
// editable settings (edit, validation, save shows the server's answer,
// revert, editing off, no permission), the change history, and accepted
// posture risk (gated by permission, its own group).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createFakeDocument } from './fakedom.mjs';

const doc = createFakeDocument();
const proto = Object.getPrototypeOf(doc.createElement('x'));
Object.defineProperty(proto, 'classList', { get() { const el = this; return { add: (c) => el.setAttribute('class', `${el.getAttribute('class') || ''} ${c}`.trim()), remove() {}, contains: () => false, toggle() {} }; } });
globalThis.document = doc;
Object.defineProperty(proto, 'dataset', { get() { this._ds ||= {}; return this._ds; } });
Object.defineProperty(proto, 'children', { get() { return this.childNodes.filter((n) => n.nodeType === 1); } });
globalThis.Event = class Event { constructor(type) { this.type = type; } };
proto.dispatchEvent = function dispatchEvent(ev) { this.dispatch(ev.type, ev); };

const { default: settings } = await import('../static/assets/js/screens/settings.js');
const { default: posture } = await import('../static/assets/js/screens/posture.js');
const { ApiError } = await import('../static/assets/js/lib/api.js');
const { parseHash } = await import('../static/assets/js/lib/route.js');
const { createPrefsStore, PREF_DEFAULTS } = await import('../static/assets/js/lib/prefs.js');
const { toCan, BUILTIN_PERMS } = await import('../static/assets/js/lib/perms.js');

const missing = () => new ApiError(404, 'not_found', 'no such endpoint');
const reply = (v) => (v instanceof Error ? Promise.reject(v) : Promise.resolve(typeof v === 'function' ? v() : v));

const ADA = { id: 'cfg:ada', name: 'ada', kind: 'person', source: 'config', role: 'admin', role_name: 'admin', permissions: [...BUILTIN_PERMS.admin], tenants: ['default'], tenant: 'default', auth_method: 'token', capabilities: { administer: true, manage_own_keys: true } };
const AUDITOR = { ...ADA, id: 'acc_8r6t2y4ua9', name: 'auditor@soc.example', source: 'managed', role: 'role_2b8f04c6e1a7', role_name: 'Auditor', permissions: ['evidence.read', 'analysis.read', 'audit.read', 'audit.export', 'accounts.read', 'settings.read', 'system.read'] };
const ROLES = {
  limits: { max_roles: 32 },
  items: [
    { id: 'viewer', name: 'viewer', builtin: true, permissions: [...BUILTIN_PERMS.viewer], assigned: { managed: 2, config: 1, oidc: 1 }, created_at: null, created_by: 'builtin', updated_at: null },
    { id: 'admin', name: 'admin', builtin: true, permissions: [...BUILTIN_PERMS.admin], assigned: { managed: 0, config: 1, oidc: 0 }, created_at: null, created_by: 'builtin', updated_at: null },
    { id: 'role_7c1e5a90b3d4', name: 'Ticket bridge', description: 'For the ticketing integration.', builtin: false, permissions: ['evidence.read', 'investigations.read', 'investigations.write'], assigned: { managed: 1, config: 0, oidc: 0 }, created_at: '2026-10-15T10:00:00Z', created_by: 'ada', updated_at: '2026-10-18T10:00:00Z' },
  ],
};
const ACCOUNTS = { limits: {}, items: [{ id: 'acc_9c4n2h7rb5', name: 'ticket-bridge', kind: 'service', source: 'managed', role: 'role_7c1e5a90b3d4', tenants: ['default'], status: 'active' }] };
const item = (o) => ({ kind: 'text', source: 'config', note: '', editable: true, overridden: false, applies: 'live', constraints: {}, ...o });
const SETTINGS = (editing = 'console') => ({
  generated_at: '2026-11-24T10:00:00Z', editing, editable: editing === 'console',
  sections: [
    { id: 'access', title: 'Access and sessions', items: [
      item({ key: 'console.session_ttl_seconds', label: 'Session lifetime', value: '12h', kind: 'duration', source: 'console', effective: '43200', file_value: '28800', overridden: true, constraints: { min: 900, max: 86400, unit: 's', reason_max_len: 200 }, editable: editing === 'console' }),
      item({ key: 'console.login_throttle', label: 'Sign-in throttling', value: '10 per 5m', editable: false, applies: 'none', effective: '10', file_value: '10' }),
    ] },
    { id: 'console', title: 'Console', items: [
      item({ key: 'console.organization_name', label: 'Organisation name', value: 'Example SOC', effective: 'Example SOC', file_value: 'Example SOC', constraints: { max_len: 80, multiline: false }, editable: editing === 'console' }),
      item({ key: 'posture.accepted', label: 'Accepted posture risks', value: '1 accepted risk', kind: 'list', effective: '1', file_value: '', constraints: { max_days: 180 }, editable: editing === 'console' }),
    ] },
  ],
});

function ctx(hash, { me = ADA, api = {} } = {}) {
  const calls = [];
  const wrap = (name, v) => (...args) => { calls.push([name, ...args.filter((a) => !(a && typeof a === 'object' && 'signal' in a))]); return reply(typeof v === 'function' ? () => v(...args) : v); };
  const store = createPrefsStore({ load: async () => PREF_DEFAULTS, save: async (p) => p, apply() {}, storage: null });
  const nav = [];
  return {
    calls, nav,
    route: parseHash(hash), role: me.role, signal: undefined, prefs: store, can: toCan(me.permissions),
    session: { principal: { name: me.name, role: me.role, auth_method: 'token' }, tenant: 'default', tenants: ['default'], expires_at: '2026-11-24T21:00:00Z' },
    setTitle() {}, navigate(h) { nav.push(h); }, rerender() { calls.push(['rerender']); }, signedOut() {}, refreshMeta() { calls.push(['refreshMeta']); },
    api: {
      me: wrap('me', me),
      accounts: wrap('accounts', api.accounts ?? ACCOUNTS),
      roles: wrap('roles', api.roles ?? ROLES),
      permissions: wrap('permissions', api.permissions ?? missing()),
      adminSettings: wrap('adminSettings', api.adminSettings ?? SETTINGS()),
      settingsHistory: wrap('settingsHistory', api.settingsHistory ?? { items: [] }),
      updateSetting: wrap('updateSetting', api.updateSetting ?? ((key, body) => ({ ...SETTINGS().sections[0].items[0], effective: String(body.value), value: '4h', overridden: true }))),
      revertSetting: wrap('revertSetting', api.revertSetting ?? null),
      updateRole: wrap('updateRole', api.updateRole ?? {}),
      posture: wrap('posture', api.posture),
      acceptPosture: wrap('acceptPosture', api.acceptPosture ?? {}),
      unacceptPosture: wrap('unacceptPosture', api.unacceptPosture ?? {}),
    },
  };
}

async function render(c, screen = settings) {
  const root = document.createElement('main');
  await screen.render(root, c);
  return root;
}
const all = (root, pred) => root.querySelectorAll(pred);
const cls = (n, c) => (n.getAttribute('class') || '').split(' ').includes(c);
const byText = (root, tag, re) => all(root, (n) => n.tagName === tag && re.test(n.textContent));
const click = (el) => el.dispatch('click', { currentTarget: el, preventDefault() {} });
const submit = async (form) => { form.dispatch('submit', { preventDefault() {} }); await new Promise((r) => setTimeout(r, 0)); };

// ---- Roles ----------------------------------------------------------------------------

test('roles list: built-in and custom roles with holders, risk summary, create for role managers only', async () => {
  const root = await render(ctx('#/settings/roles'));
  const t = root.textContent;
  for (const s of ['Viewer', 'Admin', 'Ticket bridge', 'Built in', 'Custom', '2 managed1 configured1 single sign-on', 'Risk summary', 'Held by nobody', 'High risk']) assert.ok(t.includes(s), s);
  assert.equal(byText(root, 'a', /Create role/).length, 1);
  const auditor = await render(ctx('#/settings/roles', { me: AUDITOR }));
  assert.equal(byText(auditor, 'a', /Create role/).length, 0, 'reading roles does not offer creating them');
  assert.match(auditor.textContent, /Creating or changing them needs/);
});

test('roles: older server answers with the built-in roles; a 403 is answered in place', async () => {
  const older = await render(ctx('#/settings/roles', { api: { roles: missing() } }));
  assert.match(older.textContent, /does not provide custom roles yet/);
  assert.match(older.textContent, /Analyst/);
  const denied = await render(ctx('#/settings/roles', { api: { roles: new ApiError(403, 'forbidden', 'nope') } }));
  assert.match(denied.textContent, /Your account cannot open this page/);
  const viewer = { ...ADA, role: 'viewer', role_name: 'viewer', permissions: [...BUILTIN_PERMS.viewer] };
  const c = ctx('#/settings/roles', { me: viewer });
  const r = await render(c);
  assert.match(r.textContent, /Your account cannot open this page/);
  assert.ok(!c.calls.some(([n]) => n === 'roles'), 'nothing asked of the server without accounts.read');
});

test('built-in role: read-only matrix with granted marks, duplicate as custom role', async () => {
  const root = await render(ctx('#/settings/roles/viewer'));
  assert.match(root.textContent, /Built-in role/);
  assert.equal(all(root, (n) => n.tagName === 'input' && n.getAttribute('type') === 'checkbox').length, 0, 'no disabled form');
  assert.ok(byText(root, 'a', /Duplicate as custom role/).length);
  assert.equal(all(root, (n) => cls(n, 'perm--on')).length, BUILTIN_PERMS.viewer.length);
  assert.match(root.textContent, /Granted: Read events/);
  assert.match(root.textContent, /Not granted: Create, change and delete custom roles/);
});

test('custom role editor: live summary, diff before saving, dependency warning with a fix', async () => {
  const c = ctx('#/settings/roles/role_7c1e5a90b3d4');
  const root = await render(c);
  const boxes = all(root, (n) => n.tagName === 'input' && n.getAttribute('type') === 'checkbox');
  assert.equal(boxes.length, 18);
  const box = (id) => boxes.find((b) => b.getAttribute('value') === id);
  assert.equal(box('investigations.write').checked, true);
  assert.match(root.textContent, /3 permissions/);
  // Grant a high-risk permission without its dependencies.
  box('settings.manage').checked = true;
  box('settings.manage').dispatch('change', {});
  assert.match(root.textContent, /Not saved yet/);
  assert.match(root.textContent, /Adds 1; affects 1 account — takes effect on their next request\./);
  assert.match(root.textContent, /also needs .*Create and change managed accounts/);
  const fix = byText(root, 'button', /^Also allow/)[0];
  click(fix);
  assert.equal(box('accounts.manage').checked, true);
  assert.equal(box('accounts.read').checked, true);
  assert.equal(box('settings.read').checked, true);
  assert.doesNotMatch(root.textContent, /also needs/);
  assert.match(root.textContent, /Adds 4/);
  assert.ok(byText(root, 'button', /Delete role/).length, 'custom roles can be deleted (with typed confirmation)');
  assert.match(root.textContent, /Who holds this role/);
  assert.match(root.textContent, /ticket-bridge/);
});

test('custom role without roles.manage is read-only, with the reason', async () => {
  const root = await render(ctx('#/settings/roles/role_7c1e5a90b3d4', { me: AUDITOR }));
  assert.equal(all(root, (n) => n.tagName === 'input' && n.getAttribute('type') === 'checkbox').length, 0);
  const editor = await render(ctx('#/settings/roles/new', { me: AUDITOR }));
  assert.match(editor.textContent, /Your account cannot open this page/);
});

// ---- Editable settings -------------------------------------------------------------------

test('settings: editable rows show the override and its file value; change validates, saves and shows the server answer', async () => {
  const c = ctx('#/settings/security');
  const root = await render(c);
  const t = root.textContent;
  assert.match(t, /Overrides the config file value 8 hours\./);
  assert.match(t, /Console/, 'the console source mark');
  assert.match(t, /900 to 86,400 seconds/);
  assert.match(t, /Applies at once/);
  assert.ok(byText(root, 'a', /History/).length, 'each editable setting links to its history');
  const change = byText(root, 'button', /^Change/)[0];
  assert.ok(change, 'Change for someone with settings.manage');
  assert.equal(byText(root, 'button', /^Change/).length, 1, 'only the editable row');
  click(change);
  const form = all(root, (n) => n.tagName === 'form')[0];
  assert.ok(form, 'the editor opens in place');
  assert.match(root.textContent, /Reason for change/);
  // Too short, and no reason: both reported, nothing sent.
  const amount = all(form, (n) => n.tagName === 'input' && n.getAttribute('type') === 'number')[0];
  amount.value = '10';
  const unit = all(form, (n) => n.tagName === 'select')[0];
  unit.value = 'minutes';
  await submit(form);
  assert.match(root.textContent, /Fix 2 problems before saving/);
  assert.ok(!c.calls.some(([n]) => n === 'updateSetting'));
  amount.value = '4';
  unit.value = 'hours';
  const reason = all(form, (n) => n.tagName === 'input' && n.getAttribute('type') === 'text')[0];
  reason.value = 'Shorter sessions for the audit.';
  await submit(form);
  const sent = c.calls.find(([n]) => n === 'updateSetting');
  assert.deepEqual(sent.slice(1), ['console.session_ttl_seconds', { value: 14400, reason: 'Shorter sessions for the audit.' }]);
  assert.match(root.textContent, /Saved: 12 hours → 4 hours\. Applies at once\./, 'the server answer, after the save');
});

test('settings: a server refusal stays in the form; no permission shows the reason, not a form', async () => {
  const c = ctx('#/settings/console', { api: { updateSetting: Object.assign(new ApiError(409, 'conflict', 'editing is off'), { reason: 'editing_disabled' }) } });
  const root = await render(c);
  click(byText(root, 'button', /^Change/)[0]);
  const form = all(root, (n) => n.tagName === 'form')[0];
  all(form, (n) => n.tagName === 'input' && n.getAttribute('type') === 'text').forEach((i, k) => { i.value = k === 0 ? 'Example Security' : 'Rebrand.'; });
  await submit(form);
  assert.match(root.textContent, /Console editing is off on this server/);
  assert.match(root.textContent, /Accepted and revoked on Posture/);
  const reader = await render(ctx('#/settings/console', { me: AUDITOR }));
  assert.equal(byText(reader, 'button', /^Change/).length, 0);
  assert.match(reader.textContent, /Changing it needs “Change console settings and accept posture risk”/);
});

test('settings: editing off explains how to turn it on, with no disabled form', async () => {
  const root = await render(ctx('#/settings/security', { api: { adminSettings: SETTINGS('off') } }));
  assert.match(root.textContent, /Console editing is off/);
  assert.match(root.textContent, /settings_editing: console/);
  assert.match(root.textContent, /the config file itself is never written|the file itself is never written/);
  assert.equal(byText(root, 'button', /^Change/).length, 0);
  assert.equal(all(root, (n) => n.tagName === 'input' && n.getAttribute('disabled') !== null).length, 0);
});

test('settings: revert to the file value asks first, then shows the result', async () => {
  const c = ctx('#/settings/security', { api: { revertSetting: { ...SETTINGS().sections[0].items[0], effective: '28800', value: '8h', overridden: false, source: 'config' } } });
  const root = await render(c);
  click(byText(root, 'button', /Revert to file value/)[0]);
  const dialog = all(document.body, (n) => n.tagName === 'dialog').pop();
  assert.match(dialog.textContent, /It goes back to 8 hours, the value in the config file, instead of 12 hours/);
  await submit(all(dialog, (n) => n.tagName === 'form')[0]);
  await new Promise((r) => setTimeout(r, 0));
  assert.ok(c.calls.some(([n, k]) => n === 'revertSetting' && k === 'console.session_ttl_seconds'));
  assert.match(root.textContent, /Reverted: 12 hours → 8 hours \(the config file value\)\./);
});

test('change history: from → to in words, reason, who, filter by key; an older server says so', async () => {
  const history = { items: [
    { seq: 5, key: 'console.session_ttl_seconds', from: '28800', to: '43200', actor_id: 'cfg:ada', actor_name: 'ada', reason: 'Night shift.', at: '2026-11-21T10:00:00Z' },
    { seq: 4, key: 'console.default_window', from: '7d', to: '24h', actor_id: 'cfg:ada', actor_name: 'ada', reason: '<b>not markup</b>', at: '2026-11-16T10:00:00Z' },
  ] };
  const root = await render(ctx('#/settings/history', { api: { settingsHistory: history } }));
  const t = root.textContent;
  assert.match(t, /8 hours→ to 12 hours/);
  assert.match(t, /Night shift\./);
  assert.match(t, /<b>not markup<\/b>/, 'reasons are text');
  assert.match(t, /2 changes, newest first/);
  const filtered = await render(ctx('#/settings/history?key=console.default_window', { api: { settingsHistory: history } }));
  assert.match(filtered.textContent, /1 change\./);
  assert.doesNotMatch(filtered.textContent, /Night shift/);
  const older = await render(ctx('#/settings/history', { api: { settingsHistory: missing() } }));
  assert.match(older.textContent, /does not record setting changes yet/);
});

// ---- Posture -----------------------------------------------------------------------------

const POSTURE = { generated_at: '2026-11-24T10:00:00Z', summary: { attention: 1, accepted: 1, ok: 1, info: 0 }, checks: [
  { id: 'POS-003', area: 'exposure', status: 'attention', title: 'One sensor failed to start', detail: 'd', recommendation: 'r', doc: '', accepted: null },
  { id: 'POS-004', area: 'deception', status: 'accepted', title: 'A decoy has no planted credential', detail: 'd', recommendation: 'r', doc: '', accepted: { by: 'cfg:ada', by_name: 'ada', reason: 'Ships in December.', until: '2027-01-20T00:00:00Z' } },
  { id: 'POS-005', area: 'deception', status: 'ok', title: 'Fine', detail: '', recommendation: '', doc: '', accepted: null },
] };

test('posture: accept risk for settings.manage, accepted risk in its own group and count, never "looks right"', async () => {
  const c = ctx('#/posture', { api: { posture: POSTURE } });
  const root = await render(c, posture);
  const t = root.textContent;
  assert.match(t, /Accepted risk · 1/);
  assert.match(t, /Accepted by ada until/);
  assert.match(t, /Ships in December\./);
  assert.match(t, /Still present: accepting records a decision, it does not fix anything/);
  assert.equal(byText(root, 'button', /Accept risk/).length, 1, 'only the attention item');
  assert.equal(byText(root, 'button', /Revoke acceptance/).length, 1);
  const figs = all(root, (n) => cls(n, 'pfig--accepted'));
  assert.equal(figs.length, 1);
  assert.match(figs[0].textContent, /Accepted risk1/);
  const reader = await render(ctx('#/posture', { me: AUDITOR, api: { posture: POSTURE } }), posture);
  assert.equal(byText(reader, 'button', /Accept risk|Revoke acceptance/).length, 0);
  assert.match(reader.textContent, /Accepting a risk needs/);
  const older = await render(ctx('#/posture', { api: { posture: { ...POSTURE, checks: POSTURE.checks.map(({ accepted, ...rest }) => ({ ...rest, status: rest.status === 'accepted' ? 'attention' : rest.status })) } } }), posture);
  assert.equal(byText(older, 'button', /Accept risk/).length, 0, 'an older server offers no acceptance');
});

test('posture: the accept dialog needs a reason and sends an end date at most 180 days ahead', async () => {
  const c = ctx('#/posture', { api: { posture: POSTURE } });
  const root = await render(c, posture);
  click(byText(root, 'button', /Accept risk/)[0]);
  const dialog = all(document.body, (n) => n.tagName === 'dialog').pop();
  const form = all(dialog, (n) => n.tagName === 'form')[0];
  await submit(form);
  assert.match(dialog.textContent, /Say why the risk is acceptable/);
  assert.ok(!c.calls.some(([n]) => n === 'acceptPosture'));
  all(form, (n) => n.tagName === 'textarea')[0].value = 'Compensating control: behind the VPN.';
  await submit(form);
  const sent = c.calls.find(([n]) => n === 'acceptPosture');
  assert.equal(sent[1], 'POS-003');
  assert.equal(sent[2].reason, 'Compensating control: behind the VPN.');
  const days = (Date.parse(sent[2].until) - Date.now()) / 86400e3;
  assert.ok(days > 89 && days < 91, `the 90-day preset: ${sent[2].until}`);
});
