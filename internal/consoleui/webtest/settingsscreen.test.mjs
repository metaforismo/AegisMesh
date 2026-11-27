import { toCan, permissionsOf } from '../static/assets/js/lib/perms.js';
// Renders the Settings screen into the fake DOM with a stubbed API: role
// gating, the older-server states, server refusals, and the preferences
// rows following the store.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createFakeDocument } from './fakedom.mjs';

globalThis.document = createFakeDocument();
const { default: settings } = await import('../static/assets/js/screens/settings.js');
const { ApiError } = await import('../static/assets/js/lib/api.js');
const { parseHash } = await import('../static/assets/js/lib/route.js');
const { createPrefsStore, PREF_DEFAULTS } = await import('../static/assets/js/lib/prefs.js');
const { ADMIN_SECTIONS } = await import('../static/assets/js/lib/settings.js');

const ME = {
  viewer: { id: 'cfg:vera', name: 'vera', kind: 'person', source: 'config', role: 'viewer', tenants: ['default'], tenant: 'default', auth_method: 'token', created_at: null, last_seen_at: '2026-11-23T20:00:00Z', capabilities: { manage_own_keys: false, administer: false } },
  admin: { id: 'cfg:ada', name: 'ada', kind: 'person', source: 'config', role: 'admin', tenants: ['default'], tenant: 'default', auth_method: 'token', created_at: null, last_seen_at: '2026-11-23T20:00:00Z', capabilities: { manage_own_keys: true, administer: true } },
};
const missing = () => new ApiError(404, 'not_found', 'no such endpoint');
const reply = (v) => (v instanceof Error ? Promise.reject(v) : Promise.resolve(typeof v === 'function' ? v() : v));

function ctx(hash, { me, api = {}, role } = {}) {
  const calls = [];
  const wrap = (name, v) => (...args) => { calls.push(name); return reply(v); };
  const r = role || me?.role || 'viewer';
  const store = createPrefsStore({ load: async () => PREF_DEFAULTS, save: async (p) => p, apply() {}, storage: null });
  return {
    calls,
    route: parseHash(hash), role: r, signal: undefined, prefs: store, can: toCan(permissionsOf(me, { principal: { role: r } })),
    session: { principal: { name: me?.name || 'vera', role: r, auth_method: 'token' }, tenant: 'default', tenants: ['default'], expires_at: '2026-11-23T21:00:00Z' },
    setTitle() {}, navigate() {}, rerender() {}, signedOut() {},
    api: {
      me: wrap('me', me === undefined ? missing() : me),
      mySessions: wrap('mySessions', api.mySessions ?? { items: [] }),
      myKeys: wrap('myKeys', api.myKeys ?? { items: [] }),
      accounts: wrap('accounts', api.accounts ?? { items: [], limits: {} }),
      allSessions: wrap('allSessions', api.allSessions ?? { items: [] }),
      adminSettings: wrap('adminSettings', api.adminSettings ?? { sections: [] }),
      system: wrap('system', api.system ?? { components: [] }),
      account: wrap('account', api.account ?? missing()),
      roles: wrap('roles', api.roles ?? missing()),
      permissions: wrap('permissions', api.permissions ?? missing()),
      settingsHistory: wrap('settingsHistory', api.settingsHistory ?? missing()),
      notificationPrefs: wrap('notificationPrefs', api.notificationPrefs ?? missing()),
      putNotificationPrefs: (body) => { calls.push(['putNotificationPrefs', body]); return reply(typeof api.putNotificationPrefs === 'function' ? api.putNotificationPrefs(body) : api.putNotificationPrefs ?? missing()); },
    },
  };
}

async function render(c) {
  const root = document.createElement('main');
  await settings.render(root, c);
  return root;
}
const navNames = (root) => root.querySelectorAll((el) => (el.getAttribute('class') || '').includes('settings-nav__name')).map((n) => n.textContent);

test('viewer: account sections only; an admin section answers "not permitted" without asking the server', async () => {
  const c = ctx('#/settings', { me: ME.viewer });
  const root = await render(c);
  assert.deepEqual(navNames(root), ['Profile', 'Preferences', 'Sessions', 'API keys', 'Notifications']);
  assert.match(root.textContent, /What the viewer role can do/);
  const c2 = ctx('#/settings/accounts', { me: ME.viewer });
  const r2 = await render(c2);
  assert.match(r2.textContent, /Your account cannot open this page/);
  assert.ok(!c2.calls.includes('accounts'), 'no admin request from a non-admin');
});

test('admin: administration listed; every admin page renders from the stubbed API', async () => {
  const root = await render(ctx('#/settings', { me: ME.admin }));
  assert.deepEqual(navNames(root).slice(5), ADMIN_SECTIONS.map((s) => s.label));
  for (const s of ADMIN_SECTIONS) {
    const r = await render(ctx(`#/settings/${s.id}`, { me: ME.admin }));
    assert.ok(r.textContent.length > 0, s.id);
    assert.doesNotMatch(r.textContent, /cannot open this page/, s.id);
  }
});

test('a server refusal (403) on an admin page is answered in place', async () => {
  const r = await render(ctx('#/settings/accounts', { me: ME.admin, api: { accounts: new ApiError(403, 'forbidden', 'requires admin in the local tenant') } }));
  assert.match(r.textContent, /Your account cannot open this page/);
});

test('older server: profile falls back to the session; sessions and keys say the server is older; admin hidden', async () => {
  const c = ctx('#/settings/profile', { me: undefined, role: 'admin' });
  const root = await render(c);
  assert.match(root.textContent, /This server does not provide account management yet/);
  assert.match(root.textContent, /vera/);
  assert.deepEqual(navNames(root), ['Profile', 'Preferences', 'Sessions', 'API keys', 'Notifications'], 'administration is not offered');
  for (const id of ['sessions', 'keys', 'accounts', 'system']) {
    const r = await render(ctx(`#/settings/${id}`, { me: undefined, role: 'admin' }));
    assert.match(r.textContent, /does not provide account management yet/, id);
    assert.doesNotMatch(r.textContent, /Try again/, `${id}: retrying cannot help`);
  }
  const prefs = await render(ctx('#/settings/preferences', { me: undefined }));
  assert.match(prefs.textContent, /Saved in this browser only/);
});

test('keys: an account that may not manage keys gets an explanation, not a form', async () => {
  const c = ctx('#/settings/keys', { me: ME.viewer });
  const r = await render(c);
  assert.match(r.textContent, /cannot create API keys/);
  assert.ok(!c.calls.includes('myKeys'));
  assert.equal(r.querySelectorAll((el) => el.tagName === 'form').length, 0);
});

test('keys: a key list renders status words and revoke only for active keys', async () => {
  const items = [
    { id: 'key_0123456789ab', label: 'ci', prefix: 'amk_AAAA', created_at: '2026-11-01T00:00:00Z', created_by: 'ada', expires_at: '2027-01-01T00:00:00Z', last_used_at: null, revoked_at: null, status: 'active' },
    { id: 'key_ba9876543210', label: 'old', prefix: 'amk_BBBB', created_at: '2026-01-01T00:00:00Z', created_by: 'ada', expires_at: '2026-04-01T00:00:00Z', last_used_at: null, revoked_at: '2026-02-01T00:00:00Z', status: 'revoked' },
  ];
  const r = await render(ctx('#/settings/keys', { me: ME.admin, api: { myKeys: { items } } }));
  assert.match(r.textContent, /Active/);
  assert.match(r.textContent, /Revoked/);
  const revokes = r.querySelectorAll((el) => el.tagName === 'button' && el.textContent === 'Revoke');
  assert.equal(revokes.length, 1);
  assert.equal(revokes[0].getAttribute('aria-label'), 'Revoke key ci');
});

test('sessions: the current session offers "Sign out", others "Revoke"', async () => {
  const s = (handle, current) => ({ handle, current, auth_method: 'token', tenant: 'default', created_at: '2026-11-23T19:00:00Z', last_seen_at: '2026-11-23T20:00:00Z', expires_at: '2099-01-01T00:00:00Z', idle_expires_at: null, remote: '192.0.2.10', client: 'Chrome on macOS' });
  const r = await render(ctx('#/settings/sessions', { me: ME.admin, api: { mySessions: { items: [s('ses_0123456789abcdef', true), s('ses_fedcba9876543210', false)] } } }));
  const labels = r.querySelectorAll((el) => el.tagName === 'button').map((b) => b.textContent);
  assert.ok(labels.includes('Sign out'));
  assert.ok(labels.includes('Revoke'));
  assert.ok(labels.includes('Sign out all other sessions'));
  assert.match(r.textContent, /This browser/);
});

test('preferences: one radio group per preference, checked from the store', async () => {
  const c = ctx('#/settings/preferences', { me: ME.viewer });
  await c.prefs.update({ timezone: 'local' });
  const r = await render(c);
  const radios = r.querySelectorAll((el) => el.tagName === 'input' && el.getAttribute('type') === 'radio');
  assert.equal(new Set(radios.map((i) => i.getAttribute('name'))).size, 5);
  assert.equal(radios.find((i) => i.getAttribute('name') === 'pref-timezone' && i.checked)?.getAttribute('value'), 'local');
});

test('account detail: a configured account is read-only with the reason; not found is said plainly', async () => {
  const acc = { id: 'cfg:ana', name: 'ana', kind: 'person', source: 'config', role: 'analyst', tenants: ['default'], status: 'active', created_at: null, created_by: 'config file', last_seen_at: null, active_keys: 0, active_sessions: 0, keys: [], sessions: [] };
  const r = await render(ctx('#/settings/accounts/cfg%3Aana', { me: ME.admin, api: { account: acc } }));
  assert.match(r.textContent, /changed outside the console/);
  assert.match(r.textContent, /config file/);
  assert.equal(r.querySelectorAll((el) => el.tagName === 'select').length, 0, 'no role control');
  const gone = await render(ctx('#/settings/accounts/acc_000000000000', { me: ME.admin, api: { account: new ApiError(404, 'not_found', 'account not found') } }));
  assert.match(gone.textContent, /Account not found/);
});

test('notifications: a toggle per kind with what it means, account security always on, severity choices; changes save the difference', async () => {
  const prefs = { kinds: { critical_observation: true, honeytoken_replay: true, agent_canary: true, new_campaign: false, posture_attention: true, account_security: true, assignment: true }, min_severity: 'info' };
  const c = ctx('#/settings/notifications', { me: ME.viewer, api: { notificationPrefs: prefs, putNotificationPrefs: (b) => ({ ...prefs, ...b, kinds: { ...prefs.kinds, ...(b.kinds || {}) } }) } });
  const root = await render(c);
  const boxes = root.querySelectorAll((el) => el.tagName === 'input' && el.getAttribute('type') === 'checkbox' && (el.getAttribute('id') || '').startsWith('ntf-kind-'));
  assert.equal(boxes.length, 6, 'six toggles; account security is said, not a box');
  assert.match(root.textContent, /Always on/);
  assert.match(root.textContent, /Only someone who read a decoy can hold it/);
  const campaign = boxes.find((b) => b.getAttribute('id') === 'ntf-kind-new_campaign');
  assert.equal(campaign.checked, false);
  campaign.checked = true;
  campaign.dispatch('change');
  await new Promise((r) => setTimeout(r, 0));
  assert.deepEqual(c.calls.find((x) => x[0] === 'putNotificationPrefs'), ['putNotificationPrefs', { kinds: { new_campaign: true } }]);
  const radios = root.querySelectorAll((el) => el.getAttribute('type') === 'radio' && el.getAttribute('name') === 'ntf-min-severity');
  assert.deepEqual(radios.map((r) => r.getAttribute('value')), ['info', 'medium', 'high', 'critical']);
  assert.match(root.textContent, /Stored in this browser only/);
});

test('notifications on an older server: said once, no controls', async () => {
  const root = await render(ctx('#/settings/notifications', { me: ME.viewer }));
  assert.match(root.textContent, /This server does not keep notifications yet/);
  assert.equal(root.querySelectorAll((el) => el.tagName === 'input').length, 0);
});
