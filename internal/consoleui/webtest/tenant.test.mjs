// Tenant awareness: what the shell shows, where a switch lands, the API
// client's CSRF rotation and 401 handling across a switch, the read cache
// across an invalidation, and the top-bar controls in the fake DOM.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createFakeDocument } from './fakedom.mjs';
import { tenantInfo, switchTargets, routeAfterSwitch, switchBody } from '../static/assets/js/lib/tenant.js';
import { parseHash } from '../static/assets/js/lib/route.js';
import { createApi } from '../static/assets/js/lib/api.js';
import { createSwr } from '../static/assets/js/lib/swr.js';

const session = (tenant, tenants, extra = {}) => ({
  principal: { name: 'ada', role: 'admin', auth_method: 'token', tenant, tenants }, tenant, tenants, csrf_token: 'c1', expires_at: '2026-11-15T12:00:00Z', ...extra,
});

test('tenantInfo: nothing extra for one tenant named default', () => {
  assert.deepEqual(tenantInfo(session('default', ['default'])), { active: 'default', tenants: ['default'], show: false, canSwitch: false });
  // Older server: no tenant fields at all.
  assert.deepEqual(tenantInfo({ principal: { name: 'a', role: 'viewer' } }), { active: '', tenants: [], show: false, canSwitch: false });
});

test('tenantInfo: a single non-default tenant is shown without a switcher', () => {
  const info = tenantInfo(session('alpha', ['alpha']));
  assert.equal(info.show, true);
  assert.equal(info.canSwitch, false);
});

test('tenantInfo: several tenants offer the switcher; principal fields are a fallback', () => {
  const info = tenantInfo(session('bravo', ['alpha', 'bravo', 'alpha', '', 7]));
  assert.deepEqual(info.tenants, ['alpha', 'bravo']);
  assert.equal(info.active, 'bravo');
  assert.equal(info.show && info.canSwitch, true);
  const fromPrincipal = tenantInfo({ principal: { tenant: 'alpha', tenants: ['alpha', 'bravo'] } });
  assert.equal(fromPrincipal.active, 'alpha');
  assert.equal(fromPrincipal.canSwitch, true);
  // The active tenant is always listed.
  assert.deepEqual(tenantInfo({ tenant: 'zulu', tenants: ['alpha'] }).tenants, ['zulu', 'alpha']);
});

test('switchTargets and switchBody only ever name member tenants', () => {
  const s = session('alpha', ['alpha', 'bravo', 'charlie']);
  assert.deepEqual(switchTargets(s), ['bravo', 'charlie']);
  assert.deepEqual(switchTargets(session('default', ['default'])), []);
  assert.deepEqual(switchBody(s, 'bravo'), { tenant: 'bravo' });
  assert.equal(switchBody(s, 'alpha'), null, 'already active');
  assert.equal(switchBody(s, 'delta'), null, 'not a member');
  assert.equal(switchBody(session('default', ['default']), 'default'), null);
});

test('routeAfterSwitch keeps list and screen views, leaves object views', () => {
  const at = (hash) => routeAfterSwitch(parseHash(hash), hash);
  // Same view in the new tenant.
  assert.deepEqual(at('#/overview?window=7d'), { hash: '#/overview?window=7d', moved: false, reason: '' });
  assert.deepEqual(at('#/events?live=1&severity=high'), { hash: '#/events?live=1&severity=high', moved: false, reason: '' });
  assert.deepEqual(at('#/sensors'), { hash: '#/sensors', moved: false, reason: '' });
  assert.deepEqual(at('#/audit?action=session.login'), { hash: '#/audit?action=session.login', moved: false, reason: '' });
  assert.deepEqual(at('#/fleet'), { hash: '#/fleet', moved: false, reason: '' });
  // Objects that cannot exist in another tenant: the overview.
  assert.deepEqual(at(`#/events/${'a'.repeat(32)}`), { hash: '#/overview', moved: true, reason: 'object' });
  assert.deepEqual(at('#/investigations/inv_0123'), { hash: '#/overview', moved: true, reason: 'object' });
  assert.deepEqual(at(`#/fleet/nodes/${'b'.repeat(32)}`), { hash: '#/overview', moved: true, reason: 'object' });
  assert.deepEqual(at('#/sources/203.0.113.7'), { hash: '#/overview', moved: true, reason: 'object' });
  // The events side panel and an origin filter refer to the old tenant.
  assert.deepEqual(at(`#/events?live=1&event=${'c'.repeat(32)}`), { hash: '#/events?live=1', moved: true, reason: 'cleared' });
  assert.deepEqual(at(`#/events?node=${'d'.repeat(32)}&event_node=${'d'.repeat(32)}&event=${'c'.repeat(32)}&q=x`), { hash: '#/events?q=x', moved: true, reason: 'cleared' });
});

function fakeFetch(handler) {
  const calls = [];
  const impl = async (url, init) => {
    calls.push({ url, init });
    const r = await handler(url, init);
    const { status = 200, body } = r ?? {};
    return { status, ok: status >= 200 && status < 300, headers: { get: () => null }, json: async () => body };
  };
  return { impl, calls };
}

test('switchTenant posts the tenant with the old CSRF token and keeps the new one', async () => {
  const f = fakeFetch((url, init) => {
    if (url.endsWith('/session/tenant')) return { body: session('bravo', ['alpha', 'bravo'], { csrf_token: 'c2' }) };
    if (url.endsWith('/session')) return { body: session('alpha', ['alpha', 'bravo']) };
    return { body: {} };
  });
  const api = createApi({ fetchImpl: f.impl });
  await api.session();
  const next = await api.switchTenant('bravo');
  assert.equal(next.tenant, 'bravo');
  const post = f.calls[1];
  assert.equal(post.init.method, 'POST');
  assert.deepEqual(JSON.parse(post.init.body), { tenant: 'bravo' });
  assert.equal(post.init.headers['X-AegisMesh-CSRF'], 'c1');
  await api.updateInvestigation('inv_1', { status: 'closed' });
  assert.equal(f.calls[2].init.headers['X-AegisMesh-CSRF'], 'c2');
});

test('a 401 for a request that started before a switch does not sign the operator out', async () => {
  let release;
  const gate = new Promise((r) => { release = r; });
  let unauth = 0;
  const f = fakeFetch(async (url) => {
    if (url.endsWith('/session/tenant')) return { body: session('bravo', ['alpha', 'bravo'], { csrf_token: 'c2' }) };
    if (url.includes('/overview')) { await gate; return { status: 401, body: { error: { code: 'unauthenticated', message: 'x' } } }; }
    if (url.includes('/sensors')) return { status: 401, body: { error: { code: 'unauthenticated', message: 'x' } } };
    return { body: session('alpha', ['alpha', 'bravo']) };
  });
  const api = createApi({ fetchImpl: f.impl, onUnauthenticated: () => { unauth++; } });
  await api.session();
  const stale = api.overview('24h').catch((e) => e);
  await api.switchTenant('bravo');
  release();
  const err = await stale;
  assert.equal(err.status, 401);
  assert.equal(unauth, 0, 'superseded 401 is not a sign-out');
  assert.equal(api.hasCsrf(), true, 'new CSRF token kept');
  // A 401 for a request made after the switch still ends the session.
  await api.sensors().catch(() => {});
  assert.equal(unauth, 1);
});

test('a failed switch (non-member) leaves the CSRF token in place', async () => {
  const f = fakeFetch((url) => (url.endsWith('/session/tenant')
    ? { status: 404, body: { error: { code: 'not_found', message: 'tenant not found' } } }
    : { body: session('alpha', ['alpha']) }));
  const api = createApi({ fetchImpl: f.impl });
  await api.session();
  await assert.rejects(api.switchTenant('zulu'), (e) => e.code === 'not_found');
  await api.updateInvestigation('inv_1', {});
  assert.equal(f.calls[2].init.headers['X-AegisMesh-CSRF'], 'c1');
});

test('the read cache drops answers to requests that began before an invalidation', async () => {
  const swr = createSwr();
  let release;
  const slow = new Promise((r) => { release = r; });
  const first = swr.get('k', () => slow);
  swr.invalidate(); // e.g. a tenant switch
  release('alpha data');
  assert.equal(await first, 'alpha data', 'the original caller still gets its answer');
  assert.equal(swr.has('k'), false, 'but it is not cached for the new tenant');
  assert.equal(await swr.get('k', async () => 'bravo data'), 'bravo data');
});

// ---- Top bar in the fake DOM ---------------------------------------------------

const doc = createFakeDocument();
doc.addEventListener = () => {};
doc.documentElement = { clientWidth: 1440, removeAttribute() {}, setAttribute() {} };
const proto = Object.getPrototypeOf(doc.createElement('x'));
Object.defineProperty(proto, 'firstChild', { get() { return this.childNodes[0] ?? null; } });
proto.hidePopover = function hidePopover() { this.hidden = true; };
proto.replaceChildren = function replaceChildren(...kids) { this.childNodes = []; for (const k of kids) this.appendChild(k); };
globalThis.document = doc;
const { createShell } = await import('../static/assets/js/ui/shell.js');

const metaBoth = { auth: { token: true, oidc: { enabled: true, display_name: 'Corp IdP' } } };
function topBar(sess, onSwitchTenant = () => {}) {
  const shell = createShell({ session: sess, meta: metaBoth, onLogout() {}, onSearch() {}, onSwitchTenant });
  const all = (pred) => shell.root.querySelectorAll(pred);
  const cls = (c) => (n) => (n.getAttribute('class') || '').split(' ').includes(c);
  return { shell, all, cls };
}

test('top bar: no tenant control with one tenant named default', () => {
  const { all, cls } = topBar(session('default', ['default']));
  assert.equal(all(cls('top-tenant')).length, 0);
  assert.equal(all((n) => n.getAttribute('id') === 'tenant-menu').length, 0);
  const menu = all((n) => n.getAttribute('id') === 'account-menu')[0];
  assert.match(menu.textContent, /Signed in withOperator token/);
  assert.doesNotMatch(menu.textContent, /Tenant/);
});

test('top bar: a single named tenant is a static label', () => {
  const { all, cls } = topBar(session('alpha', ['alpha']));
  const label = all(cls('top-tenant'));
  assert.equal(label.length, 1);
  assert.equal(label[0].tagName, 'span');
  assert.match(label[0].textContent, /alpha/);
});

test('top bar: several tenants open a switcher that names the current one in words', () => {
  const picked = [];
  const sess = session('alpha', ['alpha', 'bravo']);
  sess.principal.auth_method = 'oidc';
  const { all, cls } = topBar(sess, (t) => picked.push(t));
  const button = all(cls('top-tenant'))[0];
  assert.equal(button.tagName, 'button');
  assert.equal(button.getAttribute('popovertarget'), 'tenant-menu');
  const items = all(cls('menu__item'));
  assert.deepEqual(items.map((i) => i.getAttribute('data-tenant')), ['alpha', 'bravo']);
  assert.equal(items[0].getAttribute('aria-current'), 'true');
  assert.match(items[0].textContent, /Current/, 'never color alone');
  items[0].dispatch('click');
  assert.deepEqual(picked, [], 'choosing the current tenant does nothing');
  items[1].dispatch('click');
  assert.deepEqual(picked, ['bravo']);
  const account = all((n) => n.getAttribute('id') === 'account-menu')[0];
  assert.match(account.textContent, /Single sign-on \(Corp IdP\)/);
  assert.match(account.textContent, /Tenantalpha/);
});
