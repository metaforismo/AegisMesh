// Sign-in option selection, OIDC error-code mapping, and the sign-in card
// rendered into the fake DOM for each combination of methods.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createFakeDocument } from './fakedom.mjs';
import {
  signInOptions, ssoDisplayName, loginErrorCode, loginErrorMessage, authMethodLabel, LOGIN_ERROR_CODES, OIDC_LOGIN_PATH,
} from '../static/assets/js/lib/auth.js';
import { isSafeHref } from '../static/assets/js/lib/dom.js';

const meta = (token, oidc, name = 'Corp IdP') => ({ product: 'AegisMesh', api_version: 'v1', auth: { token, oidc: { enabled: oidc, display_name: name } } });

test('signInOptions picks the controls from meta.auth', () => {
  const cases = [
    [meta(true, false), { token: true, oidc: false, primary: 'token', collapseToken: false }],
    [meta(true, true), { token: true, oidc: true, primary: 'oidc', collapseToken: true }],
    [meta(false, true), { token: false, oidc: true, primary: 'oidc', collapseToken: false }],
    [meta(false, false), { token: false, oidc: false, primary: 'none', collapseToken: false }],
    // Older server without `auth`, and an unreadable /meta: token form, as before.
    [{ product: 'AegisMesh', api_version: 'v1' }, { token: true, oidc: false, primary: 'token', collapseToken: false }],
    [null, { token: true, oidc: false, primary: 'token', collapseToken: false }],
    // oidc must be an object with enabled === true.
    [{ auth: { token: true, oidc: true } }, { token: true, oidc: false, primary: 'token', collapseToken: false }],
    [{ auth: { token: true, oidc: { enabled: 'yes' } } }, { token: true, oidc: false, primary: 'token', collapseToken: false }],
  ];
  for (const [m, want] of cases) {
    const got = signInOptions(m);
    for (const [k, v] of Object.entries(want)) assert.equal(got[k], v, `${JSON.stringify(m)} → ${k}`);
  }
  assert.equal(signInOptions(null).known, false);
  assert.equal(signInOptions(meta(true, true)).known, true);
  assert.equal(signInOptions(meta(true, true, 'Okta')).displayName, 'Okta');
});

test('ssoDisplayName is plain, bounded text with a fallback', () => {
  assert.equal(ssoDisplayName('  Corp   IdP  '), 'Corp IdP');
  assert.equal(ssoDisplayName(''), 'Single sign-on');
  assert.equal(ssoDisplayName(42), 'Single sign-on');
  assert.equal(ssoDisplayName('Evil‮edis'), 'Eviledis');
  assert.equal(ssoDisplayName('a\u0000b\nc'), 'ab c');
  const long = ssoDisplayName('x'.repeat(200));
  assert.equal([...long].length, 64);
  assert.ok(long.endsWith('…'));
  // Markup stays text: nothing is stripped or interpreted, it is just a string.
  assert.equal(ssoDisplayName('<b>IdP</b>'), '<b>IdP</b>');
});

test('loginErrorCode accepts only the contract codes', () => {
  for (const c of LOGIN_ERROR_CODES) assert.equal(loginErrorCode({ error: c }), c);
  assert.equal(loginErrorCode({}), '');
  assert.equal(loginErrorCode(undefined), '');
  assert.equal(loginErrorCode({ error: '' }), 'unknown');
  assert.equal(loginErrorCode({ error: 'consent_required' }), 'unknown');
  assert.equal(loginErrorCode({ error: '<script>' }), 'unknown');
  assert.equal(loginErrorCode({ error: 'toString' }), 'unknown');
});

test('every error code has its own calm message; unknown codes get the generic one', () => {
  const titles = new Set();
  for (const c of LOGIN_ERROR_CODES) {
    const m = loginErrorMessage(c);
    assert.ok(m.title && m.detail, c);
    assert.doesNotMatch(`${m.title} ${m.detail}`, /[a-z]+_[a-z]+/, `${c}: no raw code in the message`);
    titles.add(m.title);
  }
  assert.equal(titles.size, LOGIN_ERROR_CODES.length);
  const generic = loginErrorMessage('unknown');
  assert.equal(generic.title, 'Single sign-on did not complete');
  assert.equal(loginErrorMessage('anything-else').title, generic.title);
  assert.match(loginErrorMessage('unavailable').title, /temporarily unavailable/);
  // The token fallback is mentioned only when tokens are accepted.
  assert.match(loginErrorMessage('unavailable', { tokenAvailable: true }).detail, /operator token/);
  assert.doesNotMatch(loginErrorMessage('unavailable', { tokenAvailable: false }).detail, /operator token/);
});

test('authMethodLabel names the method for the account menu', () => {
  assert.equal(authMethodLabel('token'), 'Operator token');
  assert.equal(authMethodLabel('oidc', meta(true, true, 'Corp IdP')), 'Single sign-on (Corp IdP)');
  assert.equal(authMethodLabel('oidc', null), 'Single sign-on (OIDC)');
  assert.equal(authMethodLabel('saml'), 'Unknown method');
});

test('the DOM layer allows the OIDC start path and no other server path', () => {
  assert.ok(isSafeHref(OIDC_LOGIN_PATH));
  for (const bad of ['/api/v1/session', '/api/v1/auth/oidc/callback', '//evil.test/api/v1/auth/oidc/login', '/api/v1/auth/oidc/login?x=1', 'javascript:alert(1)']) {
    assert.equal(isSafeHref(bad), false, bad);
  }
});

// ---- Sign-in card in the fake DOM -------------------------------------------------

const doc = createFakeDocument();
const proto = Object.getPrototypeOf(doc.createElement('x'));
// Just enough extra surface for the login screen (focus, class list, styles,
// and selector strings for the decorative mesh).
proto.focus = function focus() { doc.focused = this; };
proto.removeAttribute = function removeAttribute(k) { this.attributes.delete(k); };
Object.defineProperty(proto, 'classList', { get() { const el = this; return { add: (c) => el.setAttribute('class', `${el.getAttribute('class') || ''} ${c}`.trim()), remove() {}, contains: () => false, toggle() {} }; } });
Object.defineProperty(proto, 'style', { get() { return { setProperty() {} }; } });
const qsa = proto.querySelectorAll;
proto.querySelectorAll = function querySelectorAll(sel) { return qsa.call(this, typeof sel === 'function' ? sel : (n) => n.tagName === sel); };
globalThis.document = doc;
globalThis.window = { addEventListener() {} };
const { default: login } = await import('../static/assets/js/screens/login.js');

function renderLogin(m, loginError = '') {
  const root = doc.createElement('div');
  login.render(root, { api: {}, meta: m, notice: '', loginError, onLogin() {} });
  const all = (pred) => root.querySelectorAll(pred);
  return {
    root,
    text: root.textContent,
    sso: all((n) => n.tagName === 'a' && n.getAttribute('href') === OIDC_LOGIN_PATH),
    forms: all((n) => n.tagName === 'form'),
    details: all((n) => n.tagName === 'details'),
    divider: all((n) => n.getAttribute('role') === 'separator'),
    alerts: all((n) => n.getAttribute('role') === 'alert' && n.getAttribute('class') === 'login__error'),
  };
}

test('sign-in card: token only, SSO only, both, none', () => {
  const tokenOnly = renderLogin(meta(true, false));
  assert.equal(tokenOnly.sso.length, 0);
  assert.equal(tokenOnly.forms.length, 1);
  assert.equal(tokenOnly.details.length, 0);
  assert.equal(tokenOnly.divider.length, 0);

  const ssoOnly = renderLogin(meta(false, true, 'Corp IdP'));
  assert.equal(ssoOnly.sso.length, 1);
  assert.match(ssoOnly.sso[0].textContent, /Continue with Corp IdP/);
  assert.equal(ssoOnly.forms.length, 0);
  assert.equal(doc.focused, ssoOnly.sso[0]);

  const both = renderLogin(meta(true, true, 'Corp IdP'));
  assert.equal(both.sso.length, 1);
  assert.equal(both.divider.length, 1);
  assert.equal(both.details.length, 1, 'token form collapsed behind a disclosure');
  assert.match(both.details[0].textContent, /Use an operator token/);
  assert.equal(both.details[0].getAttribute('open'), null);
  assert.equal(both.forms.length, 1);
  assert.equal(both.forms[0].parentNode, both.details[0]);

  const none = renderLogin(meta(false, false));
  assert.equal(none.sso.length + none.forms.length, 0);
  assert.match(none.text, /No sign-in method is enabled/);
});

test('sign-in card shows the mapped message for an error code, never other text', () => {
  const r = renderLogin(meta(true, true), 'invalid_state');
  assert.equal(r.alerts.length, 1);
  assert.match(r.alerts[0].textContent, /That sign-in attempt expired/);
  const generic = renderLogin(meta(true, true), 'unknown');
  assert.match(generic.alerts[0].textContent, /Single sign-on did not complete/);
  assert.equal(renderLogin(meta(true, true)).alerts.length, 0);
});

test('sign-in card: organisation name and banner from /meta, as plain text only', () => {
  const evil = 'Authorised use only.\n<img src=x onerror=alert(1)> <b>bold</b>';
  const r = renderLogin({ ...meta(true, false), organization_name: 'Example SOC‮', sign_in_banner: evil });
  assert.match(r.text, /Example SOC/);
  assert.doesNotMatch(r.text, /‮/, 'direction overrides are stripped from the name');
  // The banner text is one Text node: markup stays characters.
  const texts = [];
  const walk = (n) => { for (const c of n.childNodes) { if (c.nodeType === 3) texts.push(c.data); else walk(c); } };
  walk(r.root);
  assert.ok(texts.includes(evil), 'the whole banner is a single Text node, unparsed');
  assert.equal(r.root.querySelectorAll((n) => n.tagName === 'img' || n.tagName === 'b').length, 0);
  const none = renderLogin(meta(true, false));
  assert.equal(none.root.querySelectorAll((n) => (n.getAttribute('class') || '').includes('login__banner')).length, 0, 'no banner block when none is set');
});
