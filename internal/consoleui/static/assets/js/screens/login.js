import { h, svg, mount } from '../lib/dom.js';
import { ApiError, describeError } from '../lib/api.js';
import { banner } from '../ui/components.js';
import { icon, brandMark } from '../ui/icons.js';
import { signInOptions, loginErrorMessage, OIDC_LOGIN_PATH } from '../lib/auth.js';

// A fixed constellation (not data): nodes and the links of a small mesh,
// drawn faintly behind the sign-in card.
const NODES = [[180, 160], [420, 90], [610, 230], [860, 120], [1040, 260], [260, 420], [520, 470], [780, 400], [980, 560], [140, 640], [400, 700], [700, 660], [1080, 720]];
const LINKS = [[0, 1], [1, 2], [2, 3], [3, 4], [0, 5], [5, 6], [6, 2], [6, 7], [7, 3], [7, 8], [4, 8], [5, 9], [9, 10], [10, 6], [10, 11], [11, 7], [11, 12], [8, 12]];

function mesh() {
  const el = svg('svg', { class: 'login__mesh', viewBox: '0 0 1200 800', preserveAspectRatio: 'xMidYMid slice', 'aria-hidden': 'true', focusable: 'false' },
    LINKS.map(([a, b]) => svg('line', { x1: NODES[a][0], y1: NODES[a][1], x2: NODES[b][0], y2: NODES[b][1] })),
    NODES.map(([cx, cy]) => svg('circle', { cx, cy, r: 3 })));
  // Stagger the slow breathing so the mesh never pulses in unison.
  el.querySelectorAll('circle').forEach((c, i) => c.style.setProperty('--d', `${-((i * 1.7) % 9).toFixed(1)}s`));
  return el;
}

// The token form. Collapsed behind "Use an operator token" when single
// sign-on is the primary way in.
function tokenForm({ api, onLogin, collapsed }) {
  const error = h('p', { class: 'field__error', role: 'alert', id: 'token-error' });
  const input = h('input', {
    class: ['input', 'input--mono'], id: 'token', name: 'token', type: 'password', autocomplete: 'off',
    spellcheck: 'false', required: true, 'aria-describedby': 'token-hint token-error', maxlength: 512,
  });
  const submit = h('button', { class: ['btn', collapsed ? '' : 'btn--primary', 'btn--block'], type: 'submit' }, 'Sign in with token');
  const setBusy = (busy) => {
    submit.disabled = busy;
    submit.replaceChildren(...(busy ? [h('span', { class: ['spinner', collapsed ? '' : 'spinner--inverse'], 'aria-hidden': 'true' }), 'Signing in…'] : ['Sign in with token']));
  };
  const form = h('form', { class: 'login__form', novalidate: true },
    h('div', { class: 'field' },
      h('label', { class: 'field__label', for: 'token' }, 'Operator token'),
      input,
      h('span', { class: 'field__hint', id: 'token-hint' }, 'Printed once by ', h('code', null, 'aegismesh console token'), '. The token is exchanged for a session cookie and is not stored by the browser.')),
    error,
    submit);

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const token = input.value.trim();
    error.textContent = '';
    input.removeAttribute('aria-invalid');
    if (!token) {
      error.textContent = 'Enter your operator token.';
      input.setAttribute('aria-invalid', 'true');
      input.focus();
      return;
    }
    setBusy(true);
    try {
      const session = await api.login(token);
      input.value = '';
      onLogin(session);
    } catch (err) {
      input.setAttribute('aria-invalid', 'true');
      error.textContent = err instanceof ApiError && err.status === 401
        ? 'That token was not accepted. Check for a missing character, or generate a new one.'
        : describeError(err).detail;
      setBusy(false);
      input.focus();
    }
  });

  if (!collapsed) return { el: form, focus: () => input.focus() };
  const details = h('details', { class: 'login__alt' },
    h('summary', { class: 'login__alt-summary' }, icon('key', { size: 'sm' }), 'Use an operator token'),
    form);
  details.addEventListener('toggle', () => { if (details.open) input.focus(); });
  return { el: details, focus: () => {} };
}

// Single sign-on: a plain same-origin navigation. The server answers with a
// redirect to the identity provider; nothing is fetched by script.
function ssoButton(name) {
  const label = h('span', null, `Continue with ${name}`);
  const a = h('a', { class: ['btn', 'btn--primary', 'btn--block', 'login__sso'], href: OIDC_LOGIN_PATH }, icon('sign-in'), label);
  a.addEventListener('click', (e) => {
    if (e.defaultPrevented || e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return;
    a.setAttribute('aria-disabled', 'true');
    a.classList.add('is-busy');
    label.textContent = `Redirecting to ${name}…`;
  });
  // Coming back with the browser's back button restores this page from the
  // back/forward cache: undo the busy state.
  window.addEventListener('pageshow', () => {
    a.removeAttribute('aria-disabled');
    a.classList.remove('is-busy');
    label.textContent = `Continue with ${name}`;
  }, { once: true });
  return a;
}

export default {
  title: 'Sign in',
  // loginError: a code from the OIDC callback redirect ('' when none). The
  // shell has already removed it from the address bar.
  render(root, { api, meta, notice, loginError = '', onLogin }) {
    const opts = signInOptions(meta);
    const parts = [];
    let focus = () => {};

    if (opts.oidc) {
      const sso = ssoButton(opts.displayName);
      parts.push(h('div', { class: 'login__sso-block' },
        sso,
        h('p', { class: ['field__hint', 'login__sso-note'] }, 'OpenID Connect single sign-on. Experimental: you are sent to your identity provider and back.')));
      focus = () => sso.focus();
    }
    if (opts.oidc && opts.token) parts.push(h('div', { class: 'login__divider', role: 'separator' }, h('span', null, 'or')));
    if (opts.token) {
      const t = tokenForm({ api, onLogin, collapsed: opts.collapseToken });
      parts.push(t.el);
      if (!opts.oidc) focus = t.focus;
    }
    if (opts.primary === 'none') {
      parts.push(banner('warn', 'No sign-in method is enabled',
        h('p', null, 'This console accepts neither operator tokens nor single sign-on. An administrator can enable one in the ', h('code', null, 'console'), ' section of the AegisMesh configuration.')));
    }

    let errorBlock = null;
    if (loginError) {
      const m = loginErrorMessage(loginError, { tokenAvailable: opts.token });
      errorBlock = h('div', { role: 'alert', class: 'login__error' }, banner('warn', m.title, m.detail));
    }

    mount(root, h('main', { class: 'login', id: 'main' },
      mesh(),
      h('div', { class: 'login__card' },
        h('div', { class: 'brand' }, brandMark(), 'AegisMesh'),
        h('h1', { id: 'page-title', tabindex: '-1' }, 'Operator console'),
        h('p', { class: 'muted' }, 'A read-mostly view of evidence your sensors observed.'),
        notice ? banner('info', null, notice) : null,
        errorBlock,
        parts),
      h('p', { class: 'login__foot muted' }, meta?.version ? `AegisMesh ${meta.version} · API ${meta.api_version || 'v1'}` : 'AegisMesh')));
    focus();
  },
};
