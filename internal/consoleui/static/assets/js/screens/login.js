import { h, svg, mount } from '../lib/dom.js';
import { ApiError, describeError } from '../lib/api.js';
import { brandMark } from '../ui/icons.js';
import { banner } from '../ui/components.js';

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

export default {
  title: 'Sign in',
  render(root, { api, meta, notice, onLogin }) {
    const error = h('p', { class: 'field__error', role: 'alert', id: 'token-error' });
    const input = h('input', {
      class: ['input', 'input--mono'], id: 'token', name: 'token', type: 'password', autocomplete: 'off',
      spellcheck: 'false', required: true, 'aria-describedby': 'token-hint token-error', maxlength: 512,
    });
    const submit = h('button', { class: ['btn', 'btn--primary', 'btn--block'], type: 'submit' }, 'Sign in');
    const setBusy = (busy) => {
      submit.disabled = busy;
      submit.replaceChildren(...(busy ? [h('span', { class: 'spinner spinner--inverse', 'aria-hidden': 'true' }), 'Signing in…'] : ['Sign in']));
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

    mount(root, h('main', { class: 'login', id: 'main' },
      mesh(),
      h('div', { class: 'login__card' },
        h('div', { class: 'brand' }, brandMark(), 'AegisMesh'),
        h('h1', { id: 'page-title', tabindex: '-1' }, 'Operator console'),
        h('p', { class: 'muted' }, 'A read-mostly view of evidence your sensors observed on this node.'),
        notice ? banner('info', null, notice) : null,
        form),
      h('p', { class: 'login__foot muted' }, meta?.version ? `AegisMesh ${meta.version} · API ${meta.api_version || 'v1'}` : 'AegisMesh')));
    input.focus();
  },
};
