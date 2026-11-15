import { h, clear, mount } from '../lib/dom.js';
import { ApiError, describeError } from '../lib/api.js';
import { brandMark } from '../ui/shell.js';
import { banner } from '../ui/components.js';

export default {
  title: 'Sign in',
  render(root, { api, meta, notice, onLogin }) {
    const error = h('p', { class: 'field__error', role: 'alert', id: 'token-error' });
    const input = h('input', {
      class: ['input', 'input--mono'], id: 'token', name: 'token', type: 'password', autocomplete: 'off',
      spellcheck: 'false', required: true, 'aria-describedby': 'token-hint token-error', maxlength: 512,
    });
    const submit = h('button', { class: ['btn', 'btn--primary', 'btn--block'], type: 'submit' }, 'Sign in');
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
      submit.disabled = true;
      submit.textContent = 'Signing in…';
      try {
        const session = await api.login(token);
        input.value = '';
        onLogin(session);
      } catch (err) {
        input.setAttribute('aria-invalid', 'true');
        error.textContent = err instanceof ApiError && err.status === 401
          ? 'That token was not accepted. Check for a missing character, or generate a new one.'
          : describeError(err).detail;
        submit.disabled = false;
        submit.textContent = 'Sign in';
        input.focus();
      }
    });

    mount(root, h('main', { class: 'login', id: 'main' },
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
