// Building blocks for Settings and administration: the one confirmation
// pattern for destructive actions, the one-time key reveal, form fields with
// inline validation and an error summary, radio choices, and the read-only
// renderer for the server's effective settings.
//
// Feedback rule: a form or dialog reports its own errors inline (next to the
// field, and in a summary that takes focus); an action's outcome is a toast,
// which lives in the console's polite live region. Nothing is reported only
// by colour.

import { h } from '../lib/dom.js';
import { describeError } from '../lib/api.js';
import { formatDateTime, formatRelative } from '../lib/format.js';
import { typedMatches, refusalMessage, settingSourceMeta } from '../lib/settings.js';
import { missingText } from '../lib/perms.js';
import { banner, copyable, timeEl, empty, link } from './components.js';
import { icon } from './icons.js';

let seq = 0;
const uid = (p) => `${p}-${++seq}`;

// ---- States ------------------------------------------------------------------

export const OLDER_SERVER = Object.freeze({
  title: 'This server does not provide account management yet',
  detail: 'The console is newer than the AegisMesh server answering it. Update the server to manage sessions, API keys and accounts here. Your preferences still work: they are saved in this browser.',
});

// What a section shows when the server is older than the console (404 on
// the round-5 paths). Retrying cannot help, so there is no retry button.
export function olderServerState({ title = OLDER_SERVER.title, detail = OLDER_SERVER.detail } = {}) {
  return h('div', { class: 'state', role: 'status' },
    h('span', { class: 'state__icon', 'aria-hidden': 'true' }, icon('info')),
    h('p', { class: 'state__title' }, title),
    h('p', null, detail),
    h('div', { class: ['btn-row', 'state__actions'] }, h('a', { class: 'btn', href: '#/settings/preferences' }, 'Open preferences'), h('a', { class: 'btn', href: '#/guide?t=account' }, 'Read about accounts')));
}

// What a section shows when the role (or the server's 403) refuses it.
// `needs` names the missing permission (round 6), when known.
export function notPermittedState(role, what = 'this page', needs = '') {
  return empty('Your account cannot open this page',
    needs
      ? `You are signed in as ${role || 'unknown'}. ${missingText(needs)} Administration also works only in the local tenant. Ask someone who manages roles if you need ${what}.`
      : `You are signed in as ${role || 'unknown'}. Administration needs the admin role in the local tenant. Ask an admin if you need ${what}.`,
    link('#/settings/profile', 'See what your role allows'), { icon: 'shield' });
}

// ---- Confirmation ----------------------------------------------------------

// A native modal dialog (focus trap, inert page and Esc from the platform)
// that names the target, says the consequence in one sentence and, for keys
// and accounts, asks for the target's name to be typed. `onConfirm()` runs
// the request; while it runs both buttons are disabled and Esc is held, and
// a refusal stays in the dialog. Resolves to onConfirm's value, or null when
// cancelled. Focus starts on the typed field, else on Cancel, and returns to
// the control that opened the dialog when it closes.
export function confirmAction({ title, consequence, details = null, targetLabel, target, typed = '', confirmLabel = 'Confirm', danger = true, onConfirm, refusal = {}, refuse = null }) {
  return new Promise((resolve) => {
    const titleId = uid('confirm-title');
    const errorBox = h('div', { class: 'field__error', role: 'alert' });
    const submit = h('button', { class: ['btn', danger ? 'btn--danger' : 'btn--primary'], type: 'submit' }, confirmLabel);
    const cancel = h('button', { class: 'btn', type: 'button' }, 'Cancel');
    let input = null;
    let typedField = null;
    if (typed) {
      const id = uid('confirm-typed');
      input = h('input', { class: ['input', 'input--mono'], id, type: 'text', autocomplete: 'off', spellcheck: 'false', 'aria-describedby': `${id}-hint` });
      typedField = h('div', { class: 'field' },
        h('label', { class: 'field__label', for: id }, 'Type ', h('code', null, typed), ' to confirm'),
        input,
        h('span', { class: 'field__hint', id: `${id}-hint` }, 'This guards against acting on the wrong item. Matching is exact.'));
      submit.disabled = true;
      input.addEventListener('input', () => { submit.disabled = !typedMatches(input.value, typed); });
    }
    const form = h('form', { method: 'dialog', novalidate: true });
    const dialog = h('dialog', { class: ['dialog', 'confirm'], 'aria-labelledby': titleId, 'aria-describedby': `${titleId}-c` }, form);
    form.append(
      h('div', { class: 'dialog__head' }, h('h2', { id: titleId }, title)),
      h('div', { class: 'dialog__body' },
        h('p', { class: 'confirm__consequence', id: `${titleId}-c` }, consequence),
        target ? h('dl', { class: 'confirm__target' }, h('dt', null, targetLabel || 'Target'), h('dd', null, h('code', null, target))) : null,
        details,
        typedField,
        errorBox),
      h('div', { class: 'dialog__foot' }, cancel, submit));
    let result = null;
    let busy = false;
    cancel.addEventListener('click', () => dialog.close());
    dialog.addEventListener('cancel', (e) => { if (busy) e.preventDefault(); });
    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      if (busy || (input && !typedMatches(input.value, typed))) return;
      busy = true;
      errorBox.textContent = '';
      submit.disabled = true;
      cancel.disabled = true;
      submit.setAttribute('aria-busy', 'true');
      try {
        const value = await onConfirm();
        // A 204 answers null: confirmed all the same.
        result = value ?? true;
        busy = false;
        dialog.close();
      } catch (err) {
        busy = false;
        // `refuse(err)` may return a node (links to who holds a role) or ''.
        const custom = refuse?.(err);
        if (custom && typeof custom === 'object') errorBox.replaceChildren(custom);
        else errorBox.textContent = custom || refusalMessage(err, refusal);
        cancel.disabled = false;
        submit.disabled = Boolean(input && !typedMatches(input.value, typed));
        submit.removeAttribute('aria-busy');
        (input || cancel).focus();
      }
    });
    dialog.addEventListener('close', () => {
      resolve(result);
      setTimeout(() => dialog.remove(), 220);
    });
    document.body.appendChild(dialog);
    dialog.showModal();
    (input || cancel).focus();
  });
}

// ---- One-time key reveal -----------------------------------------------------

// Shows a freshly minted token exactly once, inline where it was created.
// The value lives in this closure and one Text node. "I have stored it"
// (or leaving the page: call destroy()) empties the Text node and removes
// the panel, so nothing remains in the DOM, storage, the URL or logs.
export function keyReveal(minted, { onDone, owner = '' } = {}) {
  let value = String(minted?.token ?? '');
  const key = minted?.key || {};
  const text = document.createTextNode(value);
  const titleId = uid('reveal-title');
  const status = h('p', { class: 'field__hint', role: 'status' });
  const copy = h('button', { class: ['btn', 'btn--primary'], type: 'button' }, icon('copy', { size: 'sm' }), 'Copy key');
  const done = h('button', { class: 'btn', type: 'button' }, 'I have stored it');
  const valueEl = h('pre', { class: ['code', 'token-value', 'reveal__value'], tabindex: '0', 'aria-label': 'API key, shown once' }, text);
  const el = h('section', { class: 'reveal', role: 'region', 'aria-labelledby': titleId, tabindex: '-1' },
    h('div', { class: 'reveal__head' },
      h('h2', { class: 'reveal__title', id: titleId }, icon('key'), owner ? `New API key for ${owner}` : 'Your new API key'),
      h('p', { class: 'reveal__label' }, h('span', { class: 'muted' }, 'Label '), key.label || '—')),
    banner('warn', 'Copy it now. You will not see this key again.',
      'The server keeps only a SHA-256 fingerprint, so nobody can show it to you later. If you lose it, revoke it and create another. Paste it into a secret store, not a chat or a ticket.'),
    valueEl,
    h('dl', { class: 'reveal__facts' },
      h('div', null, h('dt', null, 'Prefix'), h('dd', null, h('code', null, key.prefix || '—'))),
      h('div', null, h('dt', null, 'Expires'), h('dd', null, key.expires_at ? timeEl(key.expires_at) : '—')),
      h('div', null, h('dt', null, 'Use it as'), h('dd', null, h('code', null, 'Authorization: Bearer <key>')))),
    h('div', { class: ['btn-row', 'reveal__actions'] }, copy, done, status));
  let destroyed = false;
  const destroy = () => {
    if (destroyed) return;
    destroyed = true;
    text.data = '';
    value = '';
    el.remove();
  };
  copy.addEventListener('click', async () => {
    try {
      await navigator.clipboard.writeText(value);
      status.textContent = 'Copied to the clipboard.';
    } catch {
      status.textContent = 'The browser blocked clipboard access. Select the key and copy it manually.';
    }
  });
  done.addEventListener('click', () => {
    destroy();
    onDone?.();
  });
  return { el, destroy, focus: () => el.focus() };
}

// ---- Forms -----------------------------------------------------------------

// A labelled control with a hint and an inline error. `control` is an input
// or select built by the caller (its id is set here).
// `wrap(control)` may place the control in a row with its companions (a
// unit, a readout); the label still points at the control itself.
export function formField({ label, control, hint, optional = false, wrap = null }) {
  const id = control.getAttribute('id') || uid('f');
  control.setAttribute('id', id);
  const error = h('p', { class: 'field__error', id: `${id}-error` });
  control.setAttribute('aria-describedby', [hint ? `${id}-hint` : '', `${id}-error`].filter(Boolean).join(' '));
  const el = h('div', { class: 'field' },
    h('label', { class: 'field__label', for: id }, label, optional ? h('span', { class: 'field__optional' }, ' (optional)') : null),
    wrap ? wrap(control) : control,
    hint ? h('span', { class: 'field__hint', id: `${id}-hint` }, hint) : null,
    error);
  return {
    el, control, label,
    setError(msg) {
      error.textContent = msg || '';
      control.setAttribute('aria-invalid', msg ? 'true' : 'false');
    },
    focus: () => control.focus(),
  };
}

// Radio choices drawn as words with the console's one selection line.
// options: [[value, label, hint?]]. Native radios: arrow keys move within
// the group, and the group has a legend.
export function choices({ legend, name, options, value, onChange, hint, compact = false }) {
  const id = uid('ch');
  const inputs = [];
  const error = h('p', { class: 'field__error', id: `${id}-error` });
  const el = h('fieldset', { class: ['choices', compact ? 'choices--compact' : ''], 'aria-describedby': [hint ? `${id}-hint` : '', `${id}-error`].filter(Boolean).join(' ') },
    h('legend', { class: 'field__label' }, legend),
    h('div', { class: 'choices__row' }, options.map(([v, label, sub]) => {
      const input = h('input', { class: 'choice__input', type: 'radio', name, value: v, prop: { checked: v === value } });
      input.addEventListener('change', () => { if (input.checked) onChange?.(v); });
      inputs.push(input);
      return h('label', { class: 'choice' }, input, h('span', { class: 'choice__label' }, label), sub ? h('span', { class: 'choice__sub' }, sub) : null);
    })),
    hint ? h('span', { class: 'field__hint', id: `${id}-hint` }, hint) : null,
    error);
  return {
    el,
    value: () => { const i = inputs.find((x) => x.checked); return i ? (i.value ?? i.getAttribute('value') ?? '') : ''; },
    set(v) { for (const i of inputs) i.checked = i.value === v; },
    setError(msg) { error.textContent = msg || ''; },
    disable(on) { for (const i of inputs) i.disabled = on; },
    focus: () => (inputs.find((i) => i.checked) || inputs[0])?.focus(),
  };
}

// Check boxes for a set (tenants). options: [[value, label]].
export function checkSet({ legend, name, options, values = [], hint }) {
  const id = uid('cs');
  const inputs = [];
  const error = h('p', { class: 'field__error', id: `${id}-error` });
  const el = h('fieldset', { class: 'checkset', 'aria-describedby': [hint ? `${id}-hint` : '', `${id}-error`].filter(Boolean).join(' ') },
    h('legend', { class: 'field__label' }, legend),
    h('div', { class: 'checkset__row' }, options.map(([v, label]) => {
      const input = h('input', { type: 'checkbox', name, value: v, prop: { checked: values.includes(v) } });
      inputs.push(input);
      return h('label', { class: 'check' }, input, h('span', null, label));
    })),
    hint ? h('span', { class: 'field__hint', id: `${id}-hint` }, hint) : null,
    error);
  return {
    el,
    values: () => inputs.filter((i) => i.checked).map((i) => i.value),
    setError(msg) { error.textContent = msg || ''; },
    focus: () => inputs[0]?.focus(),
  };
}

// The error summary at the top of a form: a count, then one button per
// problem that moves focus to its field. Takes focus when shown.
export function errorSummary() {
  const list = h('ul', { class: 'form-summary__list' });
  const head = h('p', { class: 'form-summary__title' });
  const el = h('div', { class: 'form-summary', role: 'alert', tabindex: '-1', hidden: true }, icon('warn'), h('div', null, head, list));
  return {
    el,
    show(problems) {
      list.replaceChildren(...problems.map((p) => h('li', null,
        h('button', { class: 'form-summary__link', type: 'button', on: { click: () => p.field.focus() } }, `${p.label}: ${p.message}`))));
      head.textContent = problems.length === 1 ? 'Fix one problem before saving' : `Fix ${problems.length} problems before saving`;
      el.hidden = false;
      el.focus();
    },
    serverError(message) {
      list.replaceChildren();
      head.textContent = message;
      el.hidden = false;
      el.focus();
    },
    clear() {
      el.hidden = true;
      list.replaceChildren();
    },
  };
}

// Submit handling shared by every settings form: validate every field,
// show inline errors and the summary, disable the submit button (with its
// busy label) while the request runs, and keep the form filled on failure.
// `checks`: [{ field, label, validate: () => message }].
export function wireForm(form, { submit, busyLabel = 'Saving…', checks = [], summary, onSubmit }) {
  const idle = [...submit.childNodes];
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    if (submit.disabled) return;
    const problems = [];
    for (const c of checks) {
      const message = c.validate();
      c.field.setError(message);
      if (message) problems.push({ field: c.field, label: c.label, message });
    }
    if (problems.length) {
      summary.show(problems);
      return;
    }
    summary.clear();
    submit.disabled = true;
    submit.textContent = busyLabel;
    submit.setAttribute('aria-busy', 'true');
    try {
      await onSubmit();
    } catch (err) {
      summary.serverError(err?.status !== undefined ? refusalMessage(err) : describeError(err).detail);
    } finally {
      submit.disabled = false;
      submit.replaceChildren(...idle);
      submit.removeAttribute('aria-busy');
    }
  });
}

// ---- Read-only effective settings -------------------------------------------

// One /admin/settings section: each value with where it comes from, how to
// change it, and the config key to search the file for. Values are server
// text, rendered as Text nodes; nothing here is editable.
export function settingsSection(section) {
  const items = Array.isArray(section?.items) ? section.items : [];
  return h('dl', { class: 'setting-list' }, items.map((it) => {
    const src = settingSourceMeta(it.source);
    return h('div', { class: 'setting' },
      h('dt', { class: 'setting__label' }, String(it.label ?? it.key ?? '')),
      h('dd', { class: 'setting__value' },
        h('span', { class: ['setting__text', ['address', 'text', 'duration', 'count', 'bytes'].includes(it.kind) ? 'num' : ''] }, String(it.value ?? '—')),
        h('span', { class: ['src-chip', `src-chip--${['config', 'default', 'env', 'runtime'].includes(it.source) ? it.source : 'unknown'}`], title: src.hint },
          h('span', { class: 'src-chip__mark', 'aria-hidden': 'true' }), src.label)),
      h('dd', { class: 'setting__how' },
        it.note ? h('span', { class: 'setting__note' }, String(it.note)) : null,
        typeof it.key === 'string' && it.key ? copyable(it.key, { label: `config key ${it.key}` }) : null));
  }));
}

// "3m ago (2026-11-23 20:30:00 UTC)" in plain text, for kv rows.
export function whenText(value) {
  if (!value) return 'never';
  return `${formatRelative(value)} (${formatDateTime(value)})`;
}
