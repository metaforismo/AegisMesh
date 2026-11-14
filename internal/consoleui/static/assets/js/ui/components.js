// Reusable view builders. Every builder returns DOM nodes made through dom.js;
// API strings only ever become Text nodes or validated attribute values.

import { h } from '../lib/dom.js';
import { classificationMeta, isSeverity, severityLabel, capitalize } from '../lib/taxonomy.js';
import { formatDateTime, formatRelative, truncate } from '../lib/format.js';
import { describeError } from '../lib/api.js';

// ---- Severity, classification, badges ------------------------------------

export function sevChip(severity) {
  const known = isSeverity(severity);
  return h('span', { class: ['sev', known ? `sev--${severity}` : 'sev--none'] },
    h('span', { class: 'sev__meter', 'aria-hidden': 'true' }, h('i'), h('i'), h('i'), h('i'), h('i')),
    severityLabel(known ? severity : ''));
}

export function glyph(classification) {
  const meta = classificationMeta(classification);
  return h('span', { class: ['glyph', meta.glyph ? `glyph--${meta.glyph}` : ''], 'aria-hidden': 'true' });
}

export function clsChip(classification) {
  return h('span', { class: 'cls' }, glyph(classification), classificationMeta(classification).label);
}

const BADGE_KINDS = new Set(['ok', 'warn', 'danger', 'info', 'neutral']);

export function badge(kind, label) {
  return h('span', { class: ['badge', `badge--${BADGE_KINDS.has(kind) ? kind : 'neutral'}`] }, label);
}

export function chip(label, { mono = false } = {}) {
  return h('span', { class: ['chip', mono ? 'chip--mono' : ''] }, label);
}

// Attacker-controlled text. `max` truncates for dense tables; the full value
// stays available as the title tooltip and to assistive tech.
export function evidence(value, { block = false, max = 0 } = {}) {
  const full = String(value ?? '');
  if (full === '') return h('span', { class: 'muted' }, '—');
  const shown = max > 0 ? truncate(full, max) : full;
  return h(block ? 'pre' : 'span', {
    class: ['evidence', block ? 'evidence--block' : ''],
    title: shown !== full ? full : null,
  }, shown);
}

export function timeEl(value, { relative = false, now } = {}) {
  const full = formatDateTime(value);
  if (full === '—') return h('span', { class: 'muted' }, '—');
  return h('time', { datetime: value, title: full }, relative ? formatRelative(value, now) : full);
}

export function link(href, ...children) {
  return h('a', { href }, ...children);
}

// ---- Layout ----------------------------------------------------------------

export function pageHead({ title, subtitle, actions, eyebrow }) {
  return h('header', { class: 'page-head' },
    h('div', { class: 'page-head__text' },
      eyebrow ? h('p', { class: 'page-head__eyebrow' }, eyebrow) : null,
      h('h1', { class: 'page-head__title', id: 'page-title', tabindex: '-1' }, title),
      subtitle ? h('p', { class: 'page-head__sub' }, subtitle) : null),
    actions ? h('div', { class: 'btn-row page-head__actions' }, actions) : null);
}

export function panel({ title, meta, actions, body, flush = false, foot, id, headingLevel = 'h2' }) {
  return h('section', { class: 'panel', id, 'aria-labelledby': id ? `${id}-title` : null },
    title ? h('div', { class: 'panel__head' },
      h('div', null,
        h(headingLevel, { class: 'panel__title', id: id ? `${id}-title` : null }, title),
        meta ? h('p', { class: 'panel__meta' }, meta) : null),
      actions ? h('div', { class: 'btn-row' }, actions) : null) : null,
    h('div', { class: ['panel__body', flush ? 'panel__body--flush' : ''] }, body),
    foot ? h('div', { class: 'panel__foot' }, foot) : null);
}

export function stat({ label, value, delta, icon }) {
  return h('div', { class: 'stat' },
    h('span', { class: 'stat__label' }, icon || null, label),
    h('span', { class: 'stat__value' }, value),
    delta ? h('span', { class: 'stat__delta' }, h('strong', null, delta.text), ` ${delta.detail}`) : null);
}

export function kv(pairs) {
  const items = [];
  for (const [k, v] of pairs) {
    if (v === undefined) continue;
    items.push(h('dt', null, k), h('dd', null, v === null || v === '' ? h('span', { class: 'muted' }, '—') : v));
  }
  return h('dl', { class: 'kv' }, items);
}

// columns: [{ label, num?, className?, cell(row) → Node|string }]
export function table({ columns, rows, caption, stack = true, rowClass }) {
  return h('div', { class: 'table-wrap' },
    h('table', { class: ['table', stack ? 'table--stack' : ''] },
      caption ? h('caption', { class: 'visually-hidden' }, caption) : null,
      h('thead', null, h('tr', null, columns.map((c) => h('th', { scope: 'col', class: [c.num ? 'num' : '', c.className || ''] }, c.label)))),
      h('tbody', null, rows.map((row) => h('tr', { class: rowClass ? rowClass(row) : null },
        columns.map((c) => h('td', { class: [c.num ? 'num' : '', c.className || ''], 'data-label': c.label }, c.cell(row))))))));
}

// ---- States ----------------------------------------------------------------

export function loading(label = 'Loading') {
  return h('div', { class: 'state', role: 'status', 'aria-live': 'polite' },
    h('span', { class: 'btn-row' }, h('span', { class: 'spinner', 'aria-hidden': 'true' }), `${label}…`));
}

export function empty(title, detail, action) {
  return h('div', { class: 'state' },
    h('p', { class: 'state__title' }, title),
    detail ? h('p', null, detail) : null,
    action || null);
}

export function errorState(err, onRetry) {
  const d = describeError(err);
  return h('div', { class: ['state', 'state--error'], role: 'alert' },
    h('p', { class: 'state__title' }, d.title),
    h('p', null, d.detail),
    onRetry ? h('button', { class: 'btn', type: 'button', on: { click: onRetry } }, 'Try again') : null);
}

export function banner(kind, title, ...body) {
  return h('div', { class: ['banner', `banner--${kind}`], role: kind === 'danger' ? 'alert' : null },
    h('div', null, title ? h('p', { class: 'banner__title' }, title) : null, ...body.map((b) => (typeof b === 'string' ? h('p', null, b) : b))));
}

// ---- Integrity seal ----------------------------------------------------------

export function seal(ok, label) {
  return h('span', { class: ['seal', ok ? 'seal--ok' : 'seal--fail'] },
    h('span', { class: 'seal__mark', 'aria-hidden': 'true' }), label);
}

// ---- Bar list -------------------------------------------------------------

// items: [{ label: Node|string, value: number, valueText?, href? }]
export function barList(items, { max } = {}) {
  const top = max ?? items.reduce((m, i) => Math.max(m, Number(i.value) || 0), 0);
  return h('ul', { class: 'bar-list' }, items.map((item) => {
    const fill = h('span', { class: 'bar-list__fill' });
    const ratio = top > 0 ? Math.min(1, Math.max(0, (Number(item.value) || 0) / top)) : 0;
    // CSSOM write, not a style attribute: allowed under style-src 'self'.
    fill.style.transform = `scaleX(${ratio.toFixed(4)})`;
    return h('li', { class: 'bar-list__row' },
      h('span', { class: 'bar-list__label' }, item.href ? h('a', { href: item.href }, item.label) : item.label),
      h('span', { class: 'bar-list__value' }, item.valueText ?? String(item.value)),
      h('span', { class: 'bar-list__track', 'aria-hidden': 'true' }, fill));
  }));
}

// ---- Controls ---------------------------------------------------------------

export function segmented({ label, options, value, onChange }) {
  return h('div', { class: 'segmented', role: 'group', 'aria-label': label },
    options.map(([v, text]) => h('button', {
      type: 'button', 'aria-pressed': String(v === value),
      on: { click: () => { if (v !== value) onChange(v); } },
    }, text)));
}

export function selectField({ label, name, value, options, onChange, id }) {
  const fid = id || `f-${name}`;
  return h('div', { class: 'field' },
    h('label', { class: 'field__label', for: fid }, label),
    h('select', { class: 'select', id: fid, name, on: onChange ? { change: (e) => onChange(e.target.value) } : {} },
      options.map(([v, text]) => h('option', { value: v, selected: v === value }, text))));
}

export function inputField({ label, name, value = '', type = 'text', placeholder, hint, mono = false, maxlength, id, autocomplete = 'off', required = false }) {
  const fid = id || `f-${name}`;
  return h('div', { class: 'field' },
    h('label', { class: 'field__label', for: fid }, label),
    h('input', {
      class: ['input', mono ? 'input--mono' : ''], id: fid, name, type, placeholder, maxlength, autocomplete,
      spellcheck: 'false', required, prop: { value },
      'aria-describedby': hint ? `${fid}-hint` : null,
    }),
    hint ? h('span', { class: 'field__hint', id: `${fid}-hint` }, hint) : null);
}

export function pager({ hasMore, onMore, shown, total }) {
  const btn = h('button', { class: 'btn', type: 'button' }, 'Load more');
  btn.addEventListener('click', async () => {
    btn.disabled = true;
    btn.textContent = 'Loading…';
    try {
      await onMore();
    } finally {
      btn.disabled = false;
      btn.textContent = 'Load more';
    }
  });
  return h('div', { class: 'pager' },
    h('span', { class: 'muted' }, total !== undefined ? `Showing ${shown} of ${total}` : `Showing ${shown}`),
    hasMore ? btn : h('span', { class: 'muted' }, shown ? 'End of list' : ''));
}

// ---- Toasts -----------------------------------------------------------------

let toastRegion = null;

export function toast(kind, message, { timeout = 5000 } = {}) {
  if (!toastRegion) {
    toastRegion = h('div', { class: 'toast-region', role: 'status', 'aria-live': 'polite' });
    document.body.appendChild(toastRegion);
  }
  const close = h('button', { class: ['btn', 'btn--ghost', 'btn--sm'], type: 'button', 'aria-label': 'Dismiss' }, '×');
  const el = h('div', { class: ['toast', kind === 'error' ? 'toast--error' : 'toast--ok'] },
    h('p', { class: 'toast__text' }, message), close);
  const remove = () => el.remove();
  close.addEventListener('click', remove);
  toastRegion.appendChild(el);
  if (timeout) setTimeout(remove, timeout);
}

// ---- Dialog ----------------------------------------------------------------

// Native <dialog> gives focus trapping, Esc and inert background for free.
// `build(close)` returns the body nodes; `onSubmit(form)` resolves to a value
// or throws to keep the dialog open with an error message.
export function openDialog({ title, build, submitLabel = 'Save', onSubmit, danger = false }) {
  return new Promise((resolve) => {
    const errorBox = h('p', { class: 'field__error', role: 'alert' });
    const submit = h('button', { class: ['btn', danger ? 'btn--danger' : 'btn--primary'], type: 'submit' }, submitLabel);
    const cancel = h('button', { class: 'btn', type: 'button' }, 'Cancel');
    const form = h('form', { method: 'dialog', novalidate: true });
    const dialog = h('dialog', { class: 'dialog', 'aria-labelledby': 'dialog-title' },
      form);
    form.append(
      h('div', { class: 'dialog__head' }, h('h2', { id: 'dialog-title' }, title)),
      h('div', { class: 'dialog__body' }, build(), errorBox),
      h('div', { class: 'dialog__foot' }, cancel, submit));
    let result = null;
    cancel.addEventListener('click', () => dialog.close());
    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      errorBox.textContent = '';
      submit.disabled = true;
      try {
        result = await onSubmit(form);
        dialog.close();
      } catch (err) {
        errorBox.textContent = err?.message ? describeError(err).detail : 'Could not save.';
      } finally {
        submit.disabled = false;
      }
    });
    dialog.addEventListener('close', () => {
      dialog.remove();
      resolve(result);
    });
    document.body.appendChild(dialog);
    dialog.showModal();
  });
}

export function labelFor(value) {
  return capitalize(String(value ?? '').replace(/_/g, ' '));
}
