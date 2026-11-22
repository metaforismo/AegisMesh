// Reusable view builders. Every builder returns DOM nodes made through dom.js;
// API strings only ever become Text nodes or validated attribute values.

import { h, svg } from '../lib/dom.js';
import { classificationMeta, isSeverity, severityLabel, capitalize } from '../lib/taxonomy.js';
import { formatDateTime, formatRelative, truncate } from '../lib/format.js';
import { describeError } from '../lib/api.js';
import { sparkPath } from '../lib/chart.js';
import { icon } from './icons.js';

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

// Relative times carry the absolute UTC time: in the peek on hover, and as
// visually hidden text, so assistive tech reads both.
export function timeEl(value, { relative = false, now } = {}) {
  const full = formatDateTime(value);
  if (full === '—') return h('span', { class: 'muted' }, '—');
  return relative
    ? h('time', { class: 'reltime', datetime: value, title: full }, formatRelative(value, now), h('span', { class: 'visually-hidden' }, ` (${full})`))
    : h('time', { datetime: value, title: full }, full);
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

// `primary` marks the one panel a screen is about (a stronger frame);
// everything else is secondary by default.
export function panel({ title, meta, actions, body, flush = false, foot, id, headingLevel = 'h2', primary = false }) {
  return h('section', { class: ['panel', primary ? 'panel--primary' : ''], id, 'aria-labelledby': id ? `${id}-title` : null },
    title ? h('div', { class: 'panel__head' },
      h('div', null,
        h(headingLevel, { class: 'panel__title', id: id ? `${id}-title` : null }, title),
        meta ? h('p', { class: 'panel__meta' }, meta) : null),
      actions ? h('div', { class: 'btn-row' }, actions) : null) : null,
    h('div', { class: ['panel__body', flush ? 'panel__body--flush' : ''] }, body),
    foot ? h('div', { class: 'panel__foot' }, foot) : null);
}

const TREND_ICON = { up: 'trend-up', down: 'trend-down', flat: 'trend-flat' };

// Stat tile. `spark` is an optional sparkline node; `delta` comes from
// formatDelta and is always neutral ink: the arrow states direction only.
export function stat({ label, value, delta, icon: lead, spark, title, note }) {
  return h('div', { class: 'stat', title: title || null },
    h('span', { class: 'stat__label' }, lead || null, label),
    h('span', { class: 'stat__value' }, value),
    spark ? h('span', { class: 'stat__spark' }, spark) : null,
    delta ? h('span', { class: 'stat__delta' },
      h('strong', null, icon(TREND_ICON[delta.direction] || 'trend-flat', { size: 'xs' }), delta.text),
      ` ${delta.detail}`) : null,
    !delta && note ? h('span', { class: 'stat__delta' }, note) : null);
}

// Decorative trend line beside a printed number (aria-hidden: the number
// and the chart's table view carry the data). `series` picks a class color.
export function sparkline(values, { series = '', width = 88, height = 28, label } = {}) {
  const p = sparkPath(values, { width, height, pad: 2.5 });
  const el = svg('svg', {
    class: ['spark', series ? `spark--${series}` : ''], viewBox: `0 0 ${width} ${height}`,
    'aria-hidden': label ? null : 'true', role: label ? 'img' : null, 'aria-label': label || null, focusable: 'false',
    preserveAspectRatio: 'none',
  });
  if (!p.line) return el;
  el.appendChild(svg('g', { class: 'spark__draw' },
    svg('path', { class: 'spark__area', d: p.area }),
    svg('path', { class: 'spark__line', d: p.line }),
    p.last ? svg('circle', { class: 'spark__dot', cx: p.last.x, cy: p.last.y, r: 2 }) : null));
  return el;
}

export function kv(pairs) {
  const items = [];
  for (const pair of pairs) {
    if (!pair) continue; // a row left out conditionally
    const [k, v] = pair;
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

export function empty(title, detail, action, { icon: name = 'inbox' } = {}) {
  return h('div', { class: 'state' },
    h('span', { class: 'state__icon', 'aria-hidden': 'true' }, icon(name)),
    h('p', { class: 'state__title' }, title),
    detail ? h('p', null, detail) : null,
    action || null);
}

export function errorState(err, onRetry) {
  const d = describeError(err);
  return h('div', { class: ['state', 'state--error'], role: 'alert' },
    h('span', { class: 'state__icon', 'aria-hidden': 'true' }, icon('warn')),
    h('p', { class: 'state__title' }, d.title),
    h('p', null, d.detail),
    onRetry ? h('button', { class: 'btn', type: 'button', on: { click: onRetry } }, icon('refresh'), 'Try again') : null);
}

const BANNER_ICON = { info: 'info', warn: 'warn', danger: 'warn' };

export function banner(kind, title, ...body) {
  return h('div', { class: ['banner', `banner--${kind}`], role: kind === 'danger' ? 'alert' : null },
    BANNER_ICON[kind] ? icon(BANNER_ICON[kind]) : null,
    h('div', null, title ? h('p', { class: 'banner__title' }, title) : null, ...body.map((b) => (typeof b === 'string' ? h('p', null, b) : b))));
}

// ---- Integrity seal ----------------------------------------------------------

export function seal(ok, label) {
  return h('span', { class: ['seal', ok ? 'seal--ok' : 'seal--fail'] },
    h('span', { class: 'seal__mark', 'aria-hidden': 'true' }), label);
}

// ---- Bar list -------------------------------------------------------------

// items: [{ label: Node|string, value: number, valueText?, href?, aside? }]
// `aside` is a small decorative shape (a trace) drawn between the label and
// the printed value; the value stays the number of record.
export function barList(items, { max } = {}) {
  const top = max ?? items.reduce((m, i) => Math.max(m, Number(i.value) || 0), 0);
  const withAside = items.some((i) => i.aside);
  return h('ul', { class: ['bar-list', withAside ? 'bar-list--aside' : ''] }, items.map((item) => {
    const fill = h('span', { class: 'bar-list__fill' });
    const ratio = top > 0 ? Math.min(1, Math.max(0, (Number(item.value) || 0) / top)) : 0;
    // CSSOM write, not a style attribute: allowed under style-src 'self'.
    fill.style.transform = `scaleX(${ratio.toFixed(4)})`;
    return h('li', { class: 'bar-list__row' },
      h('span', { class: 'bar-list__label' }, item.href ? h('a', { href: item.href }, item.label) : item.label),
      withAside ? h('span', { class: 'bar-list__aside', 'aria-hidden': 'true' }, item.aside || null) : null,
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
// Newest at the bottom, at most TOAST_MAX on screen. Timers pause while the
// pointer is over the stack or the tab is hidden, so a toast is never missed
// because the operator was reading another one. Errors stay twice as long.

let toastRegion = null;
const TOAST_MAX = 4;
const LEAVE_MS = 200;

function leave(el) {
  if (el.dataset.leaving) return;
  el.dataset.leaving = '1';
  el.classList.add('is-leaving');
  setTimeout(() => el.remove(), LEAVE_MS);
}

export function toast(kind, message, { timeout } = {}) {
  if (!toastRegion) {
    toastRegion = h('div', { class: 'toast-region', role: 'status', 'aria-live': 'polite' });
    document.body.appendChild(toastRegion);
    toastRegion.addEventListener('pointerenter', () => { toastRegion.dataset.hold = '1'; });
    toastRegion.addEventListener('pointerleave', () => { delete toastRegion.dataset.hold; });
  }
  const isError = kind === 'error';
  const ms = timeout ?? (isError ? 9000 : 4500);
  const close = h('button', { class: ['btn', 'btn--ghost', 'btn--sm', 'btn--icon'], type: 'button', 'aria-label': 'Dismiss' }, icon('close', { size: 'sm' }));
  const el = h('div', { class: ['toast', isError ? 'toast--error' : 'toast--ok'] },
    icon(isError ? 'warn' : 'check'),
    h('p', { class: 'toast__text' }, message), close);
  close.addEventListener('click', () => leave(el));
  toastRegion.appendChild(el);
  const live = [...toastRegion.children].filter((t) => !t.dataset.leaving);
  for (const old of live.slice(0, Math.max(0, live.length - TOAST_MAX))) leave(old);
  if (!ms) return;
  // Count down only while visible and not hovered.
  let left = ms;
  let last = performance.now();
  const tick = () => {
    if (!el.isConnected || el.dataset.leaving) return;
    const now = performance.now();
    if (!document.hidden && !toastRegion.dataset.hold) left -= now - last;
    last = now;
    if (left <= 0) leave(el);
    else setTimeout(tick, Math.min(250, left));
  };
  setTimeout(tick, 250);
}

// ---- Copy to clipboard -------------------------------------------------------

// A value with a copy button. The icon morphs to a check for 1.6s and a
// polite announcement says what was copied. `display` replaces the shown
// text (e.g. a shortened hash) while the full value is what gets copied.
export function copyable(value, { label = 'value', display, mono = true } = {}) {
  const full = String(value ?? '');
  const shown = display ?? full;
  const btn = copyButton(full, label);
  return h('span', { class: 'copyable' },
    mono ? h('code', { title: shown !== full ? full : null }, shown) : h('span', null, shown), btn);
}

export function copyButton(value, label = 'value') {
  const status = h('span', { class: 'visually-hidden', role: 'status' });
  const btn = h('button', { class: 'copy', type: 'button', 'aria-label': `Copy ${label}`, title: `Copy ${label}` },
    icon('copy', { size: 'sm' }), icon('check', { size: 'sm' }), status);
  let timer = null;
  btn.addEventListener('click', async (e) => {
    e.preventDefault();
    e.stopPropagation();
    try {
      await navigator.clipboard.writeText(String(value ?? ''));
      btn.classList.add('is-copied');
      status.textContent = `Copied ${label}`;
      clearTimeout(timer);
      timer = setTimeout(() => { btn.classList.remove('is-copied'); status.textContent = ''; }, 1600);
    } catch {
      toast('error', 'The browser blocked clipboard access. Select the text and copy it manually.');
    }
  });
  return btn;
}

// ---- Peek: full value of truncated evidence ---------------------------------
// One shared floating element. It reads the element's title (set by
// evidence() when it truncates) and shows it as a Text node: hover after a
// short delay, keyboard focus at once. The native title is parked while the
// peek is up so the browser tooltip does not double it.

export function installPeek(root = document) {
  const box = h('div', { class: 'peek', 'aria-hidden': 'true' });
  document.body.appendChild(box);
  let target = null;
  let timer = null;

  const place = (el) => {
    const r = el.getBoundingClientRect();
    const below = r.bottom + 6;
    const maxTop = window.innerHeight - box.offsetHeight - 8;
    const top = below > maxTop ? Math.max(8, r.top - box.offsetHeight - 6) : below;
    const left = Math.min(Math.max(8, r.left), Math.max(8, window.innerWidth - box.offsetWidth - 8));
    box.style.left = `${Math.round(left)}px`;
    box.style.top = `${Math.round(top)}px`;
  };
  const show = (el) => {
    const full = el.getAttribute('title') ?? el.dataset.peek;
    if (!full) return;
    if (el.hasAttribute('title')) {
      el.dataset.peek = full;
      el.removeAttribute('title');
    }
    target = el;
    box.textContent = full;
    // A time is interface text: it must not borrow the evidence look.
    box.classList.toggle('peek--plain', el.classList.contains('reltime'));
    box.classList.add('is-shown');
    place(el);
  };
  const hide = () => {
    clearTimeout(timer);
    if (target?.dataset.peek) {
      target.setAttribute('title', target.dataset.peek);
      delete target.dataset.peek;
    }
    target = null;
    box.classList.remove('is-shown');
  };
  const find = (node) => node?.closest?.('.evidence[title], .evidence[data-peek], .reltime[title], .reltime[data-peek]');

  root.addEventListener('pointerover', (e) => {
    if (e.pointerType === 'touch') return;
    const el = find(e.target);
    if (!el || el === target) return;
    hide();
    timer = setTimeout(() => show(el), 350);
  });
  root.addEventListener('pointerout', (e) => {
    const el = find(e.target);
    if (el && !el.contains(e.relatedTarget)) hide();
  });
  root.addEventListener('focusin', (e) => {
    const el = e.target?.matches?.('.evidence[title]') ? e.target : e.target?.querySelector?.('.evidence[title]');
    if (el) { hide(); show(el); }
  });
  root.addEventListener('focusout', hide);
  window.addEventListener('scroll', hide, { passive: true, capture: true });
  return { hide };
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
      resolve(result);
      // Leave time for the exit transition before removing the node.
      setTimeout(() => dialog.remove(), 220);
    });
    document.body.appendChild(dialog);
    dialog.showModal();
  });
}

// ---- "What is this?" tips ------------------------------------------------------

// Place a native popover under the control that opens it (computed geometry
// through CSSOM; allowed by style-src 'self'). Left-aligned to the control,
// kept inside the viewport.
export function anchorPopover(pop, button, { align = 'left' } = {}) {
  pop.addEventListener('beforetoggle', (e) => {
    if (e.newState !== 'open') return;
    const r = button.getBoundingClientRect();
    const vw = document.documentElement.clientWidth;
    const width = Math.min(pop.offsetWidth || 320, vw - 16);
    const left = align === 'right' ? r.right - width : r.left;
    pop.style.left = `${Math.round(Math.max(8, Math.min(left, vw - width - 8)))}px`;
    pop.style.top = `${Math.round(r.bottom + 6)}px`;
  });
  pop.addEventListener('toggle', (e) => button.setAttribute('aria-expanded', String(e.newState === 'open')));
  button.setAttribute('aria-expanded', 'false');
  return pop;
}

let tipSeq = 0;

// A small "?" beside a non-obvious term. It opens a popover with the short
// definition and a link to the full entry in the Guide. Interface text only.
export function helpTip(entry) {
  if (!entry) return null;
  const id = `tip-${entry.id}-${++tipSeq}`;
  const btn = h('button', {
    class: 'help-tip', type: 'button', popovertarget: id,
    'aria-label': `What is “${entry.term}”?`, title: 'What is this?',
  }, icon('help', { size: 'sm' }));
  const pop = h('span', { class: ['menu', 'tip-pop'], id, popover: 'auto', role: 'note', 'aria-labelledby': `${id}-t` },
    h('span', { class: 'tip-pop__term', id: `${id}-t` }, entry.term),
    h('span', { class: 'tip-pop__text' }, entry.short),
    h('a', { class: 'tip-pop__more', href: `#/guide?t=${entry.id}` }, icon('guide', { size: 'sm' }), 'Read more in the guide'));
  anchorPopover(pop, btn);
  // Following the link closes the tip; the route change does the rest.
  pop.addEventListener('click', (e) => { if (e.target.closest?.('a')) pop.hidePopover?.(); });
  return h('span', { class: 'help' }, btn, pop);
}

// ---- Filter chip ---------------------------------------------------------------

// An active filter: name, value and a remove link. `chip` comes from
// lib/filters.js activeFilterChips(); evidence values keep their treatment.
export function filterChip(chip) {
  const value = chip.evidence
    ? h('span', { class: ['evidence', 'fchip__value'], title: chip.text.length > 40 ? chip.text : null }, truncate(chip.text, 40))
    : h(chip.mono ? 'code' : 'span', { class: 'fchip__value' }, chip.text);
  return h('span', { class: 'fchip' },
    h('span', { class: 'fchip__name' }, chip.name),
    value,
    h('a', { class: 'fchip__remove', href: chip.removeHref, 'aria-label': `Remove filter ${chip.name}`, title: `Remove ${chip.name.toLowerCase()} filter` }, icon('close', { size: 'xs' })));
}

export function labelFor(value) {
  return capitalize(String(value ?? '').replace(/_/g, ' '));
}
