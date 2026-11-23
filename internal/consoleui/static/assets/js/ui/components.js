// Reusable view builders. Every builder returns DOM nodes made through dom.js;
// API strings only ever become Text nodes or validated attribute values.

import { h, svg, mount } from '../lib/dom.js';
import { classificationMeta, isSeverity, severityLabel, capitalize } from '../lib/taxonomy.js';
import { formatDateTime, formatRelative, truncate } from '../lib/format.js';
import { describeError } from '../lib/api.js';
import { sparkPath } from '../lib/chart.js';
import { sparkMarks } from '../lib/viz.js';
import { sortRows, nextSort, ariaSort } from '../lib/tablesort.js';
import { icon } from './icons.js';

// ---- Severity, classification, badges ------------------------------------

// The one severity mark: five segments filled to the rank, plus the word.
// Every table, chip, legend, card and chart key uses it, so severity reads
// the same without color (fill count) and without sight (the word). A value
// that is not a severity draws the empty meter with "No finding", or with
// `none` (e.g. "Signal" for correlation rules) and its `noneTitle`.
export const SIGNAL_NO_SEVERITY = Object.freeze({ none: 'Signal', noneTitle: 'Correlation rules write signals, which have no severity' });

export function sevChip(severity, { none, noneTitle } = {}) {
  const known = isSeverity(severity);
  return h('span', { class: ['sev', known ? `sev--${severity}` : 'sev--none'], title: !known && noneTitle ? noneTitle : null },
    h('span', { class: 'sev__meter', 'aria-hidden': 'true' }, h('i'), h('i'), h('i'), h('i'), h('i')),
    known ? severityLabel(severity) : (none || severityLabel('')));
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

// `crumbs` ([[label, href], …], the current page last and unlinked) replaces
// the eyebrow on detail pages. `hint` is one line on what the operator can
// do on this screen. Both are interface text; a crumb label may be a node
// (an evidence span for a source key).
export function pageHead({ title, subtitle, actions, eyebrow, crumbs, hint }) {
  return h('header', { class: 'page-head' },
    h('div', { class: 'page-head__text' },
      crumbs ? breadcrumbs(crumbs) : eyebrow ? h('p', { class: 'page-head__eyebrow' }, eyebrow) : null,
      h('h1', { class: 'page-head__title', id: 'page-title', tabindex: '-1' }, title),
      subtitle ? h('p', { class: 'page-head__sub' }, subtitle) : null,
      hint ? h('p', { class: 'page-head__hint' }, icon('chevron-right', { size: 'xs' }), h('span', null, hint)) : null),
    actions ? h('div', { class: 'btn-row page-head__actions' }, actions) : null);
}

export function breadcrumbs(items) {
  const list = items.filter(Boolean);
  return h('nav', { class: 'crumbs', 'aria-label': 'Breadcrumb' },
    h('ol', { class: 'crumbs__list' }, list.map(([label, target], i) => {
      const last = i === list.length - 1;
      return h('li', { class: 'crumbs__item' },
        last || !target ? h('span', { class: 'crumbs__here', 'aria-current': last ? 'page' : null }, label) : h('a', { href: target }, label));
    })));
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

// A divided list of counts: label left, figure right, its change under it on
// the same right edge. The first row may lead (a larger figure). `delta`
// comes from formatDelta; changes stay neutral ink and carry their sign in
// the text, and `baseline` (visually hidden) names what they are against.
export function tally(items, { baseline = '' } = {}) {
  return h('dl', { class: 'tally' }, items.filter(Boolean).map((it) =>
    h('div', { class: ['tally__row', it.lead ? 'tally__row--lead' : ''] },
      h('dt', { class: 'tally__label' }, it.icon || null, h('span', null, it.label)),
      h('dd', { class: 'tally__value' },
        h('span', { class: 'tally__num' }, it.value),
        it.delta
          ? h('span', { class: 'tally__delta' }, it.delta.text, baseline && it.delta.detail === 'vs previous window'
            ? h('span', { class: 'visually-hidden' }, ` ${baseline}`)
            : it.delta.detail === 'vs previous window' ? null : ` · ${it.delta.detail}`)
          : it.note ? h('span', { class: 'tally__delta' }, it.note) : null))));
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
    sparkMarks(values, { width, height, pad: 2.5 }).filter((m) => m.kind !== 'end').map((m) => svg('circle', { class: ['spark__mark', `spark__mark--${m.kind}`], cx: m.x, cy: m.y, r: 1.6 })),
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

// A table wider than its column scrolls inside its own wrapper instead of
// widening the page. From 1440px wrappers do not clip (so headers can stick
// under the top bar); a table that still does not fit switches to the
// scrolling wrapper, whose header sticks within it.
export function fitTable(wrap) {
  if (typeof ResizeObserver !== 'function') return wrap;
  const check = () => {
    const t = wrap.firstElementChild;
    if (!t || !wrap.isConnected) return;
    if (wrap.classList.contains('table-wrap--fit')) {
      wrap.classList.remove('table-wrap--scroll');
      if (t.offsetWidth > wrap.clientWidth + 1) wrap.classList.add('table-wrap--scroll');
    }
  };
  wrap.classList.add('table-wrap--fit');
  new ResizeObserver(check).observe(wrap);
  return wrap;
}

// columns: [{ label, num?, className?, cell(row) → Node|string,
//             sort?(row) → number|string|null, sortFirst?: 'asc'|'desc' }]
// A column with `sort` gets a header button (aria-sort, keyboard operable)
// that reorders the rows already in the browser; see lib/tablesort.js for
// which tables may sort. `sort` ({ key: label, dir }) is the initial order;
// without it rows keep the server's order until a header is chosen.
export function table({ columns, rows, caption, stack = true, rowClass, sort = null, scroll = false }) {
  let state = sort;
  const tbody = h('tbody');
  const status = h('span', { class: 'visually-hidden', role: 'status' });
  const paint = () => {
    const col = state && columns.find((c) => c.label === state.key && typeof c.sort === 'function');
    const ordered = col ? sortRows(rows, col.sort, state.dir) : rows;
    mount(tbody, ordered.map((row) => h('tr', { class: rowClass ? rowClass(row) : null },
      columns.map((c) => h('td', { class: [c.num ? 'num' : '', c.className || ''], 'data-label': c.label }, c.cell(row))))));
  };
  const syncs = [];
  const heads = columns.map((c) => {
    const thClass = [c.num ? 'num' : '', c.className || ''];
    if (typeof c.sort !== 'function' || rows.length < 2) return h('th', { scope: 'col', class: thClass }, c.label);
    const name = c.label.toLowerCase();
    const btn = h('button', { class: 'th-sort', type: 'button' }, h('span', null, c.label), h('span', { class: 'th-sort__mark', 'aria-hidden': 'true' }));
    const th = h('th', { scope: 'col', class: thClass }, btn);
    const sync = () => {
      const dir = ariaSort(state, c.label);
      th.setAttribute('aria-sort', dir);
      btn.setAttribute('data-dir', dir);
      btn.setAttribute('title', dir === 'none' ? `Sort by ${name}` : `Sorted by ${name}, ${dir}`);
    };
    btn.addEventListener('click', () => {
      state = nextSort(state, c.label, c.sortFirst || (c.num ? 'desc' : 'asc'));
      paint();
      for (const f of syncs) f();
      status.textContent = `Sorted by ${name}, ${state.dir === 'asc' ? 'ascending' : 'descending'}.`;
    });
    syncs.push(sync);
    sync();
    return th;
  });
  paint();
  const wrap = h('div', { class: ['table-wrap', scroll ? 'table-wrap--scroll' : ''] },
    h('table', { class: ['table', stack ? 'table--stack' : ''] },
      caption ? h('caption', { class: 'visually-hidden' }, caption) : null,
      h('thead', null, h('tr', null, heads)),
      tbody),
    status);
  return scroll ? wrap : fitTable(wrap);
}

// ---- States ----------------------------------------------------------------

export function loading(label = 'Loading') {
  return h('div', { class: 'state', role: 'status', 'aria-live': 'polite' },
    h('span', { class: 'btn-row' }, h('span', { class: 'spinner', 'aria-hidden': 'true' }), `${label}…`));
}

// A small lattice with one decoy node and a probe line that stops short of
// it: the empty states' illustration, in the product's own motif.
export function emptyArt() {
  const grid = [];
  for (let i = 0; i <= 5; i++) {
    grid.push(svg('line', { class: 'empty-art__grid', x1: i * 24, x2: i * 24, y1: 0, y2: 72 }));
    if (i <= 3) grid.push(svg('line', { class: 'empty-art__grid', x1: 0, x2: 120, y1: i * 24, y2: i * 24 }));
  }
  return svg('svg', { class: 'empty-art', viewBox: '0 0 120 72', 'aria-hidden': 'true', focusable: 'false' },
    grid,
    svg('path', { class: 'empty-art__probe', d: 'M12 60 C 36 60, 48 36, 66 30' }),
    svg('circle', { class: 'empty-art__node', cx: 12, cy: 60, r: 3.5 }),
    svg('circle', { class: 'empty-art__node', cx: 96, cy: 12, r: 3 }),
    svg('circle', { class: 'empty-art__node', cx: 108, cy: 60, r: 3 }),
    svg('rect', { class: 'empty-art__decoy', x: 66, y: 18, width: 24, height: 24, rx: 4 }));
}

// Variants for the catalog screens, in the same lattice: a decoy with its
// listening ring (no probe yet), a returning key path that ends at a marker,
// and a briefing sheet resting on the grid.
export function emptyArtVariant(kind) {
  if (kind !== 'decoys' && kind !== 'tokens' && kind !== 'digest') return emptyArt();
  const grid = [];
  for (let i = 0; i <= 5; i++) {
    grid.push(svg('line', { class: 'empty-art__grid', x1: i * 24, x2: i * 24, y1: 0, y2: 72 }));
    if (i <= 3) grid.push(svg('line', { class: 'empty-art__grid', x1: 0, x2: 120, y1: i * 24, y2: i * 24 }));
  }
  const parts = {
    decoys: [
      svg('circle', { class: 'empty-art__ring', cx: 60, cy: 36, r: 22 }),
      svg('path', { class: 'empty-art__decoy', d: 'M60 22 74 36 60 50 46 36z' }),
      svg('circle', { class: 'empty-art__node', cx: 60, cy: 36, r: 2.5 }),
      svg('circle', { class: 'empty-art__node', cx: 12, cy: 12, r: 3 }),
      svg('circle', { class: 'empty-art__node', cx: 108, cy: 60, r: 3 }),
    ],
    tokens: [
      svg('path', { class: 'empty-art__probe', d: 'M14 58 C 40 58, 44 20, 72 20 S 100 40, 100 52' }),
      svg('circle', { class: 'empty-art__node', cx: 14, cy: 58, r: 3.5 }),
      svg('circle', { class: 'empty-art__ring', cx: 100, cy: 52, r: 7 }),
      svg('path', { class: 'empty-art__decoy', d: 'M94 52h12M100 46v12' }),
      svg('rect', { class: 'empty-art__decoy', x: 62, y: 12, width: 18, height: 14, rx: 3 }),
    ],
    digest: [
      svg('rect', { class: 'empty-art__decoy', x: 40, y: 8, width: 40, height: 56, rx: 4 }),
      svg('path', { class: 'empty-art__probe', d: 'M48 20h24M48 30h24M48 40h24M48 50h14' }),
      svg('circle', { class: 'empty-art__node', cx: 12, cy: 60, r: 3 }),
      svg('circle', { class: 'empty-art__node', cx: 108, cy: 12, r: 3 }),
    ],
  }[kind];
  return svg('svg', { class: ['empty-art', `empty-art--${kind}`], viewBox: '0 0 120 72', 'aria-hidden': 'true', focusable: 'false' }, grid, parts);
}

export function empty(title, detail, action, { icon: name = 'inbox', art = false } = {}) {
  return h('div', { class: 'state' },
    art ? (typeof art === 'string' ? emptyArtVariant(art) : emptyArt()) : h('span', { class: 'state__icon', 'aria-hidden': 'true' }, icon(name)),
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

// A screen that could not load: what happened, one sentence on why, and a
// next step (`f` from lib/api.js screenFailure). Retry only where it can help.
export function failureState(f, onRetry) {
  return h('div', { class: ['state', f.retry ? 'state--error' : ''], role: f.retry ? 'alert' : 'status' },
    h('span', { class: 'state__icon', 'aria-hidden': 'true' }, icon(f.retry ? 'warn' : 'info')),
    h('p', { class: 'state__title' }, f.title),
    h('p', null, f.detail),
    h('div', { class: ['btn-row', 'state__actions'] },
      f.retry && onRetry ? h('button', { class: 'btn', type: 'button', on: { click: onRetry } }, icon('refresh'), 'Try again') : null,
      (f.actions || []).map(([target, label]) => h('a', { class: 'btn', href: target }, label))));
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

// ---- Catalog marks (glyph plus word, never color alone) ----------------------

// A decoy surface family: meta from lib/catalogs.js familyMeta().
export function familyChip(meta) {
  return h('span', { class: ['fam', `fam--${meta.shape}`] }, h('span', { class: 'fam__glyph', 'aria-hidden': 'true' }), meta.label);
}

// A honeytoken kind: meta from tokenKindMeta().
export function tokenKindChip(meta) {
  return h('span', { class: ['tkind', `tkind--${meta.shape}`] }, icon(meta.shape === 'flag' ? 'flag' : 'key', { size: 'sm' }), meta.label);
}

// Observe only (hollow ring) or can select an action (filled square): meta
// from ruleActionMeta(). The hint is the title and visually hidden text.
export function actionChip(meta) {
  if (!meta) return h('span', { class: 'muted', title: 'This server does not report it' }, 'Not reported');
  return h('span', { class: ['ract', `ract--${meta.key}`], title: meta.hint },
    h('span', { class: 'ract__mark', 'aria-hidden': 'true' }), meta.label,
    h('span', { class: 'visually-hidden' }, `. ${meta.hint}`));
}

export function labelFor(value) {
  return capitalize(String(value ?? '').replace(/_/g, ' '));
}
