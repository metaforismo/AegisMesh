// Loading placeholders shaped like the screen that is coming, so the layout
// does not jump when data arrives. Shown only when a screen takes longer
// than a short grace period (see main.js); fast loads never flash them.

import { h } from '../lib/dom.js';

const sk = (...mods) => h('span', { class: ['skeleton', ...mods.map((m) => `skeleton--${m}`)], 'aria-hidden': 'true' });
const widths = ['w-90', 'w-70', 'w-80', 'w-60', 'w-75', 'w-85', 'w-65', 'w-95'];

function head() {
  return h('div', { class: 'page-head' },
    h('div', { class: 'page-head__text' }, sk('title'), sk('text', 'w-60', 'sub')));
}

function panelShell(body, { title = true } = {}) {
  return h('div', { class: ['panel', 'skel-panel'] },
    title ? h('div', { class: 'panel__head' }, h('div', { class: 'stack-tight' }, sk('text', 'w-30'), sk('text', 'w-50', 'meta'))) : null,
    h('div', { class: 'panel__body' }, body));
}

function rows(n, cols = 5) {
  return h('div', { class: 'skel-rows' }, Array.from({ length: n }, (_, i) => h('div', { class: 'skel-row' },
    Array.from({ length: cols }, (__, c) => sk('text', c === cols - 1 ? widths[i % widths.length] : 'w-cell')))));
}

const BUILDERS = {
  // The brief beside its counts, then the chart (Overview).
  overview: () => [
    head(),
    h('div', { class: 'lead-row' }, panelShell(lines(4)), panelShell(rows(6, 2))),
    panelShell(sk('block')),
    h('div', { class: ['grid', 'grid--2'] }, panelShell(rows(5, 2)), panelShell(rows(5, 2))),
  ],
  table: () => [head(), panelShell(rows(2, 4)), panelShell(rows(10, 6))],
  cards: () => [head(), h('div', { class: ['grid', 'grid--cards'] }, Array.from({ length: 4 }, () => panelShell(rows(4, 2))))],
  detail: () => [head(), h('div', { class: ['grid', 'grid--2'] }, panelShell(rows(6, 2)), panelShell(rows(3, 2))), panelShell(rows(5, 4))],
  // A written briefing: one column of short paragraphs (Digest).
  digest: () => [head(), panelShell(lines(4)), panelShell(rows(3, 3)), panelShell(lines(3))],
  // Counts, then a checklist (Posture).
  posture: () => [head(), h('div', { class: ['grid', 'grid--stats'] }, Array.from({ length: 3 }, () => h('div', { class: 'stat' },
    h('span', { class: 'stat__label' }, sk('text', 'w-50')), h('span', { class: 'stat__value' }, sk('value'))))), panelShell(rows(6, 2))],
  // A hero, then the timeline beside a side column (session story, campaign).
  story: () => [head(), panelShell(h('div', { class: 'stack' }, sk('text', 'w-70'), sk('block'))), h('div', { class: ['grid', 'grid--2'] }, panelShell(rows(8, 3)), panelShell(rows(5, 2)))],
  // Two key/value panels (Node, Fleet node).
  kv: () => [head(), h('div', { class: ['grid', 'grid--2'] }, panelShell(rows(6, 2)), panelShell(rows(6, 2)))],
  // Glossary entries (Guide).
  guide: () => [head(), panelShell(lines(3)), panelShell(lines(3)), panelShell(lines(3))],
};

function lines(n) {
  return h('div', { class: 'stack' }, Array.from({ length: n }, (_, i) => sk('text', widths[(i + 2) % widths.length])));
}

export const SKELETON_KINDS = Object.freeze(Object.keys(BUILDERS));

export function skeleton(kind, title) {
  const build = BUILDERS[kind] || BUILDERS.detail;
  return h('div', { class: 'skel', role: 'status', 'aria-busy': 'true', 'aria-label': `Loading ${title || 'page'}` }, build());
}
