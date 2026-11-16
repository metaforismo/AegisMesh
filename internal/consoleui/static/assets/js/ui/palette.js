// Command palette (Cmd/Ctrl+K) and the keyboard shortcut sheet (?).
//
// Both are opened from the keyboard many times a day, so neither animates
// open or closed. The palette is a native modal <dialog> (focus trap, Esc,
// inert page) with a combobox + listbox; every label is a Text node, and
// source keys keep the evidence treatment because they are attacker-supplied.

import { h, clear } from '../lib/dom.js';
import { href, isEventId, isOpaqueId } from '../lib/route.js';
import { rankItems, highlightRuns } from '../lib/palette.js';
import { moveIndex } from '../lib/keys.js';
import { roleAtLeast, capitalize } from '../lib/taxonomy.js';
import { icon } from './icons.js';
import { NAV, isApple } from './shell.js';

const GROUP_ORDER = ['Go to', 'Actions', 'Investigations', 'Sensors', 'Sources'];
const PER_GROUP_EMPTY = { 'Go to': 20, Actions: 10, Investigations: 5, Sensors: 6, Sources: 5 };

function screenItems(role) {
  const out = [];
  for (const g of NAV) {
    for (const i of g.items) {
      if (i.role && !roleAtLeast(role, i.role)) continue;
      out.push({ group: 'Go to', label: i.label, icon: i.icon, hint: i.keys || g.group, weight: 60, run: (p) => p.navigate(i.href), keywords: [g.group] });
    }
  }
  return out;
}

// Data items are fetched once per open, through the console's cached API.
async function dataItems(api, signal) {
  const out = [];
  let failed = 0;
  const [sensors, sources, invs] = await Promise.allSettled([
    api.sensors({ signal }),
    api.sources('24h', 50, { signal }),
    api.investigations('', { signal }),
  ]);
  if (sensors.status === 'fulfilled') {
    for (const s of sensors.value?.sensors || []) {
      if (typeof s?.id !== 'string') continue;
      out.push({ group: 'Sensors', label: s.id, hint: `${String(s.kind || '').toUpperCase()} sensor · events`, icon: 'sensors', keywords: [String(s.kind || '')], run: (p) => p.navigate(href('events', { sensor: s.id })) });
    }
  } else failed++;
  if (sources.status === 'fulfilled') {
    for (const s of sources.value?.sources || []) {
      if (typeof s?.source !== 'string' || !s.source) continue;
      out.push({ group: 'Sources', label: s.source, evidence: true, hint: `${s.events ?? 0} events, 24h`, icon: 'sources', run: (p) => p.navigate(href('sources', s.source)) });
    }
  } else failed++;
  if (invs.status === 'fulfilled') {
    for (const i of invs.value?.investigations || []) {
      if (!isOpaqueId(i?.id)) continue;
      out.push({ group: 'Investigations', label: String(i.title || '(untitled)'), hint: capitalize(i.status || ''), icon: 'investigations', run: (p) => p.navigate(href('investigations', i.id)) });
    }
  } else failed++;
  return { items: out, failed };
}

let openPalette = null;

// p: { api, role, navigate, actions: [{ label, icon, hint, run, role? }] }
export function togglePalette(p) {
  if (openPalette) {
    openPalette.close();
    return;
  }
  const controller = new AbortController();
  const base = [
    ...screenItems(p.role),
    ...p.actions.filter((a) => !a.role || roleAtLeast(p.role, a.role)).map((a) => ({ group: 'Actions', weight: 40, ...a })),
  ];
  let data = [];
  let note = 'Loading sensors, sources and investigations…';
  let results = [];
  let active = 0;

  const input = h('input', {
    class: 'palette__input', type: 'text', role: 'combobox', 'aria-expanded': 'true', 'aria-controls': 'palette-list',
    'aria-autocomplete': 'list', 'aria-label': 'Search screens, actions, sensors, sources and investigations',
    placeholder: 'Search or jump to…', autocomplete: 'off', spellcheck: 'false', maxlength: 64,
  });
  const list = h('ul', { class: 'palette__list', id: 'palette-list', role: 'listbox', 'aria-label': 'Results' });
  const status = h('span', { class: 'palette__status', role: 'status' });
  const dialog = h('dialog', { class: 'palette', 'aria-label': 'Command palette' },
    h('div', { class: 'palette__bar' }, icon('search', { size: 'lg' }), input, h('kbd', null, 'Esc')),
    list,
    h('div', { class: 'palette__foot' },
      h('span', null, h('kbd', null, '↑'), h('kbd', null, '↓'), 'move'),
      h('span', null, h('kbd', null, '↵'), 'open'),
      h('span', null, h('kbd', null, 'Esc'), 'close'),
      status));

  const labelNode = (r) => {
    const runs = highlightRuns(r.item.label, r.ranges).map((run) => (run.hit ? h('mark', null, run.text) : run.text));
    return h('span', { class: 'palette__label' }, r.item.evidence ? h('span', { class: 'evidence' }, runs) : runs);
  };

  const paint = () => {
    const q = input.value.trim();
    let items = [...base, ...data];
    if (isEventId(q.toLowerCase())) {
      const id = q.toLowerCase();
      items = [{ group: 'Go to', label: `Open event ${id}`, icon: 'events', hint: 'Event', weight: 2000, run: (pp) => pp.navigate(href('events', { event: id })) }, ...items];
    }
    if (q) {
      results = rankItems(items, q, { limit: 40 });
    } else {
      results = [];
      for (const g of GROUP_ORDER) {
        results.push(...items.filter((i) => i.group === g).slice(0, PER_GROUP_EMPTY[g]).map((item) => ({ item, ranges: [] })));
      }
    }
    active = Math.min(active, Math.max(0, results.length - 1));
    clear(list);
    let lastGroup = '';
    results.forEach((r, i) => {
      if (!q && r.item.group !== lastGroup) {
        lastGroup = r.item.group;
        list.appendChild(h('li', { class: 'palette__group', role: 'presentation' }, lastGroup));
      }
      const li = h('li', {
        class: 'palette__item', role: 'option', id: `palette-opt-${i}`, 'aria-selected': String(i === active), 'data-index': String(i),
      }, icon(r.item.icon || 'chevron-right'), labelNode(r), h('span', { class: 'palette__hint' }, q ? `${r.item.group} · ${r.item.hint || ''}`.replace(/ · $/, '') : (r.item.hint || '')));
      list.appendChild(li);
    });
    if (!results.length) list.appendChild(h('li', { class: 'palette__empty', role: 'presentation' }, `Nothing matches “${q}”.`));
    input.setAttribute('aria-activedescendant', results.length ? `palette-opt-${active}` : '');
    status.textContent = note || `${results.length} result${results.length === 1 ? '' : 's'}`;
  };

  const select = (i) => {
    const prev = list.querySelector('[aria-selected="true"]');
    prev?.setAttribute('aria-selected', 'false');
    active = i;
    const el = list.querySelector(`#palette-opt-${i}`);
    el?.setAttribute('aria-selected', 'true');
    el?.scrollIntoView({ block: 'nearest' });
    input.setAttribute('aria-activedescendant', el ? el.id : '');
  };

  const run = (i) => {
    const r = results[i];
    if (!r) return;
    api.close();
    r.item.run(p);
  };

  input.addEventListener('input', () => { active = 0; paint(); });
  input.addEventListener('keydown', (e) => {
    if (e.key === 'ArrowDown' || (e.ctrlKey && e.key === 'n')) { e.preventDefault(); select(moveIndex(active, 1, results.length, { wrap: true })); }
    else if (e.key === 'ArrowUp' || (e.ctrlKey && e.key === 'p')) { e.preventDefault(); select(moveIndex(active, -1, results.length, { wrap: true })); }
    else if (e.key === 'Home' && e.ctrlKey) { e.preventDefault(); select(0); }
    else if (e.key === 'End' && e.ctrlKey) { e.preventDefault(); select(results.length - 1); }
    else if (e.key === 'Enter') { e.preventDefault(); run(active); }
  });
  // Pointer moves (not mouseenter) pick an item, so scrolling under a still
  // pointer does not steal the keyboard selection.
  list.addEventListener('pointermove', (e) => {
    const li = e.target.closest?.('[role="option"]');
    if (li && Number(li.dataset.index) !== active) select(Number(li.dataset.index));
  });
  list.addEventListener('click', (e) => {
    const li = e.target.closest?.('[role="option"]');
    if (li) run(Number(li.dataset.index));
  });
  dialog.addEventListener('click', (e) => { if (e.target === dialog) api.close(); });
  dialog.addEventListener('close', () => {
    controller.abort();
    dialog.remove();
    openPalette = null;
  });

  const api = { close: () => { if (dialog.open) dialog.close(); } };
  openPalette = api;
  document.body.appendChild(dialog);
  dialog.showModal();
  paint();
  input.focus();

  dataItems(p.api, controller.signal).then(({ items, failed }) => {
    if (controller.signal.aborted) return;
    data = items;
    note = failed ? 'Some lists could not be loaded; screens and actions still work.' : '';
    paint();
  }, () => {});
}

// ---- Shortcut sheet --------------------------------------------------------

export const SHORTCUTS = [
  { title: 'Anywhere', keys: [
    [['mod', 'K'], 'Search, jump to a screen or run an action'],
    [['?'], 'Show these shortcuts'],
    [['g', 'o'], 'Go to Overview'],
    [['g', 'e'], 'Go to Events'],
    [['g', 's'], 'Go to Sources'],
    [['g', 'i'], 'Go to Investigations'],
    [['g', 'r'], 'Go to Recommendations'],
    [['g', 'n'], 'Go to Sensors'],
  ] },
  { title: 'Events list', keys: [
    [['j'], 'Next row'],
    [['k'], 'Previous row'],
    [['Enter'], 'Open the row in the side panel'],
    [['/'], 'Search events'],
  ] },
  { title: 'Event side panel', keys: [
    [['j'], 'Next event'],
    [['k'], 'Previous event'],
    [['o'], 'Open as a full page'],
    [['Esc'], 'Close and return to the list'],
  ] },
  { title: 'Overview chart', keys: [
    [['←'], 'Previous time bucket'],
    [['→'], 'Next time bucket'],
    [['Enter'], 'Open the events in that bucket'],
  ] },
];

let sheetOpen = null;

export function toggleShortcuts() {
  if (sheetOpen) {
    sheetOpen.close();
    return;
  }
  const mod = isApple() ? '⌘' : 'Ctrl';
  const close = h('button', { class: ['btn', 'btn--ghost', 'btn--icon', 'btn--sm'], type: 'button', 'aria-label': 'Close' }, icon('close'));
  const dialog = h('dialog', { class: ['dialog', 'dialog--wide'], 'aria-labelledby': 'keys-title' },
    h('div', { class: 'dialog__head' }, h('h2', { id: 'keys-title' }, 'Keyboard shortcuts'), close),
    h('div', { class: ['dialog__body', 'keys'] }, SHORTCUTS.map((s) => h('section', null,
      h('h3', null, s.title),
      h('dl', null, s.keys.map(([combo, what]) => [
        h('dt', null, what),
        h('dd', null, combo.map((k, i) => [i > 0 && combo[0] === 'g' ? h('span', { class: 'keys__then' }, 'then') : null, h('kbd', null, k === 'mod' ? mod : k)])),
      ]))))));
  close.addEventListener('click', () => dialog.close());
  dialog.addEventListener('click', (e) => { if (e.target === dialog) dialog.close(); });
  dialog.addEventListener('close', () => {
    sheetOpen = null;
    setTimeout(() => dialog.remove(), 220);
  });
  sheetOpen = dialog;
  document.body.appendChild(dialog);
  dialog.showModal();
}

export function overlayOpen() {
  return Boolean(openPalette || sheetOpen || document.querySelector('dialog[open]'));
}
