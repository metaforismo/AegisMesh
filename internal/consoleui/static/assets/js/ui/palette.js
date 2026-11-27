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
import { capitalize } from '../lib/taxonomy.js';
import { toCan, ROUTE_PERMS } from '../lib/perms.js';
import { icon } from './icons.js';
import { nodeFilterTargets } from '../lib/origin.js';
import { NAV, isApple, hasFeature } from './shell.js';
import { GLOSSARY } from '../lib/glossary.js';
import { loadRecents, storeRecents, pushRecent } from '../lib/views.js';
import { formatRelative } from '../lib/format.js';
import { assessmentOf, frameworkLabel } from '../lib/story.js';

const GROUP_ORDER = ['Recent', 'Go to', 'Actions', 'Sessions', 'Campaigns', 'Investigations', 'Rules', 'Techniques', 'Nodes', 'Sensors', 'Sources', 'Guide'];
const PER_GROUP_EMPTY = { Recent: 6, 'Go to': 20, Actions: 10, Sessions: 4, Campaigns: 3, Investigations: 5, Rules: 0, Techniques: 0, Nodes: 5, Sensors: 6, Sources: 5, Guide: 0 };
const EVENT_SEARCH_MIN = 2;
const EVENT_RESULTS = 6;

const storage = () => {
  try {
    return globalThis.localStorage || null;
  } catch {
    return null;
  }
};
const recentKey = (r) => (r ? `${r.kind}:${r.id}` : '');

function screenItems(can) {
  const out = [];
  for (const g of NAV) {
    for (const i of g.items) {
      if (!can(ROUTE_PERMS[i.route]) || !hasFeature(i.feature)) continue;
      out.push({ group: 'Go to', label: i.label, icon: i.icon, hint: i.keys || g.group, weight: 60, run: (p) => p.navigate(i.href), keywords: [g.group], recent: { kind: 'screen', id: i.route } });
    }
  }
  return out;
}

// Data items are fetched once per open, through the console's cached API.
async function dataItems(api, signal) {
  const out = [];
  let failed = 0;
  // Node filter targets exist only on a hub that accepts forwarded
  // evidence; a node without a hub is not a failure.
  const nodesOf = async () => {
    const fleet = await api.fleet({ signal }).catch(() => null);
    if (fleet?.hub?.accept_evidence !== true) return [];
    const res = await api.fleetNodes('', { signal }).catch(() => null);
    return nodeFilterTargets(fleet, res?.nodes);
  };
  const [sensors, sources, invs, nodes, rules, sessions, coverage, campaigns] = await Promise.allSettled([
    api.sensors({ signal }),
    api.sources('24h', 50, { signal }),
    api.investigations('', { signal }),
    api.fleet ? nodesOf() : Promise.resolve([]),
    api.rules ? api.rules({ signal }) : Promise.resolve({ rules: [] }),
    api.sessions ? api.sessions('24h', '', '', 50, { signal }) : Promise.resolve({ sessions: [] }),
    api.coverage ? api.coverage('7d', { signal }) : Promise.resolve({ frameworks: [] }),
    // Older servers answer 404: no campaign results, and not a failure.
    api.campaigns ? api.campaigns({ signal }).catch(() => ({ items: [] })) : Promise.resolve({ items: [] }),
  ]);
  if (sensors.status === 'fulfilled') {
    for (const s of sensors.value?.sensors || []) {
      if (typeof s?.id !== 'string') continue;
      out.push({ group: 'Sensors', label: s.id, hint: `${String(s.kind || '').toUpperCase()} sensor · events`, icon: 'sensors', keywords: [String(s.kind || '')], run: (p) => p.navigate(href('events', { sensor: s.id })), recent: { kind: 'sensor', id: s.id } });
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
      out.push({ group: 'Investigations', label: String(i.title || '(untitled)'), hint: capitalize(i.status || ''), icon: 'investigations', run: (p) => p.navigate(href('investigations', i.id)), recent: { kind: 'investigation', id: i.id } });
    }
  } else failed++;
  if (nodes.status === 'fulfilled') {
    for (const n of nodes.value) {
      out.push({ group: 'Nodes', label: n.label, hint: n.hint, icon: 'fleet', keywords: n.keywords, run: (p) => p.navigate(href('events', { node: n.node })) });
    }
  }
  if (rules.status === 'fulfilled') {
    for (const r of rules.value?.rules || []) {
      if (typeof r?.id !== 'string' || !/^[A-Za-z0-9_.:-]{1,64}$/.test(r.id)) continue;
      // Rule titles come from the runtime's rule registry (interface text).
      out.push({ group: 'Rules', label: r.id, hint: `${r.family === 'correlation' ? 'Correlation' : 'Detection'} rule · events citing it`, icon: 'rules', keywords: [String(r.title || '')], run: (p) => p.navigate(href('events', { rule: r.id })), recent: { kind: 'rule', id: r.id } });
    }
  } else failed++;
  if (sessions.status === 'fulfilled') {
    for (const x of sessions.value?.sessions || []) {
      if (!/^[0-9a-f]{32}$/.test(x?.id) || typeof x.source !== 'string') continue;
      // The source key is evidence: the label keeps the evidence treatment.
      out.push({ group: 'Sessions', label: x.source, evidence: true, icon: 'story', hint: `${x.event_count ?? 0} events · ${assessmentOf(x.automation).label}`, keywords: ['session', 'story'], run: (p) => p.navigate(href('sessions', x.id)) });
    }
  }
  if (campaigns.status === 'fulfilled') {
    for (const c of campaigns.value?.items || []) {
      if (!/^cmp_[0-9a-z]{4,64}$/.test(c?.id)) continue;
      const n = Number(c.source_count) || 0;
      out.push({ group: 'Campaigns', label: String(c.label || 'Campaign'), icon: 'campaign', hint: `${n} sources · ${Number(c.session_count) || 0} sessions`, keywords: ['campaign', 'playbook', ...(Array.isArray(c.sources) ? c.sources.slice(0, 5).map(String) : [])], run: (p) => p.navigate(href('campaigns', c.id)) });
    }
  }
  if (coverage.status === 'fulfilled') {
    for (const f of coverage.value?.frameworks || []) {
      for (const t of f?.techniques || []) {
        if (typeof t?.id !== 'string' || !/^[A-Za-z0-9.]{1,32}$/.test(t.id)) continue;
        const n = Number(t.observed_event_count) || 0;
        out.push({ group: 'Techniques', label: `${t.id} ${String(t.name || '')}`, icon: 'matrix', hint: `${frameworkLabel(f.framework)} · ${n ? `${n} events, 7d` : 'not observed, 7d'}`, keywords: [String(f.framework)], run: (p) => p.navigate(href('techniques', { window: '7d', f: f.framework, t: t.id })) });
      }
    }
  }
  return { items: out, failed };
}

function guideItems() {
  return GLOSSARY.map((e) => ({ group: 'Guide', label: e.term, hint: 'Guide', icon: 'guide', keywords: [e.id], weight: -20, run: (p) => p.navigate(`#/guide?t=${e.id}`), recent: { kind: 'guide', id: e.id } }));
}

let openPalette = null;

// p: { api, can, navigate, actions: [{ label, icon, hint, run, perm? }] }
export function togglePalette(p) {
  if (openPalette) {
    openPalette.close();
    return;
  }
  const controller = new AbortController();
  const base = [
    ...screenItems(toCan(p.can ?? p.role)),
    ...p.actions.filter((a) => toCan(p.can ?? p.role)(a.perm)).map((a) => ({ group: 'Actions', weight: 40, recent: a.recentId ? { kind: 'action', id: a.recentId } : null, ...a })),
    ...guideItems(),
  ];
  let recents = loadRecents(storage(), p.tenant);
  let eventHits = { q: '', items: [], state: 'idle' };
  let eventTimer = null;
  let eventCtl = null;
  let data = [];
  let note = 'Loading sensors, sources, rules and investigations…';
  let results = [];
  let active = 0;

  const input = h('input', {
    class: 'palette__input', type: 'text', role: 'combobox', 'aria-expanded': 'true', 'aria-controls': 'palette-list',
    'aria-autocomplete': 'list', 'aria-label': 'Search screens, actions, events, sources, rules, sensors, investigations and the guide',
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

  // Events are searched on the server (the same `q` as the Events list:
  // summary, source and rule ids), debounced, at most a handful at a time.
  const searchEvents = (q) => {
    clearTimeout(eventTimer);
    eventCtl?.abort();
    if (q.length < EVENT_SEARCH_MIN || isEventId(q.toLowerCase())) {
      eventHits = { q: '', items: [], state: 'idle' };
      return;
    }
    if (eventHits.q === q) return;
    eventHits = { q, items: [], state: 'loading' };
    eventTimer = setTimeout(async () => {
      eventCtl = new AbortController();
      const signal = eventCtl.signal;
      controller.signal.addEventListener('abort', () => eventCtl?.abort(), { once: true });
      try {
        const res = await p.api.events({ q }, '', EVENT_RESULTS, { signal });
        if (signal.aborted || eventHits.q !== q) return;
        const list = (Array.isArray(res?.events) ? res.events : []).filter((ev) => isEventId(ev?.id));
        eventHits = {
          q, state: 'done', total: Number(res?.total_matched) || list.length,
          items: list.map((ev) => ({
            group: 'Events', label: String(ev.summary || '(no summary)'), evidence: true, icon: 'events',
            hint: `${ev.sensor?.id || 'sensor'} · ${formatRelative(ev.time)}`,
            run: (pp) => pp.navigate(href('events', { q, event: ev.id, event_node: ev.node?.id || '' })),
          })),
        };
      } catch {
        if (!signal.aborted && eventHits.q === q) eventHits = { q, items: [], state: 'failed' };
      }
      if (!controller.signal.aborted) paint();
    }, 220);
  };

  const recentItems = (all) => {
    const byKey = new Map(all.filter((i) => i.recent).map((i) => [recentKey(i.recent), i]));
    return recents.map((r) => byKey.get(recentKey(r))).filter(Boolean).map((i) => ({ ...i, group: 'Recent', hint: `${i.group} · ${i.hint || ''}`.replace(/ · $/, '') }));
  };

  const paint = () => {
    const q = input.value.trim();
    let items = [...base, ...data];
    if (isEventId(q.toLowerCase())) {
      const id = q.toLowerCase();
      items = [{ group: 'Go to', label: `Open event ${id}`, icon: 'events', hint: 'Event', weight: 2000, run: (pp) => pp.navigate(href('events', { event: id })) }, ...items];
    }
    if (q) {
      // Best match first; then each group keeps the position of its best hit.
      const ranked = rankItems(items, q, { limit: 40 });
      const order = [];
      for (const r of ranked) if (!order.includes(r.item.group)) order.push(r.item.group);
      results = order.flatMap((g) => ranked.filter((r) => r.item.group === g));
      if (q.length >= EVENT_SEARCH_MIN && !isEventId(q.toLowerCase())) {
        const all = { group: 'Events', label: `Search all events for “${q}”`, icon: 'search', hint: eventHits.state === 'done' ? `${eventHits.total} matching` : 'Events list', run: (pp) => pp.navigate(href('events', { q })) };
        results.push({ item: all, ranges: [] }, ...eventHits.items.map((item) => ({ item, ranges: [] })));
      }
    } else {
      results = [];
      const pool = [...recentItems(items), ...items];
      for (const g of GROUP_ORDER) {
        results.push(...pool.filter((i) => i.group === g).slice(0, PER_GROUP_EMPTY[g] ?? 5).map((item) => ({ item, ranges: [] })));
      }
    }
    active = Math.min(active, Math.max(0, results.length - 1));
    clear(list);
    let lastGroup = '';
    results.forEach((r, i) => {
      if (r.item.group !== lastGroup) {
        lastGroup = r.item.group;
        list.appendChild(h('li', { class: 'palette__group', role: 'presentation' }, lastGroup === 'Events' && eventHits.state === 'loading' ? 'Events · searching…' : lastGroup));
      }
      const li = h('li', {
        class: 'palette__item', role: 'option', id: `palette-opt-${i}`, 'aria-selected': String(i === active), 'data-index': String(i),
      }, icon(r.item.icon || 'chevron-right'), labelNode(r), h('span', { class: 'palette__hint' }, r.item.hint || ''));
      list.appendChild(li);
    });
    if (!results.length) list.appendChild(h('li', { class: 'palette__empty', role: 'presentation' }, `Nothing matches “${q}”.`));
    input.setAttribute('aria-activedescendant', results.length ? `palette-opt-${active}` : '');
    const failedEvents = eventHits.state === 'failed' ? ' Event search failed.' : '';
    status.textContent = `${note || `${results.length} result${results.length === 1 ? '' : 's'}`}${failedEvents}`;
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
    if (r.item.recent) {
      recents = pushRecent(recents, r.item.recent);
      storeRecents(storage(), p.tenant, recents);
    }
    r.item.run(p);
  };

  input.addEventListener('input', () => { active = 0; searchEvents(input.value.trim()); paint(); });
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
    clearTimeout(eventTimer);
    eventCtl?.abort();
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

// The "go to" rows come from NAV, so the sheet lists exactly the
// g-sequences the router binds (main.js builds them from the same list).
// `who` is a permission predicate, a set, or a built-in role name.
export function shortcutGroups(who) {
  const can = toCan(who);
  const go = NAV.flatMap((g) => g.items)
    .filter((i) => i.keys && can(ROUTE_PERMS[i.route]) && hasFeature(i.feature))
    .map((i) => [i.keys.split(' '), `Go to ${i.label}`]);
  return [
    { title: 'Anywhere', keys: [
      [['mod', 'K'], 'Search events, sources, rules, screens and the guide; run an action'],
      [['?'], 'Show these shortcuts'],
      [['/'], 'Focus the search field on Events'],
      [['Esc'], 'Close a menu, dialog, side panel or this sheet'],
    ] },
    { title: 'Go to a screen', keys: go },
    { title: 'Events list', keys: [
      [['j'], 'Next row'],
      [['k'], 'Previous row'],
      [['Enter'], 'Open the row in the side panel'],
    ] },
    { title: 'Session story', keys: [
      [['j'], 'Next event'],
      [['k'], 'Previous event'],
      [['Enter'], 'Open the event in the side panel'],
      [['←'], 'Tempo ribbon: previous event'],
      [['→'], 'Tempo ribbon: next event'],
    ] },
    { title: 'Event side panel', keys: [
      [['j'], 'Next event'],
      [['k'], 'Previous event'],
      [['o'], 'Open as a full page'],
      [['Esc'], 'Close and return to the list'],
    ] },
    { title: 'Charts and tabs', keys: [
      [['←'], 'Previous time bucket or tab'],
      [['→'], 'Next time bucket or tab'],
      [['Enter'], 'Open the events in that bucket'],
    ] },
  ];
}

export const SHORTCUTS = shortcutGroups('admin');

let sheetOpen = null;

export function toggleShortcuts(who = 'admin') {
  if (sheetOpen) {
    sheetOpen.close();
    return;
  }
  const mod = isApple() ? '⌘' : 'Ctrl';
  const close = h('button', { class: ['btn', 'btn--ghost', 'btn--icon', 'btn--sm'], type: 'button', 'aria-label': 'Close' }, icon('close'));
  const dialog = h('dialog', { class: ['dialog', 'dialog--wide'], 'aria-labelledby': 'keys-title' },
    h('div', { class: 'dialog__head' }, h('h2', { id: 'keys-title' }, 'Keyboard shortcuts'), close),
    h('div', { class: ['dialog__body', 'keys'] }, shortcutGroups(who).map((s) => h('section', null,
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
