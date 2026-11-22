// Filter chips, saved views, palette recents, cadence and the glossary.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { activeFilterChips, addFilterHref, describeFilter, isFilterActive } from '../static/assets/js/lib/filters.js';
import { parseViews, addView, removeView, viewFilters, loadViews, storeViews, viewsKey, cleanName, MAX_VIEWS, parseRecents, pushRecent, recentsKey, MAX_RECENTS } from '../static/assets/js/lib/views.js';
import { cadence, formatGap, describeCadence, GAP_BINS } from '../static/assets/js/lib/cadence.js';
import { GLOSSARY, glossaryEntry, glossaryGroups } from '../static/assets/js/lib/glossary.js';
import { parseHash } from '../static/assets/js/lib/route.js';

// ---- Filter chips --------------------------------------------------------------

test('chips: one per active filter, in contract order, each removing only itself', () => {
  const chips = activeFilterChips({ severity: 'high', source: '203.0.113.7', classification: 'canary_invocation' });
  assert.deepEqual(chips.map((c) => c.key), ['classification', 'source', 'severity']);
  assert.equal(chips[0].text, 'Canary invocation');
  assert.equal(chips[2].text, 'High or higher');
  const q = parseHash(chips[1].removeHref).query;
  assert.deepEqual(q, { classification: 'canary_invocation', severity: 'high' });
  assert.equal(chips[1].evidence, true, 'a source key keeps the evidence treatment');
  assert.equal(chips[0].evidence, false);
});

test('chips: removal keeps live mode on', () => {
  const [chip] = activeFilterChips({ rule: 'PI-001' }, { live: true });
  assert.equal(chip.removeHref, '#/events?live=1');
});

test('click-to-filter: adds to the current filters and rejects invalid values', () => {
  const link = addFilterHref({ severity: 'low' }, 'sensor', 'web');
  assert.deepEqual(parseHash(link).query, { sensor: 'web', severity: 'low' });
  // A hostile source key is percent-encoded, not interpreted.
  const src = addFilterHref({}, 'source', 'a/b?c=<x>&d');
  assert.equal(parseHash(src).query.source, 'a/b?c=<x>&d');
  assert.equal(addFilterHref({}, 'sensor', 'bad id!'), null);
  assert.equal(addFilterHref({}, 'classification', 'nope'), null);
  assert.equal(addFilterHref({}, 'nonsense', 'x'), null);
  assert.equal(addFilterHref({}, 'source', 'x'.repeat(300)), null);
  assert.equal(isFilterActive({ rule: 'R' }, 'rule', 'R'), true);
  assert.equal(describeFilter('node', 'local').text, 'This node');
});

// ---- Saved views ---------------------------------------------------------------

const memoryStorage = () => {
  const m = new Map();
  return { getItem: (k) => (m.has(k) ? m.get(k) : null), setItem: (k, v) => m.set(k, String(v)), map: m };
};

test('views: source and search are never saved; other filters are', () => {
  const { filters, dropped } = viewFilters({ source: '203.0.113.7', q: 'admin', rule: 'PI-001', severity: 'high' });
  assert.deepEqual(filters, { rule: 'PI-001', severity: 'high' });
  assert.deepEqual(dropped, ['source', 'q']);
  assert.throws(() => addView([], 'x', { source: '203.0.113.7' }), /not saved/);
  assert.throws(() => addView([], '  ', { rule: 'R' }), /name/);
});

test('views: add replaces by name (case-insensitive), newest first, capped', () => {
  let { views } = addView([], 'Canaries', { classification: 'canary_invocation' });
  ({ views } = addView(views, 'High', { severity: 'high' }));
  ({ views } = addView(views, 'canaries', { classification: 'canary_invocation', sensor: 'mcp' }));
  assert.deepEqual(views.map((v) => v.name), ['canaries', 'High']);
  for (let i = 0; i < 30; i++) ({ views } = addView(views, `v${i}`, { rule: 'R' }));
  assert.equal(views.length, MAX_VIEWS);
  assert.equal(removeView(views, 'v29').length, MAX_VIEWS - 1);
});

test('views: stored per tenant and parsed as untrusted input', () => {
  const s = memoryStorage();
  assert.equal(storeViews(s, 'alpha', [{ name: 'A', filters: { rule: 'R' } }]), true);
  assert.deepEqual(loadViews(s, 'alpha'), [{ name: 'A', filters: { rule: 'R' } }]);
  assert.deepEqual(loadViews(s, 'bravo'), []);
  assert.equal(viewsKey('../x'), 'aegismesh.views.default');
  // Garbage, hostile names, smuggled evidence and invalid filters are dropped.
  s.setItem(viewsKey('alpha'), JSON.stringify([
    null, 7, { name: 'ok‮\u0007 name', filters: { severity: 'high', source: '203.0.113.7', q: 'x' } },
    { name: 'bad', filters: { classification: '<script>' } }, { name: 'OK NAME', filters: { rule: 'R' } },
  ]));
  assert.deepEqual(loadViews(s, 'alpha'), [{ name: 'ok name', filters: { severity: 'high' } }]);
  s.setItem(viewsKey('alpha'), '{not json');
  assert.deepEqual(loadViews(s, 'alpha'), []);
  assert.equal(storeViews({ setItem() { throw new Error('quota'); } }, 'alpha', []), false);
  assert.equal(cleanName('x'.repeat(100)).length, 48);
});

test('recents: only interface kinds, deduplicated, capped', () => {
  let r = [];
  for (const id of ['events', 'overview', 'events', 'rules', 'sensors', 'audit', 'node', 'fleet']) r = pushRecent(r, { kind: 'screen', id });
  assert.equal(r.length, MAX_RECENTS);
  assert.equal(r[0].id, 'fleet');
  assert.equal(pushRecent(r, { kind: 'source', id: '203.0.113.7' }), r, 'sources are evidence and never kept');
  assert.deepEqual(parseRecents(JSON.stringify([{ kind: 'source', id: 'x' }, { kind: 'rule', id: 'PI-001' }, { kind: 'rule', id: '<x>' }])), [{ kind: 'rule', id: 'PI-001' }]);
  assert.equal(recentsKey('alpha'), 'aegismesh.recent.alpha');
});

// ---- Cadence --------------------------------------------------------------------

const at = (ms) => new Date(Date.UTC(2026, 10, 22) + ms).toISOString();

test('cadence: regular machine-like gaps are described, order does not matter', () => {
  const times = [];
  for (let i = 0; i < 20; i++) times.push(at(i * 2000));
  const c = cadence(times.reverse());
  assert.equal(c.events, 20);
  assert.equal(c.gaps, 19);
  assert.equal(c.median, 2000);
  assert.equal(c.nearMedian, 1);
  assert.equal(c.bins[1].count, 19);
  assert.equal(c.peak, 1);
  assert.equal(describeCadence(c), 'Median gap 2 s; 80% of gaps fall between 2 s and 2 s; 100% are within a quarter of the median.');
});

test('cadence: too few events give no statistics; bad times are counted', () => {
  const c = cadence([at(0), 'nope', at(1000), at(5000)]);
  assert.equal(c.skipped, 1);
  assert.equal(c.gaps, 2);
  assert.equal(c.enough, false);
  assert.equal(describeCadence(c), null);
  assert.equal(cadence([]).peak, -1);
  assert.equal(GAP_BINS.length, cadence([]).bins.length);
});

test('cadence: gaps format at a readable precision', () => {
  assert.equal(formatGap(850), '850 ms');
  assert.equal(formatGap(4200), '4.2 s');
  assert.equal(formatGap(45000), '45 s');
  assert.equal(formatGap(3 * 60000), '3 min');
  assert.equal(formatGap(25 * 60000), '25 min');
  assert.equal(formatGap(5400000), '1.5 h');
  assert.equal(formatGap(88.3 * 3600000), '3.7 d');
  assert.equal(formatGap(-1), '—');
});

// ---- Glossary ------------------------------------------------------------------

test('glossary: ids are unique, cross-references resolve, copy stays honest', () => {
  const ids = GLOSSARY.map((e) => e.id);
  assert.equal(new Set(ids).size, ids.length);
  for (const e of GLOSSARY) {
    assert.match(e.id, /^[a-z]+$/);
    assert.ok(e.short && e.body.length, e.id);
    for (const s of e.see || []) assert.ok(glossaryEntry(s), `${e.id} → ${s}`);
    if (e.cli) assert.match(e.cli, /^aegismesh /);
    const all = [e.term, e.short, ...e.body].join(' ');
    assert.doesNotMatch(all, /zero false positives|guarantee|blocks? attacks|stops? attacks/i, e.id);
  }
  for (const needed of ['observation', 'incident', 'classification', 'severity', 'correlation', 'recommendation', 'index']) assert.ok(glossaryEntry(needed), needed);
  assert.match(glossaryEntry('recommendation').short, /Proposed, not executed/);
  assert.equal(glossaryGroups().reduce((n, g) => n + g.entries.length, 0), GLOSSARY.length);
});
