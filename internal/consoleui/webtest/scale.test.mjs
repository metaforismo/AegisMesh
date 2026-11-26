// Real scale: lists that grow without rebuilding, the list cap, the folded
// campaign score, and the mock's `--scale large` generators.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createFakeDocument } from './fakedom.mjs';

globalThis.document = createFakeDocument();
const C = await import('../static/assets/js/ui/components.js');
const UI = await import('../static/assets/js/ui/insight.js');
const S = await import('../devserver/mock-scale.mjs');

const cls = (el) => el.getAttribute('class') || '';
const rowsOf = (el) => el.querySelectorAll((n) => n.tagName === 'tbody')[0].childNodes;

test('a growing table appends a page without rebuilding the rows already drawn', () => {
  const columns = [{ label: 'N', num: true, cell: (r) => String(r.n) }, { label: 'Name', cell: (r) => r.name }];
  const g = C.growingTable({ caption: 'x', columns, rows: [{ n: 1, name: 'a' }, { n: 2, name: 'b' }] });
  const first = rowsOf(g.el)[0];
  g.append([{ n: 3, name: 'c' }, { n: 4, name: 'd' }]);
  const rows = rowsOf(g.el);
  assert.equal(rows.length, 4);
  assert.equal(rows[0], first, 'the first row is the same node');
  assert.equal(rows[3].textContent, '4d');
  assert.equal(g.size, 4);
  g.append([]);
  assert.equal(rowsOf(g.el).length, 4);
  // `table` is the same table without the handle.
  assert.equal(C.table({ caption: 'x', columns, rows: [{ n: 1, name: 'a' }] }).tagName, 'div');
});

test('a sorted growing table repaints in order', () => {
  const columns = [{ label: 'N', num: true, sort: (r) => r.n, cell: (r) => String(r.n) }];
  const g = C.growingTable({ caption: 'x', columns, rows: [{ n: 5 }, { n: 1 }], sort: { key: 'N', dir: 'desc' } });
  g.append([{ n: 9 }, { n: 3 }]);
  assert.deepEqual(rowsOf(g.el).map((r) => r.textContent), ['9', '5', '3', '1']);
});

test('the pager stops at the list cap and says how to reach the rest', () => {
  const capped = C.pager({ shown: 2000, total: 55264, hasMore: true, onMore: () => {}, capText: 'Narrow the filters.' });
  assert.match(capped.textContent, /Showing 2,000 of 55,264/);
  assert.match(capped.textContent, /Narrow the filters\./);
  assert.equal(capped.querySelectorAll((n) => n.tagName === 'button').length, 0);
  const open = C.pager({ shown: 100, total: 300, hasMore: true, onMore: () => {} });
  assert.equal(open.querySelectorAll((n) => n.tagName === 'button').length, 1);
  assert.match(C.pager({ shown: 2000, hasMore: true, onMore: () => {} }).textContent, /stops at 2,000 rows/);
  assert.equal(C.LIST_CAP, 2000);
});

test('chip lists fold to "+N" with the rest named', () => {
  const el = C.chipList(['a', 'b', 'c', 'd', 'e'], { max: 3 });
  const chips = el.childNodes;
  assert.equal(chips.length, 4);
  assert.equal(chips[3].getAttribute('title'), 'd, e');
  assert.match(chips[3].textContent, /^\+2 more: d, e$/);
  assert.equal(C.chipList([], {}).textContent, '—');
  assert.equal(C.chipList(['a', 'b']).childNodes.length, 2);
});

test('a campaign score folds beyond N lanes and steps, with one "Show all" per axis', () => {
  const steps = Array.from({ length: 20 }, (_, i) => ({ index: i, shape: `GET /p${i}`, stage: 'discovery', sessions: 30 }));
  const sessions = Array.from({ length: 30 }, (_, i) => ({ id: i.toString(16).padStart(32, '0'), source: `192.0.2.${i + 1}`, first_seen: '2026-11-26T10:00:00Z', step_marks: steps.map((s) => ({ index: s.index, offset_ms: s.index * 1000 })) }));
  const view = UI.campaignScoreView({ steps, sessions, sessionCount: 30 }, { sessionHref: (id) => `#/sessions/${id}` });
  const lanes = () => view.querySelectorAll((n) => cls(n) === 'score__lane');
  const heads = () => view.querySelectorAll((n) => /(^| )score__step( |$)/.test(cls(n)));
  assert.equal(lanes().length, UI.SCORE_LANES);
  assert.equal(heads().length, UI.SCORE_STEPS);
  assert.match(view.textContent, /Showing 12 of 30 sessions and 12 of 20 steps\./);
  const buttons = view.querySelectorAll((n) => n.tagName === 'button');
  assert.deepEqual(buttons.map((b) => b.textContent), ['Show all 30 sessions', 'Show all 20 steps']);
  buttons[0].dispatch('click');
  assert.equal(lanes().length, 30);
  assert.equal(heads().length, 12);
  view.querySelectorAll((n) => n.tagName === 'button')[0].dispatch('click');
  assert.equal(heads().length, 20);
  // Small scores are drawn whole (a fold of one or two would only add a click).
  const small = UI.campaignScoreView({ steps: steps.slice(0, 13), sessions: sessions.slice(0, 14), sessionCount: 14 }, { sessionHref: () => '#/sessions' });
  assert.equal(small.querySelectorAll((n) => cls(n) === 'score__lane').length, 14);
  assert.equal(small.querySelectorAll((n) => n.tagName === 'button').length, 0);
  assert.equal(UI.scoreShownText(12, 12, 5, 5), '');
});

test('mock --scale large: deterministic synthetic volume from documentation ranges', () => {
  const seeded = () => {
    let seed = 7;
    return () => { seed = (seed * 1664525 + 1013904223) >>> 0; return seed / 2 ** 32; };
  };
  const pool = S.sourcePool(S.LARGE.sources, seeded());
  assert.equal(pool.length, S.LARGE.sources);
  assert.equal(new Set(pool).size, pool.length);
  const doc = /^(192\.0\.2|198\.51\.100|203\.0\.113)\.\d{1,3}$|^2001:db8:/;
  assert.ok(pool.every((s) => doc.test(s)), 'only documentation-range sources');
  assert.deepEqual(S.sourcePool(50, seeded()), S.sourcePool(50, seeded()), 'deterministic');
  const sensors = S.extraSensors(S.LARGE.extraSensors);
  assert.equal(sensors.length, 40);
  assert.ok(sensors.every((x) => x.listen.startsWith('127.0.0.1:')));
  const now = Date.parse('2026-11-26T12:00:00Z');
  const runs = S.campaignRuns({ now, rand: seeded(), pool });
  const byCampaign = new Map();
  for (const r of runs) byCampaign.set(r.campaign, (byCampaign.get(r.campaign) || 0) + 1);
  assert.equal(byCampaign.size, S.LARGE.campaigns);
  assert.ok(Math.max(...byCampaign.values()) >= 30, 'some campaigns run from dozens of sources');
  assert.ok(runs.every((r) => r.start < now && r.start > now - 3 * 3600e3 && r.steps.length >= 4));
  const audit = S.auditBackfill({ now, rand: seeded(), count: 500 });
  assert.equal(audit.length, 500);
  assert.ok(audit.every((r, i) => i === 0 || r.time >= audit[i - 1].time), 'oldest first');
  assert.ok(audit.every((r) => Date.parse(r.time) < now));
});

test('a long ranked list keeps its top rows and sums the rest', async () => {
  const { topWithRest } = await import('../static/assets/js/lib/viz.js');
  const rows = Array.from({ length: 48 }, (_, i) => ({ sensor_id: `s${i}`, events: 100 - i }));
  const { top, rest } = topWithRest(rows, 8);
  assert.equal(top.length, 8);
  assert.deepEqual(rest, { count: 40, events: rows.slice(8).reduce((a, r) => a + r.events, 0) });
  // One left over is shown, not folded into "1 other".
  assert.equal(topWithRest(rows.slice(0, 9), 8).rest, null);
  assert.equal(topWithRest(null).top.length, 0);
});
