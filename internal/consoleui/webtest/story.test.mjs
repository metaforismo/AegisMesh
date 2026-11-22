// Attacker sessions in the UI: wording, story layout, downloads, routes.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { assessmentOf, evidenceMeta, EVIDENCE, storyItems, stageSummary, groupFrameworks, gapScalePos, formatDurationMs, regularityText, boundsNote, IDLE_MARKER_MS } from '../static/assets/js/lib/story.js';
import { buildBrief, briefText } from '../static/assets/js/lib/brief.js';
import { downloadFacts, DOWNLOAD_NAMES } from '../static/assets/js/lib/download.js';
import { parseHash, normalizeSessionFilters, normalizeFramework, href } from '../static/assets/js/lib/route.js';
import { glossaryEntry } from '../static/assets/js/lib/glossary.js';

test('assessment reads as an observation with its evidence count, never a verdict', () => {
  const a = assessmentOf({ assessment: 'consistent_with_automation', evidence: [{ code: 'sub_second_cadence' }, { code: 'honeytoken_replay' }, { code: 'agent_canary' }] });
  assert.equal(a.line, 'Consistent with automation · 3 observations');
  assert.equal(a.glyph, 'filled');
  const few = assessmentOf({ assessment: 'inconclusive', evidence: [{ code: 'honeytoken_replay' }, { code: 'insufficient_events' }] });
  assert.equal(few.line, 'Too few events to assess · 1 observation');
  assert.equal(assessmentOf({ assessment: '<b>bot</b>' }).key, 'unknown');
  for (const m of Object.values(EVIDENCE)) {
    assert.doesNotMatch(`${m.title} ${m.text}`, /\b(bot|attacker is|AI attacker|is an LLM)\b/i);
    assert.ok(glossaryEntry(m.guide), m.guide);
  }
  assert.equal(evidenceMeta('unknown_code').title, 'Observation');
});

const tl = (id, gap, extra = {}) => ({ event_id: id, node_id: 'local', time: '2026-11-22T10:00:00Z', gap_ms: gap, sensor: 's', kind: 'http', classification: 'interaction', rule_ids: [], summary: 'x', ...extra });

test('story: phase headers at stage changes, idle markers for long gaps, colliding ids consumed in order', () => {
  const timeline = [tl('a', null), tl('b', 700), tl('c', IDLE_MARKER_MS + 1), tl('a', 900)];
  const phases = [
    { stage: 'discovery', first_seen: 't0', last_seen: 't1', event_ids: ['a', 'b'] },
    { stage: 'decoy_credential_replay', first_seen: 't2', last_seen: 't3', event_ids: ['c', 'a'] },
  ];
  const items = storyItems(timeline, phases);
  assert.deepEqual(items.map((i) => i.type), ['phase', 'event', 'event', 'idle', 'phase', 'event', 'event']);
  assert.equal(items[0].stage, 'discovery');
  assert.equal(items[0].count, 2);
  assert.equal(items[1].gap, null);
  assert.equal(items[3].ms, IDLE_MARKER_MS + 1);
  assert.equal(items[4].stage, 'decoy_credential_replay');
  assert.deepEqual(stageSummary([...phases, { stage: 'discovery', event_ids: ['z'] }]), [{ stage: 'discovery', runs: 2, events: 3 }, { stage: 'decoy_credential_replay', runs: 1, events: 2 }]);
  assert.deepEqual(storyItems(null, null), []);
});

test('frameworks group in a fixed order and drop unknown frameworks', () => {
  const g = groupFrameworks([
    { framework: 'owasp-llm-2025', id: 'LLM10', name: 'Unbounded Consumption' },
    { framework: 'mitre-attack', id: 'T1595', name: 'Active Scanning' },
    { framework: 'evil', id: 'X', name: 'y' },
    { framework: 'mitre-attack', id: 'T1595', name: 'Active Scanning' },
  ]);
  assert.deepEqual(g.map((x) => x.label), ['MITRE ATT&CK', 'OWASP LLM 2025']);
  assert.equal(g[0].refs.length, 1);
});

test('durations, regularity and the log scale', () => {
  assert.equal(formatDurationMs(0), '0 s');
  assert.equal(formatDurationMs(700), '700 ms');
  assert.equal(formatDurationMs(8500), '8.5 s');
  assert.equal(formatDurationMs(null), '—');
  assert.equal(regularityText({ regularity: 0.625 }), '63%');
  assert.equal(gapScalePos(10), 0);
  assert.equal(gapScalePos(3600e3), 1);
  assert.ok(gapScalePos(1000) > 0.2 && gapScalePos(1000) < 0.5);
  assert.match(boundsNote({ scanned_events: 8192, scan_limit: 8192, scan_truncated: true, index: { history: 'truncated' } }), /scan limit was reached.*evicted older evidence.*not an actor identity/);
});

test('brief mentions automation sessions only when the endpoint answered with some', () => {
  const ov = { generated_at: '2026-11-22T12:00:00Z', totals: { events: 5 }, previous_totals: { events: 5 } };
  const sessions = { sessions: [{ automation: { assessment: 'consistent_with_automation' } }, { automation: { assessment: 'mixed' } }], next_cursor: '' };
  const b = buildBrief(ov, '24h', { sessions });
  const c = b.find((x) => x.id === 'automation');
  assert.equal(briefText([c]), '1 session with pace or rules consistent with automation (an observation, not a verdict).');
  assert.deepEqual(c.route, { name: 'sessions', query: { window: '24h' } });
  assert.match(briefText(buildBrief(ov, '24h', { sessions: { ...sessions, next_cursor: 'x' } })), /At least 1 session/);
  assert.equal(buildBrief(ov, '24h', { sessions: null }).some((x) => x.id === 'automation'), false);
});

test('downloads: fixed file names, header facts parsed defensively', () => {
  assert.deepEqual(Object.values(DOWNLOAD_NAMES), ['aegismesh-indicators.json', 'aegismesh-indicators.csv', 'aegismesh-indicators.txt', 'aegismesh-observation-report.md']);
  const headers = new Map(Object.entries({ 'X-AegisMesh-Skipped-Non-IP-Sources': '2', 'X-AegisMesh-Skipped-Non-IP-Events': 'x', 'X-AegisMesh-Scan-Truncated': 'true', 'X-AegisMesh-Index-History': '<b>' }));
  const f = downloadFacts({ get: (k) => headers.get(k) ?? null });
  assert.equal(f.skippedSources, 2);
  assert.equal(f.skippedEvents, null);
  assert.equal(f.truncated, true);
  assert.equal(f.history, '');
});

test('routes: sessions, a session, techniques; filters validated', () => {
  assert.equal(parseHash('#/sessions').name, 'sessions');
  assert.equal(parseHash(`#/sessions/${'a'.repeat(32)}`).name, 'attack_session');
  assert.equal(parseHash('#/sessions/not-an-id').name, 'not_found');
  assert.equal(parseHash('#/techniques?f=mitre-atlas').name, 'techniques');
  assert.deepEqual(normalizeSessionFilters({ window: '9d', source: '203.0.113.7' }), { window: '24h', source: '203.0.113.7' });
  assert.deepEqual(normalizeSessionFilters({ source: 'x'.repeat(300) }), { window: '24h' });
  assert.equal(normalizeFramework('nope'), 'mitre-attack');
  assert.equal(href('sessions', { source: 'a/b?c' }), '#/sessions?source=a%2Fb%3Fc');
});
