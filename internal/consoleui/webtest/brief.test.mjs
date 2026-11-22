import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildBrief, briefText, briefWindowStart } from '../static/assets/js/lib/brief.js';

const ov = {
  window: '24h', generated_at: '2026-11-22T12:00:00Z',
  totals: { events: 714, interaction: 648, canary_invocation: 55, correlation_signal: 11, sources: 8, sensors_active: 5 },
  previous_totals: { events: 229, interaction: 198, canary_invocation: 25, correlation_signal: 6 },
  by_severity: { info: 33, low: 32, medium: 41, high: 57, critical: 41, none: 510 },
  top_rules: [{ rule_id: 'PI-001', events: 51, severity: 'high' }],
  top_sources: [{ source: '<b>198.51.100.9</b>', events: 113, sensors: ['a', 'b', 'c'] }],
  open_investigations: 1,
};

test('brief: full overview yields linked, neutral clauses in a fixed order', () => {
  const b = buildBrief(ov, '24h');
  assert.deepEqual(b.map((c) => c.id), ['volume', 'canary_invocation', 'correlation_signal', 'severity', 'source', 'rule', 'investigations']);
  const text = briefText(b);
  assert.match(text, /^714 events in the last 24 hours, 485 more than the window before \(\+212%\)\./);
  assert.match(text, /55 canary invocations\./);
  assert.match(text, /Highest finding: critical, on 41 events\./);
  assert.match(text, /Most cited rule: PI-001 \(High\), cited by 51 events\./);
  assert.match(text, /\(16% of the window\) across 3 sensors\./);
  assert.doesNotMatch(text, /worse|better|alarm|attack/i);
});

test('brief: drill-downs carry the window start so they list what was counted', () => {
  const b = buildBrief(ov, '24h');
  const since = '2026-11-21T12:00:00Z';
  assert.equal(briefWindowStart(ov.generated_at, '24h'), since);
  assert.deepEqual(b.find((c) => c.id === 'volume').route, { name: 'events', query: { since } });
  assert.deepEqual(b.find((c) => c.id === 'rule').route.query, { rule: 'PI-001', since });
  assert.deepEqual(b.find((c) => c.id === 'severity').route.query, { severity: 'critical', since });
  assert.deepEqual(b.find((c) => c.id === 'source').route, { name: 'source', params: ['<b>198.51.100.9</b>'], query: {} });
});

test('brief: the source key stays an evidence segment, never interface text', () => {
  const src = buildBrief(ov, '24h').find((c) => c.id === 'source');
  const ev = src.segments.filter((s) => s.t === 'ev');
  assert.deepEqual(ev, [{ t: 'ev', v: '<b>198.51.100.9</b>' }]);
  assert.ok(src.segments.filter((s) => s.t === 'text').every((s) => !s.v.includes('198.51')));
});

test('brief: missing fields are said, not zeroed', () => {
  assert.equal(briefText(buildBrief({}, '1h')), 'The server did not report an event count for the last hour.');
  const noPrev = buildBrief({ totals: { events: 3 } }, '7d');
  assert.equal(briefText(noPrev), '3 events in the last 7 days. The previous window was not reported.');
  // No severity, rules or sources in the response: those clauses are absent.
  assert.deepEqual(noPrev.map((c) => c.id), ['volume']);
});

test('brief: quiet windows and decreases read plainly', () => {
  assert.equal(briefText(buildBrief({ totals: { events: 0 }, previous_totals: { events: 0 } }, '24h')), 'No events in the last 24 hours, and none in the window before.');
  assert.equal(briefText(buildBrief({ totals: { events: 5 }, previous_totals: { events: 10 } }, '1h')), '5 events in the last hour, 5 fewer than the window before (−50%).');
  assert.equal(briefText(buildBrief({ totals: { events: 1 }, previous_totals: { events: 0 } }, '1h')), '1 event in the last hour, none in the window before.');
  assert.equal(buildBrief({ totals: { events: 0 } }, '1h')[0].route, null);
});

test('brief: rejects nonsense numbers and unknown severities', () => {
  const b = buildBrief({
    totals: { events: 4, canary_invocation: -2, correlation_signal: 'x' },
    previous_totals: { events: 4 },
    by_severity: { critical: NaN, bogus: 9 },
    top_rules: [{ rule_id: 'R1', events: 2, severity: 'urgent' }],
    top_sources: [{ source: '', events: 9 }],
  }, '24h');
  assert.equal(briefText(b), '4 events in the last 24 hours, the same as the window before. Most cited rule: R1, cited by 2 events.');
});
