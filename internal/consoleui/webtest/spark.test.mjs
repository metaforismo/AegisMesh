import { test } from 'node:test';
import assert from 'node:assert/strict';
import { sparkPath, seriesOf, binTimes, bucketRange, waveDelays } from '../static/assets/js/lib/chart.js';

test('sparkPath scales to the box and closes the area on the baseline', () => {
  const s = sparkPath([0, 5, 10], { width: 100, height: 20, pad: 0 });
  assert.equal(s.line, 'M0 20L50 10L100 0');
  assert.equal(s.area, 'M0 20L50 10L100 0L100 20L0 20Z');
  assert.deepEqual(s.last, { x: 100, y: 0 });
  assert.equal(s.max, 10);
});

test('sparkPath: flat, single and empty series', () => {
  assert.equal(sparkPath([0, 0], { width: 10, height: 10, pad: 1 }).line, 'M1 9L9 9');
  assert.equal(sparkPath([3], { width: 10, height: 10, pad: 1 }).line, 'M5 1');
  assert.deepEqual(sparkPath([]), { line: '', area: '', last: null, max: 0 });
  assert.equal(sparkPath(['x', -4, 2], { width: 10, height: 10, pad: 0 }).line, 'M0 10L5 10L10 0', 'junk and negatives read as 0');
});

test('seriesOf reads one classification or the total', () => {
  const b = [{ interaction: 2, canary_invocation: 1 }, { interaction: 0, correlation_signal: 3 }];
  assert.deepEqual(seriesOf(b, 'interaction'), [2, 0]);
  assert.deepEqual(seriesOf(b), [3, 3]);
  assert.deepEqual(seriesOf(null), []);
});

test('binTimes counts into equal bins and never clamps outside times in', () => {
  const start = Date.parse('2026-11-15T00:00:00Z');
  const end = start + 4 * 3600e3;
  const r = binTimes(['2026-11-15T00:10:00Z', '2026-11-15T01:59:59Z', '2026-11-15T03:30:00Z', '2026-11-14T23:00:00Z', '2026-11-15T04:00:00Z', 'nope'], start, end, 4);
  assert.deepEqual(r.bins, [1, 1, 0, 1]);
  assert.equal(r.outside, 3);
  assert.deepEqual(binTimes([], 5, 5, 3), { bins: [0, 0, 0], outside: 0 });
});

test('bucketRange: inclusive until stops one second before the next bucket', () => {
  const b = [{ start: '2026-11-15T10:00:00Z' }, { start: '2026-11-15T10:30:00Z' }];
  assert.deepEqual(bucketRange(b, 0), { since: '2026-11-15T10:00:00Z', until: '2026-11-15T10:29:59Z' });
  assert.deepEqual(bucketRange(b, 1), { since: '2026-11-15T10:30:00Z', until: '2026-11-15T10:59:59Z' }, 'last bucket uses the step');
  assert.deepEqual(bucketRange([b[0]], 0, '2026-11-15T10:05:00Z'), { since: '2026-11-15T10:00:00Z', until: '2026-11-15T10:04:59Z' });
  assert.equal(bucketRange(b, 5), null);
  assert.equal(bucketRange([{ start: 'bad' }], 0), null);
});

test('waveDelays are eased, start at 0 and never exceed the budget', () => {
  const d = waveDelays(48, 240);
  assert.equal(d.length, 48);
  assert.equal(d[0], 0);
  assert.equal(d[47], 240);
  assert.ok(d[1] - d[0] > d[47] - d[46], 'early steps are wider than late ones');
  assert.deepEqual(waveDelays(1), [0]);
  assert.deepEqual(waveDelays(0), []);
});
