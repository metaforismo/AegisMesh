// Per-sensor bucket series (overview.by_sensor[].buckets) → activity traces,
// with the fallback rules for older servers and the 64-entry cap.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { sensorBuckets, bucketTrace, indexKnownFrom, BY_SENSOR_CAP } from '../static/assets/js/lib/chart.js';

const T0 = Date.parse('2026-11-15T00:00:00Z');
const STEP = 30 * 60e3;
const starts = (n) => Array.from({ length: n }, (_, i) => new Date(T0 + i * STEP).toISOString().replace('.000Z', 'Z'));
const series = (n, fill = () => [0, 0, 0]) => starts(n).map((start, i) => {
  const [a, b, c] = fill(i);
  return { start, interaction: a, canary_invocation: b, correlation_signal: c };
});

test('bucketTrace: totals per bucket, start and end from the starts', () => {
  const b = series(48, (i) => (i === 3 ? [2, 1, 0] : i === 47 ? [0, 0, 4] : [0, 0, 0]));
  const tr = bucketTrace(b);
  assert.equal(tr.bins.length, 48);
  assert.equal(tr.bins[3], 3);
  assert.equal(tr.bins[47], 4);
  assert.equal(tr.total, 7);
  assert.equal(tr.start, T0);
  assert.equal(tr.end, T0 + 48 * STEP, 'the last bucket is as long as the one before it');
});

test('bucketTrace: one bucket needs `end`; bad input gives null', () => {
  const one = series(1);
  assert.equal(bucketTrace(one), null);
  assert.deepEqual(bucketTrace(one, { end: new Date(T0 + 3600e3).toISOString() }).end, T0 + 3600e3);
  assert.equal(bucketTrace([]), null);
  assert.equal(bucketTrace(null), null);
  assert.equal(bucketTrace([{ start: 'nope' }, { start: 'later' }]), null);
  // Negative and non-numeric counts never draw activity.
  assert.deepEqual(bucketTrace([{ start: starts(1)[0], interaction: -5, canary_invocation: 'x' }, { start: starts(2)[1], interaction: 1 }]).bins, [0, 1]);
});

test('sensorBuckets: the server series when present', () => {
  const main = series(4);
  const ov = { buckets: main, by_sensor: [{ sensor_id: 'web', kind: 'http', events: 3, buckets: series(4, (i) => (i === 1 ? [3, 0, 0] : [0, 0, 0])) }] };
  const s = sensorBuckets(ov, 'web');
  assert.equal(s.status, 'ok');
  assert.equal(s.events, 3);
  assert.equal(bucketTrace(s.buckets).total, 3);
});

test('sensorBuckets: a sensor with no events in the window gets zeros on the main starts', () => {
  const ov = { buckets: series(4, () => [1, 0, 0]), by_sensor: [{ sensor_id: 'web', events: 4, buckets: series(4, () => [1, 0, 0]) }] };
  const s = sensorBuckets(ov, 'ssh-decoy');
  assert.equal(s.status, 'ok');
  assert.equal(s.events, 0);
  assert.deepEqual(s.buckets.map((b) => b.start), starts(4));
  assert.equal(bucketTrace(s.buckets).total, 0);
  // Empty by_sensor on a server that sends buckets: everything was quiet.
  assert.equal(sensorBuckets({ buckets: series(4), by_sensor: [] }, 'web').status, 'ok');
});

test('sensorBuckets: falls back on older servers and past the cap', () => {
  // Older server: by_sensor rows without buckets.
  assert.equal(sensorBuckets({ buckets: series(4), by_sensor: [{ sensor_id: 'web', events: 1 }] }, 'web').status, 'unsupported');
  assert.equal(sensorBuckets({ buckets: series(4), by_sensor: [{ sensor_id: 'web', events: 1 }] }, 'other').status, 'unsupported');
  assert.equal(sensorBuckets({}, 'web').status, 'unsupported');
  assert.equal(sensorBuckets(null, 'web').status, 'unsupported');
  // A full list: a missing sensor may simply be past the cap.
  const full = { buckets: series(2), by_sensor: Array.from({ length: BY_SENSOR_CAP }, (_, i) => ({ sensor_id: `s${i}`, events: 1, buckets: series(2) })) };
  assert.equal(sensorBuckets(full, 's3').status, 'ok');
  assert.equal(sensorBuckets(full, 'not-listed').status, 'unsupported');
});

test('indexKnownFrom: dashed time follows the index history', () => {
  assert.equal(indexKnownFrom(null), -Infinity);
  assert.equal(indexKnownFrom({ index: { history: 'complete', oldest: '2026-11-14T00:00:00Z' } }), -Infinity);
  assert.equal(indexKnownFrom({ started_at: '2026-11-14T06:00:00Z', index: { history: 'unavailable', oldest: '2026-11-14T09:00:00Z' } }), Date.parse('2026-11-14T06:00:00Z'));
  assert.equal(indexKnownFrom({ started_at: '2026-11-14T06:00:00Z', index: { history: 'truncated', oldest: '2026-11-14T09:00:00Z' } }), Date.parse('2026-11-14T09:00:00Z'));
  assert.equal(indexKnownFrom({ index: { history: 'truncated', oldest: '' } }), -Infinity);
});
