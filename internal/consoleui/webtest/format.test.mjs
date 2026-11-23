import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as f from '../static/assets/js/lib/format.js';
import { maxSeverity, severityLabel, roleAtLeast, classificationMeta } from '../static/assets/js/lib/taxonomy.js';

test('times render in UTC', () => {
  assert.equal(f.formatDateTime('2026-11-14T09:03:44+02:00'), '2026-11-14 07:03:44 UTC');
  assert.equal(f.formatDateTime(''), '—');
  assert.equal(f.formatClock('2026-11-14T09:03:44Z'), '09:03:44');
  assert.equal(f.formatBucketLabel('2026-11-14T09:30:00Z', '24h'), '09:30');
  assert.equal(f.formatBucketLabel('2026-11-14T00:00:00Z', '7d'), 'Nov 14');
});

test('relative time and durations', () => {
  const now = Date.parse('2026-11-14T10:00:00Z');
  assert.equal(f.formatRelative('2026-11-14T09:59:55Z', now), 'just now');
  assert.equal(f.formatRelative('2026-11-14T09:58:00Z', now), '2m ago');
  assert.equal(f.formatRelative('2026-11-12T10:00:00Z', now), '2d ago');
  assert.equal(f.formatRelative('', now), 'never');
  // One duration style everywhere: seconds go through formatDurationMs.
  assert.equal(f.formatDuration(90061), '25 h');
  assert.equal(f.formatDuration(3 * 86400), '3 d');
  assert.equal(f.formatDuration(-3), '0 s');
  assert.equal(f.formatDuration(undefined), '—');
  assert.equal(f.formatDurationMs(0), '0 s');
  assert.equal(f.formatDurationMs(850.4), '850 ms');
  assert.equal(f.formatDurationMs(4200), '4.2 s');
  assert.equal(f.formatDurationMs(45000), '45 s');
  assert.equal(f.formatDurationMs(5 * 60000), '5 min');
  assert.equal(f.formatDurationMs(150 * 60000), '2.5 h');
  assert.equal(f.formatDurationMs(-1), '—');
  assert.equal(f.formatDurationMs(null), '—');
  assert.equal(f.formatDurationMs('x'), '—');
});

test('numbers and bytes', () => {
  assert.equal(f.formatCount(1234567), '1,234,567');
  assert.equal(f.formatNumber(12.345), '12.3');
  assert.equal(f.formatNumber(1234.5, 0), '1,235');
  assert.equal(f.formatNumber(null), '—');
  assert.equal(f.formatNumber(Infinity), '—');
  assert.equal(f.formatCompact(12345), '12.3K');
  assert.equal(f.formatCompact(2500000), '2.5M');
  assert.equal(f.formatBytes(123456), '121 KiB');
  assert.equal(f.formatBytes(-1), '—');
  assert.equal(f.formatBytes(1536), '1.5 KiB');
});

test('deltas are descriptive', () => {
  assert.deepEqual(f.formatDelta(0, 0).direction, 'flat');
  assert.equal(f.formatDelta(5, 0).text, '+5');
  assert.equal(f.formatDelta(50, 100).text, '−50 (−50%)');
});

test('truncate never splits a surrogate pair', () => {
  assert.equal(f.truncate('🙂🙂🙂', 2), '🙂…');
  assert.equal(f.truncate('abc', 3), 'abc');
});

test('datetime-local conversion is UTC', () => {
  assert.equal(f.localInputToRfc3339('2026-11-14T09:03'), '2026-11-14T09:03:00Z');
  assert.equal(f.localInputToRfc3339('garbage'), '');
  assert.equal(f.rfc3339ToLocalInput('2026-11-14T09:03:00Z'), '2026-11-14T09:03:00');
});

test('taxonomy helpers', () => {
  assert.equal(maxSeverity(['low', '', 'high', 'medium']), 'high');
  assert.equal(severityLabel(''), 'No finding');
  assert.ok(roleAtLeast('admin', 'analyst'));
  assert.ok(!roleAtLeast('viewer', 'analyst'));
  assert.ok(!roleAtLeast('root', 'viewer'));
  assert.equal(classificationMeta('x').glyph, null);
});
