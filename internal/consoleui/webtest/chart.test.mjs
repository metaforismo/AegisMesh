import { test } from 'node:test';
import assert from 'node:assert/strict';
import { niceCeil, ticks, stackedLayout, labelIndices, share, bucketTotal } from '../static/assets/js/lib/chart.js';
import { jsonTokens, tokensToText } from '../static/assets/js/lib/json.js';

test('niceCeil and ticks', () => {
  assert.equal(niceCeil(0), 1);
  assert.equal(niceCeil(7), 10);
  assert.equal(niceCeil(1.6), 2);
  assert.equal(niceCeil(23), 25);
  assert.deepEqual(ticks(0).values, [0, 1]);
  const t = ticks(37);
  assert.ok(t.max >= 37 && t.values.every(Number.isInteger));
  assert.equal(t.values.length <= 6, true);
});

test('stackedLayout keeps classification order, gaps and baseline', () => {
  const buckets = [
    { start: 'a', interaction: 6, canary_invocation: 2, correlation_signal: 2 },
    { start: 'b', interaction: 0, canary_invocation: 0, correlation_signal: 0 },
    { start: 'c', correlation_signal: 1 },
  ];
  const L = stackedLayout(buckets, { width: 330, height: 130, padLeft: 30, padRight: 0, padTop: 0, padBottom: 30, gap: 2 });
  assert.equal(L.bars.length, 3);
  assert.deepEqual(L.bars[0].segments.map((s) => s.key), ['interaction', 'canary_invocation', 'correlation_signal']);
  assert.equal(L.bars[0].total, 10);
  assert.equal(L.bars[1].segments.length, 0);
  const base = L.plot.y + L.plot.h;
  const [s0, s1, s2] = L.bars[0].segments;
  assert.equal(s0.y + s0.h, base);
  assert.ok(Math.abs(s1.y + s1.h + 2 - s0.y) < 1e-9);
  // The top of the stack still lands on the scaled total.
  assert.ok(Math.abs(s2.y - L.yFor(10)) < 1e-9);
  assert.equal(L.bars[2].segments[0].key, 'correlation_signal');
});

test('stackedLayout ignores junk values', () => {
  const L = stackedLayout([{ interaction: -5, canary_invocation: 'x' }, null]);
  assert.equal(L.bars[0].total, 0);
  assert.equal(bucketTotal(null), 0);
});

test('labelIndices and share', () => {
  assert.deepEqual(labelIndices(48, 6), [0, 8, 16, 24, 32, 40]);
  assert.deepEqual(labelIndices(0), []);
  assert.equal(share(5, 10), 0.5);
  assert.equal(share(5, 0), 0);
  assert.equal(share(50, 10), 1);
});

test('jsonTokens reproduces JSON.stringify exactly', () => {
  const v = { a: [1, 'two', null, true, { b: '</script><x>' }], e: {}, f: [], 'k"ey': -1.5e3 };
  const { tokens, truncated } = jsonTokens(v);
  assert.equal(truncated, false);
  assert.equal(tokensToText(tokens), JSON.stringify(v, null, 2));
  assert.ok(tokens.some((t) => t.type === 'key' && t.text === '"k\\"ey"'));
});
