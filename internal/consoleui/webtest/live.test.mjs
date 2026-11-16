import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createBatcher, overflow } from '../static/assets/js/lib/batch.js';

function frames() {
  const q = [];
  return {
    schedule: (fn) => { q.push(fn); return q.length; },
    cancel: (id) => { q[id - 1] = null; },
    tick() { const fns = q.splice(0); for (const fn of fns) fn?.(); return fns.filter(Boolean).length; },
    get pending() { return q.filter(Boolean).length; },
  };
}

test('a burst becomes one flush per frame, capped per frame, in arrival order', () => {
  const f = frames();
  const flushed = [];
  const b = createBatcher({ flush: (items) => flushed.push(items), perFrame: 50, schedule: f.schedule, cancel: f.cancel });
  for (let i = 0; i < 120; i++) b.push(i);
  assert.equal(f.pending, 1, 'one frame scheduled for the whole burst');
  assert.equal(flushed.length, 0, 'nothing is written synchronously');
  f.tick();
  assert.deepEqual(flushed.map((x) => x.length), [50]);
  f.tick();
  f.tick();
  assert.deepEqual(flushed.map((x) => x.length), [50, 50, 20]);
  assert.deepEqual(flushed.flat(), Array.from({ length: 120 }, (_, i) => i));
  assert.equal(f.tick(), 0, 'idle once drained');
});

test('flushNow drains synchronously; stop drops the queue', () => {
  const f = frames();
  const flushed = [];
  const b = createBatcher({ flush: (items) => flushed.push(...items), perFrame: 2, schedule: f.schedule, cancel: f.cancel });
  b.push('a'); b.push('b'); b.push('c');
  b.flushNow();
  assert.deepEqual(flushed, ['a', 'b', 'c']);
  b.push('d');
  b.stop();
  f.tick();
  assert.deepEqual(flushed, ['a', 'b', 'c']);
  b.push('e');
  assert.equal(b.size, 0, 'a stopped batcher accepts nothing');
});

test('overflow says how many rows to drop to stay within the cap', () => {
  assert.equal(overflow(480, 50, 500), 30);
  assert.equal(overflow(10, 5, 500), 0);
  assert.equal(overflow(500, 0, 500), 0);
});
