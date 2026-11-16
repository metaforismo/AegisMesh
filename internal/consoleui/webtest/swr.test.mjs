import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createSwr, abortable } from '../static/assets/js/lib/swr.js';

test('in-flight requests are shared and fresh values reused', async () => {
  let t = 0;
  let calls = 0;
  const c = createSwr({ freshMs: 1000, now: () => t });
  const fetcher = () => { calls++; return Promise.resolve({ n: calls }); };
  c.prefetch('k', fetcher);
  const [a, b] = await Promise.all([c.get('k', fetcher), c.get('k', fetcher)]);
  assert.equal(calls, 1);
  assert.deepEqual(a, { n: 1 });
  assert.equal(a, b);
  t = 500;
  assert.deepEqual(await c.get('k', fetcher), { n: 1 }, 'fresh');
  t = 1500;
  assert.deepEqual(await c.get('k', fetcher), { n: 2 }, 'expired without allowStale refetches and waits');
});

test('allowStale returns the stale value now and reports a changed refresh', async () => {
  let t = 0;
  let v = 1;
  const updates = [];
  const c = createSwr({ freshMs: 100, staleMs: 10000, now: () => t, onUpdate: (k) => updates.push(k) });
  const fetcher = () => Promise.resolve({ v });
  await c.get('k', fetcher);
  t = 5000;
  v = 2;
  assert.deepEqual(await c.get('k', fetcher, { allowStale: true }), { v: 1 });
  await new Promise((r) => setTimeout(r, 0));
  assert.deepEqual(updates, ['k']);
  assert.deepEqual(await c.get('k', fetcher), { v: 2 });
  // Unchanged refresh: no update event.
  t = 9000;
  await c.get('k', fetcher, { allowStale: true });
  await new Promise((r) => setTimeout(r, 0));
  assert.deepEqual(updates, ['k']);
  t = 99999;
  v = 3;
  assert.deepEqual(await c.get('k', fetcher, { allowStale: true }), { v: 3 }, 'too old even for stale');
});

test('errors are not cached and invalidate clears everything', async () => {
  const c = createSwr();
  await assert.rejects(c.get('k', () => Promise.reject(new Error('boom'))));
  assert.equal(c.has('k'), false);
  await c.get('k', () => Promise.resolve(1));
  c.invalidate();
  assert.equal(c.size, 0);
});

test('entries are bounded', async () => {
  const c = createSwr({ maxEntries: 3 });
  for (const k of ['a', 'b', 'c', 'd']) await c.get(k, () => Promise.resolve(k));
  assert.equal(c.size, 3);
  assert.equal(c.has('a'), false);
});

test('abortable rejects for its caller without cancelling the shared promise', async () => {
  const ctl = new AbortController();
  let resolve;
  const shared = new Promise((r) => { resolve = r; });
  const mine = abortable(shared, ctl.signal);
  ctl.abort();
  await assert.rejects(mine, { name: 'AbortError' });
  resolve(7);
  assert.equal(await shared, 7);
  assert.equal(await abortable(Promise.resolve(1), undefined), 1);
});
