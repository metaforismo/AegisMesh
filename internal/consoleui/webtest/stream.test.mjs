import { test } from 'node:test';
import assert from 'node:assert/strict';
import { RingBuffer, backoffDelay, parseObservation, createLiveStream } from '../static/assets/js/lib/stream.js';

test('RingBuffer keeps the newest items and counts drops', () => {
  const r = new RingBuffer(3);
  for (let i = 1; i <= 5; i++) r.push(i);
  assert.deepEqual(r.newestFirst(), [5, 4, 3]);
  assert.equal(r.dropped, 2);
  assert.throws(() => new RingBuffer(0));
});

test('backoffDelay grows, caps and jitters within [50%, 100%]', () => {
  assert.equal(backoffDelay(0, { random: () => 1 }), 1000);
  assert.equal(backoffDelay(3, { random: () => 1 }), 8000);
  assert.equal(backoffDelay(20, { random: () => 1 }), 30000);
  assert.equal(backoffDelay(20, { random: () => 0 }), 15000);
});

test('parseObservation rejects malformed payloads', () => {
  assert.equal(parseObservation('nope'), null);
  assert.equal(parseObservation('[1]'), null);
  assert.equal(parseObservation('{"id":1,"time":"t"}'), null);
  assert.deepEqual(parseObservation('{"id":"a","time":"t"}'), { id: 'a', time: 't' });
});

function harness(checkSession) {
  const sources = [];
  class FakeES {
    constructor(url, opts) { this.url = url; this.opts = opts; this.l = {}; this.closed = false; sources.push(this); }
    addEventListener(t, fn) { (this.l[t] ||= []).push(fn); }
    emit(t, data) { for (const fn of this.l[t] || []) fn({ data }); }
    close() { this.closed = true; }
  }
  const timers = [];
  const states = [];
  const events = [];
  const s = createLiveStream({
    EventSourceImpl: FakeES, checkSession, onEvent: (e) => events.push(e), onState: (st, d) => states.push([st, d]),
    setTimer: (fn, ms) => { timers.push({ fn, ms }); return timers.length; }, clearTimer: () => {}, random: () => 1,
  });
  return { s, sources, timers, states, events };
}

const tick = () => new Promise((r) => setImmediate(r));

test('delivers observations and ignores garbage', () => {
  const t = harness(async () => true);
  t.s.start();
  const es = t.sources[0];
  assert.equal(es.opts.withCredentials, true);
  es.emit('open');
  es.emit('observation', '{"id":"a","time":"2026-11-14T00:00:00Z"}');
  es.emit('observation', '<script>');
  es.emit('heartbeat', '{"time":"2026-11-14T00:00:15Z"}');
  assert.equal(t.events.length, 1);
  assert.equal(t.s.state, 'live');
});

test('drop with a live session reconnects with backoff', async () => {
  const t = harness(async () => true);
  t.s.start();
  t.sources[0].emit('error');
  assert.equal(t.sources[0].closed, true);
  await tick();
  assert.equal(t.s.state, 'reconnecting');
  assert.equal(t.timers[0].ms, 1000);
  t.timers[0].fn();
  assert.equal(t.sources.length, 2);
  t.sources[1].emit('error');
  await tick();
  assert.equal(t.timers[1].ms, 2000);
});

test('drop with an expired session stops for good', async () => {
  const t = harness(async () => { const e = new Error('401'); e.status = 401; throw e; });
  t.s.start();
  t.sources[0].emit('error');
  await tick();
  assert.equal(t.s.state, 'expired');
  assert.equal(t.timers.length, 0);
});

test('outage (session probe fails) keeps retrying', async () => {
  const t = harness(async () => { throw new Error('network'); });
  t.s.start();
  t.sources[0].emit('error');
  await tick();
  assert.equal(t.s.state, 'reconnecting');
});

test('stop wins over a pending session check and late events', async () => {
  let release;
  const t = harness(() => new Promise((r) => { release = r; }));
  t.s.start();
  const es = t.sources[0];
  es.emit('error');
  t.s.stop();
  release(true);
  await tick();
  assert.equal(t.s.state, 'stopped');
  assert.equal(t.timers.length, 0);
  es.emit('observation', '{"id":"late","time":"t"}');
  assert.equal(t.events.length, 0);
});
