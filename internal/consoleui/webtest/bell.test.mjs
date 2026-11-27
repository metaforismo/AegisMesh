// Round 8: the bell in the fake DOM with a stubbed API and stream. An
// older server gets no bell; a newer one shows the count in the badge and
// the accessible name; live arrivals update both and are announced once
// per burst; a stream that never opens gives way to polling.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createFakeDocument } from './fakedom.mjs';

const doc = createFakeDocument();
globalThis.document = doc;
const proto = Object.getPrototypeOf(doc.createElement('x'));
proto.toggleAttribute = function toggleAttribute(k, on) { if (on) this.setAttribute(k, ''); else this.removeAttribute(k); };

const { createBell, STREAM_GIVE_UP, POLL_MS } = await import('../static/assets/js/ui/bell.js');
const { ApiError } = await import('../static/assets/js/lib/api.js');

const ID = (n) => `ntf_${String(n).padStart(16, '0')}`;
const item = (n, o = {}) => ({ id: ID(n), kind: 'critical_observation', severity: 'high', title: `Finding ${n}`, summary: '', created_at: '2026-11-27T10:00:00Z', read: false, link: null, group_count: 1, ...o });

function timers() {
  let seq = 0;
  const q = new Map();
  return {
    setTimer: (fn, ms) => { const id = ++seq; q.set(id, { fn, ms }); return id; },
    clearTimer: (id) => q.delete(id),
    runAll(filter = () => true) {
      for (const [id, t] of [...q]) if (filter(t)) { q.delete(id); t.fn(); }
    },
    pending: () => [...q.values()].map((t) => t.ms),
  };
}

function fakeStream() {
  const s = { opts: null, started: 0, stopped: 0 };
  s.factory = (opts) => { s.opts = opts; return { start() { s.started++; }, stop() { s.stopped++; } }; };
  return s;
}

test('an older server: no bell, no stream, no error', async () => {
  const stream = fakeStream();
  const bell = createBell({ api: { notifications: async () => { throw new ApiError(404, 'not_found', 'no such endpoint'); } }, streamFactory: stream.factory, ...timers() });
  assert.equal(await bell.start(), false);
  assert.equal(bell.button.getAttribute('hidden'), '', 'the bell stays hidden');
  assert.equal(bell.available, false);
  assert.equal(stream.started, 0);
});

test('the count shows in the badge and the name; live arrivals update both, announced once per burst', async () => {
  const stream = fakeStream();
  const t = timers();
  const bell = createBell({ api: { notifications: async () => ({ items: [item(1), item(2, { read: true })], unread: 4 }) }, streamFactory: stream.factory, storage: { getItem: () => 'off' }, ...t });
  assert.equal(await bell.start(), true);
  assert.equal(bell.button.hidden, false);
  assert.equal(bell.button.getAttribute('aria-label'), 'Notifications, 4 unread');
  assert.equal(bell.button.childNodes[1].textContent, '4');
  assert.equal(stream.opts.url, '/api/v1/notifications/stream');
  // A burst: three arrivals and the server's counts.
  for (const n of [3, 4, 5]) {
    stream.opts.events.notification(JSON.stringify(item(n, { severity: 'critical' })));
    stream.opts.events.unread(JSON.stringify({ unread: 4 + n - 2 }));
  }
  stream.opts.events.notification('not json');
  stream.opts.events.unread('{"unread":"lots"}');
  assert.equal(bell.button.getAttribute('aria-label'), 'Notifications, 7 unread');
  assert.equal(bell.live.textContent, '', 'nothing announced during the burst');
  t.runAll((x) => x.ms === 2000); // the quiet spell ends
  t.runAll((x) => x.ms === 50); // the live region is written
  assert.equal(bell.live.textContent, '3 new notifications. 7 unread.');
  assert.equal(bell.inbox.state().items[0].id, ID(5), 'newest first');
  bell.stop();
  assert.equal(stream.stopped, 1);
});

test('a stream that never opens gives way to polling every minute', async () => {
  const stream = fakeStream();
  const t = timers();
  let polls = 0;
  const bell = createBell({ api: { notifications: async () => { polls++; return { items: [], unread: 0 }; } }, streamFactory: stream.factory, ...t });
  await bell.start();
  for (let i = 0; i < STREAM_GIVE_UP; i++) stream.opts.onState('reconnecting');
  assert.equal(stream.stopped, 1);
  assert.deepEqual(t.pending(), [POLL_MS]);
  t.runAll();
  await new Promise((r) => setImmediate(r));
  assert.equal(polls, 2, 'the first load, then one poll');
  bell.stop();
});

test('a stream that opened once keeps reconnecting instead of polling', async () => {
  const stream = fakeStream();
  const t = timers();
  const bell = createBell({ api: { notifications: async () => ({ items: [], unread: 0 }) }, streamFactory: stream.factory, ...t });
  await bell.start();
  stream.opts.onState('live');
  for (let i = 0; i < STREAM_GIVE_UP + 2; i++) stream.opts.onState('reconnecting');
  assert.equal(stream.stopped, 0);
  bell.stop();
});
