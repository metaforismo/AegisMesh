import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createApi, ApiError, describeError } from '../static/assets/js/lib/api.js';

function fakeFetch(handler) {
  const calls = [];
  const impl = async (url, init) => {
    calls.push({ url, init });
    const { status = 200, body, headers = {} } = handler(url, init) ?? {};
    return {
      status, ok: status >= 200 && status < 300,
      headers: { get: (k) => headers[k] ?? null },
      json: async () => { if (typeof body === 'string') throw new SyntaxError('not json'); return body; },
    };
  };
  return { impl, calls };
}

const SESSION = { principal: { name: 'alice', role: 'analyst' }, csrf_token: 'csrf-1', expires_at: '2026-11-14T12:00:00Z' };

test('login stores CSRF in memory and sends it only on mutations', async () => {
  const f = fakeFetch((url, init) => (init.method === 'POST' && url.endsWith('/session') ? { body: SESSION } : { body: {} }));
  const api = createApi({ fetchImpl: f.impl });
  await api.login('tok');
  assert.deepEqual(JSON.parse(f.calls[0].init.body), { token: 'tok' });
  await api.sensors();
  await api.updateInvestigation('inv_1', { status: 'closed' });
  assert.equal(f.calls[1].init.headers['X-AegisMesh-CSRF'], undefined);
  assert.equal(f.calls[2].init.headers['X-AegisMesh-CSRF'], 'csrf-1');
  assert.equal(f.calls[2].init.method, 'PATCH');
  assert.equal(f.calls[2].init.credentials, 'same-origin');
});

test('logout sends CSRF (contract: DELETE /session is a mutation) and forgets it', async () => {
  const f = fakeFetch((url, init) => (init.method === 'DELETE' ? { status: 204 } : { body: SESSION }));
  const api = createApi({ fetchImpl: f.impl });
  await api.session();
  await api.logout();
  assert.equal(f.calls[1].init.headers['X-AegisMesh-CSRF'], 'csrf-1');
  assert.equal(api.hasCsrf(), false);
});

test('path segments and query values are encoded', async () => {
  const f = fakeFetch(() => ({ body: {} }));
  const api = createApi({ fetchImpl: f.impl });
  await api.source('2001:db8::1/x', 'c1', 10);
  await api.events({ q: 'a b&c', severity: 'high', sensor: undefined });
  assert.equal(f.calls[0].url, '/api/v1/sources/2001%3Adb8%3A%3A1%2Fx?cursor=c1&limit=10');
  assert.equal(f.calls[1].url, '/api/v1/events?q=a%20b%26c&severity=high');
});

test('401 on a data call clears CSRF and notifies once', async () => {
  let notified = 0;
  const f = fakeFetch((url) => (url.endsWith('/session') ? { body: SESSION } : { status: 401, body: { error: { code: 'unauthenticated', message: 'expired' } } }));
  const api = createApi({ fetchImpl: f.impl, onUnauthenticated: () => notified++ });
  await api.session();
  await assert.rejects(api.node(), (e) => e instanceof ApiError && e.status === 401 && e.code === 'unauthenticated');
  assert.equal(notified, 1);
  assert.equal(api.hasCsrf(), false);
});

test('401 from the session probe or login does not trigger the redirect hook', async () => {
  let notified = 0;
  const f = fakeFetch(() => ({ status: 401, body: { error: { code: 'unauthenticated', message: 'no' } } }));
  const api = createApi({ fetchImpl: f.impl, onUnauthenticated: () => notified++ });
  await assert.rejects(api.session());
  await assert.rejects(api.login('bad'));
  assert.equal(notified, 0);
});

test('error envelope parsing tolerates junk and unknown codes', async () => {
  const f = fakeFetch((url) => {
    if (url.includes('rules')) return { status: 502, body: '<html>bad gateway</html>' };
    if (url.includes('node')) return { status: 400, body: { error: { code: 'pwned', message: 'x'.repeat(1000) } } };
    return { status: 429, body: { error: { code: 'rate_limited', message: 'slow' } }, headers: { 'Retry-After': '7' } };
  });
  const api = createApi({ fetchImpl: f.impl });
  await assert.rejects(api.rules(), (e) => e.code === 'internal' && e.status === 502);
  await assert.rejects(api.node(), (e) => e.code === 'invalid_argument' && e.message.length === 300);
  await assert.rejects(api.login('t'), (e) => e.code === 'rate_limited' && e.retryAfter === 7);
});

test('network failure becomes unavailable; abort passes through', async () => {
  const api = createApi({ fetchImpl: async () => { throw new TypeError('Failed to fetch'); } });
  await assert.rejects(api.node(), (e) => e.code === 'unavailable' && e.status === 0);
  const abort = createApi({ fetchImpl: async () => { const e = new Error('aborted'); e.name = 'AbortError'; throw e; } });
  await assert.rejects(abort.node(), (e) => e.name === 'AbortError');
});

test('describeError gives operator-facing text for every code', () => {
  for (const code of ['unauthenticated', 'forbidden', 'not_found', 'rate_limited', 'unavailable', 'invalid_argument', 'conflict', 'internal']) {
    const d = describeError(new ApiError(400, code, 'm'));
    assert.ok(d.title && d.detail, code);
  }
  assert.equal(describeError(new Error('boom')).detail, 'boom');
});

test('screenFailure: older server, missing object, retryable outage', async () => {
  const { screenFailure, ApiError: E } = await import('../static/assets/js/lib/api.js');
  const missing = new E(404, 'not_found', 'not found');
  const older = screenFailure(missing, { name: 'decoys', title: 'Decoys' });
  assert.equal(older.title, 'This server does not provide decoys yet');
  assert.equal(older.retry, false);
  assert.deepEqual(older.actions.map((a) => a[0]), ['#/overview', '#/guide']);
  assert.equal(screenFailure(new E(501, 'internal', 'x'), { name: 'digest', title: 'Digest' }).retry, false);
  // On a detail route a 404 is a missing object; the way back is its list.
  const gone = screenFailure(missing, { name: 'attack_session', title: 'Session' });
  assert.equal(gone.title, 'Not found');
  assert.equal(gone.retry, false);
  assert.deepEqual(gone.actions, [['#/sessions', 'Go to sessions']]);
  const down = screenFailure(new E(0, 'unavailable', 'offline'), { name: 'events', title: 'Events' });
  assert.equal(down.retry, true);
  assert.equal(down.title, 'Console unavailable');
  assert.equal(screenFailure(new TypeError('boom'), { name: 'node', title: 'Node' }).retry, true);
});
