import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseHash, href, encodeSegment, normalizeEventFilters, matchesEventFilters, normalizeWindow, normalizeAuditFilters, isRfc3339 } from '../static/assets/js/lib/route.js';
import { isSafeHref } from '../static/assets/js/lib/dom.js';

const ID = '0123456789abcdef0123456789abcdef';

test('parseHash resolves every screen', () => {
  const cases = [
    ['', 'overview'], ['#/', 'overview'], ['#/overview?window=7d', 'overview'], ['#/events', 'events'],
    [`#/events/${ID}`, 'event'], ['#/sources', 'sources'], ['#/sources/203.0.113.7', 'source'],
    ['#/sensors', 'sensors'], ['#/rules', 'rules'], ['#/recommendations', 'recommendations'], ['#/node', 'node'],
    ['#/investigations', 'investigations'], ['#/investigations/inv_01', 'investigation'], ['#/audit', 'audit'], ['#/login', 'login'],
  ];
  for (const [hash, name] of cases) assert.equal(parseHash(hash).name, name, hash);
});

test('invalid params and unknown paths are not_found', () => {
  for (const hash of ['#/events/xyz', '#/events/' + ID.toUpperCase(), '#/nope', '#/investigations/a%2Fb', '#/sources/%E0%A4%A', `#/events/${ID}/x`]) {
    assert.equal(parseHash(hash).name, 'not_found', hash);
  }
});

test('source keys round-trip through href and parseHash', () => {
  for (const key of ['2001:db8::1', 'corr/key with space', "it's(*)!", 'ünï', '203.0.113.7']) {
    const link = href('sources', key);
    assert.ok(isSafeHref(link), link);
    const r = parseHash(link);
    assert.equal(r.name, 'source');
    assert.equal(r.params.source, key);
  }
});

test('oversized source key is rejected', () => {
  assert.equal(parseHash(href('sources', 'a'.repeat(256))).name, 'not_found');
  assert.equal(parseHash(href('sources', 'a'.repeat(255))).name, 'source');
});

test('query round-trip, first value wins, empty dropped', () => {
  const link = href('events', { q: 'a&b=c', severity: 'high', sensor: '' });
  assert.equal(link, '#/events?q=a%26b%3Dc&severity=high');
  assert.deepEqual(parseHash(link).query, { q: 'a&b=c', severity: 'high' });
  assert.equal(parseHash('#/events?q=1&q=2').query.q, '1');
});

test('encodeSegment escapes the characters encodeURIComponent leaves', () => {
  assert.equal(encodeSegment("!'()*"), '%21%27%28%29%2A');
});

test('normalizeEventFilters keeps valid values and reports the rest', () => {
  const { filters, rejected } = normalizeEventFilters({
    classification: 'interaction', severity: 'bogus', kind: 'grpc', sensor: 'web', since: '2026-11-14T00:00:00Z',
    until: 'yesterday', q: 'x'.repeat(129), rule: 'PI-001', other: 'ignored',
  });
  assert.deepEqual(filters, { classification: 'interaction', sensor: 'web', rule: 'PI-001', since: '2026-11-14T00:00:00Z' });
  assert.deepEqual(rejected.sort(), ['kind', 'q', 'severity', 'until']);
});

test('inverted time range is rejected', () => {
  const { filters, rejected } = normalizeEventFilters({ since: '2026-11-14T10:00:00Z', until: '2026-11-14T09:00:00Z' });
  assert.deepEqual(filters, {});
  assert.deepEqual(rejected, ['since', 'until']);
});

test('isRfc3339', () => {
  assert.ok(isRfc3339('2026-11-14T09:03:44.123Z'));
  assert.ok(isRfc3339('2026-11-14T09:03:44+01:00'));
  assert.ok(!isRfc3339('2026-11-14 09:03:44'));
  assert.ok(!isRfc3339('2026-13-45T09:03:44Z'));
});

test('windows and audit filters fall back to safe defaults', () => {
  assert.equal(normalizeWindow('7d'), '7d');
  assert.equal(normalizeWindow('30d'), '24h');
  assert.deepEqual(normalizeAuditFilters({ action: 'audit.read', actor: 'alice' }), { action: 'audit.read', actor: 'alice' });
  assert.deepEqual(normalizeAuditFilters({ action: 'drop.table', actor: 'a b' }), {});
});

const ev = {
  id: ID, time: '2026-11-14T09:00:00Z', classification: 'interaction', source: '203.0.113.7',
  sensor: { id: 'web', kind: 'http' }, summary: 'GET /Admin → 200', severity: 'medium', rule_ids: ['PI-001'],
};

test('matchesEventFilters mirrors the server filter semantics', () => {
  const yes = [{}, { classification: 'interaction' }, { sensor: 'web' }, { kind: 'http' }, { source: '203.0.113.7' },
    { rule: 'PI-001' }, { severity: 'low' }, { severity: 'medium' }, { since: '2026-11-14T09:00:00Z' },
    { until: '2026-11-14T09:00:00Z' }, { q: 'admin' }, { q: 'pi-0' }, { q: '113.7' }];
  const no = [{ classification: 'correlation_signal' }, { sensor: 'mcp' }, { kind: 'ssh' }, { source: '203.0.113.8' },
    { rule: 'PI-002' }, { severity: 'high' }, { since: '2026-11-14T09:00:01Z' }, { until: '2026-11-14T08:59:59Z' }, { q: 'zzz' }];
  for (const f of yes) assert.ok(matchesEventFilters(ev, f), JSON.stringify(f));
  for (const f of no) assert.ok(!matchesEventFilters(ev, f), JSON.stringify(f));
});

test('events without a finding never meet a minimum severity', () => {
  assert.ok(!matchesEventFilters({ ...ev, severity: '' }, { severity: 'info' }));
  assert.ok(!matchesEventFilters(null, {}));
});
