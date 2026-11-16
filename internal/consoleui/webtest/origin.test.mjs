// Evidence origin (forwarded evidence on a hub): node filter normalization,
// browser-side live matching, origin formatting and row identity.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  LOCAL, isNodeFilter, normalizeNodeFilter, originOf, matchesNodeFilter, describeOrigin, originVisible,
  rankByNode, eventKey, parseEventKey, originQuery, nodeFilterOptions, nodeFilterTargets, shortNodeId,
} from '../static/assets/js/lib/origin.js';
import { normalizeEventFilters, matchesEventFilters, parseHash, href } from '../static/assets/js/lib/route.js';

const A = 'a1'.repeat(16);
const B = 'b2'.repeat(16);
const ID = 'cd'.repeat(16);
const local = { id: ID, time: '2026-11-15T10:00:00Z', summary: 'GET /', source: '203.0.113.7', rule_ids: [] };
const fromA = { ...local, node: { id: A, name: 'edge-berlin-01' } };

test('node filter accepts exactly "local" or a lowercase 32-hex id', () => {
  for (const ok of [LOCAL, A]) assert.equal(isNodeFilter(ok), true, ok);
  for (const bad of ['', 'LOCAL', 'Local', A.toUpperCase(), A.slice(1), `${A}0`, '../x', 'local ', null, 7]) assert.equal(isNodeFilter(bad), false, String(bad));
  assert.equal(normalizeNodeFilter(` ${A} `), A);
  assert.equal(normalizeNodeFilter('remote'), '');
  assert.equal(normalizeNodeFilter(undefined), '');
});

test('the node filter goes through URL normalization and is reported when invalid', () => {
  assert.deepEqual(normalizeEventFilters({ node: LOCAL, severity: 'high' }).filters, { node: LOCAL, severity: 'high' });
  assert.deepEqual(normalizeEventFilters({ node: A }).filters, { node: A });
  const bad = normalizeEventFilters({ node: 'evil<script>', classification: 'interaction' });
  assert.deepEqual(bad.filters, { classification: 'interaction' });
  assert.deepEqual(bad.rejected, ['node']);
  // URL → filters round trip.
  const r = parseHash(href('events', { node: A, q: 'x' }));
  assert.equal(normalizeEventFilters(r.query).filters.node, A);
});

test('origin of an event: absent or "local" node means this node', () => {
  assert.equal(originOf(local), LOCAL);
  assert.equal(originOf({ ...local, node: null }), LOCAL);
  assert.equal(originOf({ ...local, node: { id: '' } }), LOCAL);
  assert.equal(originOf(fromA), A);
});

test('live matching mirrors the server node filter', () => {
  assert.equal(matchesNodeFilter(local, ''), true);
  assert.equal(matchesNodeFilter(fromA, ''), true);
  assert.equal(matchesNodeFilter(local, LOCAL), true);
  assert.equal(matchesNodeFilter(fromA, LOCAL), false);
  assert.equal(matchesNodeFilter(fromA, A), true);
  assert.equal(matchesNodeFilter(fromA, B), false);
  assert.equal(matchesNodeFilter(local, A), false);
  // Combined with the other filters in the shared matcher.
  assert.equal(matchesEventFilters(fromA, { node: A, q: 'get' }), true);
  assert.equal(matchesEventFilters(fromA, { node: A, q: 'post' }), false);
  assert.equal(matchesEventFilters(local, { node: A }), false);
  assert.equal(matchesEventFilters(local, { node: LOCAL }), true);
});

test('origin formatting: this node, named node with short id, unnamed and malformed', () => {
  assert.deepEqual(describeOrigin(undefined), { local: true, id: LOCAL, linkable: false, name: 'This node', named: true, short: '', text: 'This node' });
  assert.equal(describeOrigin({ id: LOCAL, name: '' }).text, 'This node');
  const a = describeOrigin(fromA.node);
  assert.equal(a.local, false);
  assert.equal(a.text, `edge-berlin-01 (${A.slice(0, 8)})`);
  assert.equal(a.linkable, true);
  assert.equal(describeOrigin({ id: A, name: '  ' }).text, `Unnamed node (${A.slice(0, 8)})`);
  const odd = describeOrigin({ id: 'not-an-id', name: 'x' });
  assert.equal(odd.linkable, false);
  assert.equal(odd.short, '');
  assert.equal(shortNodeId('zz'), '');
});

test('origin column: only on an accepting hub, a node filter, or forwarded rows', () => {
  assert.equal(originVisible({ fleet: null, events: [local] }), false);
  assert.equal(originVisible({ fleet: { hub: { enabled: true, accept_evidence: false } }, events: [local] }), false);
  assert.equal(originVisible({ fleet: { hub: { enabled: true, accept_evidence: true } }, events: [] }), true);
  assert.equal(originVisible({ events: [local, fromA] }), true);
  assert.equal(originVisible({ filter: LOCAL }), true);
});

test('by_node is ranked by events, ties by id, malformed rows dropped', () => {
  const ranked = rankByNode([
    { id: LOCAL, name: '', events: 40 },
    { id: B, name: 'b', events: 40 },
    { id: A, name: 'a', events: 90 },
    { id: 'bogus', name: 'x', events: 1000 },
    { id: 'ff'.repeat(16), name: 'neg', events: -3 },
    null,
  ]);
  assert.deepEqual(ranked.map((r) => r.id), [A, B, LOCAL, 'ff'.repeat(16)]);
  assert.equal(ranked[3].events, 0);
  assert.deepEqual(rankByNode(undefined), []);
});

test('row identity and detail links carry the origin', () => {
  assert.equal(eventKey(local), ID);
  assert.equal(eventKey(fromA), `${ID}@${A}`);
  assert.notEqual(eventKey(local), eventKey(fromA), 'same id, different origin, different row');
  assert.deepEqual(parseEventKey(eventKey(fromA)), { id: ID, node: A });
  assert.deepEqual(parseEventKey(ID), { id: ID, node: '' });
  assert.deepEqual(parseEventKey(`${ID}@nope`), { id: ID, node: '' });
  assert.deepEqual(originQuery(local), {});
  assert.deepEqual(originQuery(fromA), { node: A });
});

test('node filter options: any, this node, nodes by name, unknown current value kept', () => {
  const opts = nodeFilterOptions([{ id: B, name: 'zulu' }, { id: A, name: 'alpha' }, { id: 'bad', name: 'x' }], 'ee'.repeat(16));
  assert.deepEqual(opts.map((o) => o[0]), ['', LOCAL, A, B, 'ee'.repeat(16)]);
  assert.match(opts[4][1], /not in the registry/);
  assert.equal(nodeFilterOptions([], LOCAL).length, 2);
});

test('palette node targets exist only on an accepting hub', () => {
  assert.deepEqual(nodeFilterTargets({ hub: { enabled: true, accept_evidence: false } }, [{ id: A, name: 'a' }]), []);
  const t = nodeFilterTargets({ hub: { enabled: true, accept_evidence: true } }, [{ id: A, name: 'edge' }, { id: 'x' }]);
  assert.deepEqual(t.map((x) => x.node), [LOCAL, A]);
  assert.ok(t[1].keywords.includes(A), 'searchable by full id');
});
