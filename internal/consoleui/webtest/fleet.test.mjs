import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  FLEET_STATUSES, fleetStatusMeta, normalizeFleetStatus, isNodeId, idMatchesFingerprint, formatFingerprint,
  sensorSummary, isValidTtl, validateTokenNote, normalizeExpiry, formatExpiresIn, TTL_CHOICES,
} from '../static/assets/js/lib/fleet.js';
import { parseHash, href } from '../static/assets/js/lib/route.js';
import { AUDIT_ACTIONS } from '../static/assets/js/lib/taxonomy.js';

const FP = 'ab'.repeat(32);
const ID = FP.slice(0, 32);

test('every status has a distinct badge kind (and so a distinct shape) and a word', () => {
  const kinds = FLEET_STATUSES.map((s) => fleetStatusMeta(s).badge);
  assert.equal(new Set(kinds).size, FLEET_STATUSES.length);
  for (const s of FLEET_STATUSES) assert.ok(fleetStatusMeta(s).label);
  assert.equal(fleetStatusMeta('pwned').label, 'Unknown');
  assert.equal(normalizeFleetStatus('stale'), 'stale');
  assert.equal(normalizeFleetStatus('online '), '');
});

test('node id is the fingerprint prefix', () => {
  assert.ok(isNodeId(ID));
  assert.ok(!isNodeId(ID.toUpperCase()));
  assert.ok(idMatchesFingerprint(ID, FP));
  assert.ok(!idMatchesFingerprint('cd'.repeat(16), FP));
  assert.ok(!idMatchesFingerprint(ID, 'xyz'));
  assert.equal(formatFingerprint(FP).split(' ').length, 8);
  assert.equal(formatFingerprint('nope'), '');
});

test('sensor summary counts states and tolerates junk', () => {
  assert.deepEqual(sensorSummary([{ state: 'running' }, { state: 'failed' }, { state: 'stopped' }, { state: 'weird' }, null]),
    { total: 5, running: 1, stopped: 1, failed: 1, other: 2 });
  assert.equal(sensorSummary(undefined).total, 0);
});

test('token TTL and note bounds follow the contract', () => {
  assert.ok(isValidTtl(1) && isValidTtl(86400));
  assert.ok(!isValidTtl(0) && !isValidTtl(86401) && !isValidTtl(1.5));
  for (const [v] of TTL_CHOICES) assert.ok(isValidTtl(v));
  assert.equal(validateTokenNote(''), '');
  assert.equal(validateTokenNote('edge-01 rollout (ops)'), '');
  assert.notEqual(validateTokenNote('ünïcode'), '');
  assert.notEqual(validateTokenNote('tab\there'), '');
  assert.notEqual(validateTokenNote('x'.repeat(257)), '');
  assert.equal(validateTokenNote('x'.repeat(256)), '');
});

test('expiry accepts RFC 3339 and legacy Unix seconds', () => {
  assert.equal(normalizeExpiry('2026-11-15T10:00:00.123456789Z'), '2026-11-15T10:00:00.123456789Z');
  assert.equal(normalizeExpiry(1794736800), '2026-11-15T10:00:00Z');
  assert.equal(normalizeExpiry('soon'), '');
  const now = Date.parse('2026-11-15T09:00:00Z');
  assert.equal(formatExpiresIn('2026-11-15T09:45:00Z', now), 'in 45m');
  assert.equal(formatExpiresIn('2026-11-15T12:10:00Z', now), 'in 3h 10m');
  assert.equal(formatExpiresIn('2026-11-15T10:00:00Z', now), 'in 1h');
  assert.equal(formatExpiresIn('2026-11-15T09:00:00Z', now), 'expired');
  assert.equal(formatExpiresIn('', now), 'unknown expiry');
});

test('fleet routes parse and reject bad node ids', () => {
  assert.equal(parseHash('#/fleet').name, 'fleet');
  assert.equal(parseHash('#/fleet/nodes').name, 'fleet');
  assert.equal(parseHash('#/fleet?status=stale').query.status, 'stale');
  const r = parseHash(href('fleet', 'nodes', ID));
  assert.equal(r.name, 'fleet_node');
  assert.equal(r.params.id, ID);
  for (const bad of ['#/fleet/nodes/xyz', `#/fleet/nodes/${ID.toUpperCase()}`, `#/fleet/nodes/${ID}0`]) {
    assert.equal(parseHash(bad).name, 'not_found', bad);
  }
});

test('fleet audit actions are part of the closed vocabulary', () => {
  for (const a of ['fleet.token.create', 'fleet.token.delete', 'fleet.node.enroll', 'fleet.node.revoke', 'fleet.node.rejected']) {
    assert.ok(AUDIT_ACTIONS.includes(a), a);
  }
});
