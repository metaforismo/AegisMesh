import { toCan } from '../static/assets/js/lib/perms.js';
// Renders the Fleet screen into the fake DOM with a stubbed API, to check
// role gating and the hub-disabled / roles-off states without a browser.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createFakeDocument } from './fakedom.mjs';

globalThis.document = createFakeDocument();
const { default: fleet } = await import('../static/assets/js/screens/fleet.js');
const { ApiError } = await import('../static/assets/js/lib/api.js');
const { roleAtLeast } = await import('../static/assets/js/lib/taxonomy.js');

const FP = 'ab'.repeat(32);
const NODE = {
  id: FP.slice(0, 32), name: 'edge-01', status: 'stale', enrolled_at: '2026-11-15T08:00:00Z', last_seen_at: '2026-11-15T09:00:00Z',
  version: { version: '0.3.0', commit: 'abc1234', go: 'go1.25' }, uptime_seconds: 60, sensors: [{ id: 'web', kind: 'http', state: 'failed' }],
  counters: { interaction: 5, canary_invocation: 1, correlation_signal: 0 }, bus_dropped_events: 0, storage_healthy: true, public_key_fingerprint: FP,
};

function ctx(role, fleetRes, { nodes = { nodes: [NODE] }, tokens = { tokens: [{ id: 'tok_1', note: 'n', expires_at: '2026-11-15T10:00:00Z' }] } } = {}) {
  const calls = [];
  const reply = (v) => (v instanceof Error ? Promise.reject(v) : Promise.resolve(v));
  return {
    calls,
    role, can: toCan(role), route: { query: {}, params: {} }, signal: undefined,
    navigate() {}, rerender() {},
    api: {
      fleet: () => { calls.push('fleet'); return reply(fleetRes); },
      fleetNodes: () => { calls.push('nodes'); return reply(nodes); },
      enrollmentTokens: () => { calls.push('tokens'); return reply(tokens); },
    },
  };
}

const HUB = { hub: { enabled: true, listen: '127.0.0.1:9130', tls: false }, agent: { enabled: false, hub_url: '', node_id: '', enrolled: false, last_heartbeat_at: '', last_error: '' } };
const NONE = { hub: { enabled: false, listen: '', tls: false }, agent: { enabled: false, hub_url: '', node_id: '', enrolled: false, last_heartbeat_at: '', last_error: '' } };

async function render(c) {
  const root = document.createElement('main');
  await fleet.render(root, c);
  return root;
}

test('roles off: teaching state, no inventory requests', async () => {
  const c = ctx('admin', NONE);
  const root = await render(c);
  assert.match(root.textContent, /not enabled on this node/);
  assert.match(root.textContent, /docs\/configuration\.md/);
  assert.match(root.textContent, /cannot command or configure nodes/);
  assert.deepEqual(c.calls, ['fleet']);
});

test('viewer on a hub sees inventory but no token controls', async () => {
  const c = ctx('viewer', HUB);
  const root = await render(c);
  assert.match(root.textContent, /edge-01/);
  assert.match(root.textContent, /Stale/);
  assert.match(root.textContent, /1 failed/);
  assert.doesNotMatch(root.textContent, /Enrollment tokens/);
  assert.ok(!c.calls.includes('tokens'));
});

test('admin on a hub sees the token panel', async () => {
  const root = await render(ctx('admin', HUB));
  assert.match(root.textContent, /Enrollment tokens/);
  assert.match(root.textContent, /tok_1/);
  assert.match(root.textContent, /Create enrollment token/);
});

test('hub routes answering 503 render a hub-unavailable notice instead of failing', async () => {
  const down = new ApiError(503, 'unavailable', 'fleet hub is disabled');
  const root = await render(ctx('admin', HUB, { nodes: down, tokens: down }));
  assert.match(root.textContent, /Hub unavailable/);
  assert.match(root.textContent, /fleet hub is disabled/);
});

test('agent-only node explains where the inventory lives', async () => {
  const agent = { ...NONE, agent: { enabled: true, hub_url: 'https://hub.example.test:9130', node_id: NODE.id, enrolled: false, last_heartbeat_at: '', last_error: 'hub_unreachable' } };
  const c = ctx('admin', agent);
  const root = await render(c);
  assert.match(root.textContent, /This node is an agent, not a hub/);
  assert.match(root.textContent, /Not enrolled/);
  assert.match(root.textContent, /hub_unreachable/);
  assert.deepEqual(c.calls, ['fleet']);
});

// ---- Evidence forwarding ------------------------------------------------------

const ACCEPTING = { ...HUB, hub: { ...HUB.hub, accept_evidence: true } };
const LOSSY = { ...NODE, forwarding: { enabled: true, forwarded_total: 980, dropped_total: 37, last_forwarded_at: '2026-11-15T09:00:00Z', gaps_total: 2, queued_events: 500, queued_bytes: 1048576, last_error: 'queue_full' } };
const OFF = { ...NODE, id: 'cd'.repeat(16), name: 'quiet-01', forwarding: { enabled: false, forwarded_total: 0, dropped_total: 0, last_forwarded_at: '', gaps_total: 0 } };
const links = (root) => root.querySelectorAll((el) => el.tagName === 'a').map((a) => a.getAttribute('href'));

test('accepting hub: reception state, forwarding per node, labelled loss and view-events links', async () => {
  const root = await render(ctx('viewer', ACCEPTING, { nodes: { nodes: [LOSSY, OFF, NODE] } }));
  const text = root.textContent;
  assert.match(text, /Accepts forwarded evidence/);
  assert.match(text, /980 forwarded/);
  assert.match(text, /Not forwarded: 37 dropped, 2 gaps/);
  assert.match(text, /still exists in the node’s own store/);
  assert.match(text, /queue_full/);
  assert.match(text, /not reported/, 'a node without a forwarding block');
  assert.ok(links(root).includes(`#/events?node=${LOSSY.id}`));
  // Loss is a warning, never the danger color.
  const lossBadge = root.querySelectorAll((el) => /Not forwarded/.test(el.textContent) && String(el.getAttribute('class')).includes('badge'));
  assert.ok(lossBadge.length && lossBadge.every((b) => b.getAttribute('class').includes('badge--warn')));
});

test('hub refusing evidence: reception off, no view-events links', async () => {
  const root = await render(ctx('viewer', { ...HUB, hub: { ...HUB.hub, accept_evidence: false } }, { nodes: { nodes: [LOSSY] } }));
  assert.match(root.textContent, /Inventory only: this hub refuses forwarded evidence/);
  assert.ok(!links(root).some((h) => h.startsWith('#/events?node=')));
});

test('agent role shows its own forwarding state and error category', async () => {
  const agent = { ...NONE, agent: { enabled: true, hub_url: 'https://hub.example.test:9130', node_id: NODE.id, enrolled: true, last_heartbeat_at: '', last_error: '', forwarding: { enabled: true, forwarded_total: 12, dropped_total: 5, last_forwarded_at: '', gaps_total: 0, last_error: 'evidence_disabled' } } };
  const root = await render(ctx('viewer', agent));
  assert.match(root.textContent, /Evidence forwarding/);
  assert.match(root.textContent, /evidence_disabled/);
  assert.match(root.textContent, /The hub does not accept evidence/);
  assert.match(root.textContent, /Not forwarded: 5 dropped/);
});
