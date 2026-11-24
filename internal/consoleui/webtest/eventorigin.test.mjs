import { toCan } from '../static/assets/js/lib/perms.js';
// Event detail for local and forwarded evidence, rendered into the fake DOM
// with a stubbed API: origin, hub-side integrity wording, and that a
// forwarded copy cannot be attached to a (local-only) investigation.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createFakeDocument } from './fakedom.mjs';

globalThis.document = createFakeDocument();
const { renderEventDetail } = await import('../static/assets/js/screens/event.js');
const { roleAtLeast } = await import('../static/assets/js/lib/taxonomy.js');

const ID = 'cd'.repeat(16);
const NODE = { id: 'a1'.repeat(16), name: 'edge-berlin-01' };
const summary = { id: ID, time: '2026-11-15T10:00:00Z', seq: 4, sensor: { id: 'web', kind: 'http', listen: '' }, classification: 'interaction', source: '203.0.113.7', summary: 'GET /', severity: '', rule_ids: [], action: '' };
const detail = (extra = {}) => ({ summary, envelope: {}, integrity: { verified: true, algorithm: 'sha256', error: '' }, findings: [], related: [], investigations: [], ...extra });

function ctx(d, { accepting = true } = {}) {
  const calls = [];
  return {
    calls, role: 'analyst', can: toCan('analyst'), route: { query: {}, params: {} }, signal: undefined, rerender() {},
    api: {
      event: (id, node) => { calls.push([id, node]); return Promise.resolve(d); },
      fleet: () => Promise.resolve({ hub: { enabled: true, listen: '', tls: false, accept_evidence: accepting }, agent: {} }),
    },
  };
}
const render = async (c, opts) => {
  const root = document.createElement('main');
  await renderEventDetail(root, c, ID, opts);
  return root;
};
const buttons = (root) => root.querySelectorAll((el) => el.tagName === 'button').map((b) => b.textContent);
const hrefs = (root) => root.querySelectorAll((el) => el.tagName === 'a').map((a) => a.getAttribute('href'));

test('forwarded copy: origin, hub-side integrity scope, no investigation attach', async () => {
  const d = detail({
    node: NODE, summary: { ...summary, node: NODE },
    integrity: { verified: true, algorithm: 'sha256', error: '', scope: 'hub_payload_hash_consistency', description: '<b>server text</b>' },
  });
  const c = ctx(d);
  const root = await render(c, { node: NODE.id });
  assert.deepEqual(c.calls, [[ID, NODE.id]], 'detail request pinned to the origin');
  const text = root.textContent;
  assert.match(text, /edge-berlin-01/);
  assert.match(text, /Payload sha256 consistent on this hub/);
  assert.match(text, /consistency, not provenance/);
  assert.doesNotMatch(text, /server text/, 'the server description is not used as interface text');
  assert.match(text, /authoritative record/);
  assert.match(text, /Investigations hold this node’s own observations only/);
  assert.ok(!buttons(root).includes('Add to investigation'));
  assert.ok(hrefs(root).includes(`#/fleet/nodes/${NODE.id}`));
  assert.ok(hrefs(root).includes(`#/events?node=${NODE.id}`));
});

test('local event on an accepting hub: "This node", attach offered, no hub scope', async () => {
  const c = ctx(detail());
  const root = await render(c, { node: 'bogus' });
  assert.deepEqual(c.calls, [[ID, '']], 'an invalid origin is not sent');
  assert.match(root.textContent, /This node/);
  assert.match(root.textContent, /Payload sha256 verified/);
  assert.ok(buttons(root).includes('Add to investigation'));
});

test('local event on a node that receives no evidence: no origin row', async () => {
  const root = await render(ctx(detail(), { accepting: false }));
  assert.doesNotMatch(root.textContent, /Origin/);
});
