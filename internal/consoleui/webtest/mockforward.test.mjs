// Forwarded-evidence additions of the dev mock (console API, experimental
// forwarded evidence additions), started on loopback as an accepting hub, as
// a hub that refuses evidence, and as an agent.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const MOCK = fileURLToPath(new URL('../devserver/mock-server.mjs', import.meta.url));
const procs = [];

function start(...args) {
  const port = 22000 + Math.floor(Math.random() * 2000);
  const proc = spawn(process.execPath, [MOCK, '--port', String(port), ...args], { stdio: ['ignore', 'pipe', 'inherit'] });
  procs.push(proc);
  return new Promise((resolve, reject) => {
    const t = setTimeout(() => reject(new Error('mock did not start')), 30000);
    proc.stdout.on('data', (d) => { if (String(d).includes('console mock on')) { clearTimeout(t); resolve(`http://127.0.0.1:${port}`); } });
  });
}

let HUB;
let REFUSING;
let AGENT;
before(async () => { [HUB, REFUSING, AGENT] = await Promise.all([start('--fleet', 'hub'), start('--fleet', 'hub', '--accept-evidence', 'off'), start('--fleet', 'agent')]); });
after(() => { for (const p of procs) p.kill(); });

async function viewer(base) {
  const res = await fetch(`${base}/api/v1/session`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ token: 'dev-viewer' }) });
  const cookie = (res.headers.get('set-cookie') || '').split(';')[0];
  return async (path) => {
    const r = await fetch(`${base}/api/v1${path}`, { headers: { Cookie: cookie } });
    return { status: r.status, body: r.headers.get('content-type')?.includes('json') ? await r.json() : null };
  };
}

const allEvents = async (get, query = '') => {
  const out = [];
  let cursor = '';
  do {
    const { body } = await get(`/events?limit=200${query}${cursor ? `&cursor=${cursor}` : ''}`);
    out.push(...body.events);
    cursor = body.next_cursor;
  } while (cursor);
  return out;
};

test('accepting hub: fleet reports reception, forwarded events carry their origin', async () => {
  const get = await viewer(HUB);
  const f = (await get('/fleet')).body;
  assert.equal(f.hub.accept_evidence, true);
  assert.deepEqual(Object.keys(f.agent.forwarding).sort(), ['dropped_total', 'enabled', 'forwarded_total', 'gaps_total', 'last_forwarded_at']);
  const events = await allEvents(get);
  const forwarded = events.filter((e) => e.node);
  assert.ok(forwarded.length > 0 && forwarded.length < events.length);
  for (const e of forwarded) {
    assert.match(e.node.id, /^[0-9a-f]{32}$/);
    assert.equal(typeof e.node.name, 'string');
  }
});

test('node filter: local, one node, and invalid values', async () => {
  const get = await viewer(HUB);
  const all = await allEvents(get);
  const local = await allEvents(get, '&node=local');
  assert.ok(local.length > 0 && local.every((e) => !e.node));
  const nodeId = all.find((e) => e.node).node.id;
  const one = await allEvents(get, `&node=${nodeId}`);
  assert.ok(one.length > 0 && one.every((e) => e.node?.id === nodeId));
  assert.equal((await get('/events?node=LOCAL')).status, 400);
  assert.equal((await get(`/events?node=${nodeId.toUpperCase()}`)).status, 400);
  assert.equal((await get('/events?node=../x')).status, 400);
  assert.equal((await get('/events/stream?node=nope')).status, 400);
});

test('overview: by_node on an accepting hub, sorted by id, summing to the window total', async () => {
  const get = await viewer(HUB);
  const ov = (await get('/overview?window=7d')).body;
  assert.ok(Array.isArray(ov.by_node));
  assert.deepEqual(ov.by_node.map((r) => r.id), [...ov.by_node.map((r) => r.id)].sort());
  const local = ov.by_node.find((r) => r.id === 'local');
  assert.equal(local.name, '');
  assert.equal(ov.by_node.reduce((n, r) => n + r.events, 0), ov.totals.events);
});

test('detail: forwarded integrity scope, origin, and id disambiguation', async () => {
  const get = await viewer(HUB);
  const all = await allEvents(get);
  const ids = new Map();
  for (const e of all) ids.set(e.id, [...(ids.get(e.id) || []), e]);
  const twin = [...ids.values()].find((list) => list.length === 2);
  assert.ok(twin, 'the mock holds one id shared by a local and a forwarded event');
  const remote = twin.find((e) => e.node);
  // No node: local wins.
  const plain = (await get(`/events/${remote.id}`)).body;
  assert.equal(plain.node, undefined);
  assert.equal(plain.integrity.scope, undefined);
  // Pinned to the forwarding node: the forwarded copy, with the hub scope.
  const pinned = (await get(`/events/${remote.id}?node=${remote.node.id}`)).body;
  assert.deepEqual(pinned.node, remote.node);
  assert.deepEqual(pinned.summary.node, remote.node);
  assert.equal(pinned.integrity.scope, 'hub_payload_hash_consistency');
  assert.match(pinned.integrity.description, /consistency, not provenance/);
  assert.deepEqual(pinned.investigations, []);
  assert.equal((await get(`/events/${remote.id}?node=local`)).body.node, undefined);
  assert.equal((await get(`/events/${remote.id}?node=bad`)).status, 400);
  assert.equal((await get(`/events/${remote.id}?bogus=1`)).status, 400);
});

test('fleet nodes: forwarding states, one node with drops and gaps', async () => {
  const get = await viewer(HUB);
  const nodes = (await get('/fleet/nodes')).body.nodes;
  const fwd = nodes.filter((n) => n.forwarding);
  assert.ok(fwd.some((n) => n.forwarding.enabled === false), 'a node with forwarding off');
  assert.ok(nodes.some((n) => !n.forwarding), 'an agent that never reported forwarding');
  const lossy = fwd.filter((n) => n.forwarding.dropped_total > 0 && n.forwarding.gaps_total > 0);
  assert.equal(lossy.length, 1);
  assert.equal(typeof lossy[0].forwarding.queued_events, 'number');
  assert.match(lossy[0].forwarding.last_error, /^[a-z_]+$/);
  for (const n of fwd) for (const k of ['enabled', 'forwarded_total', 'dropped_total', 'last_forwarded_at', 'gaps_total']) assert.ok(k in n.forwarding, `${n.name}.${k}`);
});

test('hub refusing evidence: no by_node, no forwarded events, agents report evidence_disabled', async () => {
  const get = await viewer(REFUSING);
  assert.equal((await get('/fleet')).body.hub.accept_evidence, false);
  assert.equal('by_node' in (await get('/overview')).body, false);
  assert.ok((await allEvents(get)).every((e) => !e.node));
  assert.equal((await get('/node')).body.index.history, 'complete');
  const enabled = (await get('/fleet/nodes')).body.nodes.filter((n) => n.forwarding?.enabled);
  assert.ok(enabled.length > 0 && enabled.every((n) => n.forwarding.last_error === 'evidence_disabled' && n.forwarding.last_forwarded_at === ''));
});

test('agent: forwarding status always present, hub flag off', async () => {
  const get = await viewer(AGENT);
  const f = (await get('/fleet')).body;
  assert.equal(f.hub.accept_evidence, false);
  assert.equal(f.agent.forwarding.enabled, true);
  assert.equal(typeof f.agent.forwarding.queued_bytes, 'number');
});
