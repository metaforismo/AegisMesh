// Mock contract for round 4 (contract r4): campaigns, actor profiles on
// sessions and the posture review, and `--round4 off` behaving like an
// older server (404 on the new routes, no new session fields).
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { stepShape, SIGNAL_CODES } from '../devserver/mock-insight.mjs';

const start = (args) => new Promise((resolve, reject) => {
  const port = 22000 + Math.floor(Math.random() * 1000);
  const proc = spawn(process.execPath, [fileURLToPath(new URL('../devserver/mock-server.mjs', import.meta.url)), '--port', String(port), ...args], { stdio: ['ignore', 'pipe', 'inherit'] });
  const t = setTimeout(() => reject(new Error('mock did not start')), 5000);
  proc.stdout.on('data', (d) => { if (String(d).includes('console mock on')) { clearTimeout(t); resolve({ proc, base: `http://127.0.0.1:${port}` }); } });
});
let on;
let off;
before(async () => { [on, off] = await Promise.all([start([]), start(['--round4', 'off'])]); });
after(() => { on?.proc.kill(); off?.proc.kill(); });

async function login(base, token = 'dev-viewer') {
  const res = await fetch(`${base}/api/v1/session`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ token }) });
  return (res.headers.get('set-cookie') || '').split(';')[0];
}
const get = (base, cookie, path) => fetch(`${base}/api/v1${path}`, { headers: { cookie } });

const ITEM_KEYS = ['automation_counts', 'basis', 'event_count', 'first_seen', 'id', 'label', 'last_seen', 'max_severity', 'rule_ids', 'sensor_kinds', 'session_count', 'session_ids', 'source_count', 'sources', 'sources_truncated', 'stages'].sort();

test('step shapes are normalised and never carry query strings or ids', () => {
  const ev = (kind, summary, classification = 'interaction') => ({ sensor: { kind }, summary, classification });
  assert.equal(stepShape(ev('http', 'GET /v1/models?key=secret → 200')), 'GET /v1/models');
  assert.equal(stepShape(ev('http', 'GET /users/123/keys → 200')), 'GET /users/{n}/keys');
  assert.equal(stepShape(ev('mcp', 'tools/call read_file path=".env"')), 'tools/call read_file');
  assert.equal(stepShape(ev('ssh', 'auth password user=root password=[redacted]')), 'auth password');
  assert.equal(stepShape(ev('ssh', 'exec class=download cmd="wget"')), 'exec download');
  assert.equal(stepShape(ev('http', 'x', 'correlation_signal')), '');
});

test('campaigns: contract keys, at least two sources each, scripted playbooks present', async () => {
  const c = await login(on.base);
  const body = await (await get(on.base, c, '/campaigns')).json();
  assert.deepEqual(Object.keys(body).sort(), ['generated_at', 'items', 'scanned_sessions', 'truncated']);
  assert.ok(body.items.length >= 3);
  for (const item of body.items) {
    assert.deepEqual(Object.keys(item).sort(), ITEM_KEYS);
    assert.match(item.id, /^cmp_[0-9a-f]{12}$/);
    assert.ok(item.source_count >= 2 && new Set(item.sources).size === item.sources.length);
    assert.ok(item.basis.includes('same_step_sequence'));
  }
  const llm = body.items.find((x) => x.sources.includes('203.0.113.66'));
  assert.deepEqual(llm.sources, ['198.51.100.212', '2001:db8::77', '203.0.113.66', '203.0.113.81']);
  assert.ok(body.items.some((x) => x.sources.includes('198.51.100.140') && x.basis.includes('same_client_family')));
  assert.equal((await get(on.base, c, '/campaigns?window=24h')).status, 400, 'strict query');
});

test('campaign detail: steps, sessions with actor and step marks, caveats; 404 and 400', async () => {
  const c = await login(on.base);
  const list = await (await get(on.base, c, '/campaigns')).json();
  const id = list.items.find((x) => x.sources.includes('203.0.113.66')).id;
  const d = await (await get(on.base, c, `/campaigns/${id}`)).json();
  assert.ok(d.steps.length >= 6);
  assert.deepEqual(d.steps.map((s) => s.index), d.steps.map((_, i) => i));
  assert.deepEqual(d.steps.slice(0, 4).map((s) => s.shape), ['GET /', 'GET /api/version', 'GET /api/tags', 'GET /v1/models']);
  assert.ok(d.steps.some((s) => s.sessions < d.session_count), 'some steps are taken by only some sessions');
  for (const s of d.sessions) {
    assert.equal(s.campaign_id, id);
    assert.ok(Array.isArray(s.step_marks) && s.step_marks[0].offset_ms === 0);
    assert.ok(Object.keys(s.actor).includes('signals'));
  }
  assert.ok(d.caveats.some((t) => /not prove a shared operator/.test(t)));
  assert.equal((await get(on.base, c, '/campaigns/cmp_000000000000')).status, 404);
  assert.equal((await get(on.base, c, '/campaigns/nope')).status, 400);
});

test('sessions carry campaign_id and an actor profile listing every signal', async () => {
  const c = await login(on.base);
  const body = await (await get(on.base, c, '/sessions?window=24h&limit=200')).json();
  for (const s of body.sessions) {
    assert.ok(s.campaign_id === null || /^cmp_/.test(s.campaign_id));
    assert.ok(['likely_automated', 'possibly_ai_agent', 'likely_human', 'inconclusive'].includes(s.actor.assessment));
    assert.deepEqual(s.actor.signals.map((x) => x.code), SIGNAL_CODES);
    for (const x of s.actor.signals) assert.ok(['strong', 'moderate', 'weak'].includes(x.strength));
    assert.doesNotMatch(s.actor.summary, /\d+%|certain|confirmed/i);
  }
  const by = (src) => body.sessions.find((s) => s.source === src);
  assert.equal(by('203.0.113.66').actor.assessment, 'possibly_ai_agent');
  assert.equal(by('192.0.2.150').actor.assessment, 'likely_human');
});

test('posture: summary matches checks, every area present, ok items carry no recommendation', async () => {
  const c = await login(on.base);
  const p = await (await get(on.base, c, '/posture')).json();
  assert.deepEqual(Object.keys(p).sort(), ['checks', 'disclaimer', 'generated_at', 'scope', 'summary']);
  const count = (k) => p.checks.filter((x) => x.status === k).length;
  assert.deepEqual(p.summary, { attention: count('attention'), ok: count('ok'), info: count('info') });
  assert.deepEqual([...new Set(p.checks.map((x) => x.area))].sort(), ['access', 'deception', 'detection', 'evidence', 'exposure']);
  for (const x of p.checks) {
    if (x.status === 'ok') assert.equal(x.recommendation, '');
    assert.match(x.doc, /^docs\/[a-z0-9/_-]+\.md(#[a-z0-9-]+)?$/);
  }
});

test('--round4 off behaves like an older server', async () => {
  const c = await login(off.base);
  for (const path of ['/campaigns', '/campaigns/cmp_000000000000', '/posture']) assert.equal((await get(off.base, c, path)).status, 404, path);
  const body = await (await get(off.base, c, '/sessions?window=24h')).json();
  assert.ok(body.sessions.every((s) => !('actor' in s) && !('campaign_id' in s)));
});
