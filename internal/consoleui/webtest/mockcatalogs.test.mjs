// Mock contract for the round-3 additions (decoy and honeytoken catalogs,
// digest, local SIEM event formats, rule prose, overview index, event
// session links, source inter-arrival): shapes, roles, strict queries and
// the scripted MCP decoy-environment session the UI is developed against.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { interArrival, renderEvents, ruleRecord } from '../devserver/mock-catalogs.mjs';

const PORT = 25000 + Math.floor(Math.random() * 1000);
const BASE = `http://127.0.0.1:${PORT}`;
let proc;

before(async () => {
  proc = spawn(process.execPath, [fileURLToPath(new URL('../devserver/mock-server.mjs', import.meta.url)), '--port', String(PORT)], { stdio: ['ignore', 'pipe', 'inherit'] });
  await new Promise((resolve, reject) => {
    const t = setTimeout(() => reject(new Error('mock did not start')), 5000);
    proc.stdout.on('data', (d) => { if (String(d).includes('console mock on')) { clearTimeout(t); resolve(); } });
  });
});
after(() => proc?.kill());

async function login(token) {
  const res = await fetch(`${BASE}/api/v1/session`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ token }) });
  return (res.headers.get('set-cookie') || '').split(';')[0];
}
const get = (cookie, path) => fetch(`${BASE}/api/v1${path}`, { headers: { cookie } });
const BOUNDS_KEYS = ['index', 'scan_limit', 'scan_truncated', 'scanned_events'];
const sortedCopy = (a) => [...a].sort();

test('decoys: documented shape, sorted catalog, windows and strict queries', async () => {
  const c = await login('dev-viewer');
  const body = await (await get(c, '/decoys')).json();
  assert.deepEqual(Object.keys(body).sort(), ['bounds', 'decoys']);
  assert.deepEqual(Object.keys(body.bounds).sort(), BOUNDS_KEYS);
  const ids = body.decoys.map((d) => d.id);
  assert.deepEqual(ids, sortedCopy(ids));
  for (const d of body.decoys) {
    assert.deepEqual(Object.keys(d).sort(), ['events', 'fake_files', 'honeytoken_ids', 'id', 'kind', 'last_activity', 'listen', 'rules', 'surface_families', 'tools']);
    assert.deepEqual(d.surface_families, sortedCopy(d.surface_families));
    assert.ok(d.surface_families.length >= 1);
    if (d.events === 0) assert.equal(d.last_activity, '');
  }
  const ws = body.decoys.find((d) => d.id === 'ai-workspace');
  assert.deepEqual(ws.surface_families, ['mcp_environment']);
  assert.equal(ws.tools, 5);
  assert.equal(ws.fake_files, 3);
  assert.deepEqual(ws.honeytoken_ids, ['workspace-key']);
  assert.ok(ws.events >= 8);
  for (const w of ['1h', '24h', '7d']) assert.equal((await get(c, `/decoys?window=${w}`)).status, 200);
  assert.equal((await get(c, '/decoys?window=30d')).status, 400);
  assert.equal((await get(c, '/decoys?window=24h&window=7d')).status, 400);
  assert.equal((await get(c, '/decoys?bogus=1')).status, 400);
});

test('honeytokens: ids and kinds only, never a value; hits from planted ids', async () => {
  const c = await login('dev-viewer');
  const res = await get(c, '/honeytokens?window=24h');
  const text = await res.text();
  assert.doesNotMatch(text, /"value"/);
  const body = JSON.parse(text);
  assert.deepEqual(Object.keys(body).sort(), ['bounds', 'honeytokens']);
  for (const t of body.honeytokens) {
    assert.deepEqual(Object.keys(t).sort(), ['hit_count', 'id', 'kind', 'last_hit', 'sensor_ids', 'sources']);
    assert.ok(['credential', 'agent_canary'].includes(t.kind));
    if (!t.hit_count) assert.equal(t.last_hit, '');
  }
  const by = (id) => body.honeytokens.find((t) => t.id === id);
  assert.deepEqual(by('unplanted-spare').sensor_ids, []);
  assert.deepEqual(by('workspace-key').sources, ['198.51.100.140']);
  assert.equal(by('diagnostic-echo').kind, 'agent_canary');
  // The LLMjacking story and one campaign variant (198.51.100.212) replay it.
  assert.equal(by('planted-key').hit_count, 2);
  assert.equal((await get(c, '/honeytokens?window=2d')).status, 400);
});

test('digest: documented keys, arrays present, 24h and 7d only', async () => {
  const c = await login('dev-viewer');
  const d = await (await get(c, '/digest')).json();
  assert.deepEqual(Object.keys(d).sort(), ['agent_canary_hits', 'as_of', 'bounds', 'dry_run_recommendations', 'honeytoken_hits', 'limits', 'new_sources', 'new_techniques', 'open_investigations', 'previous_totals', 'returning_sources', 'sessions_consistent_with_automation', 'top_rules', 'totals', 'window']);
  assert.equal(d.window, '24h');
  assert.deepEqual(Object.keys(d.limits).sort(), ['history', 'interpretation', 'investigations_available', 'recommendation_cap', 'recommendation_excluded', 'recommendation_missing', 'scan_truncated', 'source_comparison']);
  assert.ok(Array.isArray(d.top_rules) && d.top_rules.length <= 10);
  for (const r of d.top_rules) assert.deepEqual(Object.keys(r).sort(), ['events', 'rule_id', 'severity', 'title']);
  for (const tq of d.new_techniques) assert.deepEqual(Object.keys(tq).sort(), ['framework', 'id', 'name']);
  assert.ok(d.honeytoken_hits >= 2, 'the LLMjacking and MCP replays');
  assert.ok(d.agent_canary_hits >= 1);
  assert.ok(d.sessions_consistent_with_automation >= 2);
  assert.ok(d.dry_run_recommendations <= d.limits.recommendation_cap);
  assert.equal((await get(c, '/digest?window=7d')).status, 200);
  assert.equal((await get(c, '/digest?window=1h')).status, 400);
});

test('event export: analyst only, one scope, fixed names, audited', async () => {
  const viewer = await login('dev-viewer');
  assert.equal((await get(viewer, '/export/events?format=cef&window=24h')).status, 403);
  const c = await login('dev-admin');
  const names = { cef: 'aegismesh-events-cef.log', 'syslog-rfc5424': 'aegismesh-events-syslog-rfc5424.log', 'otlp-json': 'aegismesh-events-otlp-json.json', ecs: 'aegismesh-events-ecs.ndjson' };
  for (const [format, name] of Object.entries(names)) {
    const res = await get(c, `/export/events?format=${format}&source=198.51.100.140`);
    assert.equal(res.status, 200, format);
    assert.match(res.headers.get('content-disposition'), new RegExp(name.replace(/\./g, '\\.')));
    assert.equal(res.headers.get('x-aegismesh-scan-limit'), '8192');
    const body = await res.text();
    if (format === 'otlp-json') assert.ok(JSON.parse(body).resourceLogs[0].scopeLogs[0].logRecords.length >= 9);
    if (format === 'cef') assert.match(body, /^CEF:0\|AegisMesh\|AegisMesh\|/);
    if (format === 'syslog-rfc5424') assert.match(body, /^<\d+>1 \S+ - AegisMesh - observation \[aegismesh@32473 /);
  }
  assert.equal((await get(c, '/export/events?format=pdf&window=24h')).status, 400);
  assert.equal((await get(c, '/export/events?format=cef')).status, 400);
  assert.equal((await get(c, '/export/events?format=cef&window=24h&source=x')).status, 400);
  const audit = await (await get(c, '/audit?action=export.events')).json();
  assert.ok(audit.records.length >= 4);
});

test('rules carry description, guidance and observe_only; MCP rules are observe-only', async () => {
  const c = await login('dev-viewer');
  const { rules } = await (await get(c, '/rules')).json();
  for (const r of rules) {
    assert.equal(typeof r.description, 'string');
    assert.ok(r.description.length > 0 && r.guidance.length > 0, r.id);
    assert.equal(typeof r.observe_only, 'boolean');
    if (r.family === 'correlation') assert.equal(r.observe_only, true);
  }
  for (const id of ['MCP-001', 'MCP-002', 'MCP-003', 'HT-001']) assert.equal(rules.find((r) => r.id === id).observe_only, true, id);
  assert.equal(rules.find((r) => r.id === 'PI-001').observe_only, false);
  assert.equal(ruleRecord({ id: 'X', family: 'detection' }).observe_only, false);
});

test('overview index and titled top rules; event session link; source inter-arrival', async () => {
  const c = await login('dev-viewer');
  const ov = await (await get(c, '/overview')).json();
  assert.deepEqual(Object.keys(ov.index).sort(), ['capacity', 'events', 'history', 'oldest']);
  assert.ok(ov.index.events > 0);
  for (const r of ov.top_rules) assert.equal(typeof r.title, 'string');
  const { sessions } = await (await get(c, '/sessions?source=198.51.100.140')).json();
  assert.equal(sessions.length, 1);
  const s = sessions[0];
  assert.equal(s.automation.assessment, 'consistent_with_automation');
  for (const code of ['sub_second_cadence', 'honeytoken_replay', 'cross_sensor_replay']) assert.ok(s.automation.evidence.some((e) => e.code === code), code);
  assert.ok(s.rule_ids.includes('MCP-001') && s.rule_ids.includes('MCP-003'));
  const src = await (await get(c, `/sources/${encodeURIComponent('198.51.100.140')}`)).json();
  assert.equal(src.inter_arrival.length, 7);
  assert.equal(src.inter_arrival[6].lt_ms, null);
  assert.equal(src.inter_arrival.reduce((n, b) => n + b.count, 0), src.source.events - 1);
  const ev = await (await get(c, `/events/${src.events[0].id}`)).json();
  assert.equal(ev.session_id, s.id);
});

test('inter-arrival buckets: exclusive upper bounds, equal times count', () => {
  const at = (msv) => ({ time: new Date(Date.UTC(2026, 0, 1) + msv).toISOString() });
  const h = interArrival([at(0), at(0), at(1000), at(1000 + 3600e3)]);
  assert.deepEqual(h.map((b) => b.count), [1, 0, 1, 0, 0, 0, 1]);
  assert.deepEqual(interArrival([]).map((b) => b.count), [0, 0, 0, 0, 0, 0, 0]);
});

test('event formats escape attacker text for their syntax', () => {
  const e = { id: 'a'.repeat(32), time: '2026-01-01T00:00:00Z', classification: 'interaction', source: 'x|y=z', sensor: { id: 'web' }, rule_ids: ['PI-001'], severity: 'high', summary: 'a]b"c\\d\nnext' };
  const cef = renderEvents('cef', [e]);
  assert.match(cef, /\|7\|/);
  assert.match(cef, /cs1=x\|y\\=z/);
  assert.equal(cef.trim().split('\n').length, 1, 'controls neutralised');
  const sys = renderEvents('syslog-rfc5424', [e]);
  assert.match(sys, /^<131>1 /);
  assert.match(sys, /source="x\|y=z"/);
  assert.equal(sys.trim().split('\n').length, 1);
  assert.equal(JSON.parse(renderEvents('otlp-json', [e])).resourceLogs[0].scopeLogs[0].logRecords[0].severityNumber, 17);
});
