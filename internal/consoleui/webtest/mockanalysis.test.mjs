// Mock contract for the derived views (sessions, framework relations,
// indicator downloads, reports): shapes, roles, strict queries and the
// scripted sessions the UI is developed against.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { cadenceOf, automationOf } from '../devserver/mock-analysis.mjs';

const PORT = 21000 + Math.floor(Math.random() * 1000);
const BASE = `http://127.0.0.1:${PORT}`;
let proc;

before(async () => {
  proc = spawn(process.execPath, [fileURLToPath(new URL('../devserver/mock-server.mjs', import.meta.url)), '--port', String(PORT)], { stdio: ['ignore', 'pipe', 'inherit'] });
  await new Promise((resolve, reject) => {
    const t = setTimeout(() => reject(new Error('mock did not start')), 30000);
    proc.stdout.on('data', (d) => { if (String(d).includes('console mock on')) { clearTimeout(t); resolve(); } });
  });
});
after(() => proc?.kill());

async function login(token) {
  const res = await fetch(`${BASE}/api/v1/session`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ token }) });
  return (res.headers.get('set-cookie') || '').split(';')[0];
}
const get = (cookie, path) => fetch(`${BASE}/api/v1${path}`, { headers: { cookie } });

// Round 4 adds campaign_id and actor (contract r4); see mockinsight.test.mjs.
const SESSION_KEYS = ['campaign_id', 'actor', 'id', 'source', 'first_seen', 'last_seen', 'duration_ms', 'event_count', 'sensors', 'sensor_kinds', 'sensors_truncated', 'classification_counts', 'rule_ids', 'max_severity', 'frameworks', 'cadence', 'automation'].sort();

test('sessions: documented shape, bounds and the scripted stories', async () => {
  const c = await login('dev-viewer');
  const res = await get(c, '/sessions?window=24h&limit=200');
  assert.equal(res.status, 200);
  const body = await res.json();
  assert.deepEqual(Object.keys(body).sort(), ['as_of', 'bounds', 'next_cursor', 'sessions', 'total_matched', 'window']);
  assert.deepEqual(Object.keys(body.bounds).sort(), ['index', 'scan_limit', 'scan_truncated', 'scanned_events']);
  assert.equal(body.bounds.scan_limit, 8192);
  for (const s of body.sessions) {
    assert.deepEqual(Object.keys(s).sort(), SESSION_KEYS);
    assert.match(s.id, /^[0-9a-f]{32}$/);
    assert.deepEqual(Object.keys(s.cadence).sort(), ['events_per_minute', 'median_gap_ms', 'min_gap_ms', 'p90_gap_ms', 'regularity']);
  }
  const by = (src) => body.sessions.find((s) => s.source === src);
  const llm = by('203.0.113.66');
  assert.equal(llm.automation.assessment, 'consistent_with_automation');
  assert.deepEqual(llm.automation.evidence.map((e) => e.code), ['sub_second_cadence', 'agent_canary', 'correlation_cadence', 'multi_surface_enumeration', 'honeytoken_replay', 'cross_sensor_replay']);
  assert.equal(llm.max_severity, 'critical');
  assert.ok(llm.frameworks.some((f) => f.framework === 'mitre-atlas' && f.id === 'AML.T0040'));
  assert.equal(by('198.51.100.77').automation.assessment, 'consistent_with_automation');
  assert.equal(by('198.51.100.77').automation.evidence[0].code, 'regular_cadence');
  assert.equal(by('192.0.2.150').automation.assessment, 'mixed');
  // Sorted by last seen, newest first.
  const times = body.sessions.map((s) => Date.parse(s.last_seen));
  assert.deepEqual(times, [...times].sort((a, b) => b - a));
});

test('sessions: source filter, cursor paging and strict queries', async () => {
  const c = await login('dev-viewer');
  const one = await (await get(c, '/sessions?source=203.0.113.66')).json();
  assert.equal(one.sessions.length, 1);
  const p1 = await (await get(c, '/sessions?window=7d&limit=2')).json();
  assert.ok(p1.next_cursor);
  const p2 = await (await get(c, `/sessions?window=7d&limit=2&cursor=${p1.next_cursor}`)).json();
  assert.notEqual(p2.sessions[0].id, p1.sessions[0].id);
  assert.equal((await get(c, `/sessions?window=1h&cursor=${p1.next_cursor}`)).status, 400);
  assert.equal((await get(c, '/sessions?bogus=1')).status, 400);
  assert.equal((await get(c, '/sessions?window=2d')).status, 400);
  assert.equal((await get(c, '/sessions/not-hex')).status, 400);
  assert.equal((await get(c, `/sessions/${'0'.repeat(32)}`)).status, 404);
});

test('session detail: timeline with gaps, contiguous phases in precedence order', async () => {
  const c = await login('dev-viewer');
  const { sessions } = await (await get(c, '/sessions?source=203.0.113.66')).json();
  const d = await (await get(c, `/sessions/${sessions[0].id}`)).json();
  assert.equal(d.timeline.length, d.event_count);
  assert.equal(d.timeline[0].gap_ms, null);
  assert.ok(d.timeline.slice(1).every((e) => typeof e.gap_ms === 'number'));
  assert.deepEqual(Object.keys(d.timeline[0]).sort(), ['classification', 'event_id', 'gap_ms', 'kind', 'node_id', 'rule_ids', 'sensor', 'summary', 'time']);
  assert.equal(d.timeline[0].node_id, 'local');
  assert.deepEqual(d.phases.map((p) => p.stage), ['discovery', 'ai_service_abuse', 'discovery', 'decoy_credential_replay', 'discovery', 'ai_service_abuse', 'discovery']);
  assert.equal(d.phases.flatMap((p) => p.event_ids).length, d.timeline.length);
  assert.equal(d.timeline_truncated, false);
  assert.ok(d.bounds);
});

test('coverage: three frameworks, unobserved techniques included, interpretation text', async () => {
  const c = await login('dev-viewer');
  const body = await (await get(c, '/coverage?window=24h')).json();
  assert.deepEqual(body.frameworks.map((f) => f.framework), ['mitre-attack', 'mitre-atlas', 'owasp-llm-2025']);
  assert.match(body.interpretation, /not technique execution or completeness/);
  const attack = body.frameworks[0].techniques;
  assert.deepEqual(attack.map((t) => t.id), [...attack.map((t) => t.id)].sort());
  assert.ok(attack.find((t) => t.id === 'T1595').observed_event_count > 0);
  const quiet = body.frameworks[2].techniques.find((t) => t.id === 'LLM01');
  assert.ok(quiet, 'LLM01 is listed');
  for (const f of body.frameworks) for (const t of f.techniques) if (!t.observed_event_count) assert.equal(t.last_seen, '');
});

test('downloads: analyst only, fixed filenames, bounds headers, proposed blocklist', async () => {
  const viewer = await login('dev-viewer');
  const analyst = await login('dev-analyst');
  const { sessions } = await (await get(analyst, '/sessions?source=203.0.113.66')).json();
  const id = sessions[0].id;
  assert.equal((await get(viewer, `/export/indicators?session=${id}&format=csv`)).status, 403);
  assert.equal((await get(viewer, `/sessions/${id}/report`)).status, 403);
  assert.equal((await get(analyst, `/export/indicators?session=${id}&source=x&format=csv`)).status, 400);
  assert.equal((await get(analyst, `/export/indicators?session=${id}&format=pdf`)).status, 400);

  const csv = await get(analyst, `/export/indicators?session=${id}&format=csv`);
  assert.equal(csv.status, 200);
  assert.match(csv.headers.get('content-disposition'), /attachment; filename="aegismesh-indicators\.csv"/);
  assert.equal(csv.headers.get('x-aegismesh-scan-limit'), '8192');
  assert.equal(csv.headers.get('x-aegismesh-skipped-non-ip-sources'), '0');
  const text = await csv.text();
  assert.match(text, /^indicator,type,first_seen,last_seen,event_count,confidence,interpretation,skipped_non_ip_sources,skipped_non_ip_events\n203\.0\.113\.66,ipv4-addr,/);
  const txt = await (await get(analyst, '/export/indicators?window=7d&format=txt')).text();
  assert.match(txt, /^# PROPOSED blocklist for operator review; never applied by AegisMesh/);
  const stix = await (await get(analyst, `/export/indicators?source=203.0.113.66&format=stix`)).json();
  assert.equal(stix.type, 'bundle');
  assert.equal(stix.spec_version, undefined);
  assert.ok(stix.objects.every((o) => o.spec_version === '2.1'));
  assert.ok(stix.objects.some((o) => o.pattern === "[ipv4-addr:value = '203.0.113.66']" && o.confidence === 15));

  const report = await get(analyst, `/sessions/${id}/report`);
  assert.match(report.headers.get('content-disposition'), /aegismesh-observation-report\.md/);
  assert.match(await report.text(), /^# AegisMesh observation report/);
  const invs = await (await get(analyst, '/investigations')).json();
  const inv = await get(analyst, `/investigations/${invs.investigations[0].id}/report`);
  assert.equal(inv.status, 200);
});

test('cadence and automation follow the documented formulas', () => {
  const at = (s) => ({ time: new Date(Date.UTC(2026, 0, 1) + s).toISOString(), classification: 'interaction' });
  const c = cadenceOf([at(0), at(100), at(300), at(600)]);
  // gaps 100,200,300: upper median 200, nearest-rank p90 300, rate 3/0.01 min.
  assert.equal(c.median_gap_ms, 200);
  assert.equal(c.p90_gap_ms, 300);
  assert.equal(c.min_gap_ms, 100);
  assert.equal(Math.round(c.events_per_minute), 300);
  assert.equal(c.regularity, 1 / 3);
  assert.equal(cadenceOf([at(0)]).events_per_minute, 0);
  const few = automationOf([at(0), at(1)], new Set(['HT-001']));
  assert.equal(few.assessment, 'inconclusive');
  assert.deepEqual(few.evidence.map((e) => e.code), ['honeytoken_replay', 'insufficient_events']);
});
