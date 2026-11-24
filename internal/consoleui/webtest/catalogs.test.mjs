import { toCan } from '../static/assets/js/lib/perms.js';
// Pure logic and rendering for the decoy and honeytoken catalogs, the
// digest (lead sentences, figures, limits, Markdown export), the rule action
// indicator, the server inter-arrival histogram and the Overview's empty
// states. Screens render into the fake DOM with a stubbed API.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createFakeDocument } from './fakedom.mjs';

globalThis.document = createFakeDocument();
const C = await import('../static/assets/js/lib/catalogs.js');
const { emptyKind, buildBrief, briefText } = await import('../static/assets/js/lib/brief.js');
const { default: decoys } = await import('../static/assets/js/screens/decoys.js');
const { default: honeytokens } = await import('../static/assets/js/screens/honeytokens.js');
const { default: digest } = await import('../static/assets/js/screens/digest.js');
const { roleAtLeast } = await import('../static/assets/js/lib/taxonomy.js');

const HOSTILE = '<img src=x onerror=alert(1)>‮|`x`';
const BOUNDS = { index: { events: 11, capacity: 50000, oldest: '2026-11-21T00:00:00Z', history: 'complete' }, scanned_events: 11, scan_limit: 8192, scan_truncated: false };
const DECOYS = [
  { id: 'ai-workspace', kind: 'mcp', listen: '127.0.0.1:8002', surface_families: ['mcp_environment'], rules: 0, tools: 5, fake_files: 2, honeytoken_ids: ['decoy-key'], events: 4, last_activity: '2026-11-22T10:00:00.000000000Z' },
  { id: 'ai-api', kind: 'http', listen: '127.0.0.1:8001', surface_families: ['litellm', 'openai_compatible'], rules: 9, tools: 0, fake_files: 0, honeytoken_ids: ['decoy-key', 'echo'], events: 8, last_activity: '' },
  { id: 'ssh', kind: 'ssh', listen: '127.0.0.1:2222', surface_families: ['ssh'], rules: 0, tools: 0, fake_files: 0, honeytoken_ids: [], events: 0, last_activity: '' },
  { id: 'odd', kind: 'http', listen: '', surface_families: ['someday'], rules: 'x', tools: -1, fake_files: null, honeytoken_ids: null, events: 'many', last_activity: 5 },
];
const TOKENS = [
  { id: 'unused', kind: 'credential', sensor_ids: [], hit_count: 0, last_hit: '', sources: [] },
  { id: 'decoy-key', kind: 'credential', sensor_ids: ['ai-api', 'ai-workspace'], hit_count: 2, last_hit: '2026-11-22T10:00:00Z', sources: ['192.0.2.4', HOSTILE] },
  { id: 'echo', kind: 'agent_canary', sensor_ids: ['ai-api'], hit_count: 1, last_hit: '2026-11-22T11:00:00Z', sources: ['192.0.2.5'] },
];
const DIGEST = {
  window: '24h', as_of: '2026-11-22T12:00:00.123456789Z',
  totals: { events: 9, interaction: 8, canary_invocation: 1, correlation_signal: 0, sources: 2, sensors_active: 2 },
  previous_totals: { events: 2, interaction: 2, canary_invocation: 0, correlation_signal: 0, sources: 1, sensors_active: 1 },
  new_sources: 1, returning_sources: 1, sessions_consistent_with_automation: 1,
  top_rules: [{ rule_id: 'MCP-001', title: `declared ${HOSTILE}`, severity: 'medium', events: 3 }, { rule_id: 'COR-008', title: 'replay', severity: '', events: 1 }],
  new_techniques: [{ framework: 'mitre-atlas', id: 'AML.T0055', name: 'Unsecured Credentials' }, { framework: 'mitre-attack', id: 'T1552', name: 'Unsecured Credentials' }, { framework: 'bogus', id: 'X', name: 'Y' }],
  honeytoken_hits: 1, agent_canary_hits: 0, open_investigations: null, dry_run_recommendations: 1,
  bounds: BOUNDS,
  limits: { interpretation: 'Retained observations, not incidents.', history: 'complete', scan_truncated: false, source_comparison: 'New means absent from the preceding sampled window, not first-ever seen.', investigations_available: false, recommendation_excluded: 2, recommendation_missing: 0, recommendation_cap: 20 },
};

function ctx(api, query = {}, role = 'analyst') {
  return { role, can: toCan(role), route: { query, params: {} }, signal: undefined, navigate() {}, rerender() {}, api };
}
const find = (root, pred) => root.querySelectorAll(pred);
const cls = (el) => String(el.getAttribute('class') || '').split(' ');

test('surface families: closed vocabulary with a shape each; unknown is "Other surface"', () => {
  assert.deepEqual(C.familyMeta('ollama'), { id: 'ollama', label: 'Ollama', shape: 'ai', ai: true });
  assert.equal(C.familyMeta('mcp_environment').shape, 'mcp');
  assert.equal(C.familyMeta('ssh').shape, 'proto');
  assert.equal(C.familyMeta('__proto__').label, 'Other surface');
  for (const m of Object.values(C.SURFACE_FAMILIES)) assert.ok(['ai', 'mcp', 'proto'].includes(m.shape));
});

test('decoys: summary, figures per kind, malformed fields never become numbers', () => {
  const s = C.decoySummary(DECOYS);
  assert.deepEqual(s, { decoys: 4, aiServices: 1, mcpEnvironments: 1, plantedIds: 2, events: 12, busiest: 8 });
  assert.deepEqual(C.decoyFigures(DECOYS[0]).map((f) => [f.key, f.value]), [['tools', 5], ['files', 2]]);
  assert.deepEqual(C.decoyFigures(DECOYS[1]).map((f) => [f.key, f.value]), [['rules', 9]]);
  assert.deepEqual(C.decoyFigures(DECOYS[2]), []);
  const odd = C.normalizeDecoy(DECOYS[3]);
  assert.equal(odd.rules, null);
  assert.equal(odd.events, 0);
  assert.equal(odd.lastActivity, '');
  assert.deepEqual(odd.honeytokenIds, []);
  assert.equal(C.activityShare(4, 8), 0.5);
  assert.equal(C.activityShare(4, 0), 0);
});

test('catalog bounds note states scan, history and forwarded exclusion', () => {
  assert.match(C.catalogBoundsNote(BOUNDS, 'the last 24 hours'), /within the newest 11 indexed events\. Forwarded copies/);
  const t = C.catalogBoundsNote({ ...BOUNDS, scan_truncated: true, index: { ...BOUNDS.index, history: 'truncated' } });
  assert.match(t, /8,192-event scan limit was reached/);
  assert.match(t, /evicted older evidence/);
});

test('honeytokens: kinds, ranking by hits then recency, summary', () => {
  assert.equal(C.tokenKindMeta('agent_canary').rule, 'AGT-001');
  assert.equal(C.tokenKindMeta('credential').rule, 'HT-001');
  assert.equal(C.tokenKindMeta('constructor').label, 'Other marker');
  assert.deepEqual(C.rankTokens(TOKENS).map((t) => t.id), ['decoy-key', 'echo', 'unused']);
  assert.deepEqual(C.tokenSummary(TOKENS), { tokens: 3, credentials: 2, canaries: 1, withHits: 2, hits: 3, unplanted: 1 });
  for (const k of Object.values(C.TOKEN_KINDS)) assert.match(k.not, /not|cannot/);
});

test('rule action: observe only, can select an action, or not reported', () => {
  assert.equal(C.ruleActionMeta({ observe_only: true }).label, 'Observe only');
  assert.equal(C.ruleActionMeta({ observe_only: false }).key, 'act');
  assert.match(C.ruleActionMeta({ observe_only: false }).hint, /decoy’s own connection/);
  assert.equal(C.ruleActionMeta({}), null);
  assert.equal(C.ruleActionMeta({ observe_only: 'false' }), null);
});

test('server inter-arrival: labels from bounds; malformed falls back (null)', () => {
  const raw = [100, 1000, 10000, 60000, 300000, 1800000].map((lt_ms, i) => ({ lt_ms, count: i })).concat([{ lt_ms: null, count: 2 }]);
  const g = C.serverGapBins(raw);
  assert.deepEqual(g.bins.map((b) => b.label), ['< 100 ms', '0.1–1 s', '1–10 s', '10–60 s', '1–5 min', '5–30 min', '≥ 30 min']);
  assert.equal(g.gaps, 17);
  assert.equal(g.peak, 5);
  assert.equal(C.serverGapBins(null), null);
  assert.equal(C.serverGapBins([{ lt_ms: 100, count: 1 }, { lt_ms: 50, count: 0 }, { lt_ms: null, count: 0 }]), null, 'bounds must ascend');
  assert.equal(C.serverGapBins([{ lt_ms: 100, count: -1 }, { lt_ms: null, count: 0 }]), null);
  assert.equal(C.serverGapBins([{ lt_ms: 100, count: 1 }, { lt_ms: 200, count: 0 }]), null, 'the last bound is infinity');
  assert.equal(C.serverGapBins(raw.map((b) => ({ ...b, count: 0 }))).peak, -1);
});

test('event formats: the four documented formats; OTLP says file only', () => {
  assert.deepEqual(C.EVENT_FORMATS.map((f) => f.format), ['cef', 'syslog-rfc5424', 'otlp-json', 'ecs']);
  assert.match(C.EVENT_FORMATS.find((f) => f.format === 'otlp-json').hint, /File format only: AegisMesh sends nothing/);
  assert.ok(C.isEventFormat('ecs') && !C.isEventFormat('json'));
});

test('digest lead: neutral comparison, never invents numbers', () => {
  const text = C.digestLeadText(DIGEST);
  assert.match(text, /^In the last 24 hours the decoys recorded 9 events, 7 more than the 24 hours before\./);
  assert.match(text, /2 distinct sources: 1 not seen in the window before and 1 returning\./);
  assert.match(text, /1 session was consistent with automation \(an observation, not a verdict\)\./);
  assert.match(text, /A planted decoy credential came back on 1 event\./);
  assert.match(text, /The most cited rule was MCP-001/);
  assert.match(text, /3 related techniques were cited that the window before did not cite\./);
  assert.doesNotMatch(text, /worse|better|alarm|attack(ed)?\b/i);
  assert.equal(C.digestLeadText({ window: '7d', totals: {}, previous_totals: {} }), 'The server did not report an event count for this window.');
  assert.match(C.digestLeadText({ window: '7d', totals: { events: 0 }, previous_totals: { events: 3 } }), /no events in the last 7 days; the 7 days before held 3\./);
  assert.equal(C.normalizeDigestWindow('1h'), '24h');
});

test('digest figures, techniques and limits', () => {
  const f = C.digestFigures(DIGEST);
  assert.deepEqual(f.map((x) => x.change), ['+7', '+6', '+1', 'same', '+1', '+1']);
  assert.deepEqual(C.digestFigures({}).map((x) => x.change), Array(6).fill('—'));
  const g = C.groupTechniques(DIGEST.new_techniques);
  assert.deepEqual(g.map((x) => x.framework), ['mitre-attack', 'mitre-atlas'], 'fixed order; unknown frameworks dropped');
  const limits = C.digestLimits(DIGEST);
  assert.deepEqual(limits.map((l) => l.key), ['interpretation', 'source_comparison', 'history', 'scan', 'investigations', 'recommendations', 'delivery']);
  assert.equal(limits[0].text, DIGEST.limits.interpretation, 'verbatim');
  assert.ok(limits[0].verbatim && limits[1].verbatim);
  assert.match(limits.find((l) => l.key === 'recommendations').text, /2 forwarded or over-cap events were left out/);
  assert.match(limits.find((l) => l.key === 'delivery').text, /Nothing is scheduled, stored or sent/);
});

test('Markdown export fences every server string; controls and bidi removed', () => {
  assert.equal(C.mdFence('a`b'), '``a`b``');
  assert.equal(C.mdFence('`x'), '`` `x ``');
  assert.equal(C.mdFence('a|b'), '`a\\|b`');
  assert.equal(C.mdFence('a\nb‮c'), '`a b c`');
  const md = C.digestMarkdown(DIGEST, { asOfText: '2026-11-22 12:00:00 UTC' });
  assert.match(md, /^# AegisMesh digest: the last 24 hours\n/);
  assert.match(md, /\| Events \| 9 \| 2 \| \+7 \|/);
  assert.match(md, /1\. `MCP-001` `` declared <img src=x onerror=alert\(1\)> \\\|`x` `` \(Medium\): 3 events/);
  assert.match(md, /The most cited rule was `MCP-001`, `` declared <img/);
  assert.doesNotMatch(md, /‮/);
  assert.match(md, /- Open investigations: not available/);
  assert.match(md, /Interpretation: `Retained observations, not incidents\.`/);
  for (const line of md.split('\n')) assert.ok(!line.includes('<img') || line.includes('`'), 'hostile text only inside code spans');
});

test('overview empty states: first run, quiet window, unknown', () => {
  assert.equal(emptyKind({ totals: { events: 0 }, index: { events: 0 } }), 'empty');
  assert.equal(emptyKind({ totals: { events: 0 }, index: { events: 40 } }), 'quiet');
  assert.equal(emptyKind({ totals: { events: 0 } }), 'unknown');
  assert.equal(emptyKind({ totals: { events: 3 }, index: { events: 0 } }), null);
  const b = buildBrief({ generated_at: '2026-11-22T12:00:00Z', totals: { events: 5 }, previous_totals: { events: 5 }, top_rules: [{ rule_id: 'PI-001', title: 'instruction-override phrasing', events: 2, severity: 'high' }] }, '24h');
  assert.match(briefText(b), /Most cited rule: PI-001, “instruction-override phrasing” \(High\), cited by 2 events\./);
});

test('decoys screen: one card per decoy, families as glyph plus word, links to events', async () => {
  const root = document.createElement('main');
  await decoys.render(root, ctx({ decoys: () => Promise.resolve({ decoys: DECOYS, bounds: BOUNDS }) }, { window: '7d' }));
  const text = root.textContent;
  assert.match(text, /What attackers see, and what is real/);
  assert.match(text, /No model runs/);
  assert.equal(find(root, (e) => e.tagName === 'article' && cls(e).includes('decoy')).length, 4);
  const fams = find(root, (e) => cls(e).includes('fam'));
  assert.ok(fams.some((f) => cls(f).includes('fam--mcp') && /MCP environment/.test(f.textContent)));
  assert.ok(fams.every((f) => f.textContent.trim().length > 0), 'every glyph has a word');
  const links = find(root, (e) => e.tagName === 'a').map((a) => a.getAttribute('href'));
  assert.ok(links.some((l) => l.startsWith('#/events?sensor=ai-api&since=')));
  assert.ok(links.includes('#/honeytokens?t=decoy-key'));
  assert.match(text, /within the newest 11 indexed events/);
});

test('decoys screen: empty catalog explains how to scaffold', async () => {
  const root = document.createElement('main');
  await decoys.render(root, ctx({ decoys: () => Promise.resolve({ decoys: [], bounds: BOUNDS }) }));
  assert.match(root.textContent, /No decoys in this catalog/);
  assert.match(root.textContent, /aegismesh init --profile ai-decoy --dir \.\/ai-lab/);
});

test('honeytokens screen: values never shown, sources stay evidence text, empty state mints', async () => {
  const root = document.createElement('main');
  await honeytokens.render(root, ctx({ honeytokens: () => Promise.resolve({ honeytokens: TOKENS, bounds: BOUNDS }) }, { t: 'echo' }));
  assert.match(root.textContent, /Values are never shown/);
  const ev = find(root, (e) => cls(e).includes('evidence'));
  assert.ok(ev.some((e) => e.getAttribute('title') === HOSTILE && HOSTILE.startsWith(e.textContent.replace(/…$/, ''))), 'the hostile source stays text in an evidence span (full value in the peek)');
  assert.equal(find(root, (e) => e.tagName === 'img').length, 0);
  const rows = find(root, (e) => e.tagName === 'tr' && e.getAttribute('data-token'));
  assert.deepEqual(rows.map((r) => r.getAttribute('data-token')), ['decoy-key', 'echo', 'unused']);
  assert.ok(cls(rows[1]).includes('is-focus'));
  assert.match(root.textContent, /No planting detected/);
  const empty = document.createElement('main');
  await honeytokens.render(empty, ctx({ honeytokens: () => Promise.resolve({ honeytokens: [], bounds: BOUNDS }) }));
  assert.match(empty.textContent, /aegismesh honeytoken new --kind credential --format openai --id planted-key/);
  assert.match(empty.textContent, /Never use a real credential/);
});

test('digest screen: serif briefing, limits verbatim, figures link to their views', async () => {
  const root = document.createElement('main');
  await digest.render(root, ctx({ digest: (w) => Promise.resolve({ ...DIGEST, window: w }) }, { window: '7d' }));
  const text = root.textContent;
  assert.match(text, /The last 7 days/);
  assert.match(text, /Retained observations, not incidents\./);
  assert.match(text, /open investigations \(not available\)/);
  assert.match(text, /Proposed, not executed/);
  assert.equal(find(root, (e) => e.tagName === 'img').length, 0, 'the hostile title stays text');
  const links = find(root, (e) => e.tagName === 'a').map((a) => a.getAttribute('href'));
  assert.ok(links.some((l) => l.startsWith('#/events?rule=MCP-001&since=')));
  assert.ok(links.includes('#/honeytokens?window=7d'));
  assert.ok(find(root, (e) => e.tagName === 'button').some((b) => /Copy as Markdown/.test(b.textContent)));
});
