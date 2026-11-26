// Pure logic for the decoy and honeytoken catalogs, the digest, the rule
// action indicator, the server inter-arrival histogram and the local SIEM
// event formats (docs/architecture/console-api.md, "Round 3 additions").
// Unit-tested in webtest/catalogs.test.mjs.
//
// Copy rules: decoys are synthetic surfaces (nothing behind them is real, no
// model runs); a honeytoken hit is an observation that a planted id came
// back, not proof of successful use; the digest is computed on demand, with
// no scheduler and no delivery. Every API string stays data: nothing here
// builds markup, and the Markdown export fences every server string.

import { isSeverity, severityLabel } from './taxonomy.js';
import { formatCount } from './format.js';
import { DIGEST_WINDOWS, normalizeDigestWindow } from './route.js';

const isCount = (v) => typeof v === 'number' && Number.isInteger(v) && v >= 0;
const count = (v) => (isCount(v) ? formatCount(v) : '—');
const plural = (n, one, many) => (n === 1 ? one : many);
const arr = (v) => (Array.isArray(v) ? v : []);
const str = (v) => (typeof v === 'string' ? v : '');

// ---- Surface families ---------------------------------------------------------
// shape is a glyph class (never color alone): ai = hexagon (an AI-service
// shape), mcp = bracket square (tools), proto = ring (a plain protocol).

export const SURFACE_FAMILIES = Object.freeze({
  ollama: { label: 'Ollama', shape: 'ai', ai: true },
  openai_compatible: { label: 'OpenAI-compatible', shape: 'ai', ai: true },
  litellm: { label: 'LiteLLM', shape: 'ai', ai: true },
  vllm: { label: 'vLLM', shape: 'ai', ai: true },
  mcp_http: { label: 'MCP over HTTP', shape: 'mcp', ai: true },
  mcp_environment: { label: 'MCP environment', shape: 'mcp', ai: true },
  mcp: { label: 'MCP', shape: 'mcp', ai: false },
  http: { label: 'HTTP', shape: 'proto', ai: false },
  ssh: { label: 'SSH', shape: 'proto', ai: false },
  tcp: { label: 'TCP', shape: 'proto', ai: false },
});

export function familyMeta(id) {
  return Object.hasOwn(SURFACE_FAMILIES, id) ? { id, ...SURFACE_FAMILIES[id] } : { id: str(id), label: 'Other surface', shape: 'proto', ai: false };
}

export const SENSOR_KIND_LABELS = Object.freeze({ http: 'HTTP', tcp: 'TCP', ssh: 'SSH', mcp: 'MCP' });
export const kindLabel = (k) => SENSOR_KIND_LABELS[k] || 'Other';

// ---- Decoys --------------------------------------------------------------------

export function normalizeDecoy(d) {
  return {
    id: str(d?.id), kind: str(d?.kind), listen: str(d?.listen),
    families: arr(d?.surface_families).filter((f) => typeof f === 'string').map(familyMeta),
    rules: isCount(d?.rules) ? d.rules : null,
    tools: isCount(d?.tools) ? d.tools : null,
    fakeFiles: isCount(d?.fake_files) ? d.fake_files : null,
    honeytokenIds: arr(d?.honeytoken_ids).filter((x) => typeof x === 'string' && x !== ''),
    events: isCount(d?.events) ? d.events : 0,
    lastActivity: str(d?.last_activity),
  };
}

// Headline figures for the catalog: how many decoys, how many present an
// AI-service shape, how many are MCP environments, planted ids, events.
export function decoySummary(decoys) {
  const list = arr(decoys).map(normalizeDecoy);
  const planted = new Set(list.flatMap((d) => d.honeytokenIds));
  return {
    decoys: list.length,
    aiServices: list.filter((d) => d.families.some((f) => f.ai && f.shape === 'ai')).length,
    mcpEnvironments: list.filter((d) => d.families.some((f) => f.id === 'mcp_environment')).length,
    plantedIds: planted.size,
    events: list.reduce((n, d) => n + d.events, 0),
    busiest: list.reduce((m, d) => Math.max(m, d.events), 0),
  };
}

// The per-decoy figures worth printing: rules for HTTP/TCP, tools and fake
// files for MCP. A zero is printed where the surface could have them.
export function decoyFigures(d) {
  const n = normalizeDecoy(d);
  const out = [];
  if (n.kind === 'http' || n.kind === 'tcp' || n.rules) out.push({ key: 'rules', label: plural(n.rules, 'static rule', 'static rules'), value: n.rules });
  if (n.kind === 'mcp' || n.tools) out.push({ key: 'tools', label: plural(n.tools, 'tool', 'tools'), value: n.tools });
  if (n.families.some((f) => f.id === 'mcp_environment') || n.fakeFiles) out.push({ key: 'files', label: plural(n.fakeFiles, 'fake file', 'fake files'), value: n.fakeFiles });
  return out.filter((f) => f.value !== null);
}

// Share of the busiest decoy's events, 0..1, for a decorative mark beside
// the printed count.
export const activityShare = (events, busiest) => (busiest > 0 && isCount(events) ? Math.min(1, events / busiest) : 0);

// One sentence on what the catalog's activity counts cover.
export function catalogBoundsNote(bounds, windowText = 'this window') {
  const b = bounds || {};
  const parts = [];
  if (isCount(b.scanned_events) && isCount(b.scan_limit)) {
    parts.push(`Activity in ${windowText} is counted within the newest ${count(b.scanned_events)} indexed events${b.scan_truncated ? ` (the ${count(b.scan_limit)}-event scan limit was reached, so older activity is not counted)` : ''}.`);
  }
  if (b.index?.history === 'truncated') parts.push('The index has evicted older evidence; it remains on disk.');
  if (b.index?.history === 'unavailable') parts.push('The index starts at process start, so earlier activity is not counted.');
  parts.push('Forwarded copies from other nodes do not count: the catalog describes this node’s own configuration.');
  return parts.join(' ');
}

// ---- Honeytokens ------------------------------------------------------------------

export const TOKEN_KINDS = Object.freeze({
  credential: {
    label: 'Decoy credential', shape: 'key', rule: 'HT-001',
    means: 'A fake credential that exists only in decoy material was presented to a sensor. Whoever sent it read decoy material, or received it from someone who did.',
    not: 'It does not show the credential worked anywhere (it cannot: it is fake), who the sender is, or which response disclosed it.',
  },
  agent_canary: {
    label: 'Agent canary', shape: 'flag', rule: 'AGT-001',
    means: 'A marker planted as an instruction in decoy text came back, consistent with a client that acted on what it read, such as an LLM-driven agent.',
    not: 'A person or a script can copy the marker too, so a hit is consistent with an LLM client, not proof of one.',
  },
});

export function tokenKindMeta(kind) {
  return Object.hasOwn(TOKEN_KINDS, kind) ? { kind, ...TOKEN_KINDS[kind] } : { kind: str(kind), label: 'Other marker', shape: 'key', rule: '', means: '', not: '' };
}

export function normalizeToken(t) {
  return {
    id: str(t?.id), kind: str(t?.kind),
    sensorIds: arr(t?.sensor_ids).filter((x) => typeof x === 'string' && x !== ''),
    hits: isCount(t?.hit_count) ? t.hit_count : 0,
    lastHit: str(t?.last_hit),
    sources: arr(t?.sources).filter((x) => typeof x === 'string' && x !== ''),
  };
}

export function tokenSummary(tokens) {
  const list = arr(tokens).map(normalizeToken);
  return {
    tokens: list.length,
    credentials: list.filter((t) => t.kind === 'credential').length,
    canaries: list.filter((t) => t.kind === 'agent_canary').length,
    withHits: list.filter((t) => t.hits > 0).length,
    hits: list.reduce((n, t) => n + t.hits, 0),
    unplanted: list.filter((t) => !t.sensorIds.length).length,
  };
}

// Tokens with hits first (most hits, then newest), then by id.
export function rankTokens(tokens) {
  return arr(tokens).map(normalizeToken).sort((a, b) => b.hits - a.hits || (Date.parse(b.lastHit) || 0) - (Date.parse(a.lastHit) || 0) || (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
}

// ---- Rule action indicator ------------------------------------------------------

export function ruleActionMeta(rule) {
  if (typeof rule?.observe_only !== 'boolean') return null;
  return rule.observe_only
    ? { key: 'observe', label: 'Observe only', hint: 'A match is recorded and never selects a response action.' }
    : { key: 'act', label: 'Can select an action', hint: 'Under the configured severity mapping a match may tag, throttle, isolate or refuse the decoy’s own connection. Nothing outside the decoy is touched.' };
}

// ---- Server inter-arrival histogram ----------------------------------------------

const gapText = (ms) => (ms < 1000 ? `${ms} ms` : ms < 60000 ? `${ms / 1000} s` : ms < 3600000 ? `${ms / 60000} min` : `${ms / 3600000} h`);
// "0.1–1 s", "10–60 s", "5–30 min": both bounds in the largest unit that
// keeps them at one decimal or better, so column labels stay short.
const UNITS = [['h', 3600000], ['min', 60000], ['s', 1000], ['ms', 1]];
function gapRange(lo, hi) {
  for (const [u, f] of UNITS) {
    const a = lo / f;
    const b = hi / f;
    if (a >= 0.1 && Number.isInteger(Math.round(a * 1e6) / 1e5) && Number.isInteger(Math.round(b * 1e6) / 1e5)) return `${a}–${b} ${u}`;
  }
  return `${gapText(lo)}–${gapText(hi)}`;
}

// GET /sources/{source} `inter_arrival`: ascending exclusive upper bounds in
// milliseconds, the last null (infinity). Anything else returns null so the
// caller falls back to the browser's histogram of loaded events.
export function serverGapBins(raw) {
  const list = arr(raw);
  if (list.length < 2) return null;
  let prev = 0;
  const bins = [];
  for (let i = 0; i < list.length; i++) {
    const b = list[i];
    const last = i === list.length - 1;
    if (!b || typeof b !== 'object' || !isCount(b.count)) return null;
    if (last ? b.lt_ms !== null : !(isCount(b.lt_ms) && b.lt_ms > prev)) return null;
    bins.push({ label: last ? `≥ ${gapText(prev)}` : i === 0 ? `< ${gapText(b.lt_ms)}` : gapRange(prev, b.lt_ms), count: b.count });
    if (!last) prev = b.lt_ms;
  }
  const gaps = bins.reduce((n, b) => n + b.count, 0);
  const peak = gaps ? bins.reduce((best, b, i) => (b.count > bins[best].count ? i : best), 0) : -1;
  return { bins, gaps, peak };
}

// ---- Local SIEM event formats -------------------------------------------------------

export const EVENT_FORMATS = Object.freeze([
  { format: 'cef', label: 'CEF', hint: 'Common Event Format, one line per observation' },
  { format: 'syslog-rfc5424', label: 'Syslog (RFC 5424)', hint: 'One RFC 5424 line per observation, structured data aegismesh@32473 (a documentation number)' },
  { format: 'otlp-json', label: 'OTLP JSON', hint: 'OpenTelemetry log records as a JSON file. File format only: AegisMesh sends nothing and ships no exporter' },
  { format: 'ecs', label: 'ECS NDJSON', hint: 'Elastic Common Schema, one JSON document per line, with the native envelope' },
]);
export const isEventFormat = (f) => EVENT_FORMATS.some((x) => x.format === f);

// ---- Digest ------------------------------------------------------------------------

// Defined with the other route vocabularies, so the router does not pull
// this module into the first screen; re-exported for the digest.
export { DIGEST_WINDOWS, normalizeDigestWindow };
const WINDOW_TEXT = { '24h': 'the last 24 hours', '7d': 'the last 7 days' };
const PREV_TEXT = { '24h': 'the 24 hours before', '7d': 'the 7 days before' };

const FIGURES = [
  ['events', 'Events'],
  ['interaction', 'Interactions'],
  ['canary_invocation', 'Canary invocations'],
  ['correlation_signal', 'Correlation signals'],
  ['sources', 'Distinct sources'],
  ['sensors_active', 'Sensors with events'],
];

// Rows for the volume table: this window, the one before, and the neutral
// difference (a sign and a number; never "better" or "worse").
export function digestFigures(d) {
  return FIGURES.map(([key, label]) => {
    const cur = d?.totals?.[key];
    const prev = d?.previous_totals?.[key];
    const known = isCount(cur) && isCount(prev);
    const diff = known ? cur - prev : null;
    return { key, label, current: isCount(cur) ? cur : null, previous: isCount(prev) ? prev : null, change: diff === null ? '—' : diff === 0 ? 'same' : `${diff > 0 ? '+' : '−'}${formatCount(Math.abs(diff))}` };
  });
}

const t = (v) => ({ t: 'text', v });
const num = (v) => ({ t: 'num', v: count(v) });

// The digest's lead: a few sentences in a fixed order, built only from the
// response. A missing count is said, never zeroed. Segments as in the
// Overview brief: { t: 'text'|'num'|'code'|'title', v }.
export function digestLead(d) {
  const w = normalizeDigestWindow(d?.window);
  const out = [];
  const cur = d?.totals?.events;
  const prev = d?.previous_totals?.events;
  if (!isCount(cur)) out.push([t('The server did not report an event count for this window.')]);
  else if (cur === 0) out.push([t(`The decoys recorded no events in ${WINDOW_TEXT[w]}`), t(isCount(prev) ? (prev === 0 ? ', and none in the window before.' : `; ${PREV_TEXT[w]} held `) : '.'), ...(isCount(prev) && prev > 0 ? [num(prev), t('.')] : [])]);
  else {
    const s = [t(`In ${WINDOW_TEXT[w]} the decoys recorded `), num(cur), t(` ${plural(cur, 'event', 'events')}`)];
    if (isCount(prev)) {
      const diff = cur - prev;
      if (diff === 0) s.push(t(`, the same as ${PREV_TEXT[w]}.`));
      else if (prev === 0) s.push(t(`, against none in ${PREV_TEXT[w]}.`));
      else s.push(t(', '), num(Math.abs(diff)), t(` ${diff > 0 ? 'more' : 'fewer'} than ${PREV_TEXT[w]}.`));
    } else s.push(t('.'));
    out.push(s);
  }
  const src = d?.totals?.sources;
  if (isCount(src) && src > 0) {
    const s = [num(src), t(` distinct ${plural(src, 'source', 'sources')}`)];
    if (isCount(d?.new_sources) && isCount(d?.returning_sources)) s.push(t(': '), num(d.new_sources), t(' not seen in the window before and '), num(d.returning_sources), t(' returning.'));
    else s.push(t('.'));
    out.push(s);
  }
  const auto = d?.sessions_consistent_with_automation;
  if (isCount(auto) && auto > 0) out.push([num(auto), t(` ${plural(auto, 'session was', 'sessions were')} consistent with automation (an observation, not a verdict).`)]);
  const ht = d?.honeytoken_hits;
  const ac = d?.agent_canary_hits;
  if ((isCount(ht) && ht > 0) || (isCount(ac) && ac > 0)) {
    const s = [];
    if (isCount(ht) && ht > 0) s.push(t('A planted decoy credential came back on '), num(ht), t(` ${plural(ht, 'event', 'events')}`));
    if (isCount(ac) && ac > 0) s.push(t(s.length ? ', and an agent canary on ' : 'An agent canary came back on '), num(ac), t(` ${plural(ac, 'event', 'events')}`));
    s.push(t('.'));
    out.push(s);
  }
  const top = arr(d?.top_rules).find((r) => typeof r?.rule_id === 'string' && r.rule_id && isCount(r.events) && r.events > 0);
  if (top) {
    const s = [t('The most cited rule was '), { t: 'code', v: top.rule_id }];
    // The catalog title is server text: its own segment, so the Markdown
    // export can fence it ({ t: 'title' } renders as quoted plain text).
    if (str(top.title)) s.push(t(', '), { t: 'title', v: str(top.title) });
    s.push(t(', on '), num(top.events), t(` ${plural(top.events, 'event', 'events')}.`));
    out.push(s);
  }
  const techs = arr(d?.new_techniques).length;
  if (techs) out.push([num(techs), t(` related ${plural(techs, 'technique was', 'techniques were')} cited that the window before did not cite.`)]);
  return out;
}

export function digestLeadText(d) {
  return digestLead(d).map((s) => s.map((x) => (x.t === 'title' ? `“${x.v}”` : x.v)).join('')).join(' ');
}

export const FRAMEWORK_ORDER = Object.freeze(['mitre-attack', 'mitre-atlas', 'owasp-llm-2025']);
const FRAMEWORK_TEXT = { 'mitre-attack': 'MITRE ATT&CK', 'mitre-atlas': 'MITRE ATLAS', 'owasp-llm-2025': 'OWASP LLM 2025' };

export function groupTechniques(list) {
  const groups = [];
  for (const x of arr(list)) {
    if (!x || typeof x.id !== 'string' || !Object.hasOwn(FRAMEWORK_TEXT, x.framework)) continue;
    let g = groups.find((y) => y.framework === x.framework);
    if (!g) groups.push((g = { framework: x.framework, label: FRAMEWORK_TEXT[x.framework], items: [] }));
    if (!g.items.some((i) => i.id === x.id)) g.items.push({ id: x.id, name: str(x.name) });
  }
  return groups.sort((a, b) => FRAMEWORK_ORDER.indexOf(a.framework) - FRAMEWORK_ORDER.indexOf(b.framework));
}

// The digest's stated limits, in display order. Server sentences are kept
// verbatim; the rest are fixed console wording around server fields.
export function digestLimits(d) {
  const l = d?.limits || {};
  const out = [];
  if (str(l.interpretation)) out.push({ key: 'interpretation', label: 'Interpretation', text: l.interpretation, verbatim: true });
  if (str(l.source_comparison)) out.push({ key: 'source_comparison', label: 'Source comparison', text: l.source_comparison, verbatim: true });
  const hist = { complete: 'Complete: the index holds every event since the console started recording.', truncated: 'Truncated: the index evicted older evidence (it remains on disk), so the comparison window may be incomplete.', unavailable: 'Unavailable: the index starts at process start, so the window before may be partly unknown.' }[l.history];
  if (hist) out.push({ key: 'history', label: 'Index history', text: hist });
  out.push({ key: 'scan', label: 'Scan', text: l.scan_truncated ? `The ${count(d?.bounds?.scan_limit)}-event scan limit was reached: only the newest ${count(d?.bounds?.scanned_events)} indexed events were read.` : `Read ${count(d?.bounds?.scanned_events)} indexed events; the scan limit was not reached.` });
  if (l.investigations_available === false) out.push({ key: 'investigations', label: 'Investigations', text: 'The investigation store did not answer, so open investigations are not counted.' });
  if (isCount(l.recommendation_cap)) {
    const bits = [`At most ${count(l.recommendation_cap)} dry-run recommendations are proposed per digest.`];
    if (isCount(l.recommendation_excluded) && l.recommendation_excluded > 0) bits.push(`${count(l.recommendation_excluded)} forwarded or over-cap ${plural(l.recommendation_excluded, 'event was', 'events were')} left out.`);
    if (isCount(l.recommendation_missing) && l.recommendation_missing > 0) bits.push(`${count(l.recommendation_missing)} ${plural(l.recommendation_missing, 'reference was', 'references were')} no longer indexed.`);
    out.push({ key: 'recommendations', label: 'Recommendations', text: bits.join(' ') });
  }
  out.push({ key: 'delivery', label: 'Delivery', text: 'Computed on demand when this page loads. Nothing is scheduled, stored or sent.' });
  return out;
}

// ---- Markdown export -----------------------------------------------------------------

// Every server string goes into an inline code span: control, format and
// bidi characters become spaces, the fence is longer than any backtick run
// inside, and table pipes cannot break out.
export function mdFence(value) {
  // Controls, C1, line/paragraph separators, zero-width and bidi format characters.
  const clean = String(value ?? '').replace(/[\u0000-\u001f\u007f-\u009f\u200b-\u200f\u2028-\u202e\u2066-\u2069\ufeff]/g, ' ').replace(/\|/g, '\\|').slice(0, 300);
  const runs = clean.match(/`+/g) || [];
  const fence = '`'.repeat(Math.max(0, ...runs.map((r) => r.length)) + 1);
  const pad = clean.startsWith('`') || clean.endsWith('`') ? ' ' : '';
  return `${fence}${pad}${clean || ' '}${pad}${fence}`;
}

export function digestMarkdown(d, { asOfText = '', organization = '' } = {}) {
  const w = normalizeDigestWindow(d?.window);
  const lines = [];
  lines.push(`# AegisMesh digest: ${WINDOW_TEXT[w]}`, '');
  // Configured by an administrator, fenced like every other server string.
  if (str(organization)) lines.push(`Organization: ${mdFence(organization)}`, '');
  if (asOfText) lines.push(`As of ${asOfText}. Observations, not incidents.`, '');
  lines.push(digestLead(d).map((s) => s.map((x) => (x.t === 'code' || x.t === 'title' ? mdFence(x.v) : x.v)).join('')).join(' ') || 'No figures were reported.', '');
  lines.push('## Volume', '', `| Measure | ${w === '7d' ? 'Last 7 days' : 'Last 24 hours'} | Window before | Change |`, '| --- | ---: | ---: | ---: |');
  for (const f of digestFigures(d)) lines.push(`| ${f.label} | ${count(f.current)} | ${count(f.previous)} | ${f.change} |`);
  lines.push('', '## Sources and sessions', '');
  lines.push(`- New sources (absent from the window before): ${count(d?.new_sources)}`);
  lines.push(`- Returning sources: ${count(d?.returning_sources)}`);
  lines.push(`- Sessions consistent with automation: ${count(d?.sessions_consistent_with_automation)}`);
  lines.push('', '## Most cited rules', '');
  const rules = arr(d?.top_rules).filter((r) => typeof r?.rule_id === 'string');
  if (rules.length) {
    rules.forEach((r, i) => lines.push(`${i + 1}. ${mdFence(r.rule_id)}${str(r.title) ? ` ${mdFence(r.title)}` : ''}${isSeverity(r.severity) ? ` (${severityLabel(r.severity)})` : ''}: ${count(r.events)} ${plural(r.events, 'event', 'events')}`));
  } else lines.push('No rule was cited in this window.');
  lines.push('', '## Newly observed techniques', '');
  const groups = groupTechniques(d?.new_techniques);
  if (groups.length) {
    for (const g of groups) lines.push(`- ${g.label}: ${g.items.map((x) => `${mdFence(x.id)} ${mdFence(x.name)}`).join(', ')}`);
    lines.push('', 'Editorial "relates to" references: a related rule fired, not proof the technique was used.');
  } else lines.push('No related technique was cited that the window before did not cite.');
  lines.push('', '## Planted markers and open work', '');
  lines.push(`- Decoy credential (HT-001) hits: ${count(d?.honeytoken_hits)}`);
  lines.push(`- Agent canary (AGT-001) hits: ${count(d?.agent_canary_hits)}`);
  lines.push(`- Open investigations: ${d?.open_investigations === null ? 'not available' : count(d?.open_investigations)}`);
  lines.push(`- Dry-run recommendations (proposed, not executed): ${count(d?.dry_run_recommendations)}`);
  lines.push('', '## Limits', '');
  for (const l of digestLimits(d)) lines.push(`- ${l.label}: ${l.verbatim ? mdFence(l.text) : l.text}`);
  lines.push('');
  return lines.join('\n');
}
