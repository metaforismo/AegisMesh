// Dev-mock twin of the backend's derived views (ADR-0022): attacker sessions,
// framework relations, indicator downloads and observation reports. It follows
// docs/architecture/console-api.md ("Attacker sessions, framework relations
// and downloads") and the Go handlers' field names. A fixture: not embedded,
// not shipped. All data it reads is the mock's synthetic index.

import { createHash } from 'node:crypto';
import { isIP } from 'node:net';

export const SCAN_LIMIT = 8192;
export const IDLE_MS = 30 * 60 * 1000;
export const MIN_AUTOMATION_EVENTS = 8;
export const TIMELINE_CAP = 200;
export const FRAMEWORKS = ['mitre-attack', 'mitre-atlas', 'owasp-llm-2025'];
export const INTERPRETATION = 'Editorial rule relations and retained observations; not technique execution or completeness.';

// rule → [framework, id, name] (from the backend catalog's frameworks.tsv;
// the mock's own synthetic rules have no references).
const T = (framework, id, name) => ({ framework, id, name });
export const RULE_FRAMEWORKS = {
  'PI-001': [T('mitre-atlas', 'AML.T0051', 'LLM Prompt Injection'), T('mitre-atlas', 'AML.T0054', 'LLM Jailbreak'), T('owasp-llm-2025', 'LLM01', 'Prompt Injection')],
  'PI-002': [T('mitre-attack', 'T1027', 'Obfuscated Files or Information'), T('mitre-atlas', 'AML.T0051', 'LLM Prompt Injection'), T('owasp-llm-2025', 'LLM01', 'Prompt Injection')],
  'EXF-001': [T('mitre-attack', 'T1552', 'Unsecured Credentials'), T('mitre-atlas', 'AML.T0057', 'LLM Data Leakage'), T('owasp-llm-2025', 'LLM02', 'Sensitive Information Disclosure')],
  'ESC-001': [T('mitre-attack', 'T1059', 'Command and Scripting Interpreter'), T('mitre-atlas', 'AML.T0053', 'LLM Plugin Compromise'), T('owasp-llm-2025', 'LLM06', 'Excessive Agency')],
  'RES-001': [T('mitre-attack', 'T1499', 'Endpoint Denial of Service'), T('mitre-atlas', 'AML.T0029', 'Denial of ML Service'), T('owasp-llm-2025', 'LLM10', 'Unbounded Consumption')],
  'LLM-001': [T('mitre-attack', 'T1595', 'Active Scanning'), T('mitre-atlas', 'AML.T0006', 'Active Scanning')],
  'LLM-002': [T('mitre-attack', 'T1078', 'Valid Accounts'), T('mitre-atlas', 'AML.T0012', 'Valid Accounts'), T('mitre-atlas', 'AML.T0040', 'AI Model Inference API Access'), T('owasp-llm-2025', 'LLM10', 'Unbounded Consumption')],
  'LLM-003': [T('mitre-attack', 'T1496', 'Resource Hijacking'), T('mitre-atlas', 'AML.T0034', 'Cost Harvesting'), T('owasp-llm-2025', 'LLM10', 'Unbounded Consumption')],
  'LLM-004': [T('mitre-attack', 'T1078', 'Valid Accounts'), T('mitre-atlas', 'AML.T0012', 'Valid Accounts')],
  'HT-001': [T('mitre-attack', 'T1552', 'Unsecured Credentials'), T('mitre-attack', 'T1078', 'Valid Accounts'), T('mitre-atlas', 'AML.T0055', 'Unsecured Credentials'), T('owasp-llm-2025', 'LLM02', 'Sensitive Information Disclosure')],
  'AGT-001': [T('mitre-atlas', 'AML.T0051', 'LLM Prompt Injection'), T('owasp-llm-2025', 'LLM01', 'Prompt Injection')],
  'MCP-001': [T('mitre-attack', 'T1552', 'Unsecured Credentials'), T('mitre-atlas', 'AML.T0055', 'Unsecured Credentials'), T('owasp-llm-2025', 'LLM02', 'Sensitive Information Disclosure')],
  'MCP-002': [T('mitre-atlas', 'AML.T0053', 'LLM Plugin Compromise'), T('owasp-llm-2025', 'LLM06', 'Excessive Agency')],
  'MCP-003': [T('mitre-atlas', 'AML.T0053', 'LLM Plugin Compromise'), T('owasp-llm-2025', 'LLM06', 'Excessive Agency')],
  'COR-005': [T('mitre-attack', 'T1595', 'Active Scanning')],
  'COR-006': [T('mitre-attack', 'T1595', 'Active Scanning'), T('mitre-atlas', 'AML.T0006', 'Active Scanning')],
  'COR-007': [T('mitre-attack', 'T1110', 'Brute Force')],
  'COR-008': [T('mitre-attack', 'T1078', 'Valid Accounts'), T('mitre-atlas', 'AML.T0012', 'Valid Accounts'), T('owasp-llm-2025', 'LLM02', 'Sensitive Information Disclosure')],
};

const frameworkSort = (a, b) => FRAMEWORKS.indexOf(a.framework) - FRAMEWORKS.indexOf(b.framework) || (a.id < b.id ? -1 : a.id > b.id ? 1 : 0);
export const frameworksFor = (ruleIds) => {
  const seen = new Map();
  for (const r of ruleIds) for (const f of RULE_FRAMEWORKS[r] || []) seen.set(`${f.framework}|${f.id}`, f);
  return [...seen.values()].sort(frameworkSort);
};

const SEV = ['info', 'low', 'medium', 'high', 'critical'];
const originOf = (e) => e.node?.id || 'local';
const originKey = (e) => `${originOf(e)}:${e.id}`;
const ms = (t) => Date.parse(t);
const nano = (t) => new Date(ms(t)).toISOString().replace(/\.(\d{3})Z$/, '.$1000000Z');

// The newest SCAN_LIMIT entries, as one snapshot.
export function snapshot(events, history = 'complete', capacity = 50000) {
  const newest = [...events].sort((a, b) => ms(b.time) - ms(a.time)).slice(0, SCAN_LIMIT);
  const oldest = events.reduce((m, e) => (m === '' || ms(e.time) < ms(m) ? e.time : m), '');
  return {
    events: newest,
    bounds: { index: { events: events.length, capacity, oldest, history }, scanned_events: newest.length, scan_limit: SCAN_LIMIT, scan_truncated: events.length > SCAN_LIMIT },
  };
}

function gaps(list) {
  const out = [];
  for (let i = 1; i < list.length; i++) out.push(Math.max(0, ms(list[i].time) - ms(list[i - 1].time)));
  return out;
}

export function cadenceOf(list) {
  const g = gaps(list);
  if (!g.length) return { min_gap_ms: 0, median_gap_ms: 0, p90_gap_ms: 0, events_per_minute: 0, regularity: 0 };
  const sorted = [...g].sort((a, b) => a - b);
  const median = sorted[Math.floor(sorted.length / 2)];
  const p90 = sorted[Math.max(0, Math.ceil(0.9 * sorted.length) - 1)];
  const elapsedMin = (ms(list[list.length - 1].time) - ms(list[0].time)) / 60000;
  const regular = g.filter((x) => (median === 0 ? x === 0 : Math.abs(x - median) <= 0.25 * median)).length;
  return { min_gap_ms: sorted[0], median_gap_ms: median, p90_gap_ms: p90, events_per_minute: elapsedMin > 0 ? (list.length - 1) / elapsedMin : 0, regularity: regular / g.length };
}

export function automationOf(list, rules) {
  const a = { assessment: 'inconclusive', evidence: [] };
  const inter = list.filter((e) => e.classification !== 'correlation_signal');
  const c = cadenceOf(inter);
  const enough = inter.length >= MIN_AUTOMATION_EVENTS;
  if (enough && c.median_gap_ms < 1000) a.evidence.push({ code: 'sub_second_cadence', detail: 'Median interaction gap below 1000 ms; timestamps alone do not establish reactions or intent.' });
  if (enough && c.median_gap_ms >= 1000 && c.median_gap_ms <= 30000 && c.regularity >= (inter.length - 2) / (inter.length - 1)) a.evidence.push({ code: 'regular_cadence', detail: 'Median interaction gap at most 30 s, with at most one gap outside 25% of the median.' });
  for (const [id, code, detail] of [
    ['AGT-001', 'agent_canary', 'AGT-001 observed an instruction marker from decoy content; this does not prove an LLM client.'],
    ['COR-005', 'correlation_cadence', 'COR-005 fired in the retained sequence.'],
    ['COR-006', 'multi_surface_enumeration', 'COR-006 observed multiple AI surface families.'],
    ['HT-001', 'honeytoken_replay', 'HT-001 observed an operator-owned decoy credential marker inbound.'],
    ['COR-008', 'cross_sensor_replay', 'COR-008 linked a decoy credential observation to earlier contact on another sensor.'],
  ]) if (rules.has(id)) a.evidence.push({ code, detail });
  if (!enough) {
    a.evidence.push({ code: 'insufficient_events', detail: `At least ${MIN_AUTOMATION_EVENTS} non-signal events are required; retained ${inter.length}.` });
    return a;
  }
  a.assessment = a.evidence.length ? 'consistent_with_automation' : 'mixed';
  return a;
}

const sortStr = (arr) => [...new Set(arr)].sort();

function sessionOf(tenant, source, list) {
  const rules = new Set(list.flatMap((e) => e.rule_ids || []));
  const sensors = sortStr(list.map((e) => e.sensor?.id).filter(Boolean));
  const kinds = sortStr(list.map((e) => e.sensor?.kind).filter(Boolean));
  const counts = {};
  for (const e of list) counts[e.classification] = (counts[e.classification] || 0) + 1;
  let max = '';
  for (const e of list) if (e.classification !== 'correlation_signal' && SEV.indexOf(e.severity) > SEV.indexOf(max)) max = e.severity;
  const id = createHash('sha256').update(JSON.stringify([tenant, source, originKey(list[0])])).digest('hex').slice(0, 32);
  return {
    id, source, first_seen: nano(list[0].time), last_seen: nano(list[list.length - 1].time),
    duration_ms: ms(list[list.length - 1].time) - ms(list[0].time), event_count: list.length,
    sensors: sensors.slice(0, 64), sensor_kinds: kinds.slice(0, 64), sensors_truncated: sensors.length > 64 || kinds.length > 64,
    classification_counts: counts, rule_ids: sortStr([...rules]), max_severity: max,
    frameworks: frameworksFor([...rules]), cadence: cadenceOf(list), automation: automationOf(list, rules),
    _events: list,
  };
}

// Group the snapshot by source, splitting on idle gaps > 30 minutes.
export function sessionsOf(tenant, events) {
  const asc = [...events].filter((e) => e.source).sort((a, b) => ms(a.time) - ms(b.time) || (originKey(a) < originKey(b) ? -1 : 1));
  const open = new Map();
  const out = [];
  for (const e of asc) {
    const cur = open.get(e.source);
    if (cur && ms(e.time) - ms(cur[cur.length - 1].time) <= IDLE_MS) cur.push(e);
    else {
      if (cur) out.push(sessionOf(tenant, e.source, cur));
      open.set(e.source, [e]);
    }
  }
  for (const [src, list] of open) out.push(sessionOf(tenant, src, list));
  return out.sort((a, b) => ms(b.last_seen) - ms(a.last_seen) || (a.id < b.id ? -1 : 1));
}

export const publicSession = ({ _events, ...rest }) => rest;

function stageOf(e) {
  const r = new Set(e.rule_ids || []);
  if (r.has('HT-001') || r.has('COR-008')) return 'decoy_credential_replay';
  if (['LLM-002', 'LLM-003', 'AGT-001', 'PI-001', 'PI-002', 'ESC-001'].some((x) => r.has(x))) return 'ai_service_abuse';
  if (['EXF-001', 'LLM-004', 'COR-007'].some((x) => r.has(x)) || e.sensor?.kind === 'ssh') return 'credential_access';
  return 'discovery';
}

export function sessionDetail(session) {
  const list = session._events.slice(0, TIMELINE_CAP);
  const timeline = list.map((e, i) => ({
    event_id: e.id, node_id: originOf(e), time: nano(e.time), gap_ms: i ? Math.max(0, ms(e.time) - ms(list[i - 1].time)) : null,
    sensor: e.sensor?.id || '', kind: e.sensor?.kind || '', classification: e.classification, rule_ids: [...(e.rule_ids || [])].sort(), summary: e.summary,
  }));
  const phases = [];
  for (const e of list) {
    const stage = stageOf(e);
    const last = phases[phases.length - 1];
    if (last && last.stage === stage) { last.last_seen = nano(e.time); last.event_ids.push(e.id); }
    else phases.push({ stage, first_seen: nano(e.time), last_seen: nano(e.time), event_ids: [e.id] });
  }
  return { ...publicSession(session), timeline, phases, timeline_truncated: session._events.length > TIMELINE_CAP };
}

export function coverageOf(events, since, until) {
  const inWindow = events.filter((e) => ms(e.time) >= since && ms(e.time) <= until);
  return FRAMEWORKS.map((framework) => {
    const techniques = new Map();
    for (const [rule, refs] of Object.entries(RULE_FRAMEWORKS)) {
      for (const f of refs) {
        if (f.framework !== framework) continue;
        const t = techniques.get(f.id) || { id: f.id, name: f.name, rule_ids: [] };
        t.rule_ids.push(rule);
        techniques.set(f.id, t);
      }
    }
    const list = [...techniques.values()].sort((a, b) => (a.id < b.id ? -1 : 1)).map((t) => {
      const hits = inWindow.filter((e) => (e.rule_ids || []).some((r) => t.rule_ids.includes(r)));
      const last = hits.reduce((m, e) => (m === '' || ms(e.time) > ms(m) ? e.time : m), '');
      return { id: t.id, name: t.name, rule_ids: t.rule_ids.sort(), observed_event_count: new Set(hits.map(originKey)).size, last_seen: last ? nano(last) : '' };
    });
    return { framework, techniques: list };
  });
}

// ---- Downloads ------------------------------------------------------------

export function indicatorsOf(events) {
  const byIp = new Map();
  const skippedSources = new Set();
  let skippedEvents = 0;
  for (const e of events) {
    let ip = String(e.source || '');
    if (ip.startsWith('::ffff:') && isIP(ip.slice(7)) === 4) ip = ip.slice(7);
    if (!ip || isIP(ip) === 0) { skippedSources.add(ip); skippedEvents++; continue; }
    const cur = byIp.get(ip) || { indicator: ip, type: isIP(ip) === 4 ? 'ipv4-addr' : 'ipv6-addr', first: e.time, last: e.time, refs: new Set() };
    if (ms(e.time) < ms(cur.first)) cur.first = e.time;
    if (ms(e.time) > ms(cur.last)) cur.last = e.time;
    cur.refs.add(originKey(e));
    byIp.set(ip, cur);
  }
  return { list: [...byIp.values()].sort((a, b) => (a.indicator < b.indicator ? -1 : 1)), skippedSources: skippedSources.size, skippedEvents };
}

const CSV_HEAD = 'indicator,type,first_seen,last_seen,event_count,confidence,interpretation,skipped_non_ip_sources,skipped_non_ip_events';
const INTERP = 'observed contact with a decoy; not attribution or intent';

export function renderIndicators(format, { list, skippedSources, skippedEvents }) {
  if (format === 'csv') {
    return [CSV_HEAD, ...list.map((i) => [i.indicator, i.type, nano(i.first), nano(i.last), i.refs.size, 15, INTERP, skippedSources, skippedEvents].join(','))].join('\n') + '\n';
  }
  if (format === 'txt') {
    return [
      '# PROPOSED blocklist for operator review; never applied by AegisMesh',
      `# skipped non-IP sources: ${skippedSources}; skipped non-IP events: ${skippedEvents}`,
      ...list.map((i) => i.indicator),
    ].join('\n') + '\n';
  }
  const uuid = (name) => {
    const h = createHash('sha1').update(name).digest('hex');
    return `${h.slice(0, 8)}-${h.slice(8, 12)}-5${h.slice(13, 16)}-${((parseInt(h[16], 16) & 3) | 8).toString(16)}${h.slice(17, 20)}-${h.slice(20, 32)}`;
  };
  const identity = { type: 'identity', spec_version: '2.1', id: `identity--${uuid('identity')}`, name: 'AegisMesh (mock instance)', identity_class: 'system', created: '2026-01-01T00:00:00.000Z', modified: '2026-01-01T00:00:00.000Z' };
  const objects = [identity];
  for (const i of list) {
    objects.push({
      type: 'indicator', spec_version: '2.1', id: `indicator--${uuid(JSON.stringify(['indicator', i.indicator]))}`, created_by_ref: identity.id,
      created: nano(i.first), modified: nano(i.last), valid_from: nano(i.first), confidence: 15,
      pattern: `[${i.type}:value = '${i.indicator}']`, pattern_type: 'stix', pattern_version: '2.1',
      description: `Observed contact with an AegisMesh decoy (${i.refs.size} events). Not attribution or intent.`,
    });
  }
  objects.push({ type: 'note', spec_version: '2.1', id: `note--${uuid('summary')}`, created: '2026-01-01T00:00:00.000Z', modified: '2026-01-01T00:00:00.000Z', content: `Export summary: ${list.length} indicators; skipped ${skippedSources} non-IP sources (${skippedEvents} events).`, object_refs: [identity.id] });
  return JSON.stringify({ type: 'bundle', id: `bundle--${uuid(JSON.stringify(objects.map((o) => o.id)))}`, objects }, null, 2) + '\n';
}

const quote = (s) => `> ${JSON.stringify(String(s ?? '').slice(0, 4000))}`;

export function renderReport({ title, scope, events, sessions = [], notes = [], unresolved = 0 }) {
  const lines = [
    '# AegisMesh observation report', '',
    'This report describes observations against decoys. It is not a declaration that an incident occurred, nor a forensic chain of custody.', '',
    '## Scope', '', `- ${scope}`, title ? `- Title:` : null, title ? quote(title) : null, `- Events: ${events.length}`, unresolved ? `- Unresolved attached references: ${unresolved}` : null, '',
    '## Timeline (first 200)', '',
  ].filter((l) => l !== null);
  for (const e of events.slice(0, 200)) lines.push(`- ${nano(e.time)} ${e.sensor?.id || ''} ${e.classification} ${(e.rule_ids || []).join(' ')}`, quote(e.summary));
  if (events.length > 200) lines.push(`- Omitted: ${events.length - 200} events`);
  lines.push('', '## Automation observations', '');
  for (const s of sessions) {
    lines.push(`- Session ${s.id}: ${s.automation.assessment}`);
    for (const o of s.automation.evidence) lines.push(`  - ${o.code}: ${o.detail}`);
  }
  if (notes.length) {
    lines.push('', '## Notes', '');
    for (const n of notes) lines.push(`- ${n.time} ${n.author}`, quote(String(n.text).replace(/\s+/g, ' ')));
  }
  lines.push('', '## Proposed recommendations (dry run, not executed)', '', '- Review the sources above; any blocking is an operator decision outside AegisMesh.', '',
    '## Limits', '', '- Derived from the newest 8192 retained index entries; older evidence may exist on disk.', '- A source key is not an actor identity.', '');
  return lines.join('\n');
}
