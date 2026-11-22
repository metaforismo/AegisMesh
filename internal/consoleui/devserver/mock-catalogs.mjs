// Dev-mock twin of the backend's round-3 additions: the decoy and honeytoken
// catalogs, the on-demand digest, local SIEM event formats, rule prose
// (description, guidance, observe_only) and the source inter-arrival
// histogram. It follows docs/architecture/console-api.md ("Round 3
// additions") and the Go handlers' field names
// (internal/console/{decoys,digest,event_export,sources}_handlers.go,
// internal/digest, internal/evidenceindex/histogram.go). A fixture: not
// embedded, not shipped. Every value is synthetic; honeytoken values do not
// exist here at all, only their ids.

import { createHash } from 'node:crypto';
import { frameworksFor, FRAMEWORKS } from './mock-analysis.mjs';

const ms = (t) => Date.parse(t);
const nano = (t) => new Date(typeof t === 'number' ? t : ms(t)).toISOString().replace(/\.(\d{3})Z$/, '.$1000000Z');
const WINDOW_MS = { '1h': 3600e3, '24h': 86400e3, '7d': 7 * 86400e3 };
export const CATALOG_WINDOWS = ['1h', '24h', '7d'];
export const DIGEST_WINDOWS = ['24h', '7d'];
export const EXPORT_FORMATS = ['cef', 'syslog-rfc5424', 'otlp-json', 'ecs'];
export const EXPORT_NAMES = {
  cef: 'aegismesh-events-cef.log',
  'syslog-rfc5424': 'aegismesh-events-syslog-rfc5424.log',
  'otlp-json': 'aegismesh-events-otlp-json.json',
  ecs: 'aegismesh-events-ecs.ndjson',
};
export const EXPORT_TYPES = {
  cef: 'text/plain; charset=utf-8',
  'syslog-rfc5424': 'text/plain; charset=utf-8',
  'otlp-json': 'application/json',
  ecs: 'application/x-ndjson',
};

// ---- Rule prose ------------------------------------------------------------
// The backend's catalog prose for its own rule ids (internal/rulecatalog/
// prose.go), plus synthetic prose for the mock's own synthetic rules. Every
// record has nonempty static prose, as the contract says.

export const RULE_PROSE = {
  'PI-001': ['Instruction override phrasing was observed.', 'Review the redacted request and surrounding session for legitimate diagnostic context.'],
  'PI-002': ['Hidden channel characters were observed in an interaction.', 'Check the redacted preview and encoding context before interpreting the observation.'],
  'EXF-001': ['A credential or environment disclosure request pattern was observed.', 'Check which synthetic surface was contacted and whether a planted token was later presented.'],
  'ESC-001': ['Tool escalation phrasing was observed.', 'Review the requested tool name and the recorded response action.'],
  'RES-001': ['The interaction exceeded the detection evaluation bound.', 'Check retained length and truncation flags before drawing conclusions from partial evidence.'],
  'LLM-001': ['An AI service shaped endpoint was contacted.', 'Review other surfaces contacted by the same retained source.'],
  'LLM-002': ['A small completion shaped probe was observed.', 'Check nearby enumeration requests and normal health monitoring context.'],
  'LLM-003': ['An AI management shaped request was observed.', 'Review the static response and adjacent requests; no management operation occurred.'],
  'LLM-004': ['A provider shaped credential was presented.', 'Check credential class metadata and planted-token matches without seeking credential values.'],
  'HT-001': ['A planted synthetic credential was presented to a sensor.', 'Follow the token identifier across retained observations and verify its configured planting.'],
  'AGT-001': ['A planted agent marker was presented to a sensor.', 'Review the originating synthetic response and subsequent request sequence.'],
  'MCP-001': ['Declared synthetic credential content was requested from the workspace.', 'Check the connection tool sequence and later HT-001 or COR-008 observations.'],
  'MCP-002': ['A connection reached the configured workspace exploration depth.', 'Review tool order and cadence; depth alone does not identify an automated client.'],
  'MCP-003': ['A write or execution shaped tool name was requested.', 'Review the tool name and not-found response; no write or execution was performed.'],
  'COR-005': ['A retained source showed a cadence consistent with automation.', 'Inspect timing gaps and clock precision; this is not client attribution.'],
  'COR-006': ['A retained source enumerated multiple AI surface families.', 'Compare contacted families with normal client and monitoring behavior.'],
  'COR-007': ['Multiple distinct credential presentations were observed.', 'Review counts and credential classes without seeking raw credential values.'],
  'COR-008': ['A planted credential was presented across sensor contexts.', 'Trace the token identifier and linked sensor observations within retained evidence.'],
  // Synthetic rules that exist only in the mock.
  'PT-002': ['A path traversal sequence was observed in a request or tool argument.', 'Check which decoy path was requested; the decoy serves no real files.'],
  'CMD-003': ['Shell command syntax was observed in tool arguments.', 'Review the redacted arguments; nothing was executed.'],
  'SCAN-004': ['A well-known scanner path was requested.', 'Compare with expected scanner schedules before reading further.'],
  'AUTH-005': ['A credential guess was observed.', 'Review the attempt count for the source; the decoy accepts no real credentials.'],
  'CR-MULTI-SENSOR': ['One source reached two or more sensors within the correlation window.', 'Open the linked observations and compare the sensors reached.'],
  'CR-CANARY-AFTER-SCAN': ['A canary was invoked after reconnaissance from the same source.', 'Read the reconnaissance events before the canary invocation.'],
};

// detect.ObserveOnly: the AI and MCP observation rules can never select a
// response action. Correlation rules are observe-only by family.
export const OBSERVE_ONLY_DETECTION = new Set(['LLM-001', 'LLM-002', 'LLM-003', 'LLM-004', 'HT-001', 'AGT-001', 'MCP-001', 'MCP-002', 'MCP-003']);

export function ruleRecord(r) {
  const prose = RULE_PROSE[r.id] || ['Synthetic rule in the development mock.', 'Read the linked observations.'];
  return {
    ...r,
    description: prose[0],
    guidance: prose[1],
    observe_only: r.family === 'correlation' || OBSERVE_ONLY_DETECTION.has(r.id),
  };
}

// ---- Decoy and honeytoken catalogs ----------------------------------------
// Value-only metadata derived from the (synthetic) configuration. Keyed by
// sensor id; kind and listen come from the sensor list.

export const DECOY_CONFIG = {
  'ai-litellm': { surface_families: ['litellm', 'openai_compatible', 'vllm'], rules: 12, tools: 0, fake_files: 0, honeytoken_ids: ['diagnostic-echo', 'planted-key'] },
  'ai-ollama': { surface_families: ['ollama'], rules: 9, tools: 0, fake_files: 0, honeytoken_ids: [] },
  'ai-workspace': { surface_families: ['mcp_environment'], rules: 0, tools: 5, fake_files: 3, honeytoken_ids: ['workspace-key'] },
  'mcp-tools': { surface_families: ['mcp'], rules: 0, tools: 6, fake_files: 0, honeytoken_ids: [] },
  'redis-lure': { surface_families: ['tcp'], rules: 3, tools: 0, fake_files: 0, honeytoken_ids: [] },
  'ssh-decoy': { surface_families: ['ssh'], rules: 0, tools: 0, fake_files: 0, honeytoken_ids: [] },
  web: { surface_families: ['http'], rules: 7, tools: 0, fake_files: 0, honeytoken_ids: [] },
};

// Planted ids only. "unplanted-spare" is declared but no inline planting was
// found, so its sensor_ids is empty (the contract's case).
export const TOKEN_CONFIG = [
  { id: 'diagnostic-echo', kind: 'agent_canary' },
  { id: 'planted-key', kind: 'credential' },
  { id: 'unplanted-spare', kind: 'credential' },
  { id: 'workspace-key', kind: 'credential' },
];

export function decoyCatalog(sensors) {
  const out = sensors.map((s) => {
    const c = DECOY_CONFIG[s.id] || { surface_families: [s.kind], rules: 0, tools: 0, fake_files: 0, honeytoken_ids: [] };
    return {
      id: s.id, kind: s.kind, listen: s.listen,
      surface_families: [...c.surface_families].sort(), rules: c.rules, tools: c.tools, fake_files: c.fake_files,
      honeytoken_ids: [...c.honeytoken_ids].sort(), events: 0, last_activity: '',
    };
  });
  return out.sort((a, b) => (a.id < b.id ? -1 : 1));
}

export function tokenCatalog(decoys) {
  return TOKEN_CONFIG.map((t) => ({
    id: t.id, kind: t.kind,
    sensor_ids: decoys.filter((d) => d.honeytoken_ids.includes(t.id)).map((d) => d.id).sort(),
    hit_count: 0, last_hit: '', sources: [],
  })).sort((a, b) => (a.id < b.id ? -1 : 1));
}

// Local events in the half-open window [now - w, now) of the snapshot.
const inWindow = (events, w, now) => events.filter((e) => !e.node && ms(e.time) >= now - WINDOW_MS[w] && ms(e.time) < now);

export function decoysView(catalog, snapshotEvents, w, now = Date.now()) {
  const list = inWindow(snapshotEvents, w, now);
  return catalog.map((d) => {
    const mine = list.filter((e) => e.sensor?.id === d.id);
    const last = mine.reduce((m, e) => (m === '' || ms(e.time) > ms(m) ? e.time : m), '');
    return { ...d, events: mine.length, last_activity: last ? nano(last) : '' };
  });
}

export function honeytokensView(catalog, snapshotEvents, w, now = Date.now()) {
  const list = inWindow(snapshotEvents, w, now);
  return catalog.map((t) => {
    const hits = list.filter((e) => (e._tokens || []).includes(t.id));
    const last = hits.reduce((m, e) => (m === '' || ms(e.time) > ms(m) ? e.time : m), '');
    return { ...t, hit_count: hits.length, last_hit: last ? nano(last) : '', sources: [...new Set(hits.map((e) => e.source).filter(Boolean))].sort() };
  });
}

// ---- Source inter-arrival histogram -----------------------------------------
// All retained events for the exact source, by time; exclusive upper bounds
// 100 ms, 1 s, 10 s, 1 min, 5 min, 30 min, then null (infinity).

export const GAP_BOUNDS = [100, 1000, 10000, 60000, 300000, 1800000];

export function interArrival(sourceEvents) {
  const out = [...GAP_BOUNDS.map((lt_ms) => ({ lt_ms, count: 0 })), { lt_ms: null, count: 0 }];
  const sorted = [...sourceEvents].sort((a, b) => ms(a.time) - ms(b.time));
  for (let i = 1; i < sorted.length; i++) {
    const gap = Math.max(0, ms(sorted[i].time) - ms(sorted[i - 1].time));
    const k = GAP_BOUNDS.findIndex((b) => gap < b);
    out[k < 0 ? GAP_BOUNDS.length : k].count++;
  }
  return out;
}

// ---- Digest ------------------------------------------------------------------

export const DIGEST_INTERPRETATION = 'Retained observations, not incidents, client attribution or technique execution; no scheduler or delivery.';
export const SOURCE_COMPARISON = 'New means absent from the preceding sampled window, not first-ever seen.';
export const RECOMMENDATION_CAP = 20;

const CLASSES = ['interaction', 'canary_invocation', 'correlation_signal'];
function totals(list) {
  return {
    events: list.length,
    ...Object.fromEntries(CLASSES.map((c) => [c, list.filter((e) => e.classification === c).length])),
    sources: new Set(list.map((e) => e.source).filter(Boolean)).size,
    sensors_active: new Set(list.map((e) => e.sensor?.id).filter(Boolean)).size,
  };
}

// events: the snapshot (newest 8192); sessions: sessionsOf(); rules: catalog
// records with title/severity; investigations: array or null when the store
// is unavailable.
export function digestOf({ window: w, now = Date.now(), snap, sessions, rules, investigations }) {
  const span = WINDOW_MS[w];
  const cur = snap.events.filter((e) => ms(e.time) >= now - span && ms(e.time) < now);
  const prev = snap.events.filter((e) => ms(e.time) >= now - 2 * span && ms(e.time) < now - span);
  const curSources = new Set(cur.map((e) => e.source).filter(Boolean));
  const prevSources = new Set(prev.map((e) => e.source).filter(Boolean));
  const counts = new Map();
  for (const e of cur) for (const r of new Set(e.rule_ids || [])) counts.set(r, (counts.get(r) || 0) + 1);
  const ruleBy = new Map(rules.map((r) => [r.id, r]));
  const top = [...counts].map(([rule_id, events]) => ({ rule_id, title: ruleBy.get(rule_id)?.title || '', severity: ruleBy.get(rule_id)?.severity || '', events }))
    .sort((a, b) => b.events - a.events || (a.rule_id < b.rule_id ? -1 : 1)).slice(0, 10);
  const key = (f) => `${f.framework}|${f.id}`;
  const prevTech = new Set(frameworksFor([...new Set(prev.flatMap((e) => e.rule_ids || []))]).map(key));
  const newTech = frameworksFor([...new Set(cur.flatMap((e) => e.rule_ids || []))]).filter((f) => !prevTech.has(key(f)))
    .sort((a, b) => FRAMEWORKS.indexOf(a.framework) - FRAMEWORKS.indexOf(b.framework) || (a.id < b.id ? -1 : 1))
    .map((f) => ({ framework: f.framework, id: f.id, name: f.name }));
  const overlaps = (s) => ms(s.last_seen) >= now - span && ms(s.first_seen) < now;
  const local = cur.filter((e) => !e.node);
  const proposals = local.filter((e) => e.classification !== 'interaction');
  return {
    window: w, as_of: nano(now),
    totals: totals(cur), previous_totals: totals(prev),
    new_sources: [...curSources].filter((s) => !prevSources.has(s)).length,
    returning_sources: [...curSources].filter((s) => prevSources.has(s)).length,
    sessions_consistent_with_automation: sessions.filter((s) => overlaps(s) && s.automation?.assessment === 'consistent_with_automation').length,
    top_rules: top,
    new_techniques: newTech,
    honeytoken_hits: cur.filter((e) => (e.rule_ids || []).includes('HT-001')).length,
    agent_canary_hits: cur.filter((e) => (e.rule_ids || []).includes('AGT-001')).length,
    open_investigations: investigations ? investigations.filter((i) => i.status !== 'closed').length : null,
    dry_run_recommendations: Math.min(RECOMMENDATION_CAP, proposals.length),
    bounds: snap.bounds,
    limits: {
      interpretation: DIGEST_INTERPRETATION,
      history: snap.bounds.index.history,
      scan_truncated: snap.bounds.scan_truncated,
      source_comparison: SOURCE_COMPARISON,
      investigations_available: Boolean(investigations),
      recommendation_excluded: cur.length - local.length,
      recommendation_missing: 0,
      recommendation_cap: RECOMMENDATION_CAP,
    },
  };
}

// ---- Local SIEM event formats ----------------------------------------------
// File encodings only (docs/siem-export.md). Nothing is sent anywhere: the
// console hands the analyst a file. Messages describe redacted observations.

const SEV_MAP = {
  '': [0, 6, 9, 'INFO'], info: [0, 6, 9, 'INFO'], low: [1, 5, 9, 'INFO'],
  medium: [4, 4, 13, 'WARN'], high: [7, 3, 17, 'ERROR'], critical: [10, 2, 21, 'FATAL'],
};
const neutral = (s) => String(s ?? '').replace(/[\u0000-\u001f\u007f-\u009f\u2028\u2029]/g, ' ');
const cefHeader = (s) => neutral(s).replace(/\\/g, '\\\\').replace(/\|/g, '\\|');
const cefExt = (s) => neutral(s).replace(/\\/g, '\\\\').replace(/=/g, '\\=');
const sdParam = (s) => neutral(s).replace(/[\\"\]]/g, (c) => `\\${c}`);
const sorted = (events) => [...events].sort((a, b) => ms(a.time) - ms(b.time) || ((a.node?.id || 'local') < (b.node?.id || 'local') ? -1 : 1) || (a.id < b.id ? -1 : 1));

export function renderEvents(format, events, version = '0.3.0-dev') {
  const list = sorted(events);
  if (format === 'cef') {
    return list.map((e) => {
      const sev = SEV_MAP[e.severity] || SEV_MAP[''];
      const sig = (e.rule_ids || [])[0] || e.classification;
      return `CEF:0|AegisMesh|AegisMesh|${cefHeader(version)}|${cefHeader(sig)}|${cefHeader(e.classification)}|${sev[0]}|rt=${ms(e.time)} externalId=${e.id} cs1Label=sourceKey cs1=${cefExt(e.source)} cs2Label=sensor cs2=${cefExt(e.sensor?.id)} cs3Label=node cs3=${cefExt(e.node?.id || 'local')} cs4Label=rules cs4=${cefExt((e.rule_ids || []).join(','))} msg=${cefExt(e.summary)}`;
    }).join('\n') + (list.length ? '\n' : '');
  }
  if (format === 'syslog-rfc5424') {
    return list.map((e) => {
      const sev = SEV_MAP[e.severity] || SEV_MAP[''];
      const pri = 16 * 8 + sev[1];
      const ts = new Date(ms(e.time)).toISOString().replace(/\.(\d{3})Z$/, '.$1000Z');
      return `<${pri}>1 ${ts} - AegisMesh - observation [aegismesh@32473 id="${sdParam(e.id)}" class="${sdParam(e.classification)}" sensor="${sdParam(e.sensor?.id)}" node="${sdParam(e.node?.id || 'local')}" source="${sdParam(e.source)}" rules="${sdParam((e.rule_ids || []).join(','))}"] ${neutral(e.summary)}`;
    }).join('\n') + (list.length ? '\n' : '');
  }
  if (format === 'otlp-json') {
    const attr = (key, value) => ({ key, value: { stringValue: String(value ?? '') } });
    return JSON.stringify({
      resourceLogs: [{
        resource: { attributes: [attr('service.name', 'aegismesh')] },
        scopeLogs: [{
          scope: { name: 'aegismesh.observation' },
          logRecords: list.map((e) => {
            const sev = SEV_MAP[e.severity] || SEV_MAP[''];
            return {
              timeUnixNano: `${BigInt(ms(e.time)) * 1000000n}`, severityNumber: sev[2], severityText: e.severity || 'none',
              body: { stringValue: String(e.summary ?? '') },
              attributes: [attr('aegismesh.event_id', e.id), attr('aegismesh.classification', e.classification), attr('aegismesh.source_key', e.source), attr('aegismesh.sensor_id', e.sensor?.id), attr('aegismesh.node_id', e.node?.id || 'local'), attr('aegismesh.rule_ids', (e.rule_ids || []).join(','))],
            };
          }),
        }],
      }],
    });
  }
  // ecs
  return list.map((e) => JSON.stringify({
    '@timestamp': e.time, 'event.kind': 'event', 'event.category': ['intrusion_detection'], 'event.dataset': 'aegismesh.observation',
    'source.address': e.source, 'observer.name': e.sensor?.id, 'aegismesh.node_id': e.node?.id || 'local',
    'rule.id': e.rule_ids || [], message: e.summary,
    aegismesh: { envelope: { schema: 'aegismesh.event/v1', id: e.id, time: e.time, classification: e.classification } },
  })).join('\n') + (list.length ? '\n' : '');
}

// A deterministic id for synthetic scripted events.
export const storyId = (label) => createHash('sha256').update(`story:${label}`).digest('hex').slice(0, 32);
