// Dev-mock twin of the round-4 API (contract r4): campaigns (sessions from
// different sources that followed the same steps), the actor profile of a
// session, and the configuration posture review. A fixture: not embedded,
// not shipped; it reads only the mock's synthetic index and configuration.
//
// Beyond the contract the mock adds one optional field the UI can use when
// present: campaign detail `sessions[].step_marks` ([{ index, offset_ms }],
// which shared steps that session performed and when, from its start).

import { createHash } from 'node:crypto';
import { cadenceOf } from './mock-analysis.mjs';

const ms = (t) => Date.parse(t);
const SEV = ['info', 'low', 'medium', 'high', 'critical'];
export const MIN_STEPS = 3;
export const SOURCES_CAP = 20;
export const SESSIONS_CAP = 50;
export const STEPS_CAP = 24;

// ---- Step shapes ------------------------------------------------------------------

// A normalised, redacted description of one step: method and path template,
// MCP method or tool name, SSH auth or command class. Correlation signals
// are not steps.
export function stepShape(e) {
  if (!e || e.classification === 'correlation_signal') return '';
  const s = String(e.summary || '');
  const kind = e.sensor?.kind || '';
  if (kind === 'http') {
    const m = s.match(/^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+(\S+)/);
    if (!m) return 'http request';
    const path = m[2].split('?')[0].split('/').map((seg) => (/^\d+$/.test(seg) ? '{n}' : seg)).join('/').slice(0, 48);
    return `${m[1]} ${path}`;
  }
  if (kind === 'mcp') {
    const call = s.match(/^tools\/call\s+([A-Za-z0-9_.-]+)/);
    if (call) return `tools/call ${call[1]}`;
    const m = s.match(/^([a-z]+\/[a-z]+|initialize)/);
    return m ? m[1] : 'mcp message';
  }
  if (kind === 'ssh') {
    const auth = s.match(/^auth\s+([a-z-]+)/);
    if (auth) return `auth ${auth[1]}`;
    const ex = s.match(/^exec\s+class=([a-z_-]+)/);
    if (ex) return `exec ${ex[1]}`;
    return s.startsWith('session') ? 'session open' : 'ssh message';
  }
  return kind ? `${kind} contact` : '';
}

// Same staging as the sessions view (mock-analysis.mjs stageOf).
function stageOf(e) {
  const r = new Set(e.rule_ids || []);
  if (r.has('HT-001') || r.has('COR-008')) return 'decoy_credential_replay';
  if (['LLM-002', 'LLM-003', 'AGT-001', 'PI-001', 'PI-002', 'ESC-001'].some((x) => r.has(x))) return 'ai_service_abuse';
  if (['EXF-001', 'LLM-004', 'COR-007'].some((x) => r.has(x)) || e.sensor?.kind === 'ssh') return 'credential_access';
  return 'discovery';
}

// Distinct shapes in first-occurrence order, with the first event of each.
function stepsOf(session) {
  const seen = new Map();
  for (const e of session._events) {
    const shape = stepShape(e);
    if (!shape || seen.has(shape)) continue;
    seen.set(shape, e);
    if (seen.size >= STEPS_CAP) break;
  }
  return [...seen.entries()].map(([shape, e]) => ({ shape, event: e }));
}

const clientOf = (session) => {
  for (const e of session._events) {
    const m = String(e.summary || '').match(/client="([^"]+)"|User-Agent: ([^\s]+)/);
    if (m) return (m[1] || m[2]).split('/')[0];
  }
  return '';
};

// ---- Actor profile -----------------------------------------------------------------

const SIGNAL_LABELS = {
  regular_cadence: 'Requests arrive at a near-constant interval',
  sub_second_bursts: 'Several requests less than a second apart',
  agent_canary_followed: 'An instruction planted in decoy content was followed',
  honeytoken_replayed: 'A planted credential was presented',
  tool_call_chaining: 'Tool calls chained back to back',
  sdk_client_family: 'Client identifies as an API library or SDK',
  adaptive_after_error: 'Request changed right after an error',
  human_think_time: 'Long, uneven pauses between steps',
  typo_corrections: 'A request was retyped with a small correction',
  multi_surface_sweep: 'Several decoy surfaces probed in one run',
};
export const SIGNAL_CODES = Object.keys(SIGNAL_LABELS);

const fmtMs = (n) => (n < 1000 ? `${Math.round(n)} ms` : n < 60000 ? `${(n / 1000).toFixed(1)} s` : `${(n / 60000).toFixed(1)} min`);

export function actorOf(session) {
  const list = session._events.filter((e) => e.classification !== 'correlation_signal');
  const rules = new Set(session._events.flatMap((e) => e.rule_ids || []));
  const c = cadenceOf(list);
  const gaps = [];
  for (let i = 1; i < list.length; i++) gaps.push(ms(list[i].time) - ms(list[i - 1].time));
  const fast = gaps.filter((g) => g < 1000).length;
  const sig = {};
  const set = (code, present, strength, detail) => { sig[code] = { code, label: SIGNAL_LABELS[code], strength, present, detail }; };
  const outliers = gaps.filter((g) => Math.abs(g - c.median_gap_ms) > 0.25 * c.median_gap_ms).length;

  const regular = list.length >= 6 && c.median_gap_ms >= 300 && c.regularity >= 0.8;
  set('regular_cadence', regular, c.regularity >= 0.9 ? 'strong' : 'moderate', gaps.length ? `median gap ${fmtMs(c.median_gap_ms)}, ${outliers} outlier${outliers === 1 ? '' : 's'} of ${gaps.length}` : 'only one interaction');
  set('sub_second_bursts', fast >= 3, fast >= gaps.length / 2 ? 'strong' : 'moderate', `${fast} of ${gaps.length} gaps under 1 s`);
  set('agent_canary_followed', rules.has('AGT-001'), 'strong', rules.has('AGT-001') ? 'AGT-001 fired: a planted diagnostic instruction was requested' : 'no planted instruction was requested');
  set('honeytoken_replayed', rules.has('HT-001'), 'strong', rules.has('HT-001') ? 'HT-001 fired: a decoy credential came back inbound' : 'no planted credential came back');
  let chain = 0;
  let best = 0;
  for (const e of list) { chain = /^tools\/call/.test(e.summary || '') ? chain + 1 : 0; best = Math.max(best, chain); }
  set('tool_call_chaining', best >= 3, best >= 5 ? 'strong' : 'moderate', best ? `${best} tool calls in a row` : 'no tool calls');
  const client = clientOf(session);
  set('sdk_client_family', Boolean(client), 'moderate', client ? `client named "${client}"` : 'no library-shaped client name');
  let adaptive = 0;
  for (let i = 1; i < list.length; i++) {
    if (/→ (40[0-9]|41[0-9]|5\d\d)|not found/.test(list[i - 1].summary || '') && ms(list[i].time) - ms(list[i - 1].time) < 3000 && stepShape(list[i]) !== stepShape(list[i - 1])) adaptive++;
  }
  set('adaptive_after_error', adaptive > 0, adaptive > 1 ? 'moderate' : 'weak', adaptive ? `${adaptive} changed request${adaptive === 1 ? '' : 's'} within 3 s of an error` : 'no quick change after an error');
  const think = list.length >= 3 && c.median_gap_ms >= 20000 && c.regularity < 0.5;
  set('human_think_time', think, c.median_gap_ms >= 120000 ? 'strong' : 'moderate', gaps.length ? `median gap ${fmtMs(c.median_gap_ms)}, ${Math.round(c.regularity * 100)}% of gaps near it` : 'only one interaction');
  let typos = 0;
  for (let i = 1; i < list.length; i++) {
    const a = stepShape(list[i - 1]);
    const b = stepShape(list[i]);
    if (a && b && a !== b && a.length === b.length && [...a].filter((ch, k) => ch !== b[k]).length === 1) typos++;
  }
  set('typo_corrections', typos > 0, 'weak', typos ? `${typos} near-identical retyped request${typos === 1 ? '' : 's'}` : 'no near-identical retyped requests');
  const surfaces = new Set(list.map((e) => e.sensor?.id).filter(Boolean));
  set('multi_surface_sweep', surfaces.size >= 2 || rules.has('COR-006'), rules.has('COR-006') ? 'strong' : 'moderate', `${surfaces.size} decoy surface${surfaces.size === 1 ? '' : 's'} touched`);

  const signals = SIGNAL_CODES.map((k) => sig[k]);
  const on = (k) => sig[k].present;
  const autoN = ['regular_cadence', 'sub_second_bursts', 'sdk_client_family', 'multi_surface_sweep'].filter(on).length;
  const agentN = ['agent_canary_followed', 'tool_call_chaining', 'adaptive_after_error'].filter(on).length;
  const humanN = ['human_think_time', 'typo_corrections'].filter(on).length;
  let assessment = 'inconclusive';
  if (list.length < 4) assessment = 'inconclusive';
  else if (agentN && autoN && !humanN) assessment = 'possibly_ai_agent';
  else if ((autoN >= 2 || ['regular_cadence', 'sub_second_bursts'].some((k) => on(k) && sig[k].strength === 'strong')) && !humanN) assessment = 'likely_automated';
  else if (humanN && !autoN) assessment = 'likely_human';
  const summary = {
    possibly_ai_agent: 'Machine pace together with signs of acting on what the decoy returned; a scripted replay of an agent’s steps would look the same.',
    likely_automated: 'The pace and request pattern are consistent with a script or tool; nothing here identifies who ran it.',
    likely_human: 'Long, uneven pauses suggest a person at a keyboard, though a throttled script can look alike.',
    inconclusive: list.length < 4 ? 'Too few interactions to lean either way.' : 'The signals point in different directions, so the reading stays open.',
  }[assessment];
  return { assessment, summary, signals };
}

// ---- Campaigns --------------------------------------------------------------------

function idOf(signature) {
  return `cmp_${createHash('sha256').update(JSON.stringify(signature)).digest('hex').slice(0, 12)}`;
}

const nano = (t) => new Date(ms(t)).toISOString().replace(/\.(\d{3})Z$/, '.$1000000Z');

// Group sessions by the opening of their ordered distinct step shapes (at
// least MIN_STEPS). A group is a campaign when it spans two or more sources.
export function campaignsOf(sessions) {
  const groups = new Map();
  for (const s of sessions) {
    const steps = stepsOf(s);
    if (steps.length < MIN_STEPS) continue;
    // The playbook's opening (its first four distinct steps) is the key;
    // later steps may differ between members.
    const key = JSON.stringify(steps.slice(0, 4).map((x) => x.shape));
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push({ session: s, steps });
  }
  const out = [];
  for (const [key, members] of groups) {
    const sources = [...new Set(members.map((m) => m.session.source))].sort();
    if (sources.length < 2) continue;
    const core = JSON.parse(key);
    members.sort((a, b) => ms(a.session.first_seen) - ms(b.session.first_seen));
    const all = members.map((m) => m.session);
    const rules = [...new Set(all.flatMap((s) => s.rule_ids))].sort();
    const kinds = [...new Set(all.flatMap((s) => s.sensor_kinds))].sort();
    let max = '';
    for (const s of all) if (SEV.indexOf(s.max_severity) > SEV.indexOf(max)) max = s.max_severity;
    const actors = all.map(actorOf);
    const automation = {};
    for (const a of actors) automation[a.assessment] = (automation[a.assessment] || 0) + 1;
    const basis = ['same_step_sequence'];
    const clients = new Set(all.map(clientOf));
    if (clients.size === 1 && [...clients][0]) basis.push('same_client_family');
    if (new Set(all.map((s) => s.rule_ids.join(' '))).size === 1 && rules.length) basis.push('same_rule_set');
    const medians = all.map((s) => s.cadence.median_gap_ms).filter((v) => v > 0);
    if (medians.length === all.length && Math.max(...medians) <= 2 * Math.min(...medians)) basis.push('similar_pace');
    const stages = [];
    const shapes = [];
    // Step order follows the member with the most steps, then any step only
    // shorter members took.
    for (const m of [...members].sort((a, b) => b.steps.length - a.steps.length)) for (const x of m.steps) if (!shapes.includes(x.shape)) shapes.push(x.shape);
    shapes.splice(STEPS_CAP);
    const steps = shapes.map((shape, index) => {
      const first = members.map((m) => m.steps.find((x) => x.shape === shape)).find(Boolean).event;
      const stage = stageOf(first);
      if (!stages.includes(stage)) stages.push(stage);
      return { index, sensor_kind: first.sensor?.kind || '', shape, stage, sessions: members.filter((m) => m.steps.some((x) => x.shape === shape)).length };
    });
    const label = labelOf(shapes);
    out.push({
      id: idOf(core), label, basis,
      source_count: sources.length, sources: sources.slice(0, SOURCES_CAP), sources_truncated: sources.length > SOURCES_CAP,
      session_count: all.length, session_ids: all.map((s) => s.id).slice(0, SESSIONS_CAP),
      event_count: all.reduce((n, s) => n + s.event_count, 0),
      first_seen: nano(all[0].first_seen), last_seen: nano(all.reduce((m, s) => (ms(s.last_seen) > ms(m) ? s.last_seen : m), all[0].last_seen)),
      sensor_kinds: kinds, rule_ids: rules, max_severity: max, stages, automation_counts: automation,
      _steps: steps, _members: members,
    });
  }
  return out.sort((a, b) => ms(b.last_seen) - ms(a.last_seen) || (a.id < b.id ? -1 : 1));
}

// A short label from the playbook's own vocabulary (server-composed, from
// shapes it already redacted).
function labelOf(shapes) {
  const words = (s) => {
    if (/tags|models|\/v1\/models/.test(s)) return 'model listing';
    if (/chat\/completions|generate/.test(s)) return 'completion probe';
    if (/^auth password/.test(s)) return 'password attempts';
    if (/^exec/.test(s)) return 'command execution';
    if (/tools\/list/.test(s)) return 'tool listing';
    if (/read_file|get_env/.test(s)) return 'secret reads';
    return '';
  };
  const parts = [...new Set(shapes.map(words).filter(Boolean))];
  if (!parts.length) return `${shapes.length}-step sequence`;
  const text = parts.length === 1 ? parts[0] : `${parts.slice(0, -1).join(', ')}, then ${parts[parts.length - 1]}`;
  return text[0].toUpperCase() + text.slice(1);
}

export const publicCampaign = ({ _steps, _members, ...rest }) => rest;

export function campaignDetail(c, publicSession) {
  return {
    ...publicCampaign(c),
    steps: c._steps,
    steps_truncated: c._steps.length >= STEPS_CAP,
    sessions: c._members.slice(0, SESSIONS_CAP).map((m) => {
      const start = ms(m.session._events[0].time);
      const marks = c._steps.map((st) => {
        const hit = m.steps.find((x) => x.shape === st.shape);
        return hit ? { index: st.index, offset_ms: ms(hit.event.time) - start } : null;
      }).filter(Boolean);
      return { ...publicSession(m.session), step_marks: marks };
    }),
    caveats: [
      'Shared behaviour does not prove a shared operator: public tools and copied playbooks produce the same steps.',
      'Sources are keys the sensors recorded; NAT, proxies and relays can make one actor look like many, or many like one.',
      'Built from the newest indexed events only; older sessions of the same playbook may exist on disk.',
    ],
  };
}

// ---- Posture ------------------------------------------------------------------------

// A static review of the mock's own configuration and what its index holds.
const pl = (n, one, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;

export function postureOf({ sensors, honeytokens, rules, index, principals, oidc }) {
  const C = (id, area, status, title, detail, recommendation, doc) => ({ id, area, status, title, detail, recommendation: status === 'ok' ? '' : recommendation, doc });
  const loopback = sensors.every((s) => /^127\.|^\[::1\]|^localhost/.test(s.listen || ''));
  const failed = sensors.filter((s) => s.state === 'failed');
  const isolated = sensors.filter((s) => s.process_isolation).length;
  const unplanted = sensors.filter((s) => !honeytokens.some((t) => t.sensor_ids.includes(s.id)) && s.kind !== 'tcp');
  const checks = [
    C('POS-001', 'exposure', loopback ? 'ok' : 'attention', loopback ? 'Every sensor listens on loopback' : 'Sensors listen beyond loopback', `${sensors.length} sensors declare a listen address; ${loopback ? 'all are loopback' : 'some are reachable from other hosts'}.`, 'Expose decoys deliberately through a single forwarding rule rather than binding every interface.', 'docs/configuration.md#sensors'),
    C('POS-002', 'exposure', 'ok', 'Console bound to loopback', 'The console listens on 127.0.0.1 with TLS off; reach it through an SSH tunnel or a reverse proxy you control.', '', 'docs/architecture/console-api.md'),
    C('POS-003', 'exposure', failed.length ? 'attention' : 'ok', failed.length ? `${pl(failed.length, 'sensor')} failed to start` : 'Every sensor is running', failed.length ? `Sensor ${failed.map((s) => s.id).join(', ')} is in state "failed"; it records nothing while down.` : 'Every declared sensor reports running.', 'Run aegismesh doctor --config FILE to see why the listener could not bind, then restart the runtime.', 'docs/cli.md#doctor'),
    C('POS-004', 'deception', unplanted.length ? 'attention' : 'ok', unplanted.length ? `${pl(unplanted.length, 'decoy')} ${unplanted.length === 1 ? 'has' : 'have'} no planted credential` : 'Every decoy carries a planted credential', unplanted.length ? `No honeytoken is planted in ${unplanted.map((s) => s.id).join(', ')}. A replayed credential is the clearest sign someone read a decoy.` : 'Each decoy can reveal a replayed credential.', 'Mint one with aegismesh honeytoken new and reference it from the decoy’s responses.', 'docs/ai-threat-detection.md#honeytokens'),
    C('POS-005', 'deception', 'ok', `${honeytokens.length} honeytokens configured`, `${pl(honeytokens.filter((t) => t.kind === 'agent_canary').length, 'agent canary', 'agent canaries')} and ${pl(honeytokens.filter((t) => t.kind === 'credential').length, 'decoy credential')}; values never leave the server.`, '', 'docs/ai-threat-detection.md#honeytokens'),
    C('POS-006', 'deception', 'info', 'AI-service decoys share one host', 'Ollama, LiteLLM and the MCP workspace answer from the same address. A careful visitor can notice that the services moved together.', 'Consider separate addresses if you want each decoy to look independent.', 'docs/ai-threat-detection.md'),
    C('POS-007', 'detection', 'ok', `${rules} rules loaded`, 'Detection and correlation rules load from the built-in catalog; none were disabled.', '', 'docs/rules.md'),
    C('POS-008', 'detection', 'info', 'Correlation window is 10 minutes', 'Correlation rules look back 10 minutes (the default). Slow, patient activity can fall outside it.', 'Leave the default unless you see low-and-slow sources the rules miss.', 'docs/configuration.md#correlation'),
    C('POS-009', 'evidence', 'ok', 'Evidence encrypted at rest', 'Observations are sealed to the configured recipient before they are written.', '', 'docs/evidence.md'),
    C('POS-010', 'evidence', 'info', `Index holds ${index.events.toLocaleString('en-US')} of ${index.capacity.toLocaleString('en-US')} events`, 'Derived views (sessions, campaigns, the digest) read the newest 8,192 entries; older evidence stays on disk.', 'Use aegismesh inspect for evidence older than the index.', 'docs/evidence.md#index'),
    C('POS-011', 'evidence', 'ok', 'Audit chain verifies', 'Every audit record links to the one before it.', '', 'docs/architecture/console-api.md'),
    C('POS-012', 'access', 'ok', 'Operator tokens are hashed', `${principals} principals with distinct roles; tokens are stored as hashes.`, '', 'docs/configuration.md#console'),
    C('POS-013', 'access', oidc ? 'ok' : 'info', oidc ? 'Single sign-on configured' : 'Single sign-on is off', oidc ? 'Sign-in through the configured identity provider is available.' : 'Operators sign in with tokens only.', 'Enable OIDC sign-in if your team already has an identity provider.', 'docs/configuration.md#oidc'),
    C('POS-014', 'exposure', isolated < sensors.length ? 'info' : 'ok', `${isolated} of ${sensors.length} sensors run process-isolated`, 'Process isolation limits what a parser bug in one sensor can reach.', 'Enable process_isolation for sensors that parse untrusted protocols.', 'docs/configuration.md#sensors'),
  ];
  const summary = { attention: 0, ok: 0, info: 0 };
  for (const c of checks) summary[c.status]++;
  return { generated_at: new Date().toISOString(), summary, checks };
}
