// Round-4 understanding views: campaigns (several sources, one playbook),
// the actor profile of a session, and the configuration posture review.
// Pure wording and layout over the API (contract r4); every word here is
// interface text. API strings that an attacker can influence (source keys,
// step shapes) are passed through untouched for the UI to render as
// evidence.
//
// Copy rules: a campaign is similar behaviour, never attribution; an actor
// profile is a reading of listed signals, never a verdict or a score; the
// posture review is a configuration review, never a security guarantee.

import { formatCount } from './format.js';

// ---- Shared helpers -----------------------------------------------------------

// "1 source", "4 sources". One helper so every screen pluralises alike.
export function plural(n, one, many = `${one}s`) {
  const v = Number(n);
  return `${formatCount(Number.isFinite(v) ? v : 0)} ${v === 1 ? one : many}`;
}

// "a, b and c"
export function listJoin(items) {
  const list = items.filter((x) => x !== '' && x !== null && x !== undefined).map(String);
  if (list.length <= 1) return list.join('');
  return `${list.slice(0, -1).join(', ')} and ${list[list.length - 1]}`;
}

export const humanize = (v) => {
  const s = String(v ?? '').replace(/[_-]+/g, ' ').trim();
  return s ? s[0].toUpperCase() + s.slice(1) : '';
};

const arr = (v) => (Array.isArray(v) ? v : []);
const num = (v) => (Number.isFinite(Number(v)) && v !== null && v !== '' ? Number(v) : null);

// An endpoint that an older server does not have answers 404 (or 405) on a
// collection path. Only used for list endpoints, where "not found" cannot
// mean a missing object.
export function isMissingEndpoint(err) {
  return Boolean(err) && (err.status === 404 || err.status === 405 || err.status === 501);
}

// ---- Campaign ids ---------------------------------------------------------------

const CAMPAIGN_ID = /^cmp_[0-9a-z]{4,64}$/;
export const isCampaignId = (v) => typeof v === 'string' && CAMPAIGN_ID.test(v);

// ---- Actor profile --------------------------------------------------------------

// Shape plus words; never a percentage, never a gauge. `mark` names the CSS
// shape: filled diamond, diamond in a ring, filled circle, dash.
export const ACTORS = Object.freeze({
  likely_automated: { label: 'Likely automated', short: 'Likely automated', mark: 'auto', lean: 'A script or tool is the simpler explanation.' },
  possibly_ai_agent: { label: 'Possibly an AI agent', short: 'Possibly an agent', mark: 'agent', lean: 'Machine pace plus signs of acting on what the decoy said.' },
  likely_human: { label: 'Likely a person', short: 'Likely a person', mark: 'human', lean: 'Pauses and corrections that people make.' },
  inconclusive: { label: 'Inconclusive', short: 'Inconclusive', mark: 'none', lean: 'Too few or too mixed signals to lean either way.' },
});
export const ACTOR_ORDER = Object.freeze(['possibly_ai_agent', 'likely_automated', 'likely_human', 'inconclusive']);

export function actorMeta(assessment) {
  return ACTORS[assessment] ? { key: assessment, ...ACTORS[assessment] } : { key: 'unknown', label: 'Not assessed', short: 'Not assessed', mark: 'none', lean: '' };
}

// What the console looked for, in plain words, and which way a present
// signal leans. "context" signals say something about the run without
// favouring a person or a machine.
export const SIGNALS = Object.freeze({
  regular_cadence: { title: 'Steady rhythm', looked: 'Loops send at a fixed interval; people drift.', leans: 'automation' },
  sub_second_bursts: { title: 'Sub-second bursts', looked: 'People rarely read and act within a second; scripts and tool loops do.', leans: 'automation' },
  agent_canary_followed: { title: 'Agent canary followed', looked: 'Only a client that reads decoy content acts on it, though a person can copy it too.', leans: 'agent' },
  honeytoken_replayed: { title: 'Planted credential presented', looked: 'Whoever sent it had read the decoy; it says nothing about person or machine.', leans: 'context' },
  tool_call_chaining: { title: 'Tool calls chained', looked: 'Agents feed one tool’s answer into the next call without pausing.', leans: 'agent' },
  sdk_client_family: { title: 'Library or SDK client', looked: 'API libraries name themselves; browsers and hand-typed requests look different.', leans: 'automation' },
  adaptive_after_error: { title: 'Adapted after an error', looked: 'A changed request right after a refusal suggests the answer was read.', leans: 'agent' },
  human_think_time: { title: 'Thinking pauses', looked: 'Uneven pauses fit someone reading and deciding; a throttled script can mimic them.', leans: 'human' },
  typo_corrections: { title: 'Typing corrections', looked: 'Retyping with one character fixed is a human habit.', leans: 'human' },
  multi_surface_sweep: { title: 'Several surfaces swept', looked: 'Sweeping many services in one run is typical of scanners and agents.', leans: 'automation' },
});

export const LEANS = Object.freeze({ automation: 'Points to automation', agent: 'Points to an agent', human: 'Points to a person', context: 'Context' });

export const STRENGTHS = Object.freeze({ strong: { label: 'Strong', bars: 3 }, moderate: { label: 'Moderate', bars: 2 }, weak: { label: 'Weak', bars: 1 } });
export const strengthMeta = (s) => (STRENGTHS[s] ? { key: s, ...STRENGTHS[s] } : { key: 'unknown', label: 'Not rated', bars: 0 });

export function signalMeta(code) {
  return SIGNALS[code] || { title: humanize(code) || 'Signal', looked: '', leans: 'context' };
}

// Normalise an actor object from the API. Signals keep the server's order
// within each group; present ones come first, strongest first.
export function actorProfile(actor) {
  if (!actor || typeof actor !== 'object') return null;
  const meta = actorMeta(actor.assessment);
  const rank = (s) => strengthMeta(s).bars;
  const signals = arr(actor.signals).filter((s) => s && typeof s === 'object').map((s, i) => ({
    code: String(s.code ?? ''),
    label: typeof s.label === 'string' && s.label ? s.label : signalMeta(s.code).title,
    meta: signalMeta(s.code),
    strength: strengthMeta(s.strength),
    present: s.present === true,
    detail: typeof s.detail === 'string' ? s.detail : '',
    i,
  }));
  const present = signals.filter((s) => s.present).sort((a, b) => rank(b.strength.key) - rank(a.strength.key) || a.i - b.i);
  const absent = signals.filter((s) => !s.present);
  return {
    ...meta,
    summary: typeof actor.summary === 'string' ? actor.summary : '',
    present, absent,
    checked: signals.length,
    tally: signals.length ? `${formatCount(present.length)} of ${plural(signals.length, 'signal')} observed` : 'No signals were reported',
  };
}

// ---- Campaigns ---------------------------------------------------------------------

export const BASIS = Object.freeze({
  same_step_sequence: 'the same sequence of steps',
  same_client_family: 'the same client family',
  same_rule_set: 'the same rules firing',
  similar_pace: 'a similar pace',
  same_pace: 'a similar pace',
  same_honeytoken: 'the same planted credential',
  same_target: 'the same decoys',
  same_tool_sequence: 'the same tool calls',
});
export const basisText = (b) => BASIS[b] || humanize(b).toLowerCase();

// "4 sources followed the same sequence of steps, with the same client family."
export function basisSentence(c) {
  const basis = arr(c?.basis).map(basisText).filter(Boolean);
  const n = num(c?.source_count) ?? arr(c?.sources).length;
  const who = plural(n, 'source');
  if (!basis.length) return `${who} behaved alike; the server did not say on what basis.`;
  const [first, ...rest] = basis;
  return `${who} showed ${first}${rest.length ? `, with ${listJoin(rest)}` : ''}.`;
}

// Automation mix as ordered rows with counts; unknown keys keep their own
// humanised label so nothing is dropped.
export function automationMix(counts) {
  if (!counts || typeof counts !== 'object') return [];
  const keys = Object.keys(counts).filter((k) => (num(counts[k]) ?? 0) > 0);
  const known = ACTOR_ORDER.filter((k) => keys.includes(k));
  const other = keys.filter((k) => !ACTOR_ORDER.includes(k)).sort();
  return [...known, ...other].map((k) => ({ key: k, meta: ACTORS[k] ? actorMeta(k) : { key: k, label: humanize(k), short: humanize(k), mark: 'none' }, count: num(counts[k]) }));
}

export function mixSentence(counts) {
  const rows = automationMix(counts);
  if (!rows.length) return 'No actor profile was reported for these sessions.';
  return rows.map((r) => `${formatCount(r.count)} ${r.meta.short.toLowerCase()}`).join(' · ');
}

// Normalise a campaign list item or detail; missing arrays become empty,
// counts that are not numbers become null (shown as "—", never zero).
export function normalizeCampaign(c) {
  const o = c && typeof c === 'object' ? c : {};
  return {
    id: isCampaignId(o.id) ? o.id : '',
    label: typeof o.label === 'string' ? o.label : '',
    basis: arr(o.basis).map(String),
    sourceCount: num(o.source_count) ?? arr(o.sources).length,
    sources: arr(o.sources).filter((s) => typeof s === 'string' && s),
    sourcesTruncated: o.sources_truncated === true,
    sessionCount: num(o.session_count) ?? arr(o.session_ids).length,
    sessionIds: arr(o.session_ids).filter((s) => typeof s === 'string'),
    eventCount: num(o.event_count),
    firstSeen: typeof o.first_seen === 'string' ? o.first_seen : '',
    lastSeen: typeof o.last_seen === 'string' ? o.last_seen : '',
    sensorKinds: arr(o.sensor_kinds).map(String),
    ruleIds: arr(o.rule_ids).filter((r) => typeof r === 'string' && /^[A-Za-z0-9_.:-]{1,64}$/.test(r)),
    maxSeverity: typeof o.max_severity === 'string' ? o.max_severity : '',
    stages: arr(o.stages).map(String),
    mix: automationMix(o.automation_counts),
    steps: arr(o.steps).filter((s) => s && typeof s === 'object').map((s, i) => ({
      index: num(s.index) ?? i, kind: String(s.sensor_kind ?? ''), shape: String(s.shape ?? ''), stage: String(s.stage ?? ''), sessions: num(s.sessions),
    })).sort((a, b) => a.index - b.index),
    stepsTruncated: o.steps_truncated === true,
    sessions: arr(o.sessions).filter((s) => s && typeof s === 'object'),
    caveats: arr(o.caveats).filter((s) => typeof s === 'string' && s),
  };
}

// The score: one lane per session, one column per shared step. A cell is
// "performed" (with its offset from the session's start when known),
// "absent", or "unknown" when the server sent no per-session step marks
// (`step_marks`, an optional extension). Without marks, a step every session
// performed (steps[].sessions equal to the session count) is known for every
// lane; a step only some performed is "unknown" for each lane, and the
// column says "n of N".
export function campaignScore(c) {
  const steps = c.steps;
  const total = c.sessions.length || c.sessionCount || 0;
  const lanes = c.sessions.map((s) => {
    const marks = Array.isArray(s.step_marks) ? s.step_marks : null;
    const byIndex = new Map();
    if (marks) for (const m of marks) if (Number.isInteger(m?.index)) byIndex.set(m.index, num(m.offset_ms));
    const cells = steps.map((st) => {
      if (marks) return byIndex.has(st.index) ? { state: 'performed', offset: byIndex.get(st.index) } : { state: 'absent', offset: null };
      if (total && st.sessions === total) return { state: 'performed', offset: null };
      return { state: 'unknown', offset: null };
    });
    return { session: s, cells, performed: cells.filter((x) => x.state === 'performed').length, exact: Boolean(marks) };
  });
  // The longest run of steps every lane performed, in order: the shared spine.
  const shared = steps.map((st, i) => lanes.length > 0 && lanes.every((l) => l.cells[i].state === 'performed'));
  return { steps, lanes, shared, total, exact: lanes.some((l) => l.exact) };
}

// Plain time span "over 3 days" / "within 40 minutes" between two RFC 3339 times.
export function spanText(first, last) {
  const a = Date.parse(first);
  const b = Date.parse(last);
  if (!Number.isFinite(a) || !Number.isFinite(b) || b < a) return '';
  const m = (b - a) / 60000;
  if (m < 1) return 'within a minute';
  if (m < 90) return `within ${Math.round(m)} minutes`;
  const hours = m / 60;
  if (hours < 48) return `over ${Math.round(hours)} hours`;
  return `over ${Math.round(hours / 24)} days`;
}

// ---- Posture --------------------------------------------------------------------------

export const AREAS = Object.freeze([
  { id: 'exposure', label: 'Exposure', text: 'What listens, where, and who can reach it.' },
  { id: 'deception', label: 'Deception', text: 'Decoys, planted credentials and canaries.' },
  { id: 'detection', label: 'Detection', text: 'Rules and correlation that turn contact into findings.' },
  { id: 'evidence', label: 'Evidence', text: 'How observations are stored, protected and retained.' },
  { id: 'access', label: 'Access', text: 'Who can use the console and how they sign in.' },
]);

export const STATUSES = Object.freeze({
  attention: { label: 'Needs attention', mark: 'attention', rank: 0 },
  info: { label: 'For your information', mark: 'info', rank: 1 },
  ok: { label: 'Looks right', mark: 'ok', rank: 2 },
});
export const statusMeta = (s) => (STATUSES[s] ? { key: s, ...STATUSES[s] } : { key: 'unknown', label: 'Not classified', mark: 'info', rank: 1 });

const DOC_PATH = /^docs\/[a-z0-9][a-z0-9/_-]{0,120}\.md(#[a-z0-9-]{1,80})?$/;
const REPO = 'https://github.com/metaforismo/AegisMesh/blob/master/';
// A server doc pointer becomes a project link only when it is a plain docs
// path; anything else is shown as text.
export function docHref(doc) {
  return typeof doc === 'string' && DOC_PATH.test(doc) && !doc.includes('..') ? `${REPO}${doc}` : '';
}

export function normalizeCheck(c) {
  const o = c && typeof c === 'object' ? c : {};
  return {
    id: typeof o.id === 'string' ? o.id : '',
    area: AREAS.some((a) => a.id === o.area) ? o.area : 'other',
    status: statusMeta(o.status),
    title: typeof o.title === 'string' && o.title ? o.title : 'Untitled check',
    detail: typeof o.detail === 'string' ? o.detail : '',
    recommendation: typeof o.recommendation === 'string' ? o.recommendation : '',
    doc: typeof o.doc === 'string' ? o.doc : '',
  };
}

// Checks grouped by area in the fixed order (an unknown area last), each
// group with attention items first; plus the attention list across areas.
export function postureGroups(checks) {
  const list = arr(checks).map(normalizeCheck);
  const byRank = (a, b) => a.status.rank - b.status.rank;
  const groups = [...AREAS, { id: 'other', label: 'Other', text: 'Checks the console does not group.' }]
    .map((a) => {
      const items = list.filter((c) => c.area === a.id).sort(byRank);
      return { ...a, items, attention: items.filter((c) => c.status.key === 'attention').length };
    })
    .filter((g) => g.items.length);
  return { groups, attention: list.filter((c) => c.status.key === 'attention'), total: list.length };
}

export function postureCounts(res) {
  const s = res?.summary;
  const checks = arr(res?.checks).map(normalizeCheck);
  const count = (k) => num(s?.[k]) ?? checks.filter((c) => c.status.key === k).length;
  return { attention: count('attention'), ok: count('ok'), info: count('info') };
}

// The Overview's one quiet line.
export function postureLine(counts) {
  if (!counts) return '';
  if (!counts.attention) return `Configuration review: nothing needs attention (${plural(counts.ok, 'check')} ${counts.ok === 1 ? 'looks' : 'look'} right).`;
  return `Configuration review: ${plural(counts.attention, 'item')} ${counts.attention === 1 ? 'needs' : 'need'} attention.`;
}
