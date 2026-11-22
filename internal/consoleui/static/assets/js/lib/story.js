// Attacker sessions and the attack story: pure wording and layout helpers
// over the API's session projection (docs/architecture/console-api.md,
// "Session contract"). Every word here is interface text; API strings
// (source keys, summaries) are passed through untouched for the UI to
// render as evidence.
//
// Rules: the automation assessment is an observation with its evidence,
// never a verdict ("AI attacker", "bot"); stages describe which rules fired,
// not intent or a forced lifecycle.

import { formatGap } from './cadence.js';

export const SESSION_IDLE_MS = 30 * 60 * 1000;
// Gaps longer than this become their own "idle" marker in the timeline.
export const IDLE_MARKER_MS = 5 * 60 * 1000;

export const ASSESSMENTS = Object.freeze({
  consistent_with_automation: { label: 'Consistent with automation', short: 'Consistent with automation', glyph: 'filled' },
  mixed: { label: 'No automation pattern established', short: 'No pattern established', glyph: 'ring' },
  inconclusive: { label: 'Too few events to assess', short: 'Too few events', glyph: 'dash' },
});

export function assessmentOf(automation) {
  const key = automation?.assessment;
  const meta = ASSESSMENTS[key] || { label: 'Not assessed', short: 'Not assessed', glyph: 'dash' };
  const evidence = Array.isArray(automation?.evidence) ? automation.evidence : [];
  const n = evidence.filter((e) => e?.code !== 'insufficient_events').length;
  return { key: ASSESSMENTS[key] ? key : 'unknown', ...meta, observations: n, line: `${meta.label} · ${n} observation${n === 1 ? '' : 's'}` };
}

// Plain-language reading of each evidence code. The API's own `detail`
// sentence is shown beside it; this is the console's explanation.
export const EVIDENCE = Object.freeze({
  sub_second_cadence: { title: 'Sub-second pace', text: 'Half or more of the gaps between interactions were under a second. People rarely act that fast; scripts and tool loops often do. Timestamps alone do not show the client reacted to responses.', guide: 'regularity' },
  regular_cadence: { title: 'Regular pace', text: 'The typical gap was between 1 and 30 seconds and at most one gap strayed more than 25% from it: a steady rhythm.', guide: 'regularity' },
  agent_canary: { title: 'Agent canary followed', text: 'A client acted on an instruction planted in decoy content (AGT-001). A person or scanner could copy it too, so this does not prove an LLM client.', guide: 'agentcanary' },
  correlation_cadence: { title: 'Machine-paced correlation', text: 'The cadence correlation rule (COR-005) fired for this source.', guide: 'regularity' },
  multi_surface_enumeration: { title: 'Several AI services probed', text: 'One source touched two or more AI service families (COR-006). Ordinary clients of two services can match too.', guide: 'llmjacking' },
  honeytoken_replay: { title: 'Decoy credential presented', text: 'A credential that exists only in decoy material came back inbound (HT-001). Whoever sent it had read the decoy.', guide: 'honeytoken' },
  cross_sensor_replay: { title: 'Credential replayed across sensors', text: 'The decoy credential arrived on one sensor after earlier contact on another (COR-008). It does not prove the first sensor disclosed it.', guide: 'honeytoken' },
  insufficient_events: { title: 'Too few events', text: 'At least eight non-signal events are needed before the console assesses pace. The other observations still stand.', guide: 'automation' },
});

export const evidenceMeta = (code) => EVIDENCE[code] || { title: 'Observation', text: '', guide: 'automation' };

export const STAGES = Object.freeze({
  discovery: { label: 'Discovery', hint: 'Observations no more specific rule claimed: browsing, listing, probing.' },
  credential_access: { label: 'Credential access', hint: 'Credential attempts, provider-shaped keys, or SSH authentication.' },
  ai_service_abuse: { label: 'AI service use', hint: 'Completion probes, model or key changes, prompt-injection phrasing, or an agent canary.' },
  decoy_credential_replay: { label: 'Decoy credential replay', hint: 'A planted credential came back (HT-001 or COR-008).' },
});
export const stageMeta = (s) => STAGES[s] || { label: 'Other', hint: '' };

export const FRAMEWORK_LABELS = Object.freeze({ 'mitre-attack': 'MITRE ATT&CK', 'mitre-atlas': 'MITRE ATLAS', 'owasp-llm-2025': 'OWASP LLM 2025' });
export const frameworkLabel = (f) => FRAMEWORK_LABELS[f] || 'Framework';
export const isFramework = (f) => Object.hasOwn(FRAMEWORK_LABELS, f);

export function formatDurationMs(ms) {
  if (ms === null || ms === undefined || ms === '') return '—';
  const n = Number(ms);
  if (!Number.isFinite(n) || n < 0) return '—';
  if (n === 0) return '0 s';
  return formatGap(n);
}

// "62% of gaps within a quarter of the median gap"
export function regularityText(c) {
  const r = Number(c?.regularity);
  if (!Number.isFinite(r)) return '—';
  return `${Math.round(r * 100)}%`;
}

// Position (0..1) of a gap on the log scale the cadence strips share:
// 10 ms on the left, one hour on the right.
const LOG_MIN = Math.log10(10);
const LOG_MAX = Math.log10(3600e3);
export function gapScalePos(ms) {
  const n = Number(ms);
  if (!Number.isFinite(n) || n <= 10) return 0;
  return Math.min(1, (Math.log10(n) - LOG_MIN) / (LOG_MAX - LOG_MIN));
}

// Lay out a capped timeline as a story: phase headers where the stage
// changes, events with their gap, and an idle marker for long gaps.
// phases[].event_ids are bare ids into the same timeline; ids can collide
// across origins, so each id is consumed in order.
export function storyItems(timeline, phases, { idleMs = IDLE_MARKER_MS } = {}) {
  const list = Array.isArray(timeline) ? timeline : [];
  const queue = new Map();
  (Array.isArray(phases) ? phases : []).forEach((p, i) => {
    for (const id of p?.event_ids || []) {
      if (!queue.has(id)) queue.set(id, []);
      queue.get(id).push(i);
    }
  });
  const items = [];
  let current = -2;
  list.forEach((ev, idx) => {
    const gap = Number(ev?.gap_ms);
    const hasGap = ev?.gap_ms !== null && ev?.gap_ms !== undefined && Number.isFinite(gap);
    if (hasGap && gap > idleMs) items.push({ type: 'idle', ms: gap });
    const phaseIndex = queue.get(ev?.event_id)?.shift() ?? -1;
    if (phaseIndex !== current) {
      current = phaseIndex;
      const p = phases?.[phaseIndex];
      const count = p ? p.event_ids.length : 0;
      items.push({ type: 'phase', index: phaseIndex, stage: p?.stage || '', first: p?.first_seen || ev?.time, last: p?.last_seen || ev?.time, count });
    }
    items.push({ type: 'event', index: idx, ev, gap: hasGap ? gap : null, longGap: hasGap && gap > idleMs });
  });
  return items;
}

// Distinct stages in the order they first appear, with how many runs each.
export function stageSummary(phases) {
  const out = [];
  for (const p of Array.isArray(phases) ? phases : []) {
    const hit = out.find((x) => x.stage === p.stage);
    if (hit) { hit.runs++; hit.events += p.event_ids?.length || 0; }
    else out.push({ stage: p.stage, runs: 1, events: p.event_ids?.length || 0 });
  }
  return out;
}

// Group framework references for chips: [{framework, label, refs:[{id,name}]}].
export function groupFrameworks(refs) {
  const out = [];
  for (const f of Array.isArray(refs) ? refs : []) {
    if (!isFramework(f?.framework) || typeof f.id !== 'string') continue;
    let g = out.find((x) => x.framework === f.framework);
    if (!g) out.push((g = { framework: f.framework, label: frameworkLabel(f.framework), refs: [] }));
    if (!g.refs.some((r) => r.id === f.id)) g.refs.push({ id: f.id, name: String(f.name || '') });
  }
  return out.sort((a, b) => Object.keys(FRAMEWORK_LABELS).indexOf(a.framework) - Object.keys(FRAMEWORK_LABELS).indexOf(b.framework));
}

// Plain sentence on the scan bounds of a derived view, or null when there
// is nothing to qualify.
export function boundsNote(bounds) {
  const b = bounds || {};
  const parts = [];
  if (Number.isFinite(b.scanned_events) && Number.isFinite(b.scan_limit)) {
    parts.push(`Built from the newest ${b.scanned_events.toLocaleString('en-US')} indexed events${b.scan_truncated ? ` (the ${b.scan_limit.toLocaleString('en-US')}-event scan limit was reached, so older events are not included)` : ''}.`);
  }
  if (b.index?.history === 'truncated') parts.push('The index has evicted older evidence; it remains on disk.');
  if (b.index?.history === 'unavailable') parts.push('The index starts at process start (evidence at rest is encrypted).');
  parts.push('A source key is not an actor identity: NAT and proxies can combine clients.');
  return parts.join(' ');
}

// "How this session unfolded": one or two sentences composed only from the
// session's own fields (source, counts, duration, sensors, stage order,
// median gap). Segments like the Overview brief: { t: 'text'|'ev', v }.
export function unfoldSentence(d) {
  if (!d || typeof d !== 'object') return [];
  const n = Number(d.event_count) || 0;
  const sensors = Array.isArray(d.sensors) ? d.sensors.length : 0;
  const kinds = Array.isArray(d.sensor_kinds) ? d.sensor_kinds.map((k) => String(k).toUpperCase()) : [];
  const out = [{ t: 'ev', v: String(d.source ?? '') }, { t: 'text', v: ` produced ${n.toLocaleString('en-US')} event${n === 1 ? '' : 's'} over ${formatDurationMs(d.duration_ms)}` }];
  if (sensors) out.push({ t: 'text', v: ` on ${sensors} sensor${sensors === 1 ? '' : 's'}${kinds.length ? ` (${kinds.join(', ')})` : ''}` });
  // Stage order, consecutive repeats merged.
  const order = [];
  for (const p of Array.isArray(d.phases) ? d.phases : []) {
    const full = stageMeta(p.stage).label;
    const label = full.startsWith('AI') ? full : full[0].toLowerCase() + full.slice(1);
    if (order[order.length - 1] !== label) order.push(label);
  }
  if (order.length === 1) out.push({ t: 'text', v: `, all of it ${order[0]}.` });
  else if (order.length > 1) {
    const mid = order.slice(1, -1);
    out.push({ t: 'text', v: `: it began with ${order[0]}${mid.length ? `, moved through ${mid.join(', then ')}` : ''}, and ended with ${order[order.length - 1]}.` });
  } else out.push({ t: 'text', v: '.' });
  const med = d.cadence?.median_gap_ms;
  if (n > 1 && Number.isFinite(Number(med))) out.push({ t: 'text', v: ` The typical gap between events was ${formatDurationMs(med)}.` });
  if (d.timeline_truncated) out.push({ t: 'text', v: ' Stages cover the first 200 events.' });
  return out;
}
