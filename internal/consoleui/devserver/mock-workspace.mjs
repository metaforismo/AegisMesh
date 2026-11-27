// Round 8 mock: the investigation workspace fields (contract r8, sections 2
// and 3): origin, assignee, a bounded activity log, a summary computed from
// the attached events, and opening an investigation from a campaign or a
// session with the member events attached (newest per session first).
// Synthetic data only.

export const ACTIVITY_CAP = 200;
export const MAX_EVIDENCE = 200;
export const ACTIVITY_KINDS = Object.freeze(['created', 'status', 'priority', 'title', 'assignee', 'note', 'attach', 'detach']);
const SEV = ['info', 'low', 'medium', 'high', 'critical'];

export function pushActivity(inv, { at, actorId, actorName, kind, detail = '' }) {
  inv.activity ||= [];
  inv.activity.push({ at, actor_id: actorId, actor_name: actorName, kind, detail });
  if (inv.activity.length > ACTIVITY_CAP) inv.activity.splice(0, inv.activity.length - ACTIVITY_CAP);
}

// Summary of the attached events that are still indexed.
export function summaryOf(events, attachedIds = null) {
  const sources = new Set();
  const sensors = new Set();
  const rules = new Set();
  let first = '';
  let last = '';
  let max = '';
  for (const e of events) {
    if (e.source) sources.add(e.source);
    if (e.sensor?.id) sensors.add(e.sensor.id);
    for (const r of e.rule_ids || []) rules.add(r);
    if (!first || e.time < first) first = e.time;
    if (!last || e.time > last) last = e.time;
    if (SEV.indexOf(e.severity) > SEV.indexOf(max)) max = e.severity;
  }
  const out = { sources: sources.size, sensors: [...sensors].sort(), first_seen: first || null, last_seen: last || null, max_severity: max, rule_ids: [...rules].sort() };
  if (attachedIds) Object.assign(out, { indexed_events: events.length, missing_events: attachedIds.length - events.length });
  return out;
}

// Member events of a campaign or session: newest per session first,
// interleaved across sessions so a cap keeps every lane represented.
export function memberEvents(sessionEventLists, max = MAX_EVIDENCE) {
  const lanes = sessionEventLists.map((list) => list.filter((e) => !e.node).slice().sort((a, b) => Date.parse(b.time) - Date.parse(a.time)));
  const out = [];
  const seen = new Set();
  for (let i = 0; out.length < max; i++) {
    let any = false;
    for (const lane of lanes) {
      const e = lane[i];
      if (!e) continue;
      any = true;
      if (seen.has(e.id)) continue;
      seen.add(e.id);
      out.push(e);
      if (out.length >= max) break;
    }
    if (!any) break;
  }
  return out;
}

const sentenceList = (xs) => (xs.length <= 1 ? xs.join('') : `${xs.slice(0, -1).join(', ')} and ${xs[xs.length - 1]}`);

// The first note on a case opened from a campaign or a session: the basis
// in plain words and the caveat, never attribution.
export function originNote(kind, d, attached) {
  if (kind === 'campaign') {
    const basis = (d.basis || []).map((b) => b.replace(/_/g, ' '));
    return `Opened from campaign ${d.id}${d.label ? ` (${d.label})` : ''}: ${d.source_count} sources and ${d.session_count} sessions followed the same steps${basis.length ? ` (${sentenceList(basis)})` : ''}. ${attached} of ${d.event_count} member events attached, newest per session first.\nShared behaviour does not prove a shared operator: public tools and copied playbooks produce the same steps.`;
  }
  return `Opened from session ${d.id} (source ${d.source}): ${d.event_count} events from ${d.first_seen} to ${d.last_seen}. ${attached} attached, newest first.\nA source key is what the sensors recorded, not a verified identity.`;
}
