// The investigation workspace (contract r8, section 3) and opening a case
// from a campaign or a session (section 2): validation of the new fields,
// the summary strip (from the server's `summary`, or computed from the
// attached events on an older server), evidence grouped by source, the
// activity feed merged with notes in time order, the assignee picker's
// choices, the list's filters and the "Assigned to me" default, the
// prefilled draft and a guard against double submission. Pure logic;
// screens/investigation*.js draw it.

import { INVESTIGATION_STATUSES, PRIORITIES, SEVERITIES, severityRank } from './taxonomy.js';
import { isOpaqueId, isSessionId } from './route.js';
import { isCampaignId } from './insight.js';

export const MAX_EVIDENCE = 200;
// The status flow the API supports, in order. "Monitoring" is the
// in-progress step: someone is watching it.
export const STATUS_FLOW = INVESTIGATION_STATUSES;
export const STATUS_WORDS = Object.freeze({
  open: { label: 'Open', hint: 'New or waiting for someone to pick it up' },
  monitoring: { label: 'Monitoring', hint: 'In progress: someone is watching it' },
  closed: { label: 'Closed', hint: 'Done; the evidence and notes stay' },
});

export const ACTIVITY_KINDS = Object.freeze(['created', 'status', 'priority', 'title', 'assignee', 'note', 'attach', 'detach']);
const ACTIVITY_WORDS = Object.freeze({
  created: { verb: 'opened the investigation', icon: 'plus' },
  status: { verb: 'changed the status', icon: 'refresh' },
  priority: { verb: 'changed the priority', icon: 'flag' },
  title: { verb: 'renamed it', icon: 'settings' },
  assignee: { verb: 'changed the assignee', icon: 'user' },
  note: { verb: 'added a note', icon: 'digest' },
  attach: { verb: 'attached evidence', icon: 'plus' },
  detach: { verb: 'detached evidence', icon: 'close' },
});
const RFC3339 = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,9})?(Z|[+-]\d{2}:\d{2})$/;
const isTime = (v) => typeof v === 'string' && RFC3339.test(v) && !Number.isNaN(Date.parse(v));
const UNSAFE = /[\u0000-\u0008\u000b-\u001f\u007f-\u009f​-‏‪-‮⁦-⁩﻿]/g;
const text = (v, max = 300) => (typeof v === 'string' ? Array.from(v.replace(UNSAFE, '')).slice(0, max).join('') : '');
// Principal ids: configured (cfg:name), managed (acc_…), single sign-on
// (oidc:…). Opaque beyond that; they never reach a URL.
const PRINCIPAL_ID = /^(cfg:[A-Za-z0-9_.@-]{1,64}|acc_[a-z0-9]{4,64}|oidc:[0-9a-f]{6,64}|[A-Za-z0-9_.:@-]{1,128})$/;
export const isPrincipalId = (v) => typeof v === 'string' && PRINCIPAL_ID.test(v);

// ---- The record ---------------------------------------------------------------

export function normalizeOrigin(o) {
  if (!o || typeof o !== 'object') return null;
  if (o.kind === 'campaign' && isCampaignId(o.id)) return { kind: 'campaign', id: o.id };
  if (o.kind === 'session' && isSessionId(o.id)) return { kind: 'session', id: o.id };
  return null;
}

export function normalizeActivity(list) {
  return (Array.isArray(list) ? list : []).filter((a) => a && typeof a === 'object' && ACTIVITY_KINDS.includes(a.kind) && isTime(a.at)).map((a) => ({
    at: a.at, kind: a.kind,
    actorId: isPrincipalId(a.actor_id) ? a.actor_id : '',
    actorName: text(a.actor_name, 80) || 'unknown',
    detail: text(a.detail, 300),
  }));
}

// Which round-8 fields the server sent. An older server has none of them,
// and the workspace then draws what it can (notes, evidence) as before.
export function workspaceFeatures(inv) {
  const o = inv && typeof inv === 'object' ? inv : {};
  return {
    assignee: 'assignee' in o,
    activity: Array.isArray(o.activity),
    summary: Boolean(o.summary && typeof o.summary === 'object'),
    origin: 'origin' in o,
  };
}

// The summary strip: the server's `summary`, or the same figures computed
// from the attached events still indexed (`computed: true`, said on screen).
export function summaryOf(inv) {
  const s = inv?.summary;
  if (s && typeof s === 'object') {
    return {
      computed: false,
      sources: Number.isInteger(s.sources) ? s.sources : null,
      sensors: (Array.isArray(s.sensors) ? s.sensors : []).filter((x) => typeof x === 'string' && x),
      firstSeen: isTime(s.first_seen) ? s.first_seen : '',
      lastSeen: isTime(s.last_seen) ? s.last_seen : '',
      maxSeverity: SEVERITIES.includes(s.max_severity) ? s.max_severity : '',
      ruleIds: (Array.isArray(s.rule_ids) ? s.rule_ids : []).filter((r) => typeof r === 'string' && /^[A-Za-z0-9_.:-]{1,64}$/.test(r)),
    };
  }
  const events = Array.isArray(inv?.events) ? inv.events : [];
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
    if (isTime(e.time)) {
      if (!first || Date.parse(e.time) < Date.parse(first)) first = e.time;
      if (!last || Date.parse(e.time) > Date.parse(last)) last = e.time;
    }
    if (severityRank(e.severity) > severityRank(max)) max = e.severity;
  }
  return { computed: true, sources: sources.size, sensors: [...sensors].sort(), firstSeen: first, lastSeen: last, maxSeverity: max, ruleIds: [...rules].sort() };
}

// Attached evidence grouped by source (sessions are derived per source),
// the group with the most recent event first; each group newest first.
export function groupEvidence(events) {
  const groups = new Map();
  for (const e of Array.isArray(events) ? events : []) {
    const key = typeof e?.source === 'string' ? e.source : '';
    if (!groups.has(key)) groups.set(key, { source: key, events: [], sensors: new Set(), latest: '', maxSeverity: '' });
    const g = groups.get(key);
    g.events.push(e);
    if (e.sensor?.id) g.sensors.add(e.sensor.id);
    if (isTime(e.time) && (!g.latest || Date.parse(e.time) > Date.parse(g.latest))) g.latest = e.time;
    if (severityRank(e.severity) > severityRank(g.maxSeverity)) g.maxSeverity = e.severity;
  }
  const t = (v) => (v ? Date.parse(v) : -Infinity);
  return [...groups.values()]
    .map((g) => ({ ...g, sensors: [...g.sensors].sort(), events: g.events.slice().sort((a, b) => t(b.time) - t(a.time)) }))
    .sort((a, b) => t(b.latest) - t(a.latest) || (a.source < b.source ? -1 : 1));
}

// The activity feed merged with the notes, oldest first. A note appears
// once, as the note (its activity entry would repeat it). Ties keep
// activity before the note it produced, and each list's own order.
export function mergeFeed(activity, notes) {
  const out = [];
  normalizeActivity(activity).forEach((a, i) => {
    if (a.kind !== 'note') out.push({ type: 'activity', at: a.at, order: i, ...a });
  });
  (Array.isArray(notes) ? notes : []).forEach((n, i) => {
    if (!n || typeof n.text !== 'string') return;
    out.push({ type: 'note', at: isTime(n.time) ? n.time : '', order: 100000 + i, author: text(n.author, 80) || 'unknown', text: n.text, pending: n.pending === true });
  });
  const t = (x) => (x.at ? Date.parse(x.at) : Infinity);
  return out.sort((a, b) => t(a) - t(b) || a.order - b.order);
}

export function activityWords(kind) {
  return ACTIVITY_WORDS[kind] || { verb: 'changed it', icon: 'history' };
}

// ---- Assignee -----------------------------------------------------------------

// Choices for the assignee picker: Unassigned, then you, then everyone else
// who may read investigations (the server's list), by name. The current
// assignee stays listed even when the list no longer includes them, so the
// picker never silently shows someone else.
export function assigneeOptions({ assignees = [], meId = '', meName = '', current = null, currentName = '' } = {}) {
  const seen = new Set();
  const out = [['', 'Unassigned']];
  const add = (id, label) => {
    if (!isPrincipalId(id) || seen.has(id)) return;
    seen.add(id);
    out.push([id, label]);
  };
  if (meId) add(meId, `You (${meName || meId})`);
  const list = (Array.isArray(assignees) ? assignees : []).filter((a) => a && isPrincipalId(a.id))
    .map((a) => ({ id: a.id, name: text(a.name, 80) || a.id }))
    .sort((a, b) => a.name.localeCompare(b.name));
  for (const a of list) add(a.id, a.name);
  if (current && !seen.has(current)) add(current, `${currentName || current} (no longer eligible)`);
  return out;
}

// Fallback on a server without the assignee list: accounts whose role
// grants investigations.read, enabled, in the active tenant. `permsOf`
// maps a role id to its permissions (the roles list, or built-ins).
export function eligibleAssignees(accounts, permsOf, tenant = '') {
  return (Array.isArray(accounts) ? accounts : [])
    .filter((a) => a && isPrincipalId(a.id) && a.status !== 'disabled' && (!tenant || !Array.isArray(a.tenants) || a.tenants.includes(tenant)))
    .filter((a) => (permsOf(a.role) || []).includes('investigations.read'))
    .map((a) => ({ id: a.id, name: text(a.name, 80) || a.id, kind: a.kind }));
}

export function assigneeName(inv, options = []) {
  if (!inv?.assignee) return '';
  const hit = options.find(([id]) => id === inv.assignee);
  return text(inv.assignee_name, 80) || (hit ? hit[1].replace(/^You \((.*)\)$/, '$1') : inv.assignee);
}

// ---- The list -----------------------------------------------------------------

export const ASSIGNEE_FILTERS = Object.freeze(['anyone', 'me', 'unassigned']);
export const LIST_DEFAULT_KEY = 'aegismesh.investigations-view';

// The view the list opens with when the link names no assignee: "anyone"
// unless the operator chose "Assigned to me" (stored in this browser).
export function readListDefault(storage) {
  try {
    return storage?.getItem(LIST_DEFAULT_KEY) === 'me' ? 'me' : 'anyone';
  } catch {
    return 'anyone';
  }
}
export function writeListDefault(storage, value) {
  try {
    storage?.setItem(LIST_DEFAULT_KEY, value === 'me' ? 'me' : 'anyone');
    return true;
  } catch {
    return false;
  }
}

export function normalizeInvestigationFilters(query, fallback = 'anyone') {
  const status = INVESTIGATION_STATUSES.includes(query?.status) ? query.status : '';
  const assignee = ASSIGNEE_FILTERS.includes(query?.assignee) ? query.assignee : (ASSIGNEE_FILTERS.includes(fallback) ? fallback : 'anyone');
  return { status, assignee };
}

// Applied in the browser: the list is unpaged, and an older server knows
// neither the assignee filter nor the field.
export function filterInvestigations(list, { status = '', assignee = 'anyone' } = {}, meId = '') {
  return (Array.isArray(list) ? list : []).filter((i) => {
    if (status && i.status !== status) return false;
    if (assignee === 'me') return Boolean(meId) && i.assignee === meId;
    if (assignee === 'unassigned') return !i.assignee;
    return true;
  });
}

export const eventCountOf = (i) => (Number.isInteger(i?.event_count) ? i.event_count : Array.isArray(i?.event_ids) ? i.event_ids.length : 0);

// ---- Opening a case from a campaign or a session ------------------------------

const clip = (s, n) => (Array.from(s).length > n ? `${Array.from(s).slice(0, n - 1).join('')}…` : s);

// The dialog's prefilled title and the count it states. A campaign's
// title comes from its label (server-composed words); a session's from its
// source key, which the operator can change before saving.
export function investigationDraft({ kind, label = '', source = '', id = '', eventCount = null } = {}) {
  const count = Number.isInteger(eventCount) && eventCount >= 0 ? Math.min(eventCount, MAX_EVIDENCE) : null;
  const title = kind === 'campaign'
    ? clip(`Campaign: ${text(label, 160) || id}`, 200)
    : clip(`Session from ${text(source, 160) || id}`, 200);
  const capped = Number.isInteger(eventCount) && eventCount > MAX_EVIDENCE;
  const what = count === null ? 'The member events will be attached' : `${count === 1 ? 'One event' : `${count} events`} will be attached`;
  return {
    title,
    count,
    capped,
    sentence: `${what}${capped ? ` (the newest ${MAX_EVIDENCE} of ${eventCount}, newest per session first)` : ''}. A first note records ${kind === 'campaign' ? 'the campaign’s basis and its caveat' : 'the session and its caveat'}.`,
  };
}

export const isPriority = (v) => PRIORITIES.includes(v);
export const isInvestigationId = isOpaqueId;

// One submission at a time: while a request runs, a second submit (a
// double click, Enter twice) gets the same promise instead of a second
// request; afterwards it may run again (a refusal can be retried).
export function createSubmitGuard() {
  let inflight = null;
  return {
    run(fn) {
      if (inflight) return inflight;
      inflight = Promise.resolve().then(fn).finally(() => { inflight = null; });
      return inflight;
    },
    get busy() { return inflight !== null; },
  };
}
