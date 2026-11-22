// Hash routing and filter normalization. Everything that comes from the URL
// is untrusted input: route parameters are matched against closed patterns
// and filter values against the contract's vocabularies before use.

import { CLASSIFICATIONS, SENSOR_KINDS, SEVERITIES, WINDOWS, INVESTIGATION_STATUSES, AUDIT_ACTIONS, severityRank } from './taxonomy.js';
import { isNodeFilter, matchesNodeFilter } from './origin.js';

const EVENT_ID = /^[0-9a-f]{32}$/;
const OPAQUE_ID = /^[A-Za-z0-9_.-]{1,128}$/;
const SENSOR_ID = /^[A-Za-z0-9_.:-]{1,64}$/;
const RULE_ID = /^[A-Za-z0-9_.:-]{1,64}$/;
const ACTOR = /^[A-Za-z0-9_.@-]{1,64}$/;
const MAX_SOURCE_BYTES = 255;
const MAX_QUERY_CHARS = 128;

export const isEventId = (v) => typeof v === 'string' && EVENT_ID.test(v);
export const isOpaqueId = (v) => typeof v === 'string' && OPAQUE_ID.test(v);
// Attacker-session ids: 32 lowercase hex (derived, not persisted).
export const isSessionId = (v) => typeof v === 'string' && EVENT_ID.test(v);

// Sessions list filters: window and an exact source key.
export function normalizeSessionFilters(query) {
  const out = { window: normalizeWindow(query?.window) };
  if (isSourceKey(query?.source)) out.source = query.source;
  return out;
}

export const TECHNIQUE_FRAMEWORKS = Object.freeze(['mitre-attack', 'mitre-atlas', 'owasp-llm-2025']);
export function normalizeFramework(value) {
  return TECHNIQUE_FRAMEWORKS.includes(value) ? value : TECHNIQUE_FRAMEWORKS[0];
}

export function isSourceKey(v) {
  return typeof v === 'string' && v.length > 0 && new TextEncoder().encode(v).length <= MAX_SOURCE_BYTES;
}

// encodeURIComponent leaves !'()* unescaped; the DOM layer only accepts a
// narrower character set in hrefs, so escape those too.
export function encodeSegment(value) {
  return encodeURIComponent(String(value)).replace(/[!'()*]/g, (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`);
}

function decodeSegment(value) {
  try {
    return decodeURIComponent(value);
  } catch {
    return null;
  }
}

// href('events', id) → "#/events/<id>"; query values that are empty are dropped.
export function href(...parts) {
  let query = null;
  if (parts.length && typeof parts[parts.length - 1] === 'object' && parts[parts.length - 1] !== null) {
    query = parts.pop();
  }
  const path = parts.map((p, i) => (i === 0 ? String(p) : encodeSegment(p))).join('/');
  const qs = query ? toQuery(query) : '';
  return `#/${path}${qs ? `?${qs}` : ''}`;
}

export function toQuery(obj) {
  const out = [];
  for (const [k, v] of Object.entries(obj)) {
    if (v === undefined || v === null || v === '' || v === false) continue;
    out.push(`${encodeSegment(k)}=${encodeSegment(v === true ? '1' : v)}`);
  }
  return out.join('&');
}

// Screens the router knows. A path that matches nothing is "not_found".
const ROUTES = [
  { name: 'overview', pattern: [] },
  { name: 'overview', pattern: ['overview'] },
  { name: 'events', pattern: ['events'] },
  { name: 'event', pattern: ['events', ':id'], valid: (p) => isEventId(p.id) },
  { name: 'sources', pattern: ['sources'] },
  { name: 'source', pattern: ['sources', ':source'], valid: (p) => isSourceKey(p.source) },
  { name: 'sensors', pattern: ['sensors'] },
  { name: 'rules', pattern: ['rules'] },
  { name: 'recommendations', pattern: ['recommendations'] },
  { name: 'node', pattern: ['node'] },
  { name: 'investigations', pattern: ['investigations'] },
  { name: 'investigation', pattern: ['investigations', ':id'], valid: (p) => isOpaqueId(p.id) },
  { name: 'audit', pattern: ['audit'] },
  { name: 'fleet', pattern: ['fleet'] },
  { name: 'fleet', pattern: ['fleet', 'nodes'] },
  { name: 'fleet_node', pattern: ['fleet', 'nodes', ':id'], valid: (p) => /^[0-9a-f]{32}$/.test(p.id) },
  { name: 'guide', pattern: ['guide'] },
  { name: 'sessions', pattern: ['sessions'] },
  { name: 'attack_session', pattern: ['sessions', ':id'], valid: (p) => isSessionId(p.id) },
  { name: 'techniques', pattern: ['techniques'] },
  { name: 'decoys', pattern: ['decoys'] },
  { name: 'honeytokens', pattern: ['honeytokens'] },
  { name: 'digest', pattern: ['digest'] },
  { name: 'login', pattern: ['login'] },
];

export function parseHash(hash) {
  let raw = String(hash ?? '');
  if (raw.startsWith('#')) raw = raw.slice(1);
  if (raw.startsWith('/')) raw = raw.slice(1);
  const qi = raw.indexOf('?');
  const pathPart = qi >= 0 ? raw.slice(0, qi) : raw;
  const queryPart = qi >= 0 ? raw.slice(qi + 1) : '';
  const segments = pathPart.split('/').filter((s) => s !== '');
  const query = {};
  for (const pair of queryPart.split('&')) {
    if (!pair) continue;
    const eq = pair.indexOf('=');
    const k = decodeSegment((eq >= 0 ? pair.slice(0, eq) : pair).replace(/\+/g, ' '));
    const v = decodeSegment((eq >= 0 ? pair.slice(eq + 1) : '').replace(/\+/g, ' '));
    if (k === null || v === null) continue;
    if (!Object.hasOwn(query, k)) query[k] = v;
  }
  for (const route of ROUTES) {
    if (route.pattern.length !== segments.length) continue;
    const params = {};
    let ok = true;
    for (let i = 0; i < segments.length; i++) {
      const want = route.pattern[i];
      if (want.startsWith(':')) {
        const decoded = decodeSegment(segments[i]);
        if (decoded === null) { ok = false; break; }
        params[want.slice(1)] = decoded;
      } else if (want !== segments[i]) {
        ok = false;
        break;
      }
    }
    if (!ok) continue;
    if (route.valid && !route.valid(params)) return { name: 'not_found', params: {}, query, path: pathPart };
    return { name: route.name, params, query, path: pathPart };
  }
  return { name: 'not_found', params: {}, query, path: pathPart };
}

export function normalizeWindow(value) {
  return WINDOWS.includes(value) ? value : '24h';
}

export function normalizeStatus(value) {
  return INVESTIGATION_STATUSES.includes(value) ? value : '';
}

const RFC3339 = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,9})?(Z|[+-]\d{2}:\d{2})$/;

export function isRfc3339(value) {
  return typeof value === 'string' && RFC3339.test(value) && !Number.isNaN(Date.parse(value));
}

// `node` selects one origin: "local" or an enrolled node's id (forwarded
// evidence on a hub). The other keys predate forwarding.
export const EVENT_FILTER_KEYS = Object.freeze(['node', 'classification', 'sensor', 'kind', 'source', 'rule', 'severity', 'since', 'until', 'q']);

const FILTER_VALIDATORS = {
  node: isNodeFilter,
  classification: (v) => CLASSIFICATIONS.includes(v),
  sensor: (v) => SENSOR_ID.test(v),
  kind: (v) => SENSOR_KINDS.includes(v),
  source: (v) => isSourceKey(v),
  rule: (v) => RULE_ID.test(v),
  severity: (v) => SEVERITIES.includes(v),
  since: isRfc3339,
  until: isRfc3339,
  q: (v) => v.length <= MAX_QUERY_CHARS,
};

// Keep only contract-valid filters. Rejected keys are reported so the UI can
// say which part of a pasted link it ignored instead of failing silently.
export function normalizeEventFilters(query) {
  const filters = {};
  const rejected = [];
  for (const key of EVENT_FILTER_KEYS) {
    const raw = query?.[key];
    if (raw === undefined || raw === '') continue;
    const value = key === 'q' ? String(raw) : String(raw).trim();
    if (FILTER_VALIDATORS[key](value)) filters[key] = value;
    else rejected.push(key);
  }
  if (filters.since && filters.until && Date.parse(filters.since) > Date.parse(filters.until)) {
    delete filters.since;
    delete filters.until;
    rejected.push('since', 'until');
  }
  return { filters, rejected };
}

export function normalizeAuditFilters(query) {
  const out = {};
  if (AUDIT_ACTIONS.includes(query?.action)) out.action = query.action;
  if (typeof query?.actor === 'string' && ACTOR.test(query.actor)) out.actor = query.actor;
  return out;
}

// Client-side twin of the server's /events filter, for the SSE stream (the
// server filters the stream by node only). Semantics follow the contract:
// origin ("local" = no `node` on the event), exact matches, minimum severity,
// inclusive time bounds, and case-insensitive substring q over summary,
// source and rule ids.
export function matchesEventFilters(ev, filters) {
  if (!ev || typeof ev !== 'object') return false;
  const f = filters || {};
  if (f.node && !matchesNodeFilter(ev, f.node)) return false;
  if (f.classification && ev.classification !== f.classification) return false;
  if (f.sensor && ev.sensor?.id !== f.sensor) return false;
  if (f.kind && ev.sensor?.kind !== f.kind) return false;
  if (f.source && ev.source !== f.source) return false;
  const rules = Array.isArray(ev.rule_ids) ? ev.rule_ids : [];
  if (f.rule && !rules.includes(f.rule)) return false;
  if (f.severity && severityRank(ev.severity) < severityRank(f.severity)) return false;
  const t = Date.parse(ev.time);
  if (f.since && !(t >= Date.parse(f.since))) return false;
  if (f.until && !(t <= Date.parse(f.until))) return false;
  if (f.q) {
    const needle = f.q.toLowerCase();
    const hay = [ev.summary, ev.source, ...rules].map((s) => String(s ?? '').toLowerCase());
    if (!hay.some((s) => s.includes(needle))) return false;
  }
  return true;
}

// Identity of the view a route renders, ignoring query keys that only change
// an overlay (e.g. the event drawer's `event`). Two routes with the same key
// update in place instead of re-rendering the screen.
export function viewKey(route, ignore = []) {
  const q = route?.query || {};
  const keys = Object.keys(q).filter((k) => !ignore.includes(k) && q[k] !== '').sort();
  const params = route?.params || {};
  const p = Object.keys(params).sort().map((k) => `${k}=${params[k]}`).join('&');
  return `${route?.name || ''}|${p}|${keys.map((k) => `${k}=${q[k]}`).join('&')}`;
}

// Rebuild a route hash with some query keys changed ('' or null removes).
export function withQuery(route, patch) {
  const q = { ...(route?.query || {}) };
  for (const [k, v] of Object.entries(patch || {})) {
    if (v === null || v === undefined || v === '') delete q[k];
    else q[k] = v;
  }
  const path = route?.path ? `#/${route.path}` : '#/';
  const qs = toQuery(q);
  return qs ? `${path}?${qs}` : path;
}
