// Pure helpers for the experimental fleet inventory (console API, ADR-0018).
// Node data is self-reported by each agent: these helpers validate shape and
// format it, they never treat it as attestation.

import { parseTime } from './format.js';

export const FLEET_STATUSES = Object.freeze(['online', 'stale', 'offline', 'revoked']);

// Status → badge kind. Each badge kind also has its own dot shape (circle,
// diamond, hollow ring, triangle), so status never depends on color alone.
const STATUS_META = Object.freeze({
  online: { badge: 'ok', label: 'Online' },
  stale: { badge: 'warn', label: 'Stale' },
  offline: { badge: 'neutral', label: 'Offline' },
  revoked: { badge: 'danger', label: 'Revoked' },
});

export function fleetStatusMeta(status) {
  return STATUS_META[status] ?? { badge: 'neutral', label: 'Unknown' };
}

export function normalizeFleetStatus(value) {
  return FLEET_STATUSES.includes(value) ? value : '';
}

const NODE_ID = /^[0-9a-f]{32}$/;
const FINGERPRINT = /^[0-9a-f]{64}$/;
const TOKEN_ID = /^[A-Za-z0-9_.-]{1,128}$/;

// Node id = first 16 bytes of SHA-256(public key), lowercase hex.
export const isNodeId = (v) => typeof v === 'string' && NODE_ID.test(v);
export const isFingerprint = (v) => typeof v === 'string' && FINGERPRINT.test(v);
export const isTokenId = (v) => typeof v === 'string' && TOKEN_ID.test(v);

// The fingerprint is the full SHA-256(public key); the node id is its first
// 32 hex characters. A mismatch means the record is inconsistent.
export function idMatchesFingerprint(id, fingerprint) {
  return isNodeId(id) && isFingerprint(fingerprint) && fingerprint.startsWith(id);
}

// "a1b2c3d4 e5f6…" groups of 8 for reading aloud and comparing by eye.
export function formatFingerprint(fingerprint) {
  if (!isFingerprint(fingerprint)) return '';
  return fingerprint.match(/.{8}/g).join(' ');
}

export function sensorSummary(sensors) {
  const out = { total: 0, running: 0, stopped: 0, failed: 0, other: 0 };
  for (const s of Array.isArray(sensors) ? sensors : []) {
    out.total++;
    if (s?.state === 'running' || s?.state === 'stopped' || s?.state === 'failed') out[s.state]++;
    else out.other++;
  }
  return out;
}

// ---- Enrollment tokens ---------------------------------------------------

export const TOKEN_TTL_MIN = 1;
export const TOKEN_TTL_MAX = 86400;
export const TOKEN_TTL_DEFAULT = 3600;
export const TOKEN_NOTE_MAX_BYTES = 256;

export const TTL_CHOICES = Object.freeze([
  [900, '15 minutes'],
  [3600, '1 hour (default)'],
  [14400, '4 hours'],
  [86400, '24 hours (maximum)'],
]);

export function isValidTtl(n) {
  return Number.isInteger(n) && n >= TOKEN_TTL_MIN && n <= TOKEN_TTL_MAX;
}

// Contract: printable ASCII only (0x20–0x7E), at most 256 bytes. Empty is fine.
export function validateTokenNote(note) {
  const s = String(note ?? '');
  if (s.length > TOKEN_NOTE_MAX_BYTES) return `Keep the note to ${TOKEN_NOTE_MAX_BYTES} characters or fewer.`;
  if (!/^[\x20-\x7e]*$/.test(s)) return 'Use plain ASCII letters, digits, spaces and punctuation only.';
  return '';
}

// Expiry arrives as an RFC 3339 string. Older backend builds sent Unix
// seconds in the list response; accept both and normalize to RFC 3339.
export function normalizeExpiry(value) {
  if (typeof value === 'number' && Number.isFinite(value) && value > 0) {
    return new Date(value * 1000).toISOString().replace('.000Z', 'Z');
  }
  return parseTime(value) ? value : '';
}

// "in 45m", "in 3h 10m", "expired".
export function formatExpiresIn(value, now = Date.now()) {
  const d = parseTime(normalizeExpiry(value));
  if (!d) return 'unknown expiry';
  const s = Math.floor((d.getTime() - now) / 1000);
  if (s <= 0) return 'expired';
  if (s < 60) return `in ${s}s`;
  const m = Math.floor(s / 60);
  if (m < 60) return `in ${m}m`;
  const h = Math.floor(m / 60);
  return m % 60 ? `in ${h}h ${m % 60}m` : `in ${h}h`;
}

// ---- Evidence forwarding (experimental) -----------------------------------
//
// FleetNode.forwarding is a heartbeat self-report (counters, queue, error)
// plus hub-authored receive time and gaps; /fleet agent.forwarding is this
// process's own view. Forwarding is best effort with counted loss: what was
// not forwarded still exists in the node's own store.

const ERROR_CATEGORY = /^[a-z][a-z0-9_]{0,63}$/;

// Known categories get words; any other well-formed category is shown as
// its code. The value is a fixed local category, never free text.
const FORWARDING_ERRORS = Object.freeze({
  evidence_disabled: 'The hub does not accept evidence',
});

export function forwardingErrorText(code) {
  if (typeof code !== 'string' || code === '') return '';
  if (!ERROR_CATEGORY.test(code)) return 'Unrecognized error category';
  return FORWARDING_ERRORS[code] || '';
}

const count = (v) => {
  const n = Number(v);
  return Number.isFinite(n) && n >= 0 ? n : 0;
};
const optionalCount = (v) => (v === undefined || v === null ? null : count(v));

// Normalized view of a forwarding block, or null when absent (an old agent,
// or no report yet).
export function forwardingSummary(fw) {
  if (!fw || typeof fw !== 'object' || Array.isArray(fw)) return null;
  const code = typeof fw.last_error === 'string' ? fw.last_error : '';
  const s = {
    enabled: fw.enabled === true,
    forwarded: count(fw.forwarded_total),
    dropped: count(fw.dropped_total),
    gaps: count(fw.gaps_total),
    lastForwardedAt: parseTime(fw.last_forwarded_at) ? fw.last_forwarded_at : '',
    queuedEvents: optionalCount(fw.queued_events),
    queuedBytes: optionalCount(fw.queued_bytes),
    lastError: code && ERROR_CATEGORY.test(code) ? code : (code ? 'unrecognized' : ''),
  };
  s.loss = s.dropped > 0 || s.gaps > 0;
  return s;
}

const plural = (n, one, many) => `${new Intl.NumberFormat('en-US').format(n)} ${n === 1 ? one : many}`;

// "37 dropped, 2 gaps" — only the parts that are non-zero.
export function lossText(s) {
  if (!s?.loss) return '';
  return [s.dropped ? `${plural(s.dropped, 'dropped', 'dropped')}` : '', s.gaps ? plural(s.gaps, 'gap', 'gaps') : ''].filter(Boolean).join(', ');
}

export const LOSS_EXPLANATION = 'Some evidence did not reach the hub. It still exists in the node’s own store, which stays authoritative.';
