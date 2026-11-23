// Pure formatters. Times are shown in UTC by default: evidence is compared
// across machines and logs. An operator may choose local time in Settings
// (Preferences); then every absolute time carries its UTC offset, so a
// copied time is never ambiguous. The choice is module state set once by
// setTimeZone(); the default stays UTC.

const pad = (n, w = 2) => String(n).padStart(w, '0');

export const TIME_ZONES = Object.freeze(['utc', 'local']);
let zone = 'utc';

export function setTimeZone(value) {
  zone = TIME_ZONES.includes(value) ? value : 'utc';
  return zone;
}

export const timeZone = () => zone;

export function parseTime(value) {
  if (typeof value !== 'string' || value === '') return null;
  const ms = Date.parse(value);
  return Number.isNaN(ms) ? null : new Date(ms);
}

// Calendar fields in the chosen zone.
function fields(d) {
  return zone === 'local'
    ? { y: d.getFullYear(), mo: d.getMonth(), da: d.getDate(), h: d.getHours(), mi: d.getMinutes(), s: d.getSeconds() }
    : { y: d.getUTCFullYear(), mo: d.getUTCMonth(), da: d.getUTCDate(), h: d.getUTCHours(), mi: d.getUTCMinutes(), s: d.getUTCSeconds() };
}

// "UTC", or the local offset at that instant ("UTC+1", "UTC−3:30").
export function zoneLabel(d = new Date()) {
  if (zone !== 'local') return 'UTC';
  const off = -d.getTimezoneOffset();
  if (off === 0) return 'UTC+0';
  const sign = off > 0 ? '+' : '−';
  const a = Math.abs(off);
  return `UTC${sign}${Math.floor(a / 60)}${a % 60 ? `:${pad(a % 60)}` : ''}`;
}

// How the interface names the zone in captions ("times in UTC").
export const zoneName = () => (zone === 'local' ? 'local time' : 'UTC');

// "2026-11-14 09:03:44 UTC" (or "… 10:03:44 UTC+1" in local time)
export function formatDateTime(value) {
  const d = parseTime(value);
  if (!d) return '—';
  const f = fields(d);
  return `${f.y}-${pad(f.mo + 1)}-${pad(f.da)} ${pad(f.h)}:${pad(f.mi)}:${pad(f.s)} ${zoneLabel(d)}`;
}

// "09:03:44" — for dense tables where the date is implied by context.
export function formatClock(value) {
  const d = parseTime(value);
  if (!d) return '—';
  const f = fields(d);
  return `${pad(f.h)}:${pad(f.mi)}:${pad(f.s)}`;
}

const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];

// Axis label for a bucket start, chosen by window length.
export function formatBucketLabel(value, window) {
  const d = parseTime(value);
  if (!d) return '';
  const f = fields(d);
  if (window === '7d') return `${MONTHS[f.mo]} ${f.da}`;
  return `${pad(f.h)}:${pad(f.mi)}`;
}

export function formatRelative(value, now = Date.now()) {
  const d = parseTime(value);
  if (!d) return 'never';
  const s = Math.round((now - d.getTime()) / 1000);
  if (s < -5) return 'in the future';
  if (s < 10) return 'just now';
  if (s < 60) return `${s}s ago`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 48) return `${h}h ago`;
  return `${Math.floor(h / 24)}d ago`;
}

// One duration style everywhere (session spans, gaps, uptime, lifetimes):
// "850 ms", "4.2 s", "45 s", "3 min", "1.5 h", "2.3 d". Unknown or negative
// is "—"; zero is "0 s".
export function formatDurationMs(value) {
  if (value === null || value === undefined || value === '') return '—';
  const ms = Number(value);
  if (!Number.isFinite(ms) || ms < 0) return '—';
  if (ms === 0) return '0 s';
  if (ms < 1000) return `${Math.round(ms)} ms`;
  const s = ms / 1000;
  if (s < 10) return `${Math.round(s * 10) / 10} s`;
  if (s < 90) return `${Math.round(s)} s`;
  const m = s / 60;
  if (m < 90) return `${m < 10 ? Math.round(m * 10) / 10 : Math.round(m)} min`;
  const h = m / 60;
  if (h < 48) return `${Math.round(h * 10) / 10} h`;
  return `${Math.round((h / 24) * 10) / 10} d`;
}

// Seconds (uptime, session lifetime) in the same style.
export function formatDuration(totalSeconds) {
  if (totalSeconds === null || totalSeconds === undefined || totalSeconds === '') return '—';
  const n = Number(totalSeconds);
  return Number.isFinite(n) ? formatDurationMs(Math.max(0, n) * 1000) : '—';
}

const integer = new Intl.NumberFormat('en-US', { maximumFractionDigits: 0 });

export function formatCount(value) {
  const n = Number(value);
  return Number.isFinite(n) ? integer.format(n) : '—';
}

// Compact axis ticks: full under 10,000, then 10K / 1.2M.
export function formatCompact(value) {
  const n = Number(value);
  if (!Number.isFinite(n)) return '—';
  if (Math.abs(n) < 10000) return integer.format(n);
  if (Math.abs(n) < 1e6) return `${trim(n / 1e3)}K`;
  return `${trim(n / 1e6)}M`;
}

// A measured rate or ratio: one decimal by default, grouped like counts.
export function formatNumber(value, digits = 1) {
  const n = Number(value);
  if (value === null || value === undefined || value === '' || !Number.isFinite(n)) return '—';
  return new Intl.NumberFormat('en-US', { maximumFractionDigits: digits }).format(n);
}

function trim(n) {
  return n >= 100 ? String(Math.round(n)) : String(Math.round(n * 10) / 10);
}

export function formatBytes(value) {
  let n = Number(value);
  if (!Number.isFinite(n) || n < 0) return '—';
  const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
  let i = 0;
  while (n >= 1024 && i < units.length - 1) {
    n /= 1024;
    i++;
  }
  return i === 0 ? `${n} B` : `${n.toFixed(n >= 100 ? 0 : 1)} ${units[i]}`;
}

// Change versus the previous window. Direction is descriptive only; the UI
// never colors more observations as "worse".
export function formatDelta(current, previous) {
  const cur = Number(current) || 0;
  const prev = Number(previous) || 0;
  const diff = cur - prev;
  if (prev === 0 && cur === 0) return { direction: 'flat', text: 'no change', detail: 'none in either window' };
  if (prev === 0) return { direction: 'up', text: `+${formatCount(diff)}`, detail: 'none in previous window' };
  const pct = Math.round((diff / prev) * 100);
  if (diff === 0) return { direction: 'flat', text: 'no change', detail: 'vs previous window' };
  const sign = diff > 0 ? '+' : '−';
  return {
    direction: diff > 0 ? 'up' : 'down',
    text: `${sign}${formatCount(Math.abs(diff))} (${sign}${Math.abs(pct)}%)`,
    detail: 'vs previous window',
  };
}

export function shortId(id, n = 8) {
  const s = String(id ?? '');
  return s.length > n ? s.slice(0, n) : s;
}

// Truncate by code points (never splitting a surrogate pair) for display.
export function truncate(value, max) {
  const chars = Array.from(String(value ?? ''));
  return chars.length <= max ? chars.join('') : `${chars.slice(0, max - 1).join('')}…`;
}

// <input type="datetime-local"> value (interpreted as UTC) → RFC 3339.
export function localInputToRfc3339(value) {
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2})?$/.test(value ?? '')) return '';
  const withSeconds = value.length === 16 ? `${value}:00` : value;
  const d = new Date(`${withSeconds}Z`);
  return Number.isNaN(d.getTime()) ? '' : d.toISOString().replace('.000Z', 'Z');
}

export function rfc3339ToLocalInput(value) {
  const d = parseTime(value);
  if (!d) return '';
  return d.toISOString().slice(0, 19);
}
