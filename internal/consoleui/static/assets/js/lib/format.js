// Pure formatters. Times are shown in UTC: evidence is compared across
// machines and logs, so the console never silently shifts to local time.

const pad = (n, w = 2) => String(n).padStart(w, '0');

export function parseTime(value) {
  if (typeof value !== 'string' || value === '') return null;
  const ms = Date.parse(value);
  return Number.isNaN(ms) ? null : new Date(ms);
}

// "2026-11-14 09:03:44 UTC"
export function formatDateTime(value) {
  const d = parseTime(value);
  if (!d) return '—';
  return `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())} ` +
    `${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())} UTC`;
}

// "09:03:44" — for dense tables where the date is implied by context.
export function formatClock(value) {
  const d = parseTime(value);
  if (!d) return '—';
  return `${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())}`;
}

const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];

// Axis label for a bucket start, chosen by window length.
export function formatBucketLabel(value, window) {
  const d = parseTime(value);
  if (!d) return '';
  if (window === '7d') return `${MONTHS[d.getUTCMonth()]} ${d.getUTCDate()}`;
  return `${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}`;
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

export function formatDuration(totalSeconds) {
  const s = Math.max(0, Math.floor(Number(totalSeconds) || 0));
  const d = Math.floor(s / 86400);
  const h = Math.floor((s % 86400) / 3600);
  const m = Math.floor((s % 3600) / 60);
  if (d > 0) return `${d}d ${h}h`;
  if (h > 0) return `${h}h ${m}m`;
  if (m > 0) return `${m}m ${s % 60}s`;
  return `${s}s`;
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
