// Pure geometry for the hand-written SVG charts. No DOM here, so the layout
// math is unit-tested directly.

import { CLASSIFICATIONS } from './taxonomy.js';

// Smallest "nice" number (1, 2, 2.5, 5 × 10^n) that is >= value.
export function niceCeil(value) {
  const v = Number(value);
  if (!Number.isFinite(v) || v <= 0) return 1;
  const exp = Math.floor(Math.log10(v));
  const base = 10 ** exp;
  for (const m of [1, 2, 2.5, 5, 10]) {
    if (m * base >= v - 1e-9) return m * base;
  }
  return 10 * base;
}

// Integer ticks from 0 to a nice maximum, at most `count` intervals.
export function ticks(maxValue, count = 4) {
  const max = Math.max(1, Number(maxValue) || 0);
  let step = niceCeil(max / count);
  if (step < 1) step = 1;
  step = Math.ceil(step);
  const top = Math.ceil(max / step) * step;
  const out = [];
  for (let v = 0; v <= top + 1e-9; v += step) out.push(v);
  return { max: top, step, values: out };
}

export function bucketTotal(bucket) {
  let t = 0;
  for (const key of CLASSIFICATIONS) t += Math.max(0, Number(bucket?.[key]) || 0);
  return t;
}

// Stacked bar layout. Segments stack in fixed classification order (color
// follows the entity, never the rank) with a `gap` px surface gap between
// filled segments. Returns plot geometry plus per-bucket rects.
export function stackedLayout(buckets, { width = 720, height = 180, padLeft = 36, padRight = 8, padTop = 8, padBottom = 22, gap = 2, barGap = 2 } = {}) {
  const list = Array.isArray(buckets) ? buckets : [];
  const plotW = Math.max(1, width - padLeft - padRight);
  const plotH = Math.max(1, height - padTop - padBottom);
  const maxTotal = list.reduce((m, b) => Math.max(m, bucketTotal(b)), 0);
  const scale = ticks(maxTotal);
  const slot = list.length ? plotW / list.length : plotW;
  const barW = Math.max(1, slot - barGap);
  const y = (v) => padTop + plotH - (v / scale.max) * plotH;
  const bars = list.map((b, i) => {
    const x = padLeft + i * slot + barGap / 2;
    let acc = 0;
    const segments = [];
    // Stack bottom-up. Every segment above the first gives up `gap` px of its
    // own height to the surface gap, so the stack top still lands on the
    // total and small segments stay at least 1px tall.
    let bottom = padTop + plotH;
    for (const key of CLASSIFICATIONS) {
      const value = Math.max(0, Number(b?.[key]) || 0);
      if (value === 0) continue;
      acc += value;
      const g = segments.length ? gap : 0;
      const full = (value / scale.max) * plotH;
      const h = Math.max(1, full - g);
      const top = bottom - g - h;
      segments.push({ key, value, x, y: top, w: barW, h });
      bottom = top;
    }
    return { index: i, start: b?.start ?? '', total: acc, x: padLeft + i * slot, slot, segments };
  });
  return {
    width, height, plot: { x: padLeft, y: padTop, w: plotW, h: plotH },
    scale, bars, yFor: y,
  };
}

// Which bucket indices get an axis label: about `target` evenly spaced.
export function labelIndices(n, target = 6) {
  if (n <= 0) return [];
  const step = Math.max(1, Math.ceil(n / target));
  const out = [];
  for (let i = 0; i < n; i += step) out.push(i);
  return out;
}

// Share of a part in a whole, clamped to [0, 1] for bar fills.
export function share(part, whole) {
  const p = Number(part);
  const w = Number(whole);
  if (!Number.isFinite(p) || !Number.isFinite(w) || w <= 0) return 0;
  return Math.min(1, Math.max(0, p / w));
}

// Sparkline geometry for a series of non-negative values. Returns SVG path
// data for the line and the closed area under it, plus the last point (for
// the end dot). Flat or empty series sit on the baseline. Coordinates are
// rounded to 0.1px to keep the path data short.
export function sparkPath(values, { width = 88, height = 28, pad = 2 } = {}) {
  const list = (Array.isArray(values) ? values : []).map((v) => Math.max(0, Number(v) || 0));
  const r = (n) => Math.round(n * 10) / 10;
  const base = height - pad;
  if (list.length === 0) return { line: '', area: '', last: null, max: 0 };
  const max = Math.max(...list);
  const n = list.length;
  const x = (i) => (n === 1 ? width / 2 : pad + (i * (width - 2 * pad)) / (n - 1));
  const y = (v) => (max > 0 ? base - (v / max) * (height - 2 * pad) : base);
  const pts = list.map((v, i) => [r(x(i)), r(y(v))]);
  const line = `M${pts.map(([px, py]) => `${px} ${py}`).join('L')}`;
  const area = `${line}L${pts[n - 1][0]} ${r(base)}L${pts[0][0]} ${r(base)}Z`;
  const [lx, ly] = pts[n - 1];
  return { line, area, last: { x: lx, y: ly }, max };
}

// Per-bucket totals for one classification key, or all of them.
export function seriesOf(buckets, key) {
  const list = Array.isArray(buckets) ? buckets : [];
  return list.map((b) => (key ? Math.max(0, Number(b?.[key]) || 0) : bucketTotal(b)));
}

// Count timestamps into `n` equal bins over [start, end). Times outside the
// range are ignored (and counted in `outside`), never clamped into an edge
// bin, so a trace never shows activity that did not happen in its window.
export function binTimes(times, start, end, n) {
  const s = Number(start);
  const e = Number(end);
  const count = Math.max(1, Math.floor(Number(n) || 1));
  const bins = new Array(count).fill(0);
  let outside = 0;
  if (!(e > s)) return { bins, outside: (times || []).length };
  const size = (e - s) / count;
  for (const t of times || []) {
    const ms = typeof t === 'number' ? t : Date.parse(t);
    if (!Number.isFinite(ms) || ms < s || ms >= e) { outside++; continue; }
    bins[Math.min(count - 1, Math.floor((ms - s) / size))]++;
  }
  return { bins, outside };
}

// Time range a bucket covers, for "open these events": [start, next start).
// The API's `until` is inclusive, so the range ends one second before the
// next bucket starts. The last bucket ends at `end` (e.g. generated_at).
export function bucketRange(buckets, index, end) {
  const list = Array.isArray(buckets) ? buckets : [];
  const b = list[index];
  const since = Date.parse(b?.start);
  if (!Number.isFinite(since)) return null;
  let next = Date.parse(list[index + 1]?.start);
  if (!Number.isFinite(next)) {
    const prev = Date.parse(list[index - 1]?.start);
    const step = Number.isFinite(prev) ? since - prev : NaN;
    const fallback = Date.parse(end);
    next = Number.isFinite(step) ? since + step : fallback;
  }
  if (!Number.isFinite(next) || next <= since) return null;
  const iso = (ms) => new Date(ms).toISOString().replace('.000Z', 'Z');
  return { since: iso(since), until: iso(Math.max(since, next - 1000)) };
}

// Delays for a left-to-right entry wave: eased, so the wave starts quickly
// and settles, and capped at `total` ms however many bars there are.
export function waveDelays(n, total = 240) {
  const count = Math.max(0, Math.floor(Number(n) || 0));
  const out = [];
  for (let i = 0; i < count; i++) {
    const t = count > 1 ? i / (count - 1) : 0;
    out.push(Math.round(total * (1 - (1 - t) ** 2)));
  }
  return out;
}

// ---- Per-sensor series (overview.by_sensor[].buckets) -------------------------

// The contract caps by_sensor at this many entries; a sensor missing from a
// full list may simply be past the cap.
export const BY_SENSOR_CAP = 64;

const zeroBucket = (b) => ({ start: b?.start, interaction: 0, canary_invocation: 0, correlation_signal: 0 });

// One sensor's bucket series from an overview response.
//   { status: 'ok', buckets, events }  the server's series (or, for a sensor
//                                      with no events in the window, zeros
//                                      on the main series' starts)
//   { status: 'unsupported' }          an older server without per-sensor
//                                      buckets, or a sensor beyond the cap:
//                                      the caller falls back to listing events
export function sensorBuckets(overview, sensorId) {
  const list = Array.isArray(overview?.by_sensor) ? overview.by_sensor : null;
  if (!list) return { status: 'unsupported' };
  if (list.some((s) => !Array.isArray(s?.buckets))) return { status: 'unsupported' };
  const row = list.find((s) => s?.sensor_id === sensorId);
  if (row) return { status: 'ok', buckets: row.buckets, events: Number(row.events) || 0 };
  const main = Array.isArray(overview?.buckets) ? overview.buckets : [];
  // Absent from a full list: it may have events past the cap. Absent from an
  // empty list: an older server says nothing either way unless main exists.
  if (list.length >= BY_SENSOR_CAP || !main.length) return { status: 'unsupported' };
  return { status: 'ok', buckets: main.map(zeroBucket), events: 0 };
}

// Bucket series → activity trace geometry. Each bucket covers [start, next
// start); the last one is as long as the one before it (or ends at `end`
// when there is only one). Returns null when the starts cannot be read.
export function bucketTrace(buckets, { end } = {}) {
  const list = Array.isArray(buckets) ? buckets : [];
  if (!list.length) return null;
  const starts = list.map((b) => Date.parse(b?.start));
  if (starts.some((t) => !Number.isFinite(t))) return null;
  const start = starts[0];
  let stop;
  if (list.length > 1) {
    const step = starts[list.length - 1] - starts[list.length - 2];
    stop = starts[list.length - 1] + step;
  } else {
    stop = Date.parse(end);
  }
  if (!Number.isFinite(stop) || stop <= start) return null;
  const bins = seriesOf(list, '');
  return { bins, start, end: stop, total: bins.reduce((a, b) => a + b, 0) };
}

// Earliest time the console's index can speak for, from GET /node.
// - complete: the index holds all retained evidence, so quiet bins are quiet.
// - unavailable (evidence-at-rest encryption, or forwarded copies): the index
//   holds what arrived since the process started; earlier bins are unknown.
// - truncated: the index dropped its oldest entries; bins older than the
//   oldest indexed event are unknown.
// Unknown bins are drawn dashed, never as zero.
export function indexKnownFrom(node) {
  const index = node?.index;
  if (!index || index.history === 'complete') return -Infinity;
  const started = Date.parse(node?.started_at);
  const oldest = Date.parse(index.oldest);
  if (index.history === 'unavailable' && Number.isFinite(started)) return started;
  if (Number.isFinite(oldest)) return oldest;
  return Number.isFinite(started) ? started : -Infinity;
}
