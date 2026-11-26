// Geometry for the identity pass: sparkline marks, the sensor mesh, the
// session tempo ribbon, and the remembered row density. Pure, so every
// mark is tested; the UI only draws what these return.

// Sparkline marks on the same geometry as sparkPath (lib/chart.js): the
// first and last points and the maximum (the first of equal maxima). A
// minimum mark is added only when it differs from both ends and is not zero
// (a zero floor is the baseline and needs no mark).
export function sparkMarks(values, { width = 88, height = 28, pad = 2.5 } = {}) {
  const list = (Array.isArray(values) ? values : []).map((v) => Math.max(0, Number(v) || 0));
  const n = list.length;
  if (n < 2) return [];
  const max = Math.max(...list);
  const r = (v) => Math.round(v * 10) / 10;
  const x = (i) => r(pad + (i * (width - 2 * pad)) / (n - 1));
  const y = (v) => r(max > 0 ? height - pad - (v / max) * (height - 2 * pad) : height - pad);
  const marks = [
    { kind: 'start', i: 0 },
    { kind: 'end', i: n - 1 },
  ];
  const iMax = list.indexOf(max);
  if (max > 0 && iMax !== 0 && iMax !== n - 1) marks.push({ kind: 'max', i: iMax });
  const min = Math.min(...list);
  const iMin = list.indexOf(min);
  if (min > 0 && iMin !== 0 && iMin !== n - 1 && iMin !== iMax) marks.push({ kind: 'min', i: iMin });
  return marks.map((m) => ({ ...m, value: list[m.i], x: x(m.i), y: y(list[m.i]) }));
}

// Sensor mesh: nodes evenly on a ring around the core, starting at the top
// and going clockwise. Radius grows with the square root of events (area
// follows the count), clamped so a quiet sensor is still a visible node.
export function meshLayout(sensors, { cx = 160, cy = 110, ring = 78, minR = 6, maxR = 15 } = {}) {
  const list = Array.isArray(sensors) ? sensors : [];
  const n = list.length;
  const top = Math.max(1, ...list.map((s) => Math.max(0, Number(s.events) || 0)));
  return list.map((s, i) => {
    const a = -Math.PI / 2 + (n > 1 ? (2 * Math.PI * i) / n : 0);
    const events = Math.max(0, Number(s.events) || 0);
    const rad = events > 0 ? minR + (maxR - minR) * Math.sqrt(events / top) : minR - 1;
    const x = Math.round((cx + ring * Math.cos(a)) * 10) / 10;
    const y = Math.round((cy + ring * Math.sin(a)) * 10) / 10;
    // Labels sit outside the ring, anchored away from the centre.
    const lx = Math.round((cx + (ring + rad + 12) * Math.cos(a)) * 10) / 10;
    const ly = Math.round((cy + (ring + rad + 12) * Math.sin(a)) * 10) / 10;
    const anchor = Math.abs(Math.cos(a)) < 0.3 ? 'middle' : Math.cos(a) > 0 ? 'start' : 'end';
    return { ...s, x, y, r: Math.round(rad * 10) / 10, lx, ly, anchor, events };
  });
}

// Whether a sensor had events in its newest bucket (the API's per-sensor
// buckets share the overview's starts). Absent buckets: unknown, not quiet.
export function lastBucketActive(buckets) {
  if (!Array.isArray(buckets) || !buckets.length) return null;
  const b = buckets[buckets.length - 1] || {};
  return ['interaction', 'canary_invocation', 'correlation_signal'].some((k) => Number(b[k]) > 0);
}

// Tempo: every timeline event on one horizontal axis. Gaps are compressed
// on a log scale (a 2 s gap and a 20 min gap both stay legible), and gaps
// longer than `breakMs` are drawn as a fixed-width break. Phase bands span
// their events. Returns x positions in [pad, width - pad].
export function tempoLayout(timeline, phases, { width = 640, pad = 8, breakMs = 5 * 60 * 1000, breakW = 18 } = {}) {
  const list = Array.isArray(timeline) ? timeline : [];
  if (!list.length) return { ticks: [], bands: [], breaks: [], width };
  const units = list.map((e, i) => {
    if (i === 0) return 0;
    const g = Math.max(0, Number(e.gap_ms) || 0);
    if (g > breakMs) return -1; // a break
    return Math.log10(1 + g / 100); // 100 ms ≈ 0.3 units, 1 min ≈ 2.8, 5 min ≈ 3.5
  });
  const breaks = units.filter((u) => u === -1).length;
  const sum = units.reduce((a, u) => a + (u > 0 ? u : 0), 0);
  const avail = Math.max(1, width - 2 * pad - breaks * breakW);
  // Equal gaps of zero still need space: a minimum share per gap.
  const minUnit = list.length > 1 ? Math.max(sum, 1) / (list.length * 6) : 0;
  const total = units.reduce((a, u, i) => a + (i === 0 || u === -1 ? 0 : Math.max(u, minUnit)), 0) || 1;
  let x = pad;
  const ticks = [];
  const breakList = [];
  list.forEach((e, i) => {
    if (i > 0) {
      if (units[i] === -1) {
        breakList.push({ x: Math.round((x + breakW / 2) * 10) / 10, ms: Number(e.gap_ms) });
        x += breakW;
      } else {
        x += (Math.max(units[i], minUnit) / total) * avail;
      }
    }
    ticks.push({ i, x: Math.round(x * 10) / 10, classification: e.classification, event_id: e.event_id });
  });
  // Bands: consume phase ids in order, like the story list.
  const queue = new Map();
  (Array.isArray(phases) ? phases : []).forEach((p, pi) => {
    for (const id of p?.event_ids || []) {
      if (!queue.has(id)) queue.set(id, []);
      queue.get(id).push(pi);
    }
  });
  const bands = [];
  ticks.forEach((t) => {
    const pi = queue.get(t.event_id)?.shift() ?? -1;
    const last = bands[bands.length - 1];
    if (last && last.phase === pi) last.x2 = t.x;
    else bands.push({ phase: pi, stage: phases?.[pi]?.stage || '', x1: t.x, x2: t.x });
  });
  // Bands meet halfway between neighbours, so they tile the axis.
  for (let b = 0; b < bands.length; b++) {
    const prev = bands[b - 1];
    const next = bands[b + 1];
    bands[b].left = prev ? Math.round(((prev.x2 + bands[b].x1) / 2) * 10) / 10 : pad;
    bands[b].right = next ? Math.round(((bands[b].x2 + next.x1) / 2) * 10) / 10 : width - pad;
  }
  return { ticks, bands, breaks: breakList, width };
}

// Row density, remembered in this browser. Anything else reads as the
// default, so a tampered value cannot reach a class name or attribute.
export const DENSITIES = Object.freeze(['comfortable', 'compact']);
export const parseDensity = (v) => (DENSITIES.includes(v) ? v : 'comfortable');
export const nextDensity = (v) => (parseDensity(v) === 'compact' ? 'comfortable' : 'compact');

// First-run tour state key, and the steps whose target is on screen now
// (the nav is in a drawer on narrow screens; those steps are skipped).
export const TOUR_KEY = 'aegismesh.tour';
export function tourStepsFor(steps, isVisible) {
  return (Array.isArray(steps) ? steps : []).filter((s) => s && typeof s.target === 'string' && isVisible(s.target));
}

// Where the tour popover goes: never over the element it describes, and
// as little as possible over the step's key content (`avoid`). Candidates:
// below, above, right and left of the target, then docked to the bottom or
// top of the viewport; each clamped inside the viewport with an 8px
// margin. The first candidate with the least covered area wins (the target
// weighs ten times the key content). Rects: { left, top, right, bottom }
// in viewport pixels. Returns { left, top, side }.
export function tourPlacement(target, box, viewport, avoid = [], gap = 10) {
  const vw = viewport.width;
  const vh = viewport.height;
  const w = Math.min(box.width, vw - 16);
  const hgt = Math.min(box.height, vh - 16);
  const clampX = (x) => Math.max(8, Math.min(x, vw - w - 8));
  const clampY = (y) => Math.max(8, Math.min(y, vh - hgt - 8));
  const cands = [
    ['below', target.left, target.bottom + gap],
    ['above', target.left, target.top - hgt - gap],
    ['right', target.right + gap, target.top],
    ['left', target.left - w - gap, target.top],
    ['dock-bottom', target.left, vh - hgt - 8],
    ['dock-top', target.left, 8],
  ];
  const overlap = (a, b) => Math.max(0, Math.min(a.right, b.right) - Math.max(a.left, b.left)) * Math.max(0, Math.min(a.bottom, b.bottom) - Math.max(a.top, b.top));
  let best = null;
  for (const [side, x0, y0] of cands) {
    const left = clampX(x0);
    const top = clampY(y0);
    const r = { left, top, right: left + w, bottom: top + hgt };
    // A candidate that had to move a long way to fit no longer sits beside
    // its target; it is kept only as a fallback.
    const moved = Math.abs(left - x0) > w / 2 || Math.abs(top - y0) > hgt / 2 ? 1 : 0;
    const score = overlap(r, target) * 10 + avoid.reduce((n, a) => n + overlap(r, a), 0) + moved;
    if (!best || score < best.score) best = { left: Math.round(left), top: Math.round(top), side, score };
    if (score === 0) break;
  }
  return { left: best.left, top: best.top, side: best.side };
}

// A long ranked list for a small chart: the first `n` rows as they are and
// the rest summed into one row, so 48 sensors read as the 8 busiest plus
// "40 other sensors". Rows keep the server's order (busiest first).
export function topWithRest(rows, n = 8, value = (r) => Number(r?.events) || 0) {
  const list = Array.isArray(rows) ? rows : [];
  if (list.length <= n + 1) return { top: list, rest: null };
  const others = list.slice(n);
  return { top: list.slice(0, n), rest: { count: others.length, events: others.reduce((a, r) => a + value(r), 0) } };
}
