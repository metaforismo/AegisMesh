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
