// Inter-arrival cadence of a source's loaded events. Pure.
//
// A machine-paced client (a script, an LLM-driven agent in a tool loop) often
// arrives at short, regular gaps; a person browsing arrives irregularly. The
// console shows the shape of the gaps and a few plain statistics. It never
// labels a source as automated: the strip is an observation from the events
// that happen to be loaded, not a verdict.

import { formatDurationMs } from './format.js';

// Gap buckets on a roughly logarithmic scale, in milliseconds (upper bound,
// exclusive). Labels are interface text.
export const GAP_BINS = Object.freeze([
  { max: 1000, label: '< 1 s' },
  { max: 5000, label: '1–5 s' },
  { max: 30000, label: '5–30 s' },
  { max: 120000, label: '30 s–2 min' },
  { max: 600000, label: '2–10 min' },
  { max: 3600000, label: '10–60 min' },
  { max: Infinity, label: '≥ 1 h' },
]);

// Minimum gaps before the statistics are worth printing.
export const MIN_GAPS = 4;

function quantile(sorted, q) {
  if (!sorted.length) return NaN;
  const pos = (sorted.length - 1) * q;
  const lo = Math.floor(pos);
  const hi = Math.ceil(pos);
  return sorted[lo] + (sorted[hi] - sorted[lo]) * (pos - lo);
}

// times: RFC 3339 strings in any order. Unparseable times are skipped and
// counted. Identical timestamps produce zero gaps (common at second
// resolution), which land in the first bin.
export function cadence(times) {
  const ms = [];
  let skipped = 0;
  for (const t of times || []) {
    const v = Date.parse(t);
    if (Number.isFinite(v)) ms.push(v);
    else skipped++;
  }
  ms.sort((a, b) => a - b);
  const gaps = [];
  for (let i = 1; i < ms.length; i++) gaps.push(ms[i] - ms[i - 1]);
  const bins = GAP_BINS.map((b) => ({ label: b.label, count: 0 }));
  for (const g of gaps) bins[GAP_BINS.findIndex((b) => g < b.max)].count++;
  const sorted = [...gaps].sort((a, b) => a - b);
  const enough = gaps.length >= MIN_GAPS;
  const median = enough ? quantile(sorted, 0.5) : NaN;
  const p10 = enough ? quantile(sorted, 0.1) : NaN;
  const p90 = enough ? quantile(sorted, 0.9) : NaN;
  // Share of gaps within ±25% of the median: a simple, explainable
  // regularity measure (no coefficient-of-variation jargon on screen).
  const near = enough && median > 0 ? gaps.filter((g) => Math.abs(g - median) <= median * 0.25).length / gaps.length : NaN;
  const peak = bins.reduce((best, b, i) => (b.count > bins[best].count ? i : best), 0);
  return {
    events: ms.length, skipped, gaps: gaps.length, bins, enough,
    median, p10, p90, nearMedian: near,
    peak: gaps.length ? peak : -1,
    span: ms.length > 1 ? ms[ms.length - 1] - ms[0] : 0,
  };
}

// "850 ms", "4.2 s", "3 min", "1.5 h": the console's one duration style.
export const formatGap = (ms) => formatDurationMs(ms);

// One neutral sentence about the gaps, or null when there are too few.
export function describeCadence(c) {
  if (!c?.enough) return null;
  const share = Math.round(c.nearMedian * 100);
  return `Median gap ${formatGap(c.median)}; 80% of gaps fall between ${formatGap(c.p10)} and ${formatGap(c.p90)}; ${Number.isFinite(share) ? share : 0}% are within a quarter of the median.`;
}
