// Command-palette search: scoring and ranking. Pure, so ranking is tested
// directly. Item labels can be API strings (source keys are attacker-
// controlled); they are only compared here, and the UI renders them as text.

const MAX_QUERY = 64;

function isBoundary(text, i) {
  if (i === 0) return true;
  const prev = text[i - 1];
  return /[\s\-_./:@()[\]]/.test(prev) || (/[a-z]/.test(prev) && /[A-Z]/.test(text[i]));
}

// Score how well `query` matches `text`. Higher is better; 0 means no match.
// Order of preference: exact, prefix, word-start substring, substring,
// then an in-order subsequence (fuzzy) that rewards word starts and runs.
// `ranges` are [start, end) index pairs into `text` for highlighting.
export function scoreMatch(query, text) {
  const q = String(query ?? '').trim().slice(0, MAX_QUERY).toLowerCase();
  const raw = String(text ?? '');
  const t = raw.toLowerCase();
  if (!q) return { score: 1, ranges: [] };
  if (!t) return { score: 0, ranges: [] };
  if (t === q) return { score: 1000, ranges: [[0, raw.length]] };
  if (t.startsWith(q)) return { score: 900 - Math.min(100, t.length - q.length), ranges: [[0, q.length]] };

  // Word-start substring beats a mid-word substring.
  let idx = t.indexOf(q);
  let firstAny = idx;
  while (idx > 0) {
    if (isBoundary(raw, idx)) return { score: 700 - Math.min(100, idx), ranges: [[idx, idx + q.length]] };
    idx = t.indexOf(q, idx + 1);
  }
  if (firstAny > 0) return { score: 500 - Math.min(100, firstAny), ranges: [[firstAny, firstAny + q.length]] };

  // Subsequence: every query character in order.
  let score = 0;
  let ti = 0;
  let run = 0;
  const ranges = [];
  for (let qi = 0; qi < q.length; qi++) {
    const c = q[qi];
    if (c === ' ') continue;
    // After a space the next query word should start a word in the text.
    let found = t.indexOf(c, ti);
    if (qi > 0 && q[qi - 1] === ' ') {
      let at = found;
      while (at >= 0 && !isBoundary(raw, at)) at = t.indexOf(c, at + 1);
      if (at >= 0) found = at;
    }
    if (found < 0) return { score: 0, ranges: [] };
    if (found === ti && qi > 0) run++;
    else run = 0;
    score += 10 + run * 6 + (isBoundary(raw, found) ? 12 : 0) - Math.min(8, found - ti);
    const last = ranges[ranges.length - 1];
    if (last && last[1] === found) last[1] = found + 1;
    else ranges.push([found, found + 1]);
    ti = found + 1;
  }
  // Spread-out matches are weak; keep fuzzy hits below every substring hit.
  return { score: Math.max(1, Math.min(399, score - ranges.length * 4)), ranges };
}

// Rank items for a query. Each item has `label` and optional `keywords`
// (extra searchable strings, never shown) and `weight` (tie-break bonus,
// e.g. screens above data). Stable: equal scores keep input order.
export function rankItems(items, query, { limit = 50 } = {}) {
  const q = String(query ?? '').trim();
  const out = [];
  items.forEach((item, order) => {
    let best = scoreMatch(q, item.label);
    for (const k of item.keywords || []) {
      const s = scoreMatch(q, k);
      // A keyword hit ranks the item but highlights nothing in the label.
      if (s.score > best.score) best = { score: s.score - 1, ranges: [] };
    }
    if (best.score <= 0) return;
    out.push({ item, score: best.score + (item.weight || 0), ranges: best.ranges, order });
  });
  out.sort((a, b) => b.score - a.score || a.order - b.order);
  return out.slice(0, limit);
}

// Split text into [{ text, hit }] runs from match ranges, for rendering
// highlighted labels as plain Text nodes (no markup is ever parsed).
export function highlightRuns(text, ranges) {
  const s = String(text ?? '');
  const runs = [];
  let at = 0;
  for (const [a, b] of [...(ranges || [])].sort((x, y) => x[0] - y[0])) {
    const start = Math.max(at, Math.min(s.length, a));
    const end = Math.max(start, Math.min(s.length, b));
    if (start > at) runs.push({ text: s.slice(at, start), hit: false });
    if (end > start) runs.push({ text: s.slice(start, end), hit: true });
    at = end;
  }
  if (at < s.length) runs.push({ text: s.slice(at), hit: false });
  return runs;
}
