// Client-side table ordering. Pure.
//
// Only tables whose rows are all in the browser sort here (a ranked top-N,
// rules, investigations, fleet nodes, a campaign's sessions). Paged lists
// (events, sessions, audit) keep the server's order: sorting one loaded page
// would misstate the order of the whole list, and the API has no ordering
// parameter for them.

// Missing values (null, undefined, '', NaN) always sort last, in both
// directions, so "unknown" never claims to be the smallest or the largest.
function missing(v) {
  return v === null || v === undefined || v === '' || (typeof v === 'number' && Number.isNaN(v));
}

const collator = new Intl.Collator('en', { numeric: true, sensitivity: 'base' });

export function compareValues(a, b) {
  if (typeof a === 'number' && typeof b === 'number') return a - b;
  if (typeof a === 'boolean' && typeof b === 'boolean') return Number(a) - Number(b);
  return collator.compare(String(a), String(b));
}

// Stable: rows that compare equal keep their incoming (server) order.
export function sortRows(rows, value, dir = 'asc') {
  const sign = dir === 'desc' ? -1 : 1;
  return rows
    .map((row, i) => ({ row, i, v: value(row) }))
    .sort((x, y) => {
      const mx = missing(x.v);
      const my = missing(y.v);
      if (mx || my) return mx === my ? x.i - y.i : mx ? 1 : -1;
      return sign * compareValues(x.v, y.v) || x.i - y.i;
    })
    .map((e) => e.row);
}

// Activating a header: a new column starts in its natural direction
// (numbers and times descending, words ascending); the same column flips.
export function nextSort(current, key, firstDir = 'asc') {
  if (current && current.key === key) return { key, dir: current.dir === 'asc' ? 'desc' : 'asc' };
  return { key, dir: firstDir === 'desc' ? 'desc' : 'asc' };
}

export function ariaSort(current, key) {
  if (!current || current.key !== key) return 'none';
  return current.dir === 'desc' ? 'descending' : 'ascending';
}

// A time string as a number for sorting; unparseable is missing.
export function timeValue(value) {
  const ms = typeof value === 'string' && value ? Date.parse(value) : NaN;
  return Number.isNaN(ms) ? null : ms;
}
