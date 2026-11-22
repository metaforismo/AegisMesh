// Event-filter helpers for the Events screen: active-filter chips with
// one-click removal, and click-to-filter links built from cell values.
// Pure: they take normalized filters (lib/route.js normalizeEventFilters)
// and return plain data, so the screen only draws.
//
// Values may be attacker-controlled (a source key, a search string). They
// are returned as data with `evidence: true` where they came from evidence,
// so the UI keeps the evidence treatment; links go through href(), which
// percent-encodes every value.

import { href, EVENT_FILTER_KEYS, normalizeEventFilters } from './route.js';
import { classificationMeta, severityLabel } from './taxonomy.js';
import { formatDateTime } from './format.js';

export const FILTER_NAMES = Object.freeze({
  node: 'Origin', classification: 'Class', sensor: 'Sensor', kind: 'Kind', source: 'Source', rule: 'Rule',
  severity: 'Severity', since: 'Since', until: 'Until', q: 'Search',
});

// How a filter value reads on its chip. `evidence` marks values that came
// from attacker-controlled data and must keep the evidence treatment.
export function describeFilter(key, value) {
  switch (key) {
    case 'classification': return { text: classificationMeta(value).label, evidence: false };
    case 'severity': return { text: `${severityLabel(value)} or higher`, evidence: false };
    case 'kind': return { text: String(value).toUpperCase(), evidence: false };
    case 'node': return { text: value === 'local' ? 'This node' : String(value).slice(0, 8), evidence: false, mono: value !== 'local' };
    case 'since':
    case 'until': return { text: formatDateTime(value), evidence: false };
    case 'source': return { text: value, evidence: true };
    case 'q': return { text: value, evidence: true };
    default: return { text: value, evidence: false, mono: true };
  }
}

// One chip per active filter, in the contract's key order. `removeHref`
// keeps every other filter (and live mode when it is on).
export function activeFilterChips(filters, { live = false } = {}) {
  const out = [];
  for (const key of EVENT_FILTER_KEYS) {
    const value = filters?.[key];
    if (!value) continue;
    const rest = { ...filters };
    delete rest[key];
    out.push({ key, name: FILTER_NAMES[key], value, ...describeFilter(key, value), removeHref: href('events', { ...rest, live: live ? '1' : '' }) });
  }
  return out;
}

// Link that adds (or replaces) one filter on top of the current ones. The
// result is normalized like any other URL input, so a value the contract
// would reject (say an over-long source key) yields null and no link.
export function addFilterHref(filters, key, value, { live = false } = {}) {
  if (!EVENT_FILTER_KEYS.includes(key) || value === undefined || value === null || value === '') return null;
  const { filters: clean, rejected } = normalizeEventFilters({ ...filters, [key]: String(value) });
  if (rejected.includes(key) || clean[key] !== String(value)) return null;
  return href('events', { ...clean, live: live ? '1' : '' });
}

// Whether a link would change nothing (the filter is already set).
export function isFilterActive(filters, key, value) {
  return Boolean(filters) && filters[key] === String(value ?? '');
}
