// The Overview's situation brief: a few plain sentences built only from the
// overview response the console loaded. Pure, so every clause is tested.
//
// Rules the brief follows:
// - It never invents a number. A field the server did not send produces a
//   sentence saying so, not a zero.
// - Changes are worded neutrally ("more than", "fewer than"): more
//   observations are not "worse".
// - Source keys stay evidence: a segment of type 'ev' is rendered as a Text
//   node with the evidence treatment, never as interface text.
// - Every clause that names something carries the route that shows it.
//
// Output: [{ id, segments: [{ t: 'text'|'num'|'ev'|'code', v }], route }]
// where route is { name, params?, query } for lib/route.js href(), or null.

import { isSeverity, severityLabel, SEVERITIES } from './taxonomy.js';
import { formatCount } from './format.js';

const WINDOW_TEXT = { '1h': 'the last hour', '24h': 'the last 24 hours', '7d': 'the last 7 days' };
const WINDOW_MS = { '1h': 3600e3, '24h': 86400e3, '7d': 7 * 86400e3 };

const count = (n) => formatCount(n);
const isCount = (v) => typeof v === 'number' && Number.isFinite(v) && v >= 0;
const plural = (n, one, many) => (n === 1 ? one : many);

const t = (v) => ({ t: 'text', v });
const num = (v) => ({ t: 'num', v: count(v) });

// RFC 3339 start of the overview window, so a drill-down lists the events
// the brief counted. '' when generated_at is unusable.
export function briefWindowStart(generatedAt, window) {
  const end = Date.parse(generatedAt);
  if (!Number.isFinite(end) || !WINDOW_MS[window]) return '';
  return new Date(end - WINDOW_MS[window]).toISOString().replace('.000Z', 'Z');
}

function volume(ov, window, since) {
  const cur = ov?.totals?.events;
  const prev = ov?.previous_totals?.events;
  const when = WINDOW_TEXT[window] || 'this window';
  if (!isCount(cur)) return { id: 'volume', segments: [t(`The server did not report an event count for ${when}.`)], route: null };
  const segs = cur === 0
    ? [t(`No events in ${when}`)]
    : [num(cur), t(` ${plural(cur, 'event', 'events')} in ${when}`)];
  if (isCount(prev)) {
    const diff = cur - prev;
    if (cur === 0 && prev === 0) segs.push(t(', and none in the window before.'));
    else if (diff === 0) segs.push(t(', the same as the window before.'));
    else if (prev === 0) segs.push(t(', none in the window before.'));
    else {
      const pct = Math.round((Math.abs(diff) / prev) * 100);
      segs.push(t(', '), num(Math.abs(diff)), t(` ${diff > 0 ? 'more' : 'fewer'} than the window before (${diff > 0 ? '+' : '−'}${pct}%).`));
    }
  } else {
    segs.push(t('. The previous window was not reported.'));
  }
  if (cur > 0 && !String(segs[segs.length - 1].v).endsWith('.')) segs.push(t('.'));
  return { id: 'volume', segments: segs, route: cur > 0 ? { name: 'events', query: { since } } : null };
}

function classClause(ov, key, one, many, since) {
  const n = ov?.totals?.[key];
  if (!isCount(n) || n === 0) return null;
  return {
    id: key,
    segments: [num(n), t(` ${plural(n, one, many)}.`)],
    route: { name: 'events', query: { classification: key, since } },
  };
}

function topSource(ov) {
  const rows = Array.isArray(ov?.top_sources) ? ov.top_sources : null;
  if (!rows) return null;
  const top = rows.find((s) => typeof s?.source === 'string' && s.source !== '' && isCount(s.events) && s.events > 0);
  if (!top) return null;
  const total = ov?.totals?.events;
  const segs = [t('Most active source: '), { t: 'ev', v: top.source }, t(', '), num(top.events), t(` ${plural(top.events, 'event', 'events')}`)];
  if (isCount(total) && total >= top.events && total > 0) segs.push(t(` (${Math.round((top.events / total) * 100)}% of the window)`));
  const sensors = Array.isArray(top.sensors) ? top.sensors.length : 0;
  if (sensors > 1) segs.push(t(` across ${count(sensors)} sensors`));
  segs.push(t('.'));
  return { id: 'source', segments: segs, route: { name: 'source', params: [top.source], query: {} } };
}

function topRule(ov, since) {
  const rows = Array.isArray(ov?.top_rules) ? ov.top_rules : null;
  if (!rows) return null;
  const top = rows.find((r) => typeof r?.rule_id === 'string' && r.rule_id !== '' && isCount(r.events) && r.events > 0);
  if (!top) return null;
  const segs = [t('Most cited rule: '), { t: 'code', v: top.rule_id }];
  // The catalog title (static rule prose, not evidence), when the server sends it.
  if (typeof top.title === 'string' && top.title.trim()) segs.push(t(`, “${top.title.trim().slice(0, 120)}”`));
  if (isSeverity(top.severity)) segs.push(t(` (${severityLabel(top.severity)})`));
  segs.push(t(', cited by '), num(top.events), t(` ${plural(top.events, 'event', 'events')}.`));
  return { id: 'rule', segments: segs, route: { name: 'events', query: { rule: top.rule_id, since } } };
}

// The highest severity with at least one event. The minimum-severity filter
// matches "this or higher", which equals "exactly this" at the top.
function topSeverity(ov, since) {
  const by = ov?.by_severity;
  if (!by || typeof by !== 'object') return null;
  for (const s of [...SEVERITIES].reverse()) {
    const n = by[s];
    if (isCount(n) && n > 0) {
      return {
        id: 'severity',
        segments: [t('Highest finding: '), t(severityLabel(s).toLowerCase()), t(', on '), num(n), t(` ${plural(n, 'event', 'events')}.`)],
        route: { name: 'events', query: { severity: s, since } },
        severity: s,
      };
    }
  }
  return null;
}

function investigations(ov) {
  const n = ov?.open_investigations;
  if (!isCount(n) || n === 0) return null;
  return {
    id: 'investigations',
    segments: [num(n), t(` open ${plural(n, 'investigation', 'investigations')}.`)],
    route: { name: 'investigations', query: { status: 'open' } },
  };
}

// Sessions consistent with automation, from GET /sessions for the same
// window. `sessions` is that response or null (endpoint absent or failed):
// then the clause is simply left out.
function automationClause(res, window) {
  const list = Array.isArray(res?.sessions) ? res.sessions : null;
  if (!list) return null;
  const n = list.filter((s) => s?.automation?.assessment === 'consistent_with_automation').length;
  if (!n) return null;
  const more = Boolean(res.next_cursor);
  return {
    id: 'automation',
    segments: [t(more ? 'At least ' : ''), num(n), t(` ${plural(n, 'session', 'sessions')} with pace or rules consistent with automation (an observation, not a verdict).`)],
    route: { name: 'sessions', query: { window } },
  };
}

export function buildBrief(ov, window, { sessions = null } = {}) {
  const since = briefWindowStart(ov?.generated_at, window);
  const out = [volume(ov, window, since)];
  if (!isCount(ov?.totals?.events) || ov.totals.events === 0) {
    const inv = investigations(ov);
    return inv ? [...out, inv] : out;
  }
  out.push(
    classClause(ov, 'canary_invocation', 'canary invocation', 'canary invocations', since),
    classClause(ov, 'correlation_signal', 'correlation signal', 'correlation signals', since),
    topSeverity(ov, since),
    topSource(ov),
    topRule(ov, since),
    automationClause(sessions, window),
    investigations(ov),
  );
  return out.filter(Boolean);
}

// Which empty state the Overview shows, from the window totals and the
// overview's `index` occupancy: 'empty' (nothing indexed yet: first run),
// 'quiet' (the index holds events, none in this window), 'unknown' (no
// events in the window and the server did not report occupancy), or null
// (the window has events).
export function emptyKind(ov) {
  const n = ov?.totals?.events;
  if (!isCount(n) || n > 0) return null;
  const idx = ov?.index?.events;
  if (!isCount(idx)) return 'unknown';
  return idx === 0 ? 'empty' : 'quiet';
}

// Plain text of a brief, for tests and for the document's accessible name.
export function briefText(clauses) {
  return clauses.map((c) => c.segments.map((s) => s.v).join('')).join(' ');
}
