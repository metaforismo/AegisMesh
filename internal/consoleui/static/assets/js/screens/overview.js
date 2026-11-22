import { h, mount } from '../lib/dom.js';
import { href, normalizeWindow } from '../lib/route.js';
import { CLASSIFICATIONS, classificationMeta } from '../lib/taxonomy.js';
import { formatCount, formatDelta } from '../lib/format.js';
import { seriesOf, bucketTrace, indexKnownFrom, BY_SENSOR_CAP } from '../lib/chart.js';
import { pageHead, panel, stat, segmented, glyph, sevChip, evidence, barList, table, timeEl, empty, link, sparkline, helpTip } from '../ui/components.js';
import { stackedBarChart, severityShare, activityTrace, SEVERITY_ORDER } from '../ui/charts.js';
import { icon } from '../ui/icons.js';
import { rankByNode, describeOrigin } from '../lib/origin.js';
import { historyBanner, eventHref, forwardedNote } from './shared.js';
import { buildBrief } from '../lib/brief.js';
import { glossaryEntry } from '../lib/glossary.js';

const tip = (id) => helpTip(glossaryEntry(id));
const titled = (text, id) => h('span', { class: 'title-help' }, text, tip(id));

function routeHref(r) {
  if (!r) return null;
  return r.params ? href(r.name, ...r.params, r.query || {}) : href(r.name, r.query || {});
}

function clauseNode(c) {
  const parts = c.segments.map((s) => {
    if (s.t === 'num') return h('strong', { class: 'brief__num' }, s.v);
    if (s.t === 'ev') return evidence(s.v, { max: 48 });
    if (s.t === 'code') return h('code', null, s.v);
    return s.v;
  });
  const r = routeHref(c.route);
  return r ? h('a', { class: ['brief__clause', `brief__clause--${c.id}`], href: r }, parts) : h('span', { class: 'brief__clause' }, parts);
}

// What to do when the index holds nothing yet. Commands are the CLI's own
// (docs/cli.md); nothing here claims the sensors are misconfigured.
function firstRun() {
  const step = (title, text, cmd) => h('li', { class: 'firstrun__step' },
    h('p', { class: 'firstrun__title' }, title), h('p', { class: 'muted' }, text), cmd ? h('code', { class: 'firstrun__cmd' }, cmd) : null);
  return h('div', { class: 'firstrun' },
    h('p', { class: 'firstrun__lead' }, 'Nothing has touched a decoy in this window, or the index is still empty. Decoys have no legitimate users, so a quiet console is a normal state. If you expected traffic:'),
    h('ol', { class: 'firstrun__steps' },
      step('Check the runtime', 'Validates the config, the data directory and that the sensor ports are free or bound.', 'aegismesh doctor --config mesh.yaml'),
      step('Check the listeners', 'Binds every sensor once and prints its address, without recording anything.', 'aegismesh run --config mesh.yaml --dry-run'),
      step('See the console with synthetic evidence', 'Runs a self-contained scenario on loopback and prints a console URL and a one-time token.', 'aegismesh demo --console')),
    h('p', { class: 'muted' }, 'Wider windows may hold older events: try ', h('a', { href: href('overview', { window: '7d' }) }, 'the last 7 days'), '. ', h('a', { href: '#/guide' }, 'Read the guide'), ' for what each screen shows.'));
}

function briefPanel(ov, window, windowText, empty) {
  const clauses = buildBrief(ov, window);
  return h('section', { class: 'brief', 'aria-labelledby': 'brief-title' },
    h('div', { class: 'brief__head' },
      h('h2', { class: 'brief__eyebrow', id: 'brief-title' }, h('span', { class: 'brief__dot', 'aria-hidden': 'true' }), 'Situation'),
      h('p', { class: 'brief__meta' }, `${windowText} · generated `, timeEl(ov.generated_at))),
    h('p', { class: 'brief__text' }, clauses.flatMap((c, i) => (i ? [' ', clauseNode(c)] : [clauseNode(c)]))),
    empty ? firstRun() : h('p', { class: 'brief__foot' },
      'Computed in your browser from this overview only. Events are observations, not incidents. ',
      h('a', { href: '#/guide?t=classification' }, 'What do the classes mean?')));
}

const WINDOW_LABELS = [['1h', 'Last hour'], ['24h', 'Last 24 hours'], ['7d', 'Last 7 days']];
const WINDOW_MS = { '1h': 3600e3, '24h': 86400e3, '7d': 7 * 86400e3 };

// Start of the overview window, so a drill-down lists the same events the
// count was made from.
function windowStart(generatedAt, window) {
  const end = Date.parse(generatedAt);
  if (!Number.isFinite(end)) return '';
  return new Date(end - WINDOW_MS[window]).toISOString().replace('.000Z', 'Z');
}

// Present only on a hub that accepts forwarded evidence. Ranked here: the
// API sends the rows sorted by id.
function byNodePanel(byNode, window, generatedAt) {
  const rows = rankByNode(byNode);
  const since = windowStart(generatedAt, window);
  return panel({
    title: 'By node', meta: 'Where this window’s events were observed: this node, or an enrolled node that forwarded them',
    actions: link(href('fleet'), 'Fleet'),
    body: rows.length
      ? barList(rows.map((r) => {
        const o = describeOrigin(r);
        return {
          label: o.local
            ? h('span', { class: 'origin origin--local' }, 'This node')
            : h('span', { class: 'origin' }, h('code', null, o.name), o.short ? h('span', { class: ['muted', 'origin__id'] }, o.short) : null),
          value: r.events, valueText: formatCount(r.events),
          href: href('events', { node: r.id, since }),
        };
      }))
      : empty('No events in this window', 'Neither this node nor any forwarding node stored an event in this window.'),
  });
}

// A small activity trace per sensor from by_sensor[].buckets (same starts as
// the main chart). Older servers send no per-sensor buckets: no trace then.
function sensorTrace(row, knownFrom) {
  if (!Array.isArray(row?.buckets)) return null;
  const tr = bucketTrace(row.buckets);
  return tr ? activityTrace(tr.bins, { start: tr.start, end: tr.end, knownFrom, height: 20 }) : null;
}

function sensorsMeta(rows) {
  if (!rows.some((r) => Array.isArray(r?.buckets))) return null;
  return rows.length >= BY_SENSOR_CAP ? `Activity over the window; the ${BY_SENSOR_CAP} sensors seen most recently` : 'Activity over the window';
}

export default {
  title: 'Overview',
  async render(root, ctx) {
    const window = normalizeWindow(ctx.route.query.window);
    const [ov, node] = await Promise.all([
      ctx.api.overview(window, { signal: ctx.signal }),
      ctx.api.node({ signal: ctx.signal }).catch(() => null),
    ]);
    const t = ov.totals || {};
    const p = ov.previous_totals || {};
    const windowText = WINDOW_LABELS.find(([w]) => w === window)[1].toLowerCase();

    const buckets = Array.isArray(ov.buckets) ? ov.buckets : [];
    // Sparklines come from the same buckets as the chart. Sources and active
    // sensors have no per-bucket series in the API, so they get none.
    const trend = (key) => (buckets.length > 1 ? sparkline(seriesOf(buckets, key), { series: key || '' }) : null);
    const tiles = h('div', { class: 'grid grid--stats' },
      stat({ label: 'Events', value: formatCount(t.events), delta: formatDelta(t.events, p.events), spark: trend('') }),
      ...CLASSIFICATIONS.map((c) => stat({
        label: classificationMeta(c).label, icon: glyph(c),
        value: formatCount(t[c]), delta: formatDelta(t[c], p[c]), spark: trend(c),
      })),
      stat({ label: 'Distinct sources', value: formatCount(t.sources), delta: formatDelta(t.sources, p.sources) }),
      stat({ label: 'Sensors with events', value: formatCount(t.sensors_active), note: 'This window only' }));

    const sev = ov.by_severity || {};
    // "No finding" links to nothing: the minimum-severity filter cannot select it.
    const sevItems = [...SEVERITY_ORDER.map((s) => ({ key: s, value: sev[s], href: href('events', { severity: s }) })), { key: 'none', value: sev.none }];

    const rules = Array.isArray(ov.top_rules) ? ov.top_rules : [];
    const sources = Array.isArray(ov.top_sources) ? ov.top_sources : [];
    const signals = Array.isArray(ov.recent_signals) ? ov.recent_signals : [];
    const sensors = Array.isArray(ov.by_sensor) ? ov.by_sensor : [];
    const hasByNode = Array.isArray(ov.by_node);
    const knownFrom = indexKnownFrom(node);

    const isEmpty = Number(t.events) === 0 && ov.totals && typeof t.events === 'number';
    mount(root,
      pageHead({
        title: 'Overview',
        subtitle: `What the decoy sensors observed in the ${windowText}, compared with the window before it.`,
        actions: segmented({ label: 'Time window', options: WINDOW_LABELS.map(([w]) => [w, w]), value: window, onChange: (w) => ctx.navigate(href('overview', { window: w })) }),
      }),
      historyBanner(node, { accepting: hasByNode }),
      hasByNode ? forwardedNote('counts') : null,
      briefPanel(ov, window, WINDOW_LABELS.find(([w]) => w === window)[1], isEmpty),
      tiles,
      panel({
        primary: true,
        title: 'Observations over time', meta: `Stacked by classification · ${buckets.length} buckets · times in UTC`,
        body: buckets.length
          ? stackedBarChart(buckets, window, { end: ov.generated_at, onSelect: (range) => ctx.navigate(href('events', range)) })
          : empty('No buckets', 'The server returned no time buckets for this window.'),
      }),
      h('div', { class: 'grid grid--2' },
        panel({ title: titled('By severity', 'severity'), meta: 'Highest finding per event; most events carry no finding', body: severityShare(sevItems) }),
        panel({
          title: titled('Top rules', 'finding'), meta: 'Rules cited by the most events',
          body: rules.length
            ? barList(rules.map((r) => ({ label: h('span', { class: 'btn-row' }, h('code', null, r.rule_id), r.severity ? sevChip(r.severity) : null), value: r.events, valueText: formatCount(r.events), href: href('events', { rule: r.rule_id }) })))
            : empty('No rule matched', 'No event in this window cited a detection or correlation rule.'),
        })),
      h('div', { class: 'grid grid--2' },
        panel({
          title: titled('Top sources', 'source'), meta: 'Remote hosts or correlation keys, ranked by events', flush: true,
          actions: link(href('sources', { window }), 'All sources'),
          body: sources.length ? table({
            caption: 'Top sources',
            columns: [
              { label: 'Source', cell: (s) => link(href('sources', s.source), evidence(s.source, { max: 40 })) },
              { label: 'Events', num: true, cell: (s) => formatCount(s.events) },
              { label: 'Max severity', cell: (s) => sevChip(s.max_severity) },
              { label: 'Last seen', cell: (s) => timeEl(s.last_seen, { relative: true }) },
            ],
            rows: sources,
          }) : empty('No sources', 'Nothing was observed in this window.'),
        }),
        panel({
          title: titled('Recent correlation signals', 'correlation'), meta: 'Up to 10, newest first',
          actions: link(href('events', { classification: 'correlation_signal' }), 'All signals'),
          body: signals.length ? h('ol', { class: 'timeline' }, signals.map((s) => h('li', { class: 'timeline__item' },
            glyph('correlation_signal'),
            h('p', { class: 'timeline__time' }, timeEl(s.time)),
            h('div', { class: 'timeline__body' },
              link(eventHref(s), evidence(s.summary, { max: 90 })),
              sevChip(s.severity))))) : empty('No signals', 'No correlation rule fired in this window.'),
        })),
      hasByNode ? byNodePanel(ov.by_node, window, ov.generated_at) : null,
      h('div', { class: 'grid grid--2' },
        panel({
          title: 'Events by sensor', flush: false,
          meta: sensorsMeta(sensors),
          body: sensors.length ? barList(sensors.map((s) => ({
            label: h('span', { class: 'btn-row' }, h('code', null, s.sensor_id), h('span', { class: 'chip' }, s.kind)),
            value: s.events, valueText: formatCount(s.events), href: href('events', { sensor: s.sensor_id }),
            aside: sensorTrace(s, knownFrom),
          }))) : empty('No sensor events', 'No sensor stored an event in this window.'),
        }),
        panel({
          title: 'Investigations',
          body: h('div', { class: 'inv-summary' },
            h('p', { class: 'inv-summary__value' }, formatCount(ov.open_investigations)),
            h('p', { class: 'muted' }, Number(ov.open_investigations) === 1 ? 'open investigation' : 'open investigations'),
            h('a', { class: ['btn', 'btn--sm'], href: href('investigations', { status: 'open' }) }, 'Review open investigations', icon('chevron-right', { size: 'sm' }))),
        })),
      h('p', { class: 'page-note' }, icon('info', { size: 'sm' }),
        h('span', null, 'Counts come from the console’s bounded in-memory index, not from all evidence ever stored. Use ', h('code', null, 'aegismesh inspect'), ' for older evidence.'),
        tip('index')),
    );
  },
};
