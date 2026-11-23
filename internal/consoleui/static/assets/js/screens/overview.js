import { h, mount, svg } from '../lib/dom.js';
import { meshLayout, lastBucketActive } from '../lib/viz.js';
import { href, normalizeWindow } from '../lib/route.js';
import { CLASSIFICATIONS, classificationMeta } from '../lib/taxonomy.js';
import { formatCount, formatDelta, zoneName } from '../lib/format.js';
import { bucketTrace, indexKnownFrom, BY_SENSOR_CAP } from '../lib/chart.js';
import { pageHead, panel, tally, segmented, glyph, sevChip, evidence, barList, table, timeEl, empty, link, helpTip } from '../ui/components.js';
import { stackedBarChart, severityShare, activityTrace, SEVERITY_ORDER } from '../ui/charts.js';
import { icon } from '../ui/icons.js';
import { rankByNode, describeOrigin } from '../lib/origin.js';
import { historyBanner, eventHref, forwardedNote } from './shared.js';
import { buildBrief, emptyKind } from '../lib/brief.js';
import { glossaryEntry } from '../lib/glossary.js';
import { postureCounts, postureLine, plural } from '../lib/insight.js';

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
// `kind` comes from emptyKind(): the overview's index occupancy tells a
// first run (nothing indexed yet) from a quiet window.
function firstRun(kind, ov) {
  const step = (title, text, cmd) => h('li', { class: 'firstrun__step' },
    h('p', { class: 'firstrun__title' }, title), h('p', { class: 'muted' }, text), cmd ? h('code', { class: 'firstrun__cmd' }, cmd) : null);
  if (kind === 'quiet') {
    return h('div', { class: 'firstrun' },
      h('p', { class: 'firstrun__lead' }, `A quiet window. The index holds ${formatCount(ov?.index?.events)} earlier event${ov?.index?.events === 1 ? '' : 's'}, none in this one. Decoys have no legitimate users, so a quiet window is a normal state.`),
      h('p', { class: 'muted' }, 'Wider windows hold the earlier events: try ', h('a', { href: href('overview', { window: '7d' }) }, 'the last 7 days'), ', ', h('a', { href: href('digest', { window: '7d' }) }, 'the 7-day digest'), ' or ', h('a', { href: href('events') }, 'every indexed event'), '.'));
  }
  const lead = kind === 'empty'
    ? 'Nothing indexed yet: no decoy has recorded an event since the console’s index started. Decoys have no legitimate users, so a quiet console is a normal state. If you expected traffic:'
    : 'Nothing has touched a decoy in this window, or the index is still empty. Decoys have no legitimate users, so a quiet console is a normal state. If you expected traffic:';
  return h('div', { class: 'firstrun' },
    h('p', { class: 'firstrun__lead' }, lead),
    h('ol', { class: 'firstrun__steps' },
      step('Check the runtime', 'Validates the config, the data directory and that the sensor ports are free or bound.', 'aegismesh doctor --config mesh.yaml'),
      step('Check the listeners', 'Binds every sensor once and prints its address, without recording anything.', 'aegismesh run --config mesh.yaml --dry-run'),
      step('See the console with synthetic evidence', 'Runs a self-contained scenario on loopback and prints a console URL and a one-time token.', 'aegismesh demo --console')),
    kind === 'empty'
      ? h('p', { class: 'muted' }, 'See what is deployed on ', h('a', { href: href('decoys') }, 'Decoys'), '. ', h('a', { href: '#/guide' }, 'Read the guide'), ' for what each screen shows.')
      : h('p', { class: 'muted' }, 'Wider windows may hold older events: try ', h('a', { href: href('overview', { window: '7d' }) }, 'the last 7 days'), '. ', h('a', { href: '#/guide' }, 'Read the guide'), ' for what each screen shows.'));
}

function briefPanel(ov, window, windowText, kind, sessions) {
  const clauses = buildBrief(ov, window, { sessions });
  return h('section', { class: 'brief', 'aria-labelledby': 'brief-title' },
    h('div', { class: 'brief__head' },
      h('h2', { class: 'brief__eyebrow', id: 'brief-title' }, h('span', { class: 'brief__dot', 'aria-hidden': 'true' }), 'Situation'),
      h('p', { class: 'brief__meta' }, `${windowText} · generated `, timeEl(ov.generated_at)),
      h('a', { class: 'brief__digest', href: href('digest', { window: window === '7d' ? '7d' : '24h' }) }, icon('digest', { size: 'sm' }), window === '7d' ? 'Read the 7-day digest' : 'Read the 24-hour digest')),
    h('p', { class: 'brief__text' }, clauses.flatMap((c, i) => (i ? [' ', clauseNode(c)] : [clauseNode(c)]))),
    kind ? firstRun(kind, ov) : h('p', { class: 'brief__foot' },
      'Computed in your browser from this overview only. Events are observations, not incidents. ',
      h('a', { href: '#/guide?t=classification' }, 'What do the classes mean?')));
}

// Overview lists are capped so paired panels end level; each links to the
// full list.
const RULES_SHOWN = 5;
const SIGNALS_SHOWN = 7;

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

// The sensor mesh: sensors as nodes around the console core, from
// overview.by_sensor. Node size follows events in the window; a ring
// pulses only for sensors with events in the newest bucket (when the API
// sends per-sensor buckets). Every node is a link with its name and count.
function meshPanel(rows, windowText) {
  const list = rows.slice(0, 12).map((r) => ({ id: String(r.sensor_id || ''), kind: String(r.kind || ''), events: r.events, active: lastBucketActive(r.buckets) }));
  if (!list.length) return panel({ title: 'Sensor mesh', body: empty('No sensor events', 'No sensor stored an event in this window.', null, { art: true }) });
  const W = 320;
  const H = 228;
  const nodes = meshLayout(list, { cx: W / 2, cy: H / 2, ring: 76 });
  const hasBuckets = list.some((n) => n.active !== null);
  const plot = svg('svg', { class: 'mesh', viewBox: `0 0 ${W} ${H}`, role: 'group', 'aria-label': `Sensors with events in the ${windowText}` },
    nodes.map((n) => svg('line', { class: ['mesh__edge', n.active ? 'mesh__edge--active' : ''], x1: W / 2, y1: H / 2, x2: n.x, y2: n.y })),
    svg('circle', { class: 'mesh__core-ring', cx: W / 2, cy: H / 2, r: 14 }),
    svg('circle', { class: 'mesh__core', cx: W / 2, cy: H / 2, r: 6 }),
    nodes.map((n) => {
      const label = `${n.id}: ${formatCount(n.events)} events${n.active === true ? ', active in the newest bucket' : n.active === false ? ', quiet in the newest bucket' : ''}`;
      return svg('a', { href: href('events', { sensor: n.id }), 'aria-label': label },
        n.active ? svg('circle', { class: 'mesh__pulse', cx: n.x, cy: n.y, r: n.r }) : null,
        svg('circle', { class: ['mesh__node', n.active ? 'mesh__node--active' : '', n.active === false ? 'mesh__node--quiet' : ''], cx: n.x, cy: n.y, r: n.r }),
        svg('text', { class: 'mesh__label', x: n.lx, y: n.ly - 2, 'text-anchor': n.anchor }, n.id),
        svg('text', { class: 'mesh__count', x: n.lx, y: n.ly + 10, 'text-anchor': n.anchor }, formatCount(n.events)));
    }));
  return panel({
    title: 'Sensor mesh',
    meta: rows.length > 12 ? `The 12 sensors with events in the ${windowText}; node area follows events` : `Every sensor with events in the ${windowText}; node area follows events`,
    body: h('div', { class: 'mesh-wrap' }, plot,
      hasBuckets ? h('ul', { class: 'mesh-legend' },
        h('li', { class: 'mesh-legend__item' }, h('span', { class: ['mesh-legend__swatch', 'mesh-legend__swatch--active'] }), 'Events in the newest bucket (ring)'),
        h('li', { class: 'mesh-legend__item' }, h('span', { class: ['mesh-legend__swatch', 'mesh-legend__swatch--quiet'] }), 'None in the newest bucket (dashed)')) : null),
  });
}

export default {
  title: 'Overview',
  async render(root, ctx) {
    const window = normalizeWindow(ctx.route.query.window);
    const [ov, node, sessions, posture, campaigns] = await Promise.all([
      ctx.api.overview(window, { signal: ctx.signal }),
      ctx.api.node({ signal: ctx.signal }).catch(() => null),
      // Optional: the brief mentions sessions only when the endpoint answers.
      ctx.api.sessions ? ctx.api.sessions(window, '', '', 200, { signal: ctx.signal }).catch(() => null) : null,
      // Optional (round 4): older servers answer 404 and the Overview simply
      // leaves the posture line and the campaigns tile out.
      ctx.api.posture ? ctx.api.posture({ signal: ctx.signal }).catch(() => null) : null,
      ctx.api.campaigns ? ctx.api.campaigns({ signal: ctx.signal }).catch(() => null) : null,
    ]);
    const pc = posture && Array.isArray(posture.checks) ? postureCounts(posture) : null;
    const campaignItems = campaigns && Array.isArray(campaigns.items) ? campaigns.items : null;
    const t = ov.totals || {};
    const p = ov.previous_totals || {};
    const windowText = WINDOW_LABELS.find(([w]) => w === window)[1].toLowerCase();

    const buckets = Array.isArray(ov.buckets) ? ov.buckets : [];
    // The counts sit beside the brief they summarise: one divided list, the
    // total leading. No sparklines: the chart below draws the trend once.
    const baseline = `against the ${windowText.replace(/^last /, '')} before`;
    const counts = panel({
      title: 'Counts', meta: `The ${windowText}, ${baseline}`,
      body: tally([
        { lead: true, label: 'Events', value: formatCount(t.events), delta: formatDelta(t.events, p.events) },
        ...CLASSIFICATIONS.map((c) => ({ label: classificationMeta(c).label, icon: glyph(c), value: formatCount(t[c]), delta: formatDelta(t[c], p[c]) })),
        { label: 'Distinct sources', value: formatCount(t.sources), delta: formatDelta(t.sources, p.sources) },
        { label: 'Sensors with events', value: formatCount(t.sensors_active), note: 'This window only' },
      ], { baseline: `vs the ${windowText.replace(/^last /, '')} before` }),
    });

    const sev = ov.by_severity || {};
    // "No finding" links to nothing: the minimum-severity filter cannot select it.
    const sevItems = [...SEVERITY_ORDER.map((s) => ({ key: s, value: sev[s], href: href('events', { severity: s }) })), { key: 'none', value: sev.none }];

    const rules = Array.isArray(ov.top_rules) ? ov.top_rules : [];
    const sources = Array.isArray(ov.top_sources) ? ov.top_sources : [];
    const signals = Array.isArray(ov.recent_signals) ? ov.recent_signals : [];
    const sensors = Array.isArray(ov.by_sensor) ? ov.by_sensor : [];
    const hasByNode = Array.isArray(ov.by_node);
    const knownFrom = indexKnownFrom(node);

    const quietKind = emptyKind(ov);
    // What to read next: one divided block, each cell a count, what it
    // counts and the one action it leads to.
    const nextCell = (title, value, text, to, action) => h('section', { class: 'next__cell' },
      h('h2', { class: 'next__title' }, title),
      h('p', { class: 'next__value' }, value),
      h('p', { class: 'next__text' }, text),
      h('a', { class: ['btn', 'btn--sm', 'next__go'], href: to }, action, icon('chevron-right', { size: 'sm' })));
    const nextRow = h('div', { class: ['next', campaignItems ? 'next--3' : 'next--2'] },
      nextCell('Investigations', formatCount(ov.open_investigations),
        Number(ov.open_investigations) === 1 ? 'open investigation' : 'open investigations',
        href('investigations', { status: 'open' }), 'Review open investigations'),
      nextCell(titled('Sessions', 'session'), sessions ? formatCount(Number(sessions.total_matched) || 0) : '—',
        sessions ? 'sessions overlapping this window' : 'The sessions view did not answer.',
        href('sessions', { window }), 'Read the sessions'),
      campaignItems ? nextCell(titled('Campaigns', 'campaign'), formatCount(campaignItems.length),
        campaignItems.length
          ? `playbooks seen from more than one source, ${plural(new Set(campaignItems.flatMap((c) => (Array.isArray(c?.sources) ? c.sources : []))).size, 'source')} in all (indexed events, not this window)`
          : 'No two sources followed the same steps in the indexed events.',
        href('campaigns'), 'Compare campaigns') : null);
    mount(root,
      pageHead({
        title: 'Overview',
        subtitle: `What the decoy sensors observed in the ${windowText}, compared with the window before it.`,
        hint: 'Read the situation, then follow any clause, bar or node to the events behind it.',
        actions: segmented({ label: 'Time window', options: WINDOW_LABELS.map(([w]) => [w, w]), value: window, onChange: (w) => ctx.navigate(href('overview', { window: w })) }),
      }),
      historyBanner(node, { accepting: hasByNode }),
      hasByNode ? forwardedNote('counts') : null,
      // The screen's question, answered first and largest: the brief, with
      // the counts it summarises beside it.
      h('div', { class: 'lead-row' },
        briefPanel(ov, window, WINDOW_LABELS.find(([w]) => w === window)[1], quietKind, sessions),
        counts),
      // One quiet line, never an alarm: the count links to the review.
      pc ? h('a', { class: ['quiet-line', pc.attention ? 'quiet-line--attention' : ''], href: href('posture', pc.attention ? { show: 'attention' } : {}) },
        icon('posture', { size: 'sm' }), h('span', null, postureLine(pc)), h('span', { class: 'quiet-line__go' }, pc.attention ? 'Review' : 'Open the review', icon('chevron-right', { size: 'xs' }))) : null,
      panel({
        primary: true,
        title: 'Observations over time', meta: `Stacked by classification · ${buckets.length} buckets · times in ${zoneName()}`,
        body: buckets.length
          ? stackedBarChart(buckets, window, { end: ov.generated_at, onSelect: (range) => ctx.navigate(href('events', range)) })
          : empty('No buckets', 'The server returned no time buckets for this window.'),
      }),
      nextRow,
      h('div', { class: 'grid grid--pair' },
        panel({ title: titled('By severity', 'severity'), meta: 'Highest finding per event; most events carry no finding', body: severityShare(sevItems) }),
        panel({
          title: titled('Top rules', 'finding'), meta: rules.length > RULES_SHOWN ? `The ${RULES_SHOWN} rules cited by the most events` : 'Rules cited by the most events',
          actions: link(href('rules'), 'All rules'),
          body: rules.length
            ? barList(rules.slice(0, RULES_SHOWN).map((r) => ({
              label: h('span', { class: 'rule-label' }, h('code', null, r.rule_id),
                typeof r.title === 'string' && r.title ? h('span', { class: 'rule-label__title', title: r.title }, r.title) : null,
                r.severity ? sevChip(r.severity) : null),
              value: r.events, valueText: formatCount(r.events), href: href('events', { rule: r.rule_id }),
            })))
            : empty('No rule matched', 'No event in this window cited a detection or correlation rule.'),
        })),
      h('div', { class: 'grid grid--pair' },
        panel({
          title: titled('Top sources', 'source'), meta: 'Remote hosts or correlation keys, ranked by events', flush: true,
          actions: link(href('sources', { window }), 'All sources'),
          body: sources.length ? h('div', { class: 'overview-sources' }, table({
            caption: 'Top sources',
            columns: [
              { label: 'Source', cell: (s) => link(href('sources', s.source), evidence(s.source, { max: 40 })) },
              { label: 'Events', num: true, cell: (s) => formatCount(s.events) },
              { label: 'Max severity', cell: (s) => sevChip(s.max_severity) },
              { label: 'Last seen', cell: (s) => timeEl(s.last_seen, { relative: true }) },
            ],
            rows: sources,
          })) : empty('No sources', 'Nothing was observed in this window.'),
        }),
        panel({
          title: titled('Recent correlation signals', 'correlation'), meta: signals.length > SIGNALS_SHOWN ? `The ${SIGNALS_SHOWN} newest of ${signals.length}` : 'Newest first',
          actions: link(href('events', { classification: 'correlation_signal' }), 'All signals'),
          body: signals.length ? h('ol', { class: ['timeline', 'timeline--compact'] }, signals.slice(0, SIGNALS_SHOWN).map((s) => h('li', { class: 'timeline__item' },
            glyph('correlation_signal'),
            h('p', { class: 'timeline__time' }, timeEl(s.time)),
            h('div', { class: 'timeline__body' },
              link(eventHref(s), evidence(s.summary, { max: 90 })),
              sevChip(s.severity))))) : empty('No signals', 'No correlation rule fired in this window.'),
        })),
      hasByNode ? byNodePanel(ov.by_node, window, ov.generated_at) : null,
      h('div', { class: 'grid grid--pair' },
        panel({
          title: 'Events by sensor', flush: false,
          meta: sensorsMeta(sensors),
          body: sensors.length ? barList(sensors.map((s) => ({
            label: h('span', { class: 'btn-row' }, h('code', null, s.sensor_id), h('span', { class: 'chip' }, s.kind)),
            value: s.events, valueText: formatCount(s.events), href: href('events', { sensor: s.sensor_id }),
            aside: sensorTrace(s, knownFrom),
          }))) : empty('No sensor events', 'No sensor stored an event in this window.'),
        }),
        meshPanel(sensors, windowText)),
      h('p', { class: 'page-note' }, icon('info', { size: 'sm' }),
        h('span', null, 'Counts come from the console’s bounded in-memory index, not from all evidence ever stored. Use ', h('code', null, 'aegismesh inspect'), ' for older evidence.'),
        tip('index')),
    );
    // First visit in this browser: offer the short tour (non-modal; the
    // module loads only then).
    return { mounted: () => { import('../ui/tour.js').then((m) => { if (!m.tourDone()) m.startTour(); }).catch(() => {}); } };
  },
};
