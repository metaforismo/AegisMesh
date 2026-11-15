import { h, clear, mount } from '../lib/dom.js';
import { href, normalizeWindow } from '../lib/route.js';
import { CLASSIFICATIONS, SEVERITIES, classificationMeta, severityLabel } from '../lib/taxonomy.js';
import { formatCount, formatDelta, formatDateTime } from '../lib/format.js';
import { pageHead, panel, stat, segmented, glyph, sevChip, evidence, barList, table, timeEl, empty, banner, link } from '../ui/components.js';
import { stackedBarChart } from '../ui/charts.js';
import { historyBanner } from './shared.js';

const WINDOW_LABELS = [['1h', 'Last hour'], ['24h', 'Last 24 hours'], ['7d', 'Last 7 days']];

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

    const tiles = h('div', { class: 'grid grid--stats' },
      stat({ label: 'Events', value: formatCount(t.events), delta: formatDelta(t.events, p.events) }),
      ...CLASSIFICATIONS.map((c) => stat({
        label: classificationMeta(c).label, icon: glyph(c),
        value: formatCount(t[c]), delta: formatDelta(t[c], p[c]),
      })),
      stat({ label: 'Distinct sources', value: formatCount(t.sources), delta: formatDelta(t.sources, p.sources) }),
      stat({ label: 'Sensors with events', value: formatCount(t.sensors_active) }));

    const sev = ov.by_severity || {};
    const sevItems = [...SEVERITIES].reverse().map((s) => ({
      label: sevChip(s), value: Number(sev[s]) || 0, valueText: formatCount(sev[s] || 0),
      href: href('events', { severity: s }),
    }));
    sevItems.push({ label: h('span', { class: ['sev', 'sev--none'] }, severityLabel('')), value: Number(sev.none) || 0, valueText: formatCount(sev.none || 0) });

    const rules = Array.isArray(ov.top_rules) ? ov.top_rules : [];
    const sources = Array.isArray(ov.top_sources) ? ov.top_sources : [];
    const signals = Array.isArray(ov.recent_signals) ? ov.recent_signals : [];
    const sensors = Array.isArray(ov.by_sensor) ? ov.by_sensor : [];

    mount(root,
      pageHead({
        title: 'Overview',
        subtitle: `What the sensors observed in the ${windowText}, compared with the window before it. Events are observations, not incidents.`,
        actions: segmented({ label: 'Time window', options: WINDOW_LABELS.map(([w]) => [w, w]), value: window, onChange: (w) => ctx.navigate(href('overview', { window: w })) }),
      }),
      historyBanner(node),
      tiles,
      panel({
        title: 'Observations over time', meta: `Stacked by classification · generated ${formatDateTime(ov.generated_at)}`,
        body: (ov.buckets || []).length ? stackedBarChart(ov.buckets, window) : empty('No buckets', 'The server returned no time buckets for this window.'),
      }),
      h('div', { class: 'grid grid--2' },
        panel({ title: 'By severity', meta: 'Highest finding per event; most events carry no finding', body: barList(sevItems) }),
        panel({
          title: 'Top rules', meta: 'Rules cited by the most events',
          body: rules.length
            ? barList(rules.map((r) => ({ label: h('span', { class: 'btn-row' }, h('code', null, r.rule_id), r.severity ? sevChip(r.severity) : null), value: r.events, valueText: formatCount(r.events), href: href('events', { rule: r.rule_id }) })))
            : empty('No rule matched', 'No event in this window cited a detection or correlation rule.'),
        })),
      h('div', { class: 'grid grid--2' },
        panel({
          title: 'Top sources', meta: 'Remote hosts or correlation keys, ranked by events', flush: true,
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
          title: 'Recent correlation signals', meta: 'Up to 10, newest first',
          actions: link(href('events', { classification: 'correlation_signal' }), 'All signals'),
          body: signals.length ? h('ol', { class: 'timeline' }, signals.map((s) => h('li', { class: 'timeline__item' },
            glyph('correlation_signal'),
            h('p', { class: 'timeline__time' }, timeEl(s.time)),
            h('div', { class: 'timeline__body' },
              link(href('events', s.id), evidence(s.summary, { max: 90 })),
              sevChip(s.severity))))) : empty('No signals', 'No correlation rule fired in this window.'),
        })),
      h('div', { class: 'grid grid--2' },
        panel({
          title: 'Events by sensor', flush: false,
          body: sensors.length ? barList(sensors.map((s) => ({ label: h('span', { class: 'btn-row' }, h('code', null, s.sensor_id), h('span', { class: 'chip' }, s.kind)), value: s.events, valueText: formatCount(s.events), href: href('events', { sensor: s.sensor_id }) }))) : empty('No sensor events', 'No sensor stored an event in this window.'),
        }),
        panel({
          title: 'Investigations',
          body: h('div', { class: 'stack' },
            h('p', { class: 'stat__value' }, formatCount(ov.open_investigations)),
            h('p', { class: 'muted' }, 'open investigations'),
            link(href('investigations', { status: 'open' }), 'Review open investigations')),
        })),
      banner('info', null, h('p', null, 'Counts come from the console’s in-memory index. Use ', h('code', null, 'aegismesh inspect'), ' for evidence older than the index.')),
    );
  },
};
