import { h, clear, mount } from '../lib/dom.js';
import { href, normalizeWindow } from '../lib/route.js';
import { formatCount } from '../lib/format.js';
import { severityRank } from '../lib/taxonomy.js';
import { timeValue } from '../lib/tablesort.js';
import { pageHead, panel, segmented, table, sevChip, evidence, link, chip, timeEl, empty, selectField } from '../ui/components.js';

const LIMITS = ['50', '200'];

export default {
  title: 'Sources',
  async render(root, ctx) {
    const window = normalizeWindow(ctx.route.query.window);
    const limit = LIMITS.includes(ctx.route.query.limit) ? ctx.route.query.limit : '50';
    const res = await ctx.api.sources(window, Number(limit), { signal: ctx.signal });
    const sources = Array.isArray(res.sources) ? res.sources : [];
    const go = (q) => ctx.navigate(href('sources', { window, limit, ...q }));

    mount(root,
      pageHead({
        title: 'Sources',
        subtitle: 'Remote hosts and correlation keys that reached a sensor, ranked by event count. A source address is what the sensor saw; it can be spoofed or relayed.',
        hint: 'Open a source to see its activity, cadence and sessions.',
        actions: [
          segmented({ label: 'Time window', options: [['1h', '1h'], ['24h', '24h'], ['7d', '7d']], value: window, onChange: (w) => go({ window: w }) }),
        ],
      }),
      panel({
        title: `${formatCount(sources.length)} sources`, meta: `Top ${limit} in the window`,
        actions: selectField({ label: 'Show', name: 'limit', value: limit, options: LIMITS.map((l) => [l, `Top ${l}`]), onChange: (l) => go({ limit: l }) }),
        flush: true,
        body: sources.length ? table({
          caption: 'Sources',
          columns: [
            { label: 'Source', className: 'col-summary', lead: true, sort: (s) => s.source, cell: (s) => link(href('sources', s.source), evidence(s.source, { max: 60 })) },
            { label: 'Events', num: true, sort: (s) => s.events, cell: (s) => formatCount(s.events) },
            { label: 'Canary invocations', num: true, sort: (s) => s.canary_invocations, cell: (s) => formatCount(s.canary_invocations) },
            { label: 'Signals', num: true, sort: (s) => s.signals, cell: (s) => formatCount(s.signals) },
            { label: 'Max severity', sort: (s) => severityRank(s.max_severity), sortFirst: 'desc', cell: (s) => sevChip(s.max_severity) },
            { label: 'Sensors', className: 'col-chips', cell: (s) => h('span', { class: 'chip-row' }, (s.sensors || []).map((x) => chip(x, { mono: true }))) },
            { label: 'First seen', className: 'nowrap', sort: (s) => timeValue(s.first_seen), sortFirst: 'desc', cell: (s) => timeEl(s.first_seen, { relative: true }) },
            { label: 'Last seen', className: 'nowrap', sort: (s) => timeValue(s.last_seen), sortFirst: 'desc', cell: (s) => timeEl(s.last_seen, { relative: true }) },
          ],
          rows: sources,
          // The server ranks by event count; the header says so.
          sort: { key: 'Events', dir: 'desc' },
        }) : empty('No sources in this window', 'Try a longer window.'),
      }));
  },
};
