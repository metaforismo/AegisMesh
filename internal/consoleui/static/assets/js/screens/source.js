import { h, mount } from '../lib/dom.js';
import { href } from '../lib/route.js';
import { formatCount, formatDateTime } from '../lib/format.js';
import { binTimes } from '../lib/chart.js';
import { pageHead, panel, kv, sevChip, evidence, chip, timeEl, empty, pager, link } from '../ui/components.js';
import { activityTrace } from '../ui/charts.js';
import { icon } from '../ui/icons.js';
import { eventKey } from '../lib/origin.js';
import { eventTable, originContext } from './shared.js';

const STRIP_BINS = 48;
const FIRST_PAGE = 200;

// Activity strip from first to last sighting. It is drawn from the events
// loaded on this page; when the source has more, the stretch older than the
// oldest loaded event is marked as not loaded rather than shown as quiet.
function activityStrip(s, rows) {
  const first = Date.parse(s.first_seen);
  const last = Date.parse(s.last_seen);
  if (!Number.isFinite(first) || !Number.isFinite(last) || !rows.length) return empty('No activity to draw', 'No indexed event from this source is loaded.', null, { icon: 'clock' });
  const end = Math.max(last + 1000, first + 60000);
  const { bins } = binTimes(rows.map((e) => e.time), first, end, STRIP_BINS);
  const total = Number(s.events) || rows.length;
  const partial = total > rows.length;
  const oldest = Date.parse(rows[rows.length - 1]?.time);
  return h('div', null,
    h('p', { class: 'strip-head' },
      h('span', null, `${STRIP_BINS} equal slices from first to last sighting`),
      h('span', { class: 'muted' }, partial ? `${formatCount(rows.length)} of ${formatCount(total)} events loaded; dashed slices not loaded` : `${formatCount(total)} events`)),
    activityTrace(bins, { start: first, end, knownFrom: partial && Number.isFinite(oldest) ? oldest : -Infinity, height: 40, startLabel: formatDateTime(s.first_seen), endLabel: formatDateTime(s.last_seen) }));
}

const PAGE = 50;

export default {
  title: 'Source',
  async render(root, ctx) {
    const key = ctx.route.params.source;
    // The first page uses the contract maximum so the activity strip has as
    // much of the history as one request can carry.
    const [res, origin] = await Promise.all([
      ctx.api.source(key, '', FIRST_PAGE, { signal: ctx.signal }),
      originContext(ctx),
    ]);
    const s = res.source || {};
    const rows = Array.isArray(res.events) ? res.events : [];
    let cursor = res.next_cursor || '';
    const seen = new Set(rows.map(eventKey));
    const tableSlot = h('div');
    const pagerSlot = h('div');
    const stripSlot = h('div');
    const paint = () => {
      mount(stripSlot, activityStrip(s, rows));
      mount(tableSlot, rows.length ? eventTable(rows, { caption: 'Events from this source', origin: origin.accepting || 'auto' }) : empty('No indexed events', 'Events from this source may have aged out of the index.'));
      mount(pagerSlot, pager({
        shown: rows.length, total: s.events, hasMore: Boolean(cursor),
        onMore: async () => {
          const next = await ctx.api.source(key, cursor, PAGE, { signal: ctx.signal });
          for (const ev of next.events || []) if (!seen.has(eventKey(ev))) { seen.add(eventKey(ev)); rows.push(ev); }
          cursor = next.next_cursor || '';
          paint();
        },
      }));
    };
    paint();

    mount(root,
      pageHead({
        eyebrow: h('a', { href: '#/sources' }, icon('arrow-left', { size: 'xs' }), 'Sources'),
        title: evidence(key),
        subtitle: 'Everything observed from this source. The value is attacker-influenced: it is what the sensor recorded, not a verified identity.',
        actions: link(href('events', { source: key }), 'Filter events by this source'),
      }),
      panel({
        title: 'Summary',
        body: kv([
          ['Events', formatCount(s.events)],
          ['Canary invocations', formatCount(s.canary_invocations)],
          ['Correlation signals', formatCount(s.signals)],
          ['Max severity', sevChip(s.max_severity)],
          ['First seen', timeEl(s.first_seen)],
          ['Last seen', timeEl(s.last_seen)],
          ['Sensors', h('span', { class: 'chip-row' }, (s.sensors || []).map((x) => chip(x, { mono: true })))],
          ['Sensor kinds', h('span', { class: 'chip-row' }, (s.kinds || []).map((x) => chip(x)))],
        ]),
      }),
      panel({ title: 'Activity', meta: 'When this source was seen, between its first and last sighting', body: stripSlot }),
      panel({ title: 'Events', meta: 'Newest first', flush: true, body: tableSlot, foot: pagerSlot }));
  },
};
