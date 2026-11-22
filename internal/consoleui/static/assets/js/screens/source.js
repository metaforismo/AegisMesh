import { h, mount } from '../lib/dom.js';
import { href } from '../lib/route.js';
import { formatCount, formatDateTime } from '../lib/format.js';
import { binTimes } from '../lib/chart.js';
import { pageHead, panel, kv, sevChip, evidence, chip, timeEl, empty, pager, link } from '../ui/components.js';
import { activityTrace } from '../ui/charts.js';
import { cadence, describeCadence, formatGap, MIN_GAPS } from '../lib/cadence.js';
import { glossaryEntry } from '../lib/glossary.js';
import { helpTip } from '../ui/components.js';
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

// Gaps between consecutive loaded events, binned. Printed counts carry the
// data; the bars are their shape. Labelled with how many events it saw.
function cadenceView(s, rows) {
  const c = cadence(rows.map((e) => e.time));
  const total = Number(s.events) || rows.length;
  if (c.gaps < 1) return empty('Not enough events for a cadence', 'At least two loaded events are needed to measure a gap.', null, { icon: 'cadence' });
  const max = Math.max(1, ...c.bins.map((b) => b.count));
  const cols = c.bins.map((b, i) => {
    const fill = h('span', { class: 'cadence__fill' });
    fill.style.transform = `scaleY(${(b.count / max).toFixed(4)})`;
    return h('li', { class: ['cadence__col', i === c.peak ? 'is-peak' : ''] },
      h('span', { class: 'cadence__bar', 'aria-hidden': 'true' }, fill),
      h('span', { class: 'cadence__count' }, formatCount(b.count)),
      h('span', { class: 'cadence__label' }, b.label, i === c.peak ? h('span', { class: 'visually-hidden' }, ' (most gaps)') : null));
  });
  const sentence = describeCadence(c);
  return h('div', null,
    h('p', { class: 'cadence-head' },
      h('span', null, `Gaps between consecutive events, from the ${formatCount(c.events)} loaded event${c.events === 1 ? '' : 's'}`),
      h('span', { class: 'muted' }, total > c.events ? `${formatCount(total - c.events)} more not loaded` : 'All of this source’s indexed events')),
    h('ol', { class: 'cadence', 'aria-label': 'Number of gaps in each range' }, cols),
    h('p', { class: 'cadence-note' }, sentence || `Fewer than ${MIN_GAPS} gaps: too few to describe. Most common range: ${c.bins[c.peak]?.label || '—'}.`),
    h('p', { class: 'cadence-caveat' }, `Short, regular gaps are typical of scripts and agent tool loops; irregular ones of people. This is an observation, not a verdict. Span of the loaded events: ${formatGap(c.span)}.`));
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
    const cadenceSlot = h('div');
    const paint = () => {
      mount(stripSlot, activityStrip(s, rows));
      mount(cadenceSlot, cadenceView(s, rows));
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
        actions: [h('a', { class: 'btn', href: href('sessions', { source: key, window: '7d' }) }, icon('story', { size: 'sm' }), 'Sessions from this source'), link(href('events', { source: key }), 'Filter events by this source')],
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
      h('div', { class: 'grid grid--2' },
        panel({ title: 'Activity', meta: 'When this source was seen, between its first and last sighting', body: stripSlot }),
        panel({ title: h('span', { class: 'title-help' }, 'Cadence', helpTip(glossaryEntry('cadence'))), meta: 'How regularly its events arrive. Computed in your browser.', body: cadenceSlot })),
      panel({ title: 'Events', meta: 'Newest first', flush: true, body: tableSlot, foot: pagerSlot }));
  },
};
