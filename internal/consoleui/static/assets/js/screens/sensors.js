import { h, mount } from '../lib/dom.js';
import { href } from '../lib/route.js';
import { CLASSIFICATIONS, classificationMeta } from '../lib/taxonomy.js';
import { formatCount } from '../lib/format.js';
import { binTimes } from '../lib/chart.js';
import { pageHead, panel, kv, badge, chip, timeEl, empty, barList, glyph, link, labelFor } from '../ui/components.js';
import { activityTrace } from '../ui/charts.js';
import { icon } from '../ui/icons.js';

const STATE_BADGE = { running: 'ok', failed: 'danger', stopped: 'neutral' };
const HOURS = 24;
const TRACE_LIMIT = 200;

// The API has no per-sensor time series, so the trace is built from the
// sensor's newest indexed events in the last 24 hours (one events request
// per sensor, at most 200 events each). When there are more than that, the
// hours older than the oldest loaded event are drawn as unknown, not quiet.
async function traceFor(ctx, sensorId, end) {
  const since = new Date(end - HOURS * 3600e3).toISOString().replace(/\.\d+Z$/, 'Z');
  const res = await ctx.api.events({ sensor: sensorId, since }, '', TRACE_LIMIT, { signal: ctx.signal });
  const list = Array.isArray(res?.events) ? res.events : [];
  const total = Number(res?.total_matched) || list.length;
  const partial = total > list.length;
  const oldest = list.length ? Date.parse(list[list.length - 1].time) : end;
  const { bins } = binTimes(list.map((e) => e.time), end - HOURS * 3600e3, end, HOURS);
  return h('div', { class: 'sensor-trace' },
    h('p', { class: 'sensor-trace__head' },
      h('span', null, 'Last 24 hours'),
      h('span', { class: 'muted' }, `${formatCount(total)} event${total === 1 ? '' : 's'}`)),
    activityTrace(bins, { start: end - HOURS * 3600e3, end, knownFrom: partial ? oldest : -Infinity, startLabel: '24h ago', endLabel: 'now' }),
    partial ? h('p', { class: 'sensor-trace__note' }, `Drawn from the newest ${formatCount(list.length)}; dashed hours were not loaded.`) : null);
}

export default {
  title: 'Sensors',
  async render(root, ctx) {
    const res = await ctx.api.sensors({ signal: ctx.signal });
    const sensors = Array.isArray(res.sensors) ? res.sensors : [];
    // Round to the minute so a quick revisit reuses the cached requests.
    const end = Math.ceil(Date.now() / 60000) * 60000;
    const cards = sensors.map((s) => {
      const traceSlot = h('div', { class: 'sensor-trace-slot', 'aria-busy': 'true' }, h('span', { class: ['skeleton', 'skeleton--trace'], 'aria-hidden': 'true' }));
      traceFor(ctx, s.id, end).then(
        (node) => { traceSlot.removeAttribute('aria-busy'); mount(traceSlot, node); },
        (err) => {
          if (err?.name === 'AbortError') return;
          traceSlot.removeAttribute('aria-busy');
          mount(traceSlot, h('p', { class: 'muted' }, 'Activity trace unavailable.'));
        });
      return panel({
        title: h('span', { class: 'btn-row' }, icon('sensors'), h('code', null, s.id), chip(s.kind || '?')),
        actions: badge(STATE_BADGE[s.state] || 'neutral', labelFor(s.state || 'unknown')),
        body: [
          traceSlot,
          kv([
            ['Listen', s.listen ? h('code', null, s.listen) : ''],
            ['Process isolation', s.process_isolation ? 'Separate process' : 'In-process'],
            ['Events indexed', formatCount(s.events_total)],
            ['Last event', s.last_event_at ? timeEl(s.last_event_at, { relative: true }) : h('span', { class: 'muted' }, 'none indexed')],
          ]),
          barList(CLASSIFICATIONS.map((c) => ({
            label: h('span', { class: 'cls' }, glyph(c), classificationMeta(c).label),
            value: Number(s.by_classification?.[c]) || 0,
            valueText: formatCount(s.by_classification?.[c] || 0),
          })), { max: Math.max(1, Number(s.events_total) || 0) }),
        ],
        foot: link(href('events', { sensor: s.id }), 'View events'),
      });
    });

    mount(root,
      pageHead({
        title: 'Sensors',
        subtitle: 'Configured decoys and their runtime state. The console reports state only; it cannot start, stop or reconfigure a sensor.',
      }),
      sensors.length ? h('div', { class: 'grid grid--cards' }, cards) : panel({ body: empty('No sensors configured', 'Add sensors to the AegisMesh configuration file and restart.', null, { icon: 'sensors' }) }));
  },
};
