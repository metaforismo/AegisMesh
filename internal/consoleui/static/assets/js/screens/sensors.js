import { h, mount } from '../lib/dom.js';
import { href } from '../lib/route.js';
import { CLASSIFICATIONS, classificationMeta } from '../lib/taxonomy.js';
import { formatCount } from '../lib/format.js';
import { binTimes, bucketTrace, sensorBuckets, indexKnownFrom } from '../lib/chart.js';
import { pageHead, panel, kv, badge, chip, timeEl, empty, barList, glyph, link, labelFor } from '../ui/components.js';
import { activityTrace } from '../ui/charts.js';
import { icon } from '../ui/icons.js';

const STATE_BADGE = { running: 'ok', failed: 'danger', stopped: 'neutral' };
const HOURS = 24;
const TRACE_LIMIT = 200;

// Fallback for servers without overview.by_sensor[].buckets (and for a
// sensor past the 64-entry cap): the trace is built from the sensor's
// newest indexed events in the last 24 hours (one events request per
// sensor, at most 200 events each). When there are more than that, the
// hours older than the oldest loaded event are drawn as unknown, not quiet.
async function traceFromEvents(ctx, sensorId, end) {
  const since = new Date(end - HOURS * 3600e3).toISOString().replace(/\.\d+Z$/, 'Z');
  const res = await ctx.api.events({ sensor: sensorId, since }, '', TRACE_LIMIT, { signal: ctx.signal });
  const list = Array.isArray(res?.events) ? res.events : [];
  const total = Number(res?.total_matched) || list.length;
  const partial = total > list.length;
  const oldest = list.length ? Date.parse(list[list.length - 1].time) : end;
  const { bins } = binTimes(list.map((e) => e.time), end - HOURS * 3600e3, end, HOURS);
  return traceBlock({
    bins, start: end - HOURS * 3600e3, end, total, knownFrom: partial ? oldest : -Infinity,
    note: partial ? `Drawn from the newest ${formatCount(list.length)}; dashed hours were not loaded.` : null,
  });
}

function traceBlock({ bins, start, end, total, knownFrom, note }) {
  return h('div', { class: 'sensor-trace' },
    h('p', { class: 'sensor-trace__head' },
      h('span', null, 'Last 24 hours'),
      h('span', { class: 'muted' }, `${formatCount(total)} event${total === 1 ? '' : 's'}`)),
    activityTrace(bins, { start, end, knownFrom, startLabel: '24h ago', endLabel: 'now' }),
    note ? h('p', { class: 'sensor-trace__note' }, note) : null);
}

// From the overview's per-sensor buckets: one request for every card. The
// 24-hour window has 48 half-hour buckets. Time before the index can speak
// for (see indexKnownFrom) is dashed, not drawn as quiet.
function traceFromBuckets(series, node) {
  const tr = bucketTrace(series.buckets);
  if (!tr) return null;
  const knownFrom = indexKnownFrom(node);
  const partial = knownFrom > tr.start;
  return traceBlock({
    bins: tr.bins, start: tr.start, end: tr.end, total: series.events || tr.total, knownFrom,
    note: partial ? 'Dashed: before the console’s index begins, so not known to be quiet.' : null,
  });
}

export default {
  title: 'Sensors',
  async render(root, ctx) {
    // The overview and node reads are shared with the Overview screen
    // through the read cache. Without them the cards still render.
    const [res, ov, node] = await Promise.all([
      ctx.api.sensors({ signal: ctx.signal }),
      ctx.api.overview('24h', { signal: ctx.signal }).catch((err) => { if (err?.name === 'AbortError') throw err; return null; }),
      ctx.api.node({ signal: ctx.signal }).catch((err) => { if (err?.name === 'AbortError') throw err; return null; }),
    ]);
    const sensors = Array.isArray(res.sensors) ? res.sensors : [];
    // Round to the minute so a quick revisit reuses the cached requests.
    const end = Math.ceil(Date.now() / 60000) * 60000;
    const mixed = Array.isArray(ov?.by_node);
    const cards = sensors.map((s) => {
      const traceSlot = h('div', { class: 'sensor-trace-slot', 'aria-busy': 'true' }, h('span', { class: ['skeleton', 'skeleton--trace'], 'aria-hidden': 'true' }));
      const series = ov ? sensorBuckets(ov, s.id) : { status: 'unsupported' };
      const fromBuckets = series.status === 'ok' ? traceFromBuckets(series, node) : null;
      if (fromBuckets) {
        traceSlot.removeAttribute('aria-busy');
        mount(traceSlot, fromBuckets);
      } else {
        traceFromEvents(ctx, s.id, end).then(
          (block) => { traceSlot.removeAttribute('aria-busy'); mount(traceSlot, block); },
          (err) => {
            if (err?.name === 'AbortError') return;
            traceSlot.removeAttribute('aria-busy');
            mount(traceSlot, h('p', { class: 'muted' }, 'Activity trace unavailable.'));
          });
      }
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
        hint: 'Check each sensor is running and when it last recorded an event; see what each imitates on Decoys.',
      }),
      // On a hub that accepts forwarded evidence, by_sensor groups by sensor
      // id across origins, so an enrolled node's sensor with the same id
      // counts too.
      mixed && sensors.length ? h('p', { class: 'origin-note' }, icon('info', { size: 'sm' }), h('span', null, 'Traces count every stored event with the sensor’s id, including copies forwarded by enrolled nodes whose sensors share that id.')) : null,
      sensors.length ? h('div', { class: 'grid grid--cards' }, cards) : panel({ body: empty('No sensors configured', 'Add sensors to the AegisMesh configuration file and restart.', null, { icon: 'sensors' }) }));
  },
};
