import { h, clear, mount } from '../lib/dom.js';
import { href } from '../lib/route.js';
import { CLASSIFICATIONS, classificationMeta } from '../lib/taxonomy.js';
import { formatCount } from '../lib/format.js';
import { pageHead, panel, kv, badge, chip, timeEl, empty, barList, glyph, link, labelFor } from '../ui/components.js';

const STATE_BADGE = { running: 'ok', failed: 'danger', stopped: 'neutral' };

export default {
  title: 'Sensors',
  async render(root, ctx) {
    const res = await ctx.api.sensors({ signal: ctx.signal });
    const sensors = Array.isArray(res.sensors) ? res.sensors : [];
    const cards = sensors.map((s) => panel({
      title: h('span', { class: 'btn-row' }, h('code', null, s.id), chip(s.kind || '?')),
      actions: badge(STATE_BADGE[s.state] || 'neutral', labelFor(s.state || 'unknown')),
      body: [
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
    }));

    mount(root,
      pageHead({
        title: 'Sensors',
        subtitle: 'Configured decoys and their runtime state. The console reports state only; it cannot start, stop or reconfigure a sensor.',
      }),
      sensors.length ? h('div', { class: 'grid grid--cards' }, cards) : panel({ body: empty('No sensors configured', 'Add sensors to the AegisMesh configuration file and restart.') }));
  },
};
