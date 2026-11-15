import { h, clear, mount } from '../lib/dom.js';
import { href } from '../lib/route.js';
import { formatCount } from '../lib/format.js';
import { pageHead, panel, kv, sevChip, evidence, chip, timeEl, empty, pager, link } from '../ui/components.js';
import { eventTable } from './shared.js';

const PAGE = 50;

export default {
  title: 'Source',
  async render(root, ctx) {
    const key = ctx.route.params.source;
    const res = await ctx.api.source(key, '', PAGE, { signal: ctx.signal });
    const s = res.source || {};
    const rows = Array.isArray(res.events) ? res.events : [];
    let cursor = res.next_cursor || '';
    const seen = new Set(rows.map((e) => e.id));
    const tableSlot = h('div');
    const pagerSlot = h('div');
    const paint = () => {
      mount(tableSlot, rows.length ? eventTable(rows, { caption: 'Events from this source' }) : empty('No indexed events', 'Events from this source may have aged out of the index.'));
      mount(pagerSlot, pager({
        shown: rows.length, total: s.events, hasMore: Boolean(cursor),
        onMore: async () => {
          const next = await ctx.api.source(key, cursor, PAGE, { signal: ctx.signal });
          for (const ev of next.events || []) if (!seen.has(ev.id)) { seen.add(ev.id); rows.push(ev); }
          cursor = next.next_cursor || '';
          paint();
        },
      }));
    };
    paint();

    mount(root,
      pageHead({
        eyebrow: h('a', { href: '#/sources' }, '← Sources'),
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
      panel({ title: 'Events', meta: 'Newest first', flush: true, body: tableSlot, foot: pagerSlot }));
  },
};
