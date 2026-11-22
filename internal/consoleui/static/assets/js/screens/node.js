import { h, clear, mount } from '../lib/dom.js';
import { formatCount, formatBytes, formatDuration, formatDateTime } from '../lib/format.js';
import { pageHead, panel, kv, badge, timeEl, labelFor } from '../ui/components.js';
import { historyBanner } from './shared.js';

const HISTORY_BADGE = { complete: 'ok', truncated: 'warn', unavailable: 'warn' };

export default {
  title: 'Node',
  async render(root, ctx) {
    const n = await ctx.api.node({ signal: ctx.signal });
    const v = n.version || {};
    const st = n.storage || {};
    const idx = n.index || {};
    const sensors = n.sensors || {};
    const con = n.console || {};
    const dropped = Number(n.bus?.dropped_events) || 0;
    const allStarted = Number(sensors.started) === Number(sensors.wanted);

    mount(root,
      pageHead({
        title: 'Node',
        subtitle: 'Health of this AegisMesh instance. Other enrolled nodes appear on the experimental Fleet screen, as self-reported inventory.',
        hint: 'Check that sensors started, the bus dropped nothing and the index still covers the history you need.',
        actions: badge(n.healthy ? 'ok' : 'danger', n.healthy ? 'Healthy' : 'Unhealthy'),
      }),
      historyBanner(n),
      h('div', { class: 'grid grid--2' },
        panel({
          title: 'Runtime',
          body: kv([
            ['Instance', h('code', null, n.instance || '—')],
            ['Version', `${v.version || '—'} (${v.commit || 'unknown commit'}, ${v.go || 'go ?'})`],
            ['Started', formatDateTime(n.started_at)],
            ['Uptime', formatDuration(n.uptime_seconds)],
            ['Sensors', h('span', { class: 'btn-row' }, `${formatCount(sensors.started)} of ${formatCount(sensors.wanted)} started`, badge(allStarted ? 'ok' : 'warn', allStarted ? 'All up' : 'Some not started'))],
            ['Event bus drops', h('span', { class: 'btn-row' }, formatCount(dropped), dropped ? badge('warn', 'Events were dropped') : null)],
          ]),
        }),
        panel({
          title: 'Evidence storage',
          body: kv([
            ['Segments', formatCount(st.segments)],
            ['Size on disk', formatBytes(st.bytes)],
            ['Encrypted at rest', st.encrypted ? 'Yes' : 'No'],
            ['Retention', `${st.retention?.max_events ? `${formatCount(st.retention.max_events)} events` : 'no event cap'} · ${st.retention?.max_age_days ? `${st.retention.max_age_days} days` : 'no age cap'}`],
          ]),
        }),
        panel({
          title: 'Console index',
          meta: 'Bounded in-memory projection used by every console view',
          body: kv([
            ['Indexed events', `${formatCount(idx.events)} of ${formatCount(idx.capacity)} capacity`],
            ['Oldest indexed', idx.oldest ? timeEl(idx.oldest) : ''],
            ['History', badge(HISTORY_BADGE[idx.history] || 'neutral', labelFor(idx.history || 'unknown'))],
          ]),
        }),
        panel({
          title: 'Console listener',
          body: kv([
            ['Listen', h('code', null, con.listen || '—')],
            ['TLS', con.tls ? 'Enabled' : 'Off (loopback only)'],
            ['Session lifetime', formatDuration(con.session_ttl_seconds)],
            ['Your session expires', timeEl(ctx.session?.expires_at)],
          ]),
        })));
  },
};
