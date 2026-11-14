import { h, clear, mount } from '../lib/dom.js';
import { href, normalizeEventFilters, matchesEventFilters, EVENT_FILTER_KEYS } from '../lib/route.js';
import { CLASSIFICATIONS, SENSOR_KINDS, SEVERITIES, classificationMeta, severityLabel } from '../lib/taxonomy.js';
import { formatCount, localInputToRfc3339, rfc3339ToLocalInput } from '../lib/format.js';
import { RingBuffer, createLiveStream } from '../lib/stream.js';
import { pageHead, panel, selectField, inputField, empty, banner, pager, labelFor } from '../ui/components.js';
import { eventTable, historyBanner } from './shared.js';

const PAGE = 50;
const LIVE_CAP = 500;

const FILTER_LABELS = {
  classification: 'classification', sensor: 'sensor', kind: 'kind', source: 'source', rule: 'rule',
  severity: 'severity', since: 'since', until: 'until', q: 'search',
};

function filterForm(filters, sensors, onApply) {
  const form = h('form', { class: 'filters', 'aria-label': 'Event filters' },
    selectField({ label: 'Classification', name: 'classification', value: filters.classification || '', options: [['', 'Any'], ...CLASSIFICATIONS.map((c) => [c, classificationMeta(c).label])] }),
    selectField({ label: 'Minimum severity', name: 'severity', value: filters.severity || '', options: [['', 'Any (incl. no finding)'], ...SEVERITIES.map((s) => [s, `${severityLabel(s)} or higher`])] }),
    selectField({ label: 'Sensor', name: 'sensor', value: filters.sensor || '', options: [['', 'Any'], ...sensors.map((s) => [s.id, `${s.id} (${s.kind})`]), ...(filters.sensor && !sensors.some((s) => s.id === filters.sensor) ? [[filters.sensor, filters.sensor]] : [])] }),
    selectField({ label: 'Kind', name: 'kind', value: filters.kind || '', options: [['', 'Any'], ...SENSOR_KINDS.map((k) => [k, k.toUpperCase()])] }),
    inputField({ label: 'Source', name: 'source', value: filters.source || '', mono: true, placeholder: 'exact match', maxlength: 255 }),
    inputField({ label: 'Rule', name: 'rule', value: filters.rule || '', mono: true, placeholder: 'e.g. PI-001', maxlength: 64 }),
    inputField({ label: 'Since (UTC)', name: 'since', type: 'datetime-local', value: rfc3339ToLocalInput(filters.since) }),
    inputField({ label: 'Until (UTC)', name: 'until', type: 'datetime-local', value: rfc3339ToLocalInput(filters.until) }),
    h('div', { class: ['field', 'filters__search'] },
      h('label', { class: 'field__label', for: 'f-q' }, 'Search'),
      h('input', { class: 'input', id: 'f-q', name: 'q', type: 'search', maxlength: 128, placeholder: 'Summary, source or rule id', prop: { value: filters.q || '' }, autocomplete: 'off', spellcheck: 'false' })),
    h('div', { class: ['btn-row', 'filters__actions'] },
      h('button', { class: ['btn', 'btn--primary'], type: 'submit' }, 'Apply'),
      h('a', { class: 'btn', href: '#/events' }, 'Clear')));
  form.addEventListener('submit', (e) => {
    e.preventDefault();
    const el = form.elements;
    onApply({
      classification: el.classification.value, severity: el.severity.value, sensor: el.sensor.value, kind: el.kind.value,
      source: el.source.value.trim(), rule: el.rule.value.trim(), q: el.q.value,
      since: localInputToRfc3339(el.since.value), until: localInputToRfc3339(el.until.value),
    });
  });
  return form;
}

export default {
  title: 'Events',
  async render(root, ctx) {
    const { filters, rejected } = normalizeEventFilters(ctx.route.query);
    const liveRequested = ctx.route.query.live === '1';
    const [page, sensorsRes, node] = await Promise.all([
      ctx.api.events(filters, '', PAGE, { signal: ctx.signal }),
      ctx.api.sensors({ signal: ctx.signal }).catch(() => ({ sensors: [] })),
      ctx.api.node({ signal: ctx.signal }).catch(() => null),
    ]);

    let rows = Array.isArray(page.events) ? page.events : [];
    let cursor = page.next_cursor || '';
    let total = Number(page.total_matched) || rows.length;
    const seen = new Set(rows.map((e) => e.id));
    const newIds = new Set();
    const held = new RingBuffer(LIVE_CAP);
    let paused = false;

    const tableSlot = h('div');
    const pagerSlot = h('div');
    const liveBar = h('div', { class: 'live-bar', hidden: !liveRequested });
    const liveStatus = h('span', { class: 'live-status', role: 'status' });
    const heldBtn = h('button', { class: ['btn', 'btn--sm'], type: 'button', hidden: true });
    const pauseBtn = h('button', { class: ['btn', 'btn--sm'], type: 'button', 'aria-pressed': 'false' }, 'Pause');
    liveBar.append(liveStatus, pauseBtn, heldBtn);

    const paint = () => {
      mount(tableSlot, rows.length
        ? eventTable(rows, { caption: 'Matching events', newIds })
        : empty('No matching events', Object.keys(filters).length ? 'Nothing in the index matches these filters. Widen them or clear them.' : 'No event has been stored yet. Sensors record observations here as they arrive.'));
      mount(pagerSlot, pager({
        shown: rows.length, total, hasMore: Boolean(cursor),
        onMore: async () => {
          const next = await ctx.api.events(filters, cursor, PAGE, { signal: ctx.signal });
          for (const ev of next.events || []) if (!seen.has(ev.id)) { seen.add(ev.id); rows.push(ev); }
          cursor = next.next_cursor || '';
          newIds.clear();
          paint();
        },
      }));
    };

    const prepend = (events) => {
      newIds.clear();
      const fresh = events.filter((ev) => !seen.has(ev.id));
      for (const ev of fresh) { seen.add(ev.id); newIds.add(ev.id); }
      rows = [...fresh, ...rows];
      total += fresh.length;
      paint();
    };

    const paintHeld = () => {
      heldBtn.hidden = held.size === 0;
      heldBtn.textContent = `Show ${formatCount(held.size)} new${held.dropped ? ` (${formatCount(held.dropped)} older not kept)` : ''}`;
    };
    heldBtn.addEventListener('click', () => {
      prepend(held.newestFirst());
      held.clear();
      paintHeld();
    });
    pauseBtn.addEventListener('click', () => {
      paused = !paused;
      pauseBtn.textContent = paused ? 'Resume' : 'Pause';
      pauseBtn.setAttribute('aria-pressed', String(paused));
      if (!paused && held.size) heldBtn.click();
    });

    const STATE_TEXT = {
      connecting: 'Connecting to live stream…',
      live: 'Live: new matching events appear at the top',
      checking: 'Stream interrupted, checking session…',
      reconnecting: 'Stream interrupted, reconnecting',
      expired: 'Session expired. Live updates stopped.',
      stopped: 'Live updates off',
    };

    let stream = null;
    if (liveRequested) {
      stream = createLiveStream({
        checkSession: async () => Boolean(await ctx.api.session()),
        onEvent: (ev) => {
          if (!matchesEventFilters(ev, filters)) return;
          if (paused) { held.push(ev); paintHeld(); } else prepend([ev]);
        },
        onState: (state, d) => {
          liveStatus.className = `live-status live-status--${state}`;
          const extra = state === 'reconnecting' && d.delay ? ` in ${Math.ceil(d.delay / 1000)}s` : '';
          liveStatus.textContent = `${STATE_TEXT[state] || state}${extra}`;
          mount(ctx.liveSlot, h('span', { class: ['live-dot', `live-dot--${state}`] }, state === 'live' ? 'Live' : labelFor(state)));
          if (state === 'expired') ctx.rerender();
        },
      });
      stream.start();
    }

    const applyFilters = (next) => {
      const { filters: clean } = normalizeEventFilters(next);
      ctx.navigate(href('events', { ...clean, live: liveRequested ? '1' : '' }));
    };
    const liveToggle = h('a', { class: ['btn', liveRequested ? 'btn--primary' : ''], href: href('events', { ...filters, live: liveRequested ? '' : '1' }) },
      liveRequested ? 'Stop live' : 'Go live');

    const active = EVENT_FILTER_KEYS.filter((k) => filters[k]);
    paint();
    mount(root,
      pageHead({
        title: 'Events',
        subtitle: 'Every stored observation, newest first. Text in tinted monospace is attacker-supplied evidence, shown exactly as received.',
        actions: liveToggle,
      }),
      historyBanner(node),
      rejected.length ? banner('warn', 'Some filters were ignored', `These link parameters were not valid and were dropped: ${[...new Set(rejected)].map((k) => FILTER_LABELS[k]).join(', ')}.`) : null,
      panel({ title: 'Filters', body: filterForm(filters, sensorsRes.sensors || [], applyFilters), meta: active.length ? `${active.length} active` : 'None active' }),
      liveBar,
      panel({
        title: `${formatCount(total)} matching`,
        meta: liveRequested ? 'Live: the stream is unfiltered, so these filters are re-applied in the browser.' : 'Newest first. Server-side filters apply.',
        flush: true, body: tableSlot, foot: pagerSlot,
      }));

    return () => {
      stream?.stop();
      clear(ctx.liveSlot);
    };
  },
};
