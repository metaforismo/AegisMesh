import { h, mount } from '../lib/dom.js';
import { href, normalizeEventFilters, matchesEventFilters, EVENT_FILTER_KEYS, isEventId, withQuery } from '../lib/route.js';
import { CLASSIFICATIONS, SENSOR_KINDS, SEVERITIES, classificationMeta, severityLabel } from '../lib/taxonomy.js';
import { formatCount, localInputToRfc3339, rfc3339ToLocalInput } from '../lib/format.js';
import { RingBuffer, createLiveStream } from '../lib/stream.js';
import { createBatcher } from '../lib/batch.js';
import { moveIndex, isTypingTarget } from '../lib/keys.js';
import { pageHead, panel, selectField, inputField, empty, banner, pager, labelFor, errorState } from '../ui/components.js';
import { icon } from '../ui/icons.js';
import { eventTableView, historyBanner } from './shared.js';
import { renderEventDetail } from './event.js';

const PAGE = 50;
const LIVE_CAP = 500;
// Rows kept in the DOM in live mode. Older rows are trimmed from the bottom
// so a long session never grows the page without bound.
const MAX_ROWS = 300;
const PER_FRAME = 40;

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
      h('span', { class: 'input-icon' },
        icon('search', { size: 'sm' }),
        h('input', { class: 'input', id: 'f-q', name: 'q', type: 'search', maxlength: 128, placeholder: 'Summary, source or rule id', prop: { value: filters.q || '' }, autocomplete: 'off', spellcheck: 'false', 'data-search': '', 'aria-keyshortcuts': '/' }),
        h('kbd', { class: 'input-icon__kbd', 'aria-hidden': 'true' }, '/'))),
    h('div', { class: ['btn-row', 'filters__actions'] },
      h('button', { class: ['btn', 'btn--primary'], type: 'submit' }, icon('filter'), 'Apply'),
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

// ---- Side panel (event detail over the list) --------------------------------

function createDrawer({ onRequestClose, onStep, onFull }) {
  const titleText = h('span', { class: 'drawer__title-text' }, 'Event');
  const position = h('span', { class: 'muted' });
  const prev = h('button', { class: ['btn', 'btn--ghost', 'btn--icon', 'btn--sm'], type: 'button', 'aria-label': 'Previous event (k)', title: 'Previous event (k)' }, icon('chevron-up'));
  const next = h('button', { class: ['btn', 'btn--ghost', 'btn--icon', 'btn--sm'], type: 'button', 'aria-label': 'Next event (j)', title: 'Next event (j)' }, icon('chevron-down'));
  const full = h('a', { class: ['btn', 'btn--sm'], href: '#/events' }, icon('external'), 'Full page');
  const close = h('button', { class: ['btn', 'btn--ghost', 'btn--icon', 'btn--sm'], type: 'button', 'aria-label': 'Close (Esc)', title: 'Close (Esc)' }, icon('close'));
  const body = h('div', { class: 'drawer__body' });
  const scroll = h('div', { class: 'drawer__scroll' }, body);
  const dialog = h('dialog', { class: 'drawer', 'aria-labelledby': 'drawer-title' },
    h('div', { class: 'drawer__frame' },
      h('div', { class: 'drawer__head' },
        h('p', { class: 'drawer__title', id: 'drawer-title', tabindex: '-1' }, icon('events'), titleText, position),
        h('div', { class: 'btn-row' }, prev, next, full, close)),
      scroll));
  prev.addEventListener('click', () => onStep(-1));
  next.addEventListener('click', () => onStep(1));
  close.addEventListener('click', onRequestClose);
  full.addEventListener('click', onFull);
  // Esc arrives as "cancel": route it through the URL so back/forward agree.
  dialog.addEventListener('cancel', (e) => {
    e.preventDefault();
    onRequestClose();
  });
  dialog.addEventListener('click', (e) => { if (e.target === dialog) onRequestClose(); });
  document.body.appendChild(dialog);
  return {
    dialog, body, scroll,
    focusTitle: () => dialog.querySelector('#drawer-title')?.focus(),
    setNav({ index, count, id }) {
      prev.disabled = index <= 0;
      next.disabled = index < 0 || index >= count - 1;
      position.textContent = index >= 0 ? `${formatCount(index + 1)} of ${formatCount(count)}` : 'not in the loaded list';
      full.setAttribute('href', href('events', id));
    },
  };
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

    let route = ctx.route;
    const firstRows = Array.isArray(page.events) ? page.events : [];
    let cursor = page.next_cursor || '';
    let total = Number(page.total_matched) || firstRows.length;
    let trimmed = 0;
    const seen = new Set(firstRows.map((e) => e.id));
    const held = new RingBuffer(LIVE_CAP);
    let paused = false;
    let hoverHold = false;
    let unread = 0;
    const cleanups = [];

    const rowHref = (ev) => withQuery(route, { event: ev.id });
    const view = eventTableView(firstRows, { caption: 'Matching events', rowHref });
    const tableSlot = h('div', { class: 'events-table' });
    const pagerSlot = h('div');
    const titleCount = h('span', null, formatCount(total));
    const pill = h('div', { class: 'live-pill', hidden: true });
    const pillBtn = h('button', { class: ['btn', 'btn--sm', 'btn--primary'], type: 'button' });
    pill.appendChild(pillBtn);

    const paintPager = () => {
      mount(pagerSlot, trimmed
        ? h('div', { class: 'pager' }, h('span', { class: 'muted' }, `Showing the newest ${formatCount(view.size)}. ${formatCount(trimmed)} older rows were removed from view to keep the page fast; reload to page through them.`))
        : pager({
          shown: view.size, total, hasMore: Boolean(cursor),
          onMore: async () => {
            const next = await ctx.api.events(filters, cursor, PAGE, { signal: ctx.signal });
            const fresh = (next.events || []).filter((ev) => !seen.has(ev.id));
            for (const ev of fresh) seen.add(ev.id);
            view.append(fresh);
            cursor = next.next_cursor || '';
            paintPager();
          },
        }));
    };
    const paintTable = () => mount(tableSlot, view.size
      ? [pill, view.el]
      : empty('No matching events', Object.keys(filters).length ? 'Nothing in the index matches these filters. Widen them or clear them.' : 'No event has been stored yet. Sensors record observations here as they arrive.', null, { icon: Object.keys(filters).length ? 'filter' : 'inbox' }));
    paintTable();
    paintPager();

    // ---- Live mode ---------------------------------------------------------
    const liveBar = h('div', { class: 'live-bar', hidden: !liveRequested });
    const liveStatus = h('span', { class: 'live-status', role: 'status' });
    const heldBtn = h('button', { class: ['btn', 'btn--sm'], type: 'button', hidden: true });
    const pauseBtn = h('button', { class: ['btn', 'btn--sm'], type: 'button', 'aria-pressed': 'false' }, icon('pause'), 'Pause');
    liveBar.append(liveStatus, pauseBtn, heldBtn);

    const listTop = () => tableSlot.getBoundingClientRect().top;
    const topbar = () => document.querySelector('.shell__top')?.offsetHeight || 0;
    const setTitle = () => { document.title = `${unread ? `(${formatCount(unread)}) ` : ''}Events · AegisMesh`; };
    const paintPill = () => {
      pill.hidden = unread === 0;
      pillBtn.replaceChildren(icon('arrow-up', { size: 'sm' }), `${formatCount(unread)} new event${unread === 1 ? '' : 's'}`);
      setTitle();
    };
    const clearUnread = () => {
      if (!unread) return;
      unread = 0;
      paintPill();
    };
    pillBtn.addEventListener('click', () => {
      const y = window.scrollY + listTop() - topbar() - 8;
      window.scrollTo({ top: Math.max(0, y), behavior: globalThis.matchMedia?.('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth' });
      clearUnread();
    });

    // events: newest first.
    const insert = (events) => {
      const fresh = events.filter((ev) => !seen.has(ev.id));
      if (!fresh.length) return;
      for (const ev of fresh) seen.add(ev.id);
      // Read layout once, before any write in this frame.
      const away = document.hidden || listTop() < topbar() - 4;
      const wasEmpty = view.size === 0;
      view.prepend(fresh);
      const dropped = view.trim(MAX_ROWS);
      if (dropped) {
        trimmed += dropped;
        cursor = '';
      }
      total += fresh.length;
      titleCount.textContent = formatCount(total);
      if (away) {
        unread += fresh.length;
        paintPill();
      }
      if (wasEmpty) paintTable();
      paintPager();
      if (drawerId) syncDrawerNav();
    };

    const paintHeld = () => {
      heldBtn.hidden = held.size === 0;
      heldBtn.textContent = `Show ${formatCount(held.size)} new${held.dropped ? ` (${formatCount(held.dropped)} older not kept)` : ''}`;
    };
    const releaseHeld = () => {
      if (!held.size) return;
      insert(held.newestFirst());
      held.clear();
      paintHeld();
    };
    heldBtn.addEventListener('click', releaseHeld);
    const setPaused = (next) => {
      paused = next;
      pauseBtn.replaceChildren(icon(paused ? 'play' : 'pause'), paused ? 'Resume' : 'Pause');
      pauseBtn.setAttribute('aria-pressed', String(paused));
      if (!paused && !hoverHold) releaseHeld();
      paintLiveStatus();
    };
    pauseBtn.addEventListener('click', () => setPaused(!paused));

    // Pause on hover: rows never shift under the pointer. They wait in the
    // held buffer and arrive together when the pointer leaves.
    if (liveRequested) {
      tableSlot.addEventListener('pointerenter', (e) => {
        if (e.pointerType === 'touch') return;
        hoverHold = true;
        paintLiveStatus();
      });
      tableSlot.addEventListener('pointerleave', () => {
        hoverHold = false;
        if (!paused) releaseHeld();
        paintLiveStatus();
      });
      const onScroll = () => { if (unread && listTop() >= topbar() - 4) clearUnread(); };
      const onVisible = () => { if (!document.hidden && listTop() >= topbar() - 4) clearUnread(); };
      window.addEventListener('scroll', onScroll, { passive: true });
      document.addEventListener('visibilitychange', onVisible);
      cleanups.push(() => {
        window.removeEventListener('scroll', onScroll);
        document.removeEventListener('visibilitychange', onVisible);
      });
    }

    const batcher = createBatcher({
      perFrame: PER_FRAME,
      flush: (items) => {
        const matching = items.filter((ev) => matchesEventFilters(ev, filters));
        if (!matching.length) return;
        if (paused || hoverHold) {
          for (const ev of matching) held.push(ev);
          paintHeld();
          return;
        }
        insert(matching.reverse());
      },
    });
    cleanups.push(() => batcher.stop());

    const STATE_TEXT = {
      connecting: 'Connecting to live stream…',
      live: 'Live: new matching events appear at the top',
      checking: 'Stream interrupted, checking session…',
      reconnecting: 'Stream interrupted, reconnecting',
      expired: 'Session expired. Live updates stopped.',
      stopped: 'Live updates off',
    };
    let streamState = 'stopped';
    let streamExtra = '';
    function paintLiveStatus() {
      liveStatus.className = `live-status live-status--${streamState}`;
      let text = `${STATE_TEXT[streamState] || streamState}${streamExtra}`;
      if (streamState === 'live' && paused) text = 'Paused: new events are held below the limit until you resume';
      else if (streamState === 'live' && hoverHold) text = 'Holding new events while the pointer is over the list';
      liveStatus.textContent = text;
    }

    let stream = null;
    if (liveRequested) {
      stream = createLiveStream({
        checkSession: async () => Boolean(await ctx.api.session()),
        onEvent: (ev) => batcher.push(ev),
        onState: (state, d) => {
          streamState = state;
          streamExtra = state === 'reconnecting' && d.delay ? ` in ${Math.ceil(d.delay / 1000)}s` : '';
          paintLiveStatus();
          mount(ctx.liveSlot, h('span', { class: ['live-dot', `live-dot--${state}`] }, state === 'live' ? 'Live' : labelFor(state)));
          if (state === 'expired') ctx.rerender();
        },
      });
      stream.start();
      cleanups.push(() => stream.stop());
    }

    // ---- Drawer --------------------------------------------------------------
    let drawer = null;
    let drawerId = '';
    let drawerCtl = null;
    let pushedOpen = false;

    const syncDrawerNav = () => drawer?.setNav({ index: view.indexOf(drawerId), count: view.size, id: drawerId });
    const requestClose = () => {
      if (pushedOpen) history.back();
      else location.replace(withQuery(route, { event: '' }));
    };
    const step = (delta) => {
      const i = view.indexOf(drawerId);
      const j = moveIndex(i, delta, view.size);
      if (j < 0 || j === i) return;
      location.replace(withQuery(route, { event: view.ids[j] }));
    };

    const openDrawer = async (id) => {
      if (!drawer) {
        drawer = createDrawer({
          onRequestClose: requestClose,
          onStep: step,
          onFull: (e) => { e.preventDefault(); location.hash = href('events', drawerId); },
        });
      }
      if (!drawer.dialog.open) {
        drawer.dialog.showModal();
        // Start reading at the panel's title, not on its first button.
        drawer.focusTitle();
      }
      if (id === drawerId) return;
      drawerId = id;
      view.setOpen(id);
      syncDrawerNav();
      drawerCtl?.abort();
      drawerCtl = new AbortController();
      const signal = drawerCtl.signal;
      drawer.body.setAttribute('aria-busy', 'true');
      try {
        const next = h('div');
        await renderEventDetail(next, ctx, id, { inDrawer: true, signal });
        if (signal.aborted) return;
        next.querySelector('#page-title')?.setAttribute('id', 'drawer-event-title');
        mount(drawer.body, ...next.childNodes);
        drawer.scroll.scrollTop = 0;
      } catch (err) {
        if (signal.aborted || err?.name === 'AbortError') return;
        mount(drawer.body, h('div', { class: 'panel' }, errorState(err)));
      } finally {
        if (!signal.aborted) drawer.body.removeAttribute('aria-busy');
      }
    };

    const closeDrawer = () => {
      const last = drawerId;
      drawerCtl?.abort();
      drawerId = '';
      pushedOpen = false;
      view.setOpen('');
      if (drawer?.dialog.open) {
        drawer.dialog.close();
        // Return focus to the row the operator was last reading.
        if (last) view.focusRow(last);
      }
    };
    cleanups.push(() => {
      drawerCtl?.abort();
      if (drawer) {
        if (drawer.dialog.open) drawer.dialog.close();
        drawer.dialog.remove();
      }
    });

    const syncRoute = (r) => {
      route = r;
      const id = r.query.event;
      if (isEventId(id)) openDrawer(id);
      else closeDrawer();
    };

    // A click on a row link pushes a history entry; Esc then goes back.
    tableSlot.addEventListener('click', (e) => {
      if (e.metaKey || e.ctrlKey || e.shiftKey) return;
      if (e.target.closest?.('[data-row-link]')) { pushedOpen = true; return; }
      // The whole row is the target, not only its summary link. Clicks on
      // other controls and drags that selected text keep their own meaning.
      if (e.target.closest?.('a, button, input, select, summary')) return;
      if (String(getSelection?.() ?? '')) return;
      e.target.closest?.('tr')?.querySelector('[data-row-link]')?.click();
    });

    // ---- Keyboard: j/k rows, Enter opens, o for full page --------------------
    const onKey = (e) => {
      if (e.defaultPrevented || e.metaKey || e.ctrlKey || e.altKey || isTypingTarget(e.target)) return;
      const k = e.key;
      if (drawer?.dialog.open) {
        if (k === 'j' || k === 'k') { e.preventDefault(); step(k === 'j' ? 1 : -1); }
        else if (k === 'o') { e.preventDefault(); location.hash = href('events', drawerId); }
        return;
      }
      if (document.querySelector('dialog[open]')) return;
      if (k === 'j' || k === 'k') {
        if (!view.size) return;
        e.preventDefault();
        view.setCursor(moveIndex(view.cursor, k === 'j' ? 1 : -1, view.size));
      }
    };
    document.addEventListener('keydown', onKey);
    cleanups.push(() => document.removeEventListener('keydown', onKey));

    const applyFilters = (next) => {
      const { filters: clean } = normalizeEventFilters(next);
      ctx.navigate(href('events', { ...clean, live: liveRequested ? '1' : '' }));
    };
    const liveToggle = h('a', { class: ['btn', liveRequested ? 'btn--primary' : ''], href: href('events', { ...filters, live: liveRequested ? '' : '1' }) },
      icon(liveRequested ? 'pause' : 'live'), liveRequested ? 'Stop live' : 'Go live');

    const active = EVENT_FILTER_KEYS.filter((k) => filters[k]);
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
        title: h('span', null, titleCount, ' matching'),
        meta: liveRequested ? 'Live: the stream is unfiltered, so these filters are re-applied in the browser.' : 'Newest first. Server-side filters apply. j and k move between rows.',
        flush: true, body: tableSlot, foot: pagerSlot,
      }));

    return {
      cleanup() {
        for (const fn of cleanups.splice(0)) fn();
        document.title = 'Events · AegisMesh';
      },
      update: syncRoute,
      mounted: () => syncRoute(route),
    };
  },
};
