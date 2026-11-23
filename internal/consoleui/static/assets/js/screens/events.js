import { h, mount } from '../lib/dom.js';
import { href, normalizeEventFilters, matchesEventFilters, EVENT_FILTER_KEYS, isEventId, withQuery } from '../lib/route.js';
import { CLASSIFICATIONS, SENSOR_KINDS, SEVERITIES, classificationMeta, severityLabel } from '../lib/taxonomy.js';
import { formatCount, localInputToRfc3339, rfc3339ToLocalInput } from '../lib/format.js';
import { RingBuffer, createLiveStream } from '../lib/stream.js';
import { createBatcher } from '../lib/batch.js';
import { moveIndex, isTypingTarget } from '../lib/keys.js';
import { pageHead, panel, selectField, inputField, empty, banner, pager, labelFor, errorState, filterChip, anchorPopover, openDialog, toast } from '../ui/components.js';
import { activeFilterChips, addFilterHref, describeFilter, FILTER_NAMES } from '../lib/filters.js';
import { loadViews, storeViews, addView, removeView, viewFilters } from '../lib/views.js';
import { icon } from '../ui/icons.js';
import { eventKey, parseEventKey, normalizeNodeFilter, nodeFilterOptions, originVisible, isNodeId } from '../lib/origin.js';
import { eventTableView, historyBanner, forwardedNote, notFoundInTenant } from './shared.js';
import { tenantInfo } from '../lib/tenant.js';
import { renderEventDetail } from './event.js';

const PAGE = 50;
const LIVE_CAP = 500;
// Rows kept in the DOM in live mode. Older rows are trimmed from the bottom
// so a long session never grows the page without bound.
const MAX_ROWS = 300;
const PER_FRAME = 40;

const FILTER_LABELS = {
  node: 'node', classification: 'classification', sensor: 'sensor', kind: 'kind', source: 'source', rule: 'rule',
  severity: 'severity', since: 'since', until: 'until', q: 'search',
};

// Query for the side panel: the event id plus, for forwarded evidence, its
// origin (`event_node`; `node` is already the list's filter).
const drawerQuery = (key) => {
  const { id, node } = parseEventKey(key);
  return { event: id, event_node: node };
};
const pageHref = (key) => {
  const { id, node } = parseEventKey(key);
  return node ? href('events', id, { node }) : href('events', id);
};

// The filter bar: search always visible, active filters as removable chips,
// saved views, and every other filter behind "All filters".
function filterForm(filters, sensors, onApply, { showOrigin = false, nodes = [], live = false, views } = {}) {
  const chips = activeFilterChips(filters, { live });
  const more = EVENT_FILTER_KEYS.filter((k) => k !== 'q' && filters[k]).length;
  const grid = h('div', { class: 'filters' },
    showOrigin ? selectField({ label: 'Node', name: 'node', value: filters.node || '', options: nodeFilterOptions(nodes, filters.node) }) : null,
    selectField({ label: 'Classification', name: 'classification', value: filters.classification || '', options: [['', 'Any'], ...CLASSIFICATIONS.map((c) => [c, classificationMeta(c).label])] }),
    selectField({ label: 'Minimum severity', name: 'severity', value: filters.severity || '', options: [['', 'Any (incl. no finding)'], ...SEVERITIES.map((s) => [s, `${severityLabel(s)} or higher`])] }),
    selectField({ label: 'Sensor', name: 'sensor', value: filters.sensor || '', options: [['', 'Any'], ...sensors.map((s) => [s.id, `${s.id} (${s.kind})`]), ...(filters.sensor && !sensors.some((s) => s.id === filters.sensor) ? [[filters.sensor, filters.sensor]] : [])] }),
    selectField({ label: 'Kind', name: 'kind', value: filters.kind || '', options: [['', 'Any'], ...SENSOR_KINDS.map((k) => [k, k.toUpperCase()])] }),
    inputField({ label: 'Source', name: 'source', value: filters.source || '', mono: true, placeholder: 'exact match', maxlength: 255 }),
    inputField({ label: 'Rule', name: 'rule', value: filters.rule || '', mono: true, placeholder: 'e.g. PI-001', maxlength: 64 }),
    inputField({ label: 'Since (UTC)', name: 'since', type: 'datetime-local', value: rfc3339ToLocalInput(filters.since) }),
    inputField({ label: 'Until (UTC)', name: 'until', type: 'datetime-local', value: rfc3339ToLocalInput(filters.until) }),
    h('div', { class: ['btn-row', 'filters__actions'] },
      h('button', { class: ['btn', 'btn--primary'], type: 'submit' }, icon('filter'), 'Apply filters')));
  const details = h('details', { class: 'filterbar__more' },
    h('summary', null, icon('chevron-right', { size: 'sm' }), 'All filters', more ? h('span', { class: 'filterbar__count' }, ` · ${more} set`) : null),
    grid);
  const form = h('form', { class: 'filterbar', 'aria-label': 'Event filters' },
    h('div', { class: 'filterbar__row' },
      h('div', { class: ['field', 'filterbar__search'] },
        h('label', { class: 'field__label', for: 'f-q' }, 'Search summaries, sources and rule ids'),
        h('span', { class: 'input-icon' },
          icon('search', { size: 'sm' }),
          h('input', { class: 'input', id: 'f-q', name: 'q', type: 'search', maxlength: 128, placeholder: 'e.g. /admin, 203.0.113, PI-001', prop: { value: filters.q || '' }, autocomplete: 'off', spellcheck: 'false', 'data-search': '', 'aria-keyshortcuts': '/' }),
          h('kbd', { class: 'input-icon__kbd', 'aria-hidden': 'true' }, '/'))),
      h('button', { class: 'btn', type: 'submit' }, 'Search'),
      views || null),
    h('div', { class: 'filterbar__chips', role: 'group', 'aria-label': 'Active filters' },
      chips.length
        ? [...chips.map(filterChip), h('a', { class: ['btn', 'btn--ghost', 'btn--sm'], href: href('events', { live: live ? '1' : '' }) }, 'Clear all')]
        : h('span', { class: 'muted' }, 'No filters: every stored event, newest first.')),
    details);
  form.addEventListener('submit', (e) => {
    e.preventDefault();
    const el = form.elements;
    onApply({
      node: el.node ? el.node.value : (filters.node || ''),
      classification: el.classification.value, severity: el.severity.value, sensor: el.sensor.value, kind: el.kind.value,
      source: el.source.value.trim(), rule: el.rule.value.trim(), q: el.q.value,
      since: localInputToRfc3339(el.since.value), until: localInputToRfc3339(el.until.value),
    });
  });
  return form;
}

// Saved views: a menu of filter sets kept in this browser, per tenant.
// Only non-evidence filters are stored (lib/views.js says why).
function viewsControl(ctx, filters, { live }) {
  const tenant = tenantInfo(ctx.session).active || 'default';
  const store = (() => {
    try {
      return globalThis.localStorage || null;
    } catch {
      return null;
    }
  })();
  let views = loadViews(store, tenant);
  const button = h('button', { class: 'btn', type: 'button', popovertarget: 'views-menu' }, icon('bookmark'), 'Views');
  const list = h('ul', { class: 'menu__list' });
  const saveBtn = h('button', { class: ['btn', 'btn--sm', 'btn--block', 'menu__action'], type: 'button' }, icon('plus', { size: 'sm' }), 'Save current filters…');
  const menu = h('div', { class: ['menu', 'views-menu'], id: 'views-menu', popover: 'auto', tabindex: '-1', 'aria-labelledby': 'views-menu-title' },
    h('p', { class: 'menu__title', id: 'views-menu-title' }, 'Saved views'),
    list, saveBtn,
    h('p', { class: 'menu__note' }, 'Stored in this browser only, for this tenant. Source and search filters are never saved: they are attacker-supplied evidence.'));
  const summary = (f) => Object.entries(f).map(([k, v]) => `${FILTER_NAMES[k] || k} ${describeFilter(k, v).text}`).join(' · ');
  const paint = () => {
    const savable = viewFilters(filters);
    saveBtn.disabled = !store || !Object.keys(savable.filters).length;
    saveBtn.title = !store ? 'This browser does not allow local storage' : (saveBtn.disabled ? 'Set a filter other than source or search first' : '');
    mount(list, views.length ? views.map((v) => {
      const remove = h('button', { class: ['btn', 'btn--ghost', 'btn--icon', 'btn--sm'], type: 'button', 'aria-label': `Delete view ${v.name}`, title: 'Delete view' }, icon('close', { size: 'sm' }));
      remove.addEventListener('click', () => {
        views = removeView(views, v.name);
        storeViews(store, tenant, views);
        paint();
        toast('ok', `Deleted view “${v.name}”.`);
      });
      return h('li', { class: 'views-menu__row' },
        h('a', { class: 'menu__item', href: href('events', { ...v.filters, live: live ? '1' : '' }) },
          h('span', { class: 'stack-tight' }, h('span', { class: 'menu__label' }, v.name), h('span', { class: 'views-menu__summary' }, summary(v.filters)))),
        remove);
    }) : h('li', { class: 'views-menu__empty' }, 'No saved views yet. Set some filters, then save them here.'));
  };
  saveBtn.addEventListener('click', async () => {
    menu.hidePopover?.();
    const { dropped } = viewFilters(filters);
    const name = await openDialog({
      title: 'Save these filters as a view',
      submitLabel: 'Save view',
      build: () => [
        inputField({ label: 'Name', name: 'viewname', maxlength: 48, required: true, hint: 'Shown only in this browser.' }),
        h('p', { class: 'muted' }, summary(viewFilters(filters).filters)),
        dropped.length ? h('p', { class: 'muted' }, `Not saved: ${dropped.map((k) => FILTER_NAMES[k].toLowerCase()).join(' and ')} (evidence never goes into browser storage).`) : null,
      ],
      onSubmit: async (form) => {
        const next = addView(views, form.elements.viewname.value, filters);
        if (!storeViews(store, tenant, next.views)) throw new Error('This browser refused to store the view (private mode or storage full).');
        views = next.views;
        return form.elements.viewname.value;
      },
    });
    if (name) {
      paint();
      toast('ok', 'View saved in this browser.');
    }
  });
  menu.addEventListener('click', (e) => { if (e.target.closest?.('a')) menu.hidePopover?.(); });
  anchorPopover(menu, button, { align: 'right' });
  paint();
  return [button, menu];
}

// ---- Side panel (event detail over the list) --------------------------------

export function createDrawer({ onRequestClose, onStep, onFull }) {
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
      full.setAttribute('href', pageHref(id));
    },
  };
}

export default {
  title: 'Events',
  async render(root, ctx) {
    const { filters, rejected } = normalizeEventFilters(ctx.route.query);
    const liveRequested = ctx.route.query.live === '1';
    // Fleet status decides whether rows carry an origin; the node list (hub
    // only) fills the Node filter. Neither failing blocks the list.
    const fleetP = ctx.api.fleet ? ctx.api.fleet({ signal: ctx.signal }).catch(() => null) : Promise.resolve(null);
    const nodesP = fleetP.then((f) => (f?.hub?.enabled && f.hub.accept_evidence === true && ctx.api.fleetNodes
      ? ctx.api.fleetNodes('', { signal: ctx.signal }).catch(() => null)
      : null));
    const [page, sensorsRes, node, fleet, nodesRes] = await Promise.all([
      ctx.api.events(filters, '', PAGE, { signal: ctx.signal }),
      ctx.api.sensors({ signal: ctx.signal }).catch(() => ({ sensors: [] })),
      ctx.api.node({ signal: ctx.signal }).catch(() => null),
      fleetP, nodesP,
    ]);

    let route = ctx.route;
    const firstRows = Array.isArray(page.events) ? page.events : [];
    let cursor = page.next_cursor || '';
    let total = Number(page.total_matched) || firstRows.length;
    let trimmed = 0;
    const showOrigin = originVisible({ fleet, events: firstRows, filter: filters.node });
    const fleetNodes = Array.isArray(nodesRes?.nodes) ? nodesRes.nodes : [];
    const seen = new Set(firstRows.map(eventKey));
    const held = new RingBuffer(LIVE_CAP);
    let paused = false;
    let hoverHold = false;
    let unread = 0;
    const cleanups = [];

    const rowHref = (ev) => withQuery(route, drawerQuery(eventKey(ev)));
    const filterHref = (key, value) => (filters[key] === value ? null : addFilterHref(filters, key, value, { live: liveRequested }));
    const view = eventTableView(firstRows, { caption: 'Matching events', rowHref, origin: showOrigin, filterHref });
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
            const fresh = (next.events || []).filter((ev) => !seen.has(eventKey(ev)));
            for (const ev of fresh) seen.add(eventKey(ev));
            view.append(fresh);
            cursor = next.next_cursor || '';
            paintPager();
          },
        }));
    };
    const emptyChips = activeFilterChips(filters, { live: liveRequested });
    const paintTable = () => mount(tableSlot, view.size
      ? [pill, view.el]
      : emptyChips.length
        ? empty('No events match these filters', 'Nothing in the index matches all of them. Remove one to widen the list:',
          h('div', { class: 'fchip-row' }, emptyChips.map(filterChip), h('a', { class: ['btn', 'btn--sm'], href: href('events', { live: liveRequested ? '1' : '' }) }, 'Clear all')), { icon: 'filter' })
        : empty('No event has been stored yet', liveRequested ? 'Live mode is on: new observations appear here as sensors record them.' : 'Sensors record observations here as they arrive. Decoys have no legitimate users, so an empty list is a normal state.',
          h('a', { class: 'btn', href: '#/guide?t=index' }, icon('guide', { size: 'sm' }), 'What the console can see'), { icon: 'inbox', art: true }));
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
      window.scrollTo({ top: Math.max(0, y), behavior: document.documentElement.hasAttribute('data-reduce-motion') || globalThis.matchMedia?.('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth' });
      clearUnread();
    });

    // events: newest first.
    const insert = (events) => {
      const fresh = events.filter((ev) => !seen.has(eventKey(ev)));
      if (!fresh.length) return;
      for (const ev of fresh) seen.add(eventKey(ev));
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
        // The server narrows the stream by origin; every other filter is
        // re-applied in the browser.
        url: filters.node ? `/api/v1/events/stream?node=${encodeURIComponent(filters.node)}` : undefined,
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
      else location.replace(withQuery(route, { event: '', event_node: '' }));
    };
    const step = (delta) => {
      const i = view.indexOf(drawerId);
      const j = moveIndex(i, delta, view.size);
      if (j < 0 || j === i) return;
      location.replace(withQuery(route, drawerQuery(view.ids[j])));
    };

    const openDrawer = async (id) => {
      if (!drawer) {
        drawer = createDrawer({
          onRequestClose: requestClose,
          onStep: step,
          onFull: (e) => { e.preventDefault(); location.hash = pageHref(drawerId); },
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
        const ref = parseEventKey(id);
        await renderEventDetail(next, ctx, ref.id, { node: ref.node, inDrawer: true, signal });
        if (signal.aborted) return;
        next.querySelector('#page-title')?.setAttribute('id', 'drawer-event-title');
        mount(drawer.body, ...next.childNodes);
        drawer.scroll.scrollTop = 0;
      } catch (err) {
        if (signal.aborted || err?.name === 'AbortError') return;
        const tenants = tenantInfo(ctx.session);
        mount(drawer.body, h('div', { class: 'panel' }, err?.code === 'not_found' && tenants.show ? notFoundInTenant(tenants) : errorState(err)));
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
      const origin = normalizeNodeFilter(r.query.event_node);
      if (isEventId(id)) openDrawer(isNodeId(origin) ? eventKey({ id, node: { id: origin } }) : id);
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
        else if (k === 'o') { e.preventDefault(); location.hash = pageHref(drawerId); }
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
        hint: 'Search or filter, open a row in the side panel (j/k to step), or follow new events live.',
        actions: liveToggle,
      }),
      historyBanner(node, { accepting: fleet?.hub?.accept_evidence === true }),
      fleet?.hub?.accept_evidence === true ? forwardedNote('list') : null,
      rejected.length ? banner('warn', 'Some filters were ignored', `These link parameters were not valid and were dropped: ${[...new Set(rejected)].map((k) => FILTER_LABELS[k]).join(', ')}.`) : null,
      panel({ title: 'Filters', body: filterForm(filters, sensorsRes.sensors || [], applyFilters, { showOrigin, nodes: fleetNodes, live: liveRequested, views: viewsControl(ctx, filters, { live: liveRequested }) }), meta: active.length ? `${active.length} active · server-side` : 'None active' }),
      liveBar,
      panel({
        primary: true,
        title: h('span', null, titleCount, ' matching'),
        meta: liveRequested
          ? (filters.node ? 'Live: the server narrows the stream to this origin; the other filters are re-applied in the browser.' : 'Live: the stream is unfiltered, so these filters are re-applied in the browser.')
          : 'Newest first. j and k move between rows, Enter opens one. Select a value to filter by it.',
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
