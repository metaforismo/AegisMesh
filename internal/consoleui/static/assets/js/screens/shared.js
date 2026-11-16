// Pieces shared by several screens.

import { h } from '../lib/dom.js';
import { href, isEventId } from '../lib/route.js';
import { PRIORITIES } from '../lib/taxonomy.js';
import { formatClock, formatDateTime } from '../lib/format.js';
import { describeOrigin, eventKey, originQuery, originVisible } from '../lib/origin.js';
import { icon } from '../ui/icons.js';
import { banner, table, sevChip, clsChip, evidence, link, chip, openDialog, inputField, selectField, labelFor, badge, empty } from '../ui/components.js';

// Empty state for a 404 while tenants are in play. Another tenant's objects
// answer exactly like absent ones (no existence probe crosses tenants), so
// the console cannot tell which it was and says both. `info` is tenantInfo().
export function notFoundInTenant(info) {
  return empty(
    `Not found in tenant ${info.active}`,
    `This session acts in tenant ${info.active} only. The link may point at something in another tenant, which answers exactly like something that does not exist, or the item aged out of the in-memory index.${info.canSwitch ? ' To look elsewhere, switch tenant from the top bar.' : ''}`,
    link(href('overview'), 'Go to the overview'),
    { icon: 'tenant' });
}

// `accepting`: this node is a hub that accepts forwarded evidence. Such a hub
// reports history "unavailable" because forwarded copies are indexed live
// only; the forwarded-evidence note on the same screen already says so, so
// the encryption explanation is shown only when storage is encrypted.
export function historyBanner(node, { accepting = false } = {}) {
  const history = node?.index?.history;
  if (history === 'unavailable' && accepting && node?.storage?.encrypted !== true) return null;
  if (history === 'truncated') {
    return banner('warn', 'Index history is truncated',
      h('p', null, 'The in-memory index holds the newest events only. Older evidence is still on disk; use ', h('code', null, 'aegismesh inspect'), ' to read it.'));
  }
  if (history === 'unavailable') {
    return banner('warn', 'Showing events since process start only',
      'Evidence at rest is encrypted and the runtime holds no read identity, so stored history cannot be indexed.');
  }
  return null;
}

// ---- Origin (forwarded evidence on a hub) -----------------------------------

// Full-page link to one event, pinned to its origin.
export function eventHref(ev) {
  const q = originQuery(ev);
  return q.node ? href('events', ev.id, q) : href('events', ev.id);
}

// Whether this node's lists should carry an origin column, and the fleet
// status that decided it. /fleet is cheap and cached; a failure only means
// the column is decided by the rows themselves.
export async function originContext(ctx, signal = ctx.signal) {
  const fleet = ctx.api.fleet ? await ctx.api.fleet({ signal }).catch(() => null) : null;
  return { fleet, accepting: fleet?.hub?.accept_evidence === true };
}

// "This node", or the forwarding node's name with its short id. Node names
// come from the hub's registry and are shown as identifiers, never markup.
// `stack` puts the short id under the name, for dense tables.
export function originLabel(node, { link: withLink = true, stack = false } = {}) {
  const o = describeOrigin(node);
  const cls = ['origin', stack ? 'origin--stack' : ''];
  if (o.local) return h('span', { class: [...cls, 'origin--local'] }, 'This node');
  const parts = [h('code', { class: 'origin__name' }, o.name), o.short ? h('span', { class: ['muted', 'origin__id'] }, o.short) : null];
  return withLink && o.linkable
    ? h('a', { class: cls, href: href('fleet', 'nodes', o.id), title: `${o.name} · fleet node ${o.id}` }, ...parts)
    : h('span', { class: cls, title: o.id || null }, ...parts);
}

// One compact line wherever a hub's lists or counts mix in forwarded
// evidence. It states the limits rather than hiding them in docs.
export function forwardedNote(where = 'list') {
  const lead = where === 'counts'
    ? 'Counts on this hub include evidence forwarded by enrolled nodes.'
    : 'This hub also lists evidence forwarded by enrolled nodes.';
  return h('p', { class: 'origin-note' }, icon('info', { size: 'sm' }),
    h('span', null, `${lead} Forwarding is experimental and best effort: losses are counted per node on the Fleet page, forwarded history starts at the hub’s last restart, and each node’s own store remains the authoritative record.`));
}

// Event table used by the events list, source detail, related events and
// investigations. `extra` appends columns (e.g. a detach button). `origin`:
// true or false forces the origin column; 'auto' (default) shows it when any
// row was forwarded from another node.
export function eventTable(events, opts = {}) {
  return eventTableView(events, opts).el;
}

function eventColumns({ showDate = true, extra = [], rowHref, origin = false }) {
  return [
    { label: 'Time (UTC)', className: 'nowrap', cell: (ev) => h('time', { datetime: ev.time, title: formatDateTime(ev.time) }, showDate ? formatDateTime(ev.time).replace(' UTC', '') : formatClock(ev.time)) },
    ...(origin ? [{ label: 'Origin', className: 'nowrap', cell: (ev) => originLabel(ev.node, { stack: true }) }] : []),
    { label: 'Class', cell: (ev) => clsChip(ev.classification) },
    { label: 'Severity', cell: (ev) => sevChip(ev.severity) },
    { label: 'Sensor', cell: (ev) => h('span', { class: 'nowrap' }, h('code', null, ev.sensor?.id ?? '—'), ' ', ev.sensor?.kind ? chip(ev.sensor.kind) : null) },
    { label: 'Source', className: 'nowrap', cell: (ev) => (ev.source ? link(href('sources', ev.source), evidence(ev.source, { max: 24 })) : h('span', { class: 'muted' }, 'unknown')) },
    {
      label: 'Summary', className: 'col-summary',
      cell: (ev) => (isEventId(ev.id)
        ? h('a', { href: rowHref ? rowHref(ev) : eventHref(ev), class: 'row-open', 'data-row-link': '' }, evidence(ev.summary, { max: 160 }))
        : evidence(ev.summary, { max: 160 })),
    },
    { label: 'Rules', cell: (ev) => ruleChips(ev.rule_ids) },
    ...extra,
  ];
}

// Bring a row into view vertically only. (scrollIntoView would also scroll
// the page sideways when the table is wider than the viewport.)
function revealRow(tr) {
  if (!tr?.getBoundingClientRect) return;
  const r = tr.getBoundingClientRect();
  const top = (document.querySelector('.shell__top')?.offsetHeight || 0) + (tr.closest('table')?.tHead?.offsetHeight || 0);
  if (r.top < top) window.scrollBy(0, r.top - top - 8);
  else if (r.bottom > window.innerHeight) window.scrollBy(0, r.bottom - window.innerHeight + 8);
}

// The event table as a live view: rows can be prepended (live mode),
// appended (load more) and trimmed from the bottom without rebuilding the
// table, and a keyboard cursor / open-row marker can be moved. Rows are
// keyed by eventKey (id plus origin): ids are unique only within an origin.
export function eventTableView(events, { caption = 'Events', newIds, origin = 'auto', ...opts } = {}) {
  const withOrigin = origin === 'auto' ? originVisible({ events }) : Boolean(origin);
  const columns = eventColumns({ ...opts, origin: withOrigin });
  const ids = [];
  const byId = new Map();
  const buildRow = (ev, isNew) => {
    const key = eventKey(ev);
    const tr = h('tr', { class: isNew ? 'is-new' : null, 'data-id': isEventId(ev.id) ? key : null },
      columns.map((c) => h('td', { class: [c.num ? 'num' : '', c.className || ''], 'data-label': c.label }, c.cell(ev))));
    if (isEventId(ev.id)) byId.set(key, tr);
    return tr;
  };
  const tbody = h('tbody', null, events.map((ev) => {
    ids.push(eventKey(ev));
    return buildRow(ev, newIds?.has(eventKey(ev)));
  }));
  const el = h('div', { class: 'table-wrap' },
    h('table', { class: ['table', 'table--stack', withOrigin ? 'table--origin' : ''] },
      h('caption', { class: 'visually-hidden' }, caption),
      h('thead', null, h('tr', null, columns.map((c) => h('th', { scope: 'col', class: [c.num ? 'num' : '', c.className || ''] }, c.label)))),
      tbody));
  let cursor = -1;
  let openId = '';
  const rowAt = (i) => byId.get(ids[i]);

  return {
    el,
    get ids() { return ids; },
    get size() { return ids.length; },
    // events: newest first. Only the first `highlight` rows get the wash.
    prepend(list, { highlight = 20 } = {}) {
      const frag = document.createDocumentFragment();
      list.forEach((ev, i) => frag.appendChild(buildRow(ev, i < highlight)));
      tbody.insertBefore(frag, tbody.firstChild);
      ids.unshift(...list.map((ev) => eventKey(ev)));
      if (cursor >= 0) cursor += list.length;
    },
    append(list) {
      for (const ev of list) {
        tbody.appendChild(buildRow(ev, false));
        ids.push(eventKey(ev));
      }
    },
    // Drop rows beyond `max` from the bottom; returns how many were dropped.
    trim(max) {
      let dropped = 0;
      while (ids.length > max) {
        const id = ids.pop();
        byId.get(id)?.remove();
        byId.delete(id);
        dropped++;
      }
      if (cursor >= ids.length) cursor = ids.length - 1;
      return dropped;
    },
    indexOf: (id) => ids.indexOf(id),
    get cursor() { return cursor; },
    setCursor(i, { focus = true } = {}) {
      rowAt(cursor)?.classList.remove('is-cursor');
      cursor = i;
      const tr = rowAt(i);
      if (!tr) return;
      tr.classList.add('is-cursor');
      revealRow(tr);
      if (focus) tr.querySelector('[data-row-link]')?.focus({ preventScroll: true });
    },
    setOpen(id) {
      if (openId) byId.get(openId)?.classList.remove('is-open');
      openId = id || '';
      const tr = openId ? byId.get(openId) : null;
      tr?.classList.add('is-open');
      revealRow(tr);
      const i = ids.indexOf(openId);
      if (i >= 0) {
        rowAt(cursor)?.classList.remove('is-cursor');
        cursor = i;
      }
    },
    focusRow(id) {
      byId.get(id)?.querySelector('[data-row-link]')?.focus({ preventScroll: true });
    },
  };
}

export function ruleChips(ids) {
  const list = Array.isArray(ids) ? ids : [];
  if (!list.length) return h('span', { class: 'muted' }, '—');
  return h('span', { class: 'chip-row' }, list.slice(0, 4).map((id) => chip(id, { mono: true })), list.length > 4 ? chip(`+${list.length - 4}`) : null);
}

const STATUS_BADGE = { open: 'info', monitoring: 'warn', closed: 'neutral' };

export function statusBadge(status) {
  return badge(STATUS_BADGE[status] || 'neutral', labelFor(status || 'unknown'));
}

export function priorityChip(priority) {
  return chip(`${labelFor(priority || 'unknown')} priority`);
}

export async function newInvestigationDialog(ctx, { eventIds = [] } = {}) {
  return openDialog({
    title: eventIds.length ? 'New investigation with this evidence' : 'New investigation',
    submitLabel: 'Create',
    build: () => [
      inputField({ label: 'Title', name: 'title', maxlength: 200, required: true, hint: 'Operator text. Avoid pasting secrets: titles appear in lists for every viewer.' }),
      selectField({ label: 'Priority', name: 'priority', value: 'medium', options: PRIORITIES.map((p) => [p, labelFor(p)]) }),
      eventIds.length ? h('p', { class: 'muted' }, `${eventIds.length === 1 ? 'One event' : `${eventIds.length} events`} will be attached.`) : null,
    ],
    onSubmit: async (form) => {
      const title = form.elements.title.value.trim();
      if (!title) throw new Error('A title is required.');
      return ctx.api.createInvestigation({ title, priority: form.elements.priority.value, event_ids: eventIds });
    },
  });
}

// Attach one event to an existing investigation (or start a new one).
export async function attachDialog(ctx, eventId) {
  const list = await ctx.api.investigations('', { signal: ctx.signal });
  const candidates = (list.investigations || []).filter((i) => i.status !== 'closed');
  if (!candidates.length) return newInvestigationDialog(ctx, { eventIds: [eventId] });
  return openDialog({
    title: 'Add to investigation',
    submitLabel: 'Attach',
    build: () => [
      selectField({
        label: 'Investigation', name: 'inv', value: candidates[0].id,
        options: candidates.map((i) => [i.id, `${i.title} (${labelFor(i.status)})`]),
      }),
      h('p', { class: 'muted' }, 'Closed investigations are not listed. Attaching records an audit entry.'),
    ],
    onSubmit: (form) => ctx.api.attachEvent(form.elements.inv.value, eventId),
  });
}
