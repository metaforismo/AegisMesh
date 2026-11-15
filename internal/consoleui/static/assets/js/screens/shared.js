// Pieces shared by several screens.

import { h } from '../lib/dom.js';
import { href, isEventId } from '../lib/route.js';
import { PRIORITIES } from '../lib/taxonomy.js';
import { formatClock, formatDateTime } from '../lib/format.js';
import { banner, table, sevChip, clsChip, evidence, link, chip, openDialog, inputField, selectField, labelFor, badge } from '../ui/components.js';

export function historyBanner(node) {
  const history = node?.index?.history;
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

// Event table used by the events list, source detail, related events and
// investigations. `extra` appends columns (e.g. a detach button).
export function eventTable(events, opts = {}) {
  return eventTableView(events, opts).el;
}

function eventColumns({ showDate = true, extra = [], rowHref }) {
  return [
    { label: 'Time (UTC)', className: 'nowrap', cell: (ev) => h('time', { datetime: ev.time, title: formatDateTime(ev.time) }, showDate ? formatDateTime(ev.time).replace(' UTC', '') : formatClock(ev.time)) },
    { label: 'Class', cell: (ev) => clsChip(ev.classification) },
    { label: 'Severity', cell: (ev) => sevChip(ev.severity) },
    { label: 'Sensor', cell: (ev) => h('span', { class: 'nowrap' }, h('code', null, ev.sensor?.id ?? '—'), ' ', ev.sensor?.kind ? chip(ev.sensor.kind) : null) },
    { label: 'Source', className: 'nowrap', cell: (ev) => (ev.source ? link(href('sources', ev.source), evidence(ev.source, { max: 32 })) : h('span', { class: 'muted' }, 'unknown')) },
    {
      label: 'Summary', className: 'col-summary',
      cell: (ev) => (isEventId(ev.id)
        ? h('a', { href: rowHref ? rowHref(ev) : href('events', ev.id), class: 'row-open', 'data-row-link': '' }, evidence(ev.summary, { max: 160 }))
        : evidence(ev.summary, { max: 160 })),
    },
    { label: 'Rules', cell: (ev) => ruleChips(ev.rule_ids) },
    ...extra,
  ];
}

// The event table as a live view: rows can be prepended (live mode),
// appended (load more) and trimmed from the bottom without rebuilding the
// table, and a keyboard cursor / open-row marker can be moved.
export function eventTableView(events, { caption = 'Events', newIds, ...opts } = {}) {
  const columns = eventColumns(opts);
  const ids = [];
  const byId = new Map();
  const buildRow = (ev, isNew) => {
    const tr = h('tr', { class: isNew ? 'is-new' : null, 'data-id': isEventId(ev.id) ? ev.id : null },
      columns.map((c) => h('td', { class: [c.num ? 'num' : '', c.className || ''], 'data-label': c.label }, c.cell(ev))));
    if (isEventId(ev.id)) byId.set(ev.id, tr);
    return tr;
  };
  const tbody = h('tbody', null, events.map((ev) => {
    ids.push(ev.id);
    return buildRow(ev, newIds?.has(ev.id));
  }));
  const el = h('div', { class: 'table-wrap' },
    h('table', { class: ['table', 'table--stack'] },
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
      ids.unshift(...list.map((ev) => ev.id));
      if (cursor >= 0) cursor += list.length;
    },
    append(list) {
      for (const ev of list) {
        tbody.appendChild(buildRow(ev, false));
        ids.push(ev.id);
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
      tr.scrollIntoView({ block: 'nearest' });
      if (focus) tr.querySelector('[data-row-link]')?.focus({ preventScroll: true });
    },
    setOpen(id) {
      if (openId) byId.get(openId)?.classList.remove('is-open');
      openId = id || '';
      const tr = openId ? byId.get(openId) : null;
      tr?.classList.add('is-open');
      tr?.scrollIntoView({ block: 'nearest' });
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
