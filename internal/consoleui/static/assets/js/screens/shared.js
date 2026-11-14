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
export function eventTable(events, { caption = 'Events', showDate = true, extra = [], newIds } = {}) {
  return table({
    caption,
    rowClass: newIds ? (ev) => (newIds.has(ev.id) ? 'is-new' : null) : undefined,
    columns: [
      { label: 'Time (UTC)', className: 'nowrap', cell: (ev) => h('time', { datetime: ev.time, title: formatDateTime(ev.time) }, showDate ? formatDateTime(ev.time).replace(' UTC', '') : formatClock(ev.time)) },
      { label: 'Class', cell: (ev) => clsChip(ev.classification) },
      { label: 'Severity', cell: (ev) => sevChip(ev.severity) },
      { label: 'Sensor', cell: (ev) => h('span', { class: 'nowrap' }, h('code', null, ev.sensor?.id ?? '—'), ' ', ev.sensor?.kind ? chip(ev.sensor.kind) : null) },
      { label: 'Source', className: 'nowrap', cell: (ev) => (ev.source ? link(href('sources', ev.source), evidence(ev.source, { max: 32 })) : h('span', { class: 'muted' }, 'unknown')) },
      { label: 'Summary', className: 'col-summary', cell: (ev) => (isEventId(ev.id) ? link(href('events', ev.id), evidence(ev.summary, { max: 160 })) : evidence(ev.summary, { max: 160 })) },
      { label: 'Rules', cell: (ev) => ruleChips(ev.rule_ids) },
      ...extra,
    ],
    rows: events,
  });
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
