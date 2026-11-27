// Notification rows and the day-grouped list, shared by the bell's panel
// and the Inbox screen. Every string from the server is a Text node; a row
// links only to a route lib/notify.js validated.

import { h } from '../lib/dom.js';
import { KIND_META, groupByDay } from '../lib/notify.js';
import { formatCount } from '../lib/format.js';
import { sevChip, timeEl } from './components.js';
import { icon } from './icons.js';

// The kind's glyph beside its word: a shape, never colour alone.
export function kindMark(kind, { word = true } = {}) {
  const meta = KIND_META[kind];
  if (!meta) return null;
  return h('span', { class: ['nkind', `nkind--${kind}`], title: meta.name },
    icon(meta.icon, { size: 'sm' }),
    word ? h('span', { class: 'nkind__word' }, meta.label) : h('span', { class: 'visually-hidden' }, meta.label));
}

// One notification. `onOpen(it)` runs before the link navigates (marks it
// read); `onRead(it)` marks it read without leaving.
export function notificationRow(it, { onOpen, onRead, now } = {}) {
  const unread = !it.read;
  const title = it.href
    ? h('a', { class: 'notify-item__title', href: it.href, 'data-notify-link': '' }, unread ? h('span', { class: 'visually-hidden' }, 'Unread: ') : null, it.title)
    : h('span', { class: 'notify-item__title' }, unread ? h('span', { class: 'visually-hidden' }, 'Unread: ') : null, it.title);
  if (it.href && onOpen) title.addEventListener('click', () => onOpen(it));
  let mark = null;
  if (unread && onRead) {
    mark = h('button', { class: ['btn', 'btn--ghost', 'btn--sm', 'btn--icon', 'notify-item__read'], type: 'button', 'aria-label': `Mark as read: ${it.title}`, title: 'Mark as read' }, icon('check', { size: 'sm' }));
    mark.addEventListener('click', (e) => {
      e.preventDefault();
      onRead(it);
    });
  }
  return h('li', { class: ['notify-item', unread ? 'is-unread' : ''], 'data-notify-id': it.id },
    h('span', { class: 'notify-item__dot', 'aria-hidden': 'true' }),
    h('div', { class: 'notify-item__body' },
      h('p', { class: 'notify-item__meta' },
        kindMark(it.kind),
        sevChip(it.severity),
        it.created_at ? timeEl(it.created_at, { relative: true, now }) : null,
        it.group_count > 1 ? h('span', { class: 'notify-item__count', title: 'Repeats within 10 minutes are counted here rather than listed again' }, `${formatCount(it.group_count)} times`) : null),
      title,
      it.summary ? h('p', { class: 'notify-item__summary' }, it.summary) : null),
    mark);
}

// Day-grouped list: a heading per day (in the chosen time zone), newest
// first. `headingLevel` follows where the list sits on the page.
export function notificationGroups(items, { headingLevel = 'h3', now = Date.now(), ...row } = {}) {
  return groupByDay(items, now).map((g) => h('section', { class: 'notify-day', 'aria-label': g.label },
    h(headingLevel, { class: 'notify-day__label' }, g.label),
    h('ul', { class: 'notify-list' }, g.items.map((it) => notificationRow(it, { ...row, now })))));
}
