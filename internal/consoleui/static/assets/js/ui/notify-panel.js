// The bell's panel: the newest notifications grouped by day, All or
// Unread, mark one or all as read, and the ways out (the Inbox, the
// notification settings). Loaded on first open. Opened many times a day,
// so it never animates.

import { h, mount } from '../lib/dom.js';
import { describeError } from '../lib/api.js';
import { moveIndex } from '../lib/keys.js';
import { formatCount } from '../lib/format.js';
import { toast, empty } from './components.js';
import { icon } from './icons.js';
import { notificationGroups } from './notify-list.js';
import { FIRST_PAGE } from './bell.js';

let filter = 'all'; // the panel's own All / Unread choice, for this page

export function renderPanel(panel, { inbox, api, close }) {
  const status = h('p', { class: 'notify__status', role: 'status' });
  const count = h('span', { class: 'notify__count' });
  const body = h('div', { class: 'notify__body' });
  const markAll = h('button', { class: ['btn', 'btn--sm'], type: 'button' }, icon('check', { size: 'sm' }), 'Mark all as read');
  const closeBtn = h('button', { class: ['btn', 'btn--ghost', 'btn--sm', 'btn--icon', 'notify__close'], type: 'button', 'aria-label': 'Close notifications' }, icon('close', { size: 'sm' }));
  const seg = (value, label) => {
    const b = h('button', { class: 'segmented__btn', type: 'button', 'aria-pressed': String(filter === value), 'data-filter': value }, label);
    b.addEventListener('click', () => {
      filter = value;
      for (const x of segs) x.setAttribute('aria-pressed', String(x.getAttribute('data-filter') === filter));
      draw();
    });
    return b;
  };
  const segs = [seg('all', 'All'), seg('unread', 'Unread')];

  const failed = (err) => toast('error', `Could not mark as read: ${describeError(err).detail} It is still unread.`);
  const onRead = (it) => inbox.markRead([it.id]).catch(failed);
  const onOpen = (it) => {
    if (!it.read) inbox.markRead([it.id]).catch(failed);
    close();
  };
  markAll.addEventListener('click', () => {
    markAll.disabled = true;
    inbox.markAll().then(() => { status.textContent = 'Everything is marked as read.'; }, failed).finally(() => { markAll.disabled = false; });
  });
  closeBtn.addEventListener('click', () => close());

  function draw() {
    const { items, unread } = inbox.state();
    const n = Number.isInteger(unread) ? unread : items.filter((x) => !x.read).length;
    count.textContent = n ? `${formatCount(n)} unread` : 'Nothing unread';
    markAll.hidden = !n;
    const shown = filter === 'unread' ? items.filter((x) => !x.read) : items;
    mount(body, shown.length
      ? notificationGroups(shown, { headingLevel: 'h3', onRead, onOpen })
      : empty(filter === 'unread' ? 'Nothing unread' : 'No notifications yet',
        filter === 'unread' ? 'You have read everything here. The inbox keeps the rest.' : 'Findings of high severity, planted credentials coming back, new campaigns and changes to your account appear here.',
        null, { icon: 'bell' }));
  }

  // Arrow keys move between the rows' links, like a menu; Tab still
  // walks every control.
  // Installed once per panel element; every open redraws its content.
  if (!panel.hasAttribute('data-keys')) {
    panel.setAttribute('data-keys', '');
    panel.addEventListener('keydown', (e) => {
      if (e.key !== 'ArrowDown' && e.key !== 'ArrowUp') return;
      const links = [...panel.querySelectorAll('[data-notify-link]')];
      if (!links.length) return;
      e.preventDefault();
      const i = links.indexOf(globalThis.document.activeElement);
      links[moveIndex(i, e.key === 'ArrowDown' ? 1 : -1, links.length)]?.focus();
    });
  }

  mount(panel,
    h('div', { class: 'notify__head' },
      h('h2', { class: 'notify__title' }, 'Notifications'),
      count,
      closeBtn),
    h('div', { class: 'notify__bar' },
      h('div', { class: 'segmented', role: 'group', 'aria-label': 'Show' }, segs),
      markAll),
    status,
    body,
    h('div', { class: 'notify__foot' },
      h('a', { class: ['btn', 'btn--sm'], href: '#/inbox' }, icon('inbox', { size: 'sm' }), 'Open the inbox'),
      h('a', { class: 'notify__settings', href: '#/settings/notifications' }, icon('settings', { size: 'sm' }), 'Notification settings')));
  for (const a of panel.querySelectorAll('.notify__foot a')) a.addEventListener('click', () => close());
  draw();

  // Fresh on every open: live events carry no summary or link.
  api.notifications({ limit: FIRST_PAGE }).then((res) => inbox.load(res), (err) => {
    status.textContent = `Could not refresh: ${describeError(err).detail} Showing what arrived while this page was open.`;
  });
  return draw;
}
