// Inbox (#/inbox): every in-console notification this principal may see,
// grouped by day, with filters by kind, minimum severity and unread, and
// keyboard navigation (j/k move, Enter opens, x marks read). It shares the
// bell's store, so marking here updates the badge and the panel.
//
// Kind and unread are asked of the server (it pages the inbox newest
// first); the minimum severity applies to what is loaded, and the page
// says so. Filtered views use their own list and pass the server's unread
// count back to the bell.

import { h, mount } from '../lib/dom.js';
import { describeError } from '../lib/api.js';
import { withQuery } from '../lib/route.js';
import { SEVERITIES } from '../lib/taxonomy.js';
import { moveIndex, isTypingTarget } from '../lib/keys.js';
import { formatCount } from '../lib/format.js';
import { createInbox, normalizeInboxFilters, matchesInbox, NOTIFICATION_KINDS, KIND_META } from '../lib/notify.js';
import { pageHead, panel, empty, toast, pager, segmented, selectField, labelFor, LIST_CAP } from '../ui/components.js';
import { notificationGroups } from '../ui/notify-list.js';
import { icon } from '../ui/icons.js';

const PAGE = 100;

export default {
  title: 'Inbox',
  async render(root, ctx) {
    const f = normalizeInboxFilters(ctx.route.query);
    const serverQuery = { kind: f.kind || undefined, unread: f.unread ? '1' : undefined };
    const narrowed = Boolean(f.kind || f.unread);
    // The unfiltered view shares the bell's store; a narrowed one keeps its
    // own list, and its unread count (always the whole inbox's) goes to the bell.
    const inbox = !narrowed && ctx.inbox ? ctx.inbox : createInbox({ api: ctx.api });
    const forwardUnread = narrowed && ctx.inbox ? inbox.subscribe((st) => ctx.inbox.setUnread(st.unread)) : () => {};
    inbox.load(await ctx.api.notifications({ limit: PAGE, ...serverQuery }, { signal: ctx.signal }));

    const go = (patch) => ctx.navigate(withQuery(ctx.route, patch));
    const status = h('p', { class: 'visually-hidden', role: 'status' });
    const listSlot = h('div', { class: 'inbox-list' });
    const pagerSlot = h('div');
    const metaText = h('span');
    const markAll = h('button', { class: 'btn', type: 'button' }, icon('check', { size: 'sm' }), 'Mark all as read');
    const failed = (err) => toast('error', `Could not mark as read: ${describeError(err).detail} It is still unread.`);
    const onRead = (it) => inbox.markRead([it.id]).then(() => { status.textContent = `Marked as read: ${it.title}`; }, failed);
    const onOpen = (it) => { if (!it.read) inbox.markRead([it.id]).catch(failed); };
    markAll.addEventListener('click', () => {
      markAll.disabled = true;
      inbox.markAll().then(() => { status.textContent = 'Everything is marked as read.'; }, failed).finally(() => { markAll.disabled = false; });
    });

    let focusedId = '';
    function draw() {
      const { items, unread, next } = inbox.state();
      const shown = items.filter((it) => matchesInbox(it, f));
      const filtered = Boolean(f.kind || f.severity || f.unread);
      metaText.textContent = f.severity
        ? `${formatCount(shown.length)} of the ${formatCount(items.length)} loaded are ${labelFor(f.severity).toLowerCase()} or above.${next ? ' Load more to look further back.' : ''}`
        : filtered ? `${Number.isInteger(unread) ? `${formatCount(unread)} unread in the inbox. ` : ''}Newest first, grouped by day.`
        : `${Number.isInteger(unread) ? `${formatCount(unread)} unread. ` : ''}Newest first, grouped by day.`;
      markAll.hidden = !unread;
      mount(listSlot, shown.length
        ? notificationGroups(shown, { headingLevel: 'h3', onRead, onOpen })
        : empty(filtered ? 'Nothing matches these filters' : 'No notifications yet',
          filtered ? 'Clear a filter, or load older notifications.' : 'Findings of high severity, planted credentials coming back, agent canaries, new campaigns, posture changes and changes to your account appear here.',
          filtered ? h('a', { class: 'btn', href: '#/inbox' }, 'Clear filters') : null, { icon: 'bell' }));
      for (const li of listSlot.querySelectorAll('.notify-item')) li.setAttribute('tabindex', '-1');
      mount(pagerSlot, pager({
        shown: items.length, hasMore: Boolean(next), cap: LIST_CAP,
        capText: 'The inbox stops here. Older notifications stay on the server until its bounded inbox replaces them.',
        onMore: async () => {
          inbox.load(await ctx.api.notifications({ limit: PAGE, cursor: next, ...serverQuery }, { signal: ctx.signal }), { append: true });
        },
      }));
      if (focusedId) listSlot.querySelector(`[data-notify-id="${focusedId}"]`)?.focus({ preventScroll: true });
    }
    const unsubscribe = inbox.subscribe(() => draw());

    // j/k between rows, Enter opens the focused one, x marks it read.
    const rows = () => [...listSlot.querySelectorAll('.notify-item')];
    const onKey = (e) => {
      if (e.defaultPrevented || e.metaKey || e.ctrlKey || e.altKey || isTypingTarget(e.target) || e.target?.closest?.('.menu') || globalThis.document.querySelector('dialog[open]')) return;
      const list = rows();
      if (!list.length) return;
      const current = e.target?.closest?.('.notify-item');
      const i = list.indexOf(current);
      if (e.key === 'j' || e.key === 'k') {
        e.preventDefault();
        const row = list[moveIndex(i, e.key === 'j' ? 1 : -1, list.length)];
        focusedId = row?.getAttribute('data-notify-id') || '';
        row?.focus();
        row?.scrollIntoView({ block: 'nearest' });
        return;
      }
      if (!current || e.target !== current) return;
      const it = inbox.state().items.find((x) => x.id === current.getAttribute('data-notify-id'));
      if (!it) return;
      if (e.key === 'Enter' && it.href) {
        e.preventDefault();
        onOpen(it);
        ctx.navigate(it.href);
      } else if (e.key === 'x' && !it.read) {
        e.preventDefault();
        onRead(it);
      }
    };
    globalThis.document.addEventListener('keydown', onKey);
    listSlot.addEventListener('focusin', (e) => {
      const row = e.target?.closest?.('.notify-item');
      if (row) focusedId = row.getAttribute('data-notify-id') || '';
    });

    const kindField = selectField({
      label: 'Kind', name: 'kind', value: f.kind,
      options: [['', 'All kinds'], ...NOTIFICATION_KINDS.map((k) => [k, KIND_META[k].name])],
      onChange: (v) => go({ kind: v }),
    });
    const sevField = selectField({
      label: 'Minimum severity', name: 'severity', value: f.severity,
      options: [['', 'Any severity'], ...SEVERITIES.map((s) => [s, labelFor(s)])],
      onChange: (v) => go({ severity: v }),
    });
    draw();
    mount(root,
      pageHead({
        title: 'Inbox',
        subtitle: 'Notices from this console: high-severity findings, planted credentials coming back, agent canaries, new campaigns, posture changes and your account. They stay in the console; nothing is sent anywhere.',
        hint: 'j and k move between notifications, Enter opens one, x marks it as read.',
        actions: [markAll, h('a', { class: 'btn', href: '#/settings/notifications' }, icon('settings', { size: 'sm' }), 'Notification settings')],
      }),
      h('div', { class: 'filter-bar inbox-filters' },
        segmented({ label: 'Show', options: [['', 'All'], ['1', 'Unread']], value: f.unread ? '1' : '', onChange: (v) => go({ unread: v }) }),
        kindField, sevField),
      panel({ title: 'Notifications', meta: metaText, flush: true, body: [status, listSlot], foot: pagerSlot }));

    return {
      cleanup() {
        unsubscribe();
        forwardUnread();
        globalThis.document.removeEventListener('keydown', onKey);
      },
    };
  },
};
