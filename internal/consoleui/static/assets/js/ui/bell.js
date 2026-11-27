// The notification bell in the top bar: an unread count, a quiet live
// connection, and the panel (a native popover on desktop, full screen on
// phones; ui/notify-panel.js, loaded on first open).
//
// Quiet by design. The badge changes number without moving or flashing;
// arrivals are announced to assistive tech once per quiet spell, never per
// item; the only toast is one subtle notice for a critical item while the
// tab is visible, at most once a minute, unless the operator turned it off.
// An older server (404 on /notifications) gets no bell and no errors.

import { h } from '../lib/dom.js';
import { createInbox, createAnnouncer, shouldToast, readToastPref, badgeText, bellLabel } from '../lib/notify.js';
import { createLiveStream } from '../lib/stream.js';
import { isMissingEndpoint } from '../lib/insight.js';
import { icon } from './icons.js';
import { toast } from './components.js';

export const FIRST_PAGE = 30;
export const POLL_MS = 60000;
// A stream that never opened after this many attempts (a server with the
// inbox but without its stream) gives way to polling.
export const STREAM_GIVE_UP = 3;

let panelModule = null;
const loadPanel = () => {
  panelModule ||= import('./notify-panel.js').catch((err) => { panelModule = null; throw err; });
  return panelModule;
};

const parse = (data) => {
  try {
    const v = JSON.parse(data);
    return v && typeof v === 'object' && !Array.isArray(v) ? v : null;
  } catch {
    return null;
  }
};

export function createBell({
  api, checkSession, storage = null,
  isVisible = () => globalThis.document?.visibilityState !== 'hidden',
  streamFactory = createLiveStream,
  setTimer = (fn, ms) => setTimeout(fn, ms), clearTimer = (id) => clearTimeout(id),
  wide = () => Boolean(globalThis.matchMedia?.('(min-width: 45rem)').matches),
} = {}) {
  const badge = h('span', { class: 'bell__badge', 'aria-hidden': 'true' });
  const button = h('button', { class: ['btn', 'btn--ghost', 'btn--icon', 'bell'], type: 'button', popovertarget: 'notify-panel', hidden: true, 'aria-label': bellLabel(0) }, icon('bell'), badge);
  // Polite, and written only by the announcer: one sentence per burst.
  const live = h('p', { class: 'visually-hidden', 'aria-live': 'polite', 'data-notify-live': '' });
  const panel = h('div', { class: ['menu', 'notify'], id: 'notify-panel', popover: 'auto', tabindex: '-1', role: 'dialog', 'aria-label': 'Notifications' });
  const inbox = createInbox({ api });
  let sayTimer = null;
  const announcer = createAnnouncer({
    say: (text) => {
      // Clear first, so a repeated sentence is still spoken.
      live.textContent = '';
      if (sayTimer !== null) clearTimer(sayTimer);
      sayTimer = setTimer(() => { sayTimer = null; live.textContent = text; }, 50);
    },
    setTimer, clearTimer,
  });

  let available = false;
  let stopped = false;
  let stream = null;
  let pollTimer = null;
  let retryTimer = null;
  let lastToast = 0;
  let render = null; // the open panel's redraw

  const paint = ({ unread }) => {
    const n = Number.isInteger(unread) ? unread : 0;
    badge.textContent = badgeText(n);
    button.setAttribute('aria-label', bellLabel(n));
    button.setAttribute('title', n ? `Notifications: ${n} unread` : 'Notifications');
    button.toggleAttribute?.('data-unread', n > 0);
  };
  inbox.subscribe((s) => { paint(s); render?.(); });
  paint(inbox.state());

  const maybeToast = (it) => {
    if (!shouldToast(it, { visible: isVisible(), enabled: readToastPref(storage), lastAt: lastToast })) return;
    lastToast = Date.now();
    toast('note', `Critical: ${it.title}`, { action: { label: 'Open the inbox', href: '#/inbox' } });
  };

  const onNotification = (data) => {
    const raw = parse(data);
    if (!raw) return;
    const res = inbox.live(raw);
    if (!res) return;
    if (res.isNew) announcer.arrived(1, inbox.state().unread);
    if (res.isNew) maybeToast(res.item);
  };
  const onUnread = (data) => {
    const v = parse(data);
    if (!v || !Number.isInteger(v.unread)) return;
    inbox.setUnread(v.unread);
    announcer.unread(v.unread);
  };

  // Polling, for a server with the inbox but no stream: the first page,
  // with anything new (unread, not seen before) treated as an arrival.
  async function poll() {
    pollTimer = null;
    if (stopped) return;
    try {
      const known = new Set(inbox.state().items.map((x) => x.id));
      const body = await api.notifications({ limit: FIRST_PAGE });
      const page = inbox.load(body);
      const fresh = page.items.filter((x) => !x.read && !known.has(x.id));
      if (known.size && fresh.length) {
        announcer.arrived(fresh.length, inbox.state().unread);
        const critical = fresh.find((x) => x.severity === 'critical');
        if (critical) maybeToast(critical);
      }
    } catch {
      // The next poll tries again; the badge keeps its last count.
    }
    if (!stopped) pollTimer = setTimer(poll, POLL_MS);
  }

  function openStream() {
    let opened = false;
    let failures = 0;
    stream = streamFactory({
      url: '/api/v1/notifications/stream',
      checkSession,
      events: { notification: onNotification, unread: onUnread },
      onState: (state) => {
        if (state === 'live') { opened = true; failures = 0; }
        if (state === 'reconnecting' && !opened && ++failures >= STREAM_GIVE_UP) {
          stream?.stop();
          stream = null;
          if (!stopped && pollTimer === null) pollTimer = setTimer(poll, POLL_MS);
        }
      },
    });
    stream.start();
  }

  async function start() {
    stopped = false;
    try {
      inbox.load(await api.notifications({ limit: FIRST_PAGE }));
    } catch (err) {
      if (isMissingEndpoint(err)) return false; // an older server: no bell
      if (err?.status === 401 || err?.status === 403) return false;
      // Unreachable for now: try again in a minute, still without a bell.
      if (!stopped) retryTimer = setTimer(() => { retryTimer = null; start(); }, POLL_MS);
      return false;
    }
    if (stopped) return false;
    available = true;
    button.hidden = false;
    openStream();
    return true;
  }

  function stop() {
    stopped = true;
    stream?.stop();
    stream = null;
    for (const t of [pollTimer, retryTimer, sayTimer]) if (t !== null) clearTimer(t);
    pollTimer = null;
    retryTimer = null;
    announcer.stop();
    try {
      panel.hidePopover?.();
    } catch {
      // Already closed.
    }
  }

  // Placement: under the bell on desktop (computed geometry through
  // CSSOM); on phones the stylesheet makes it full screen.
  panel.addEventListener('beforetoggle', (e) => {
    if (e.newState !== 'open') return;
    if (!wide()) {
      panel.style.top = '';
      panel.style.right = '';
      return;
    }
    const r = button.getBoundingClientRect();
    const vw = globalThis.document.documentElement.clientWidth;
    panel.style.top = `${Math.round(r.bottom + 6)}px`;
    panel.style.right = `${Math.max(8, Math.round(vw - r.right))}px`;
  });
  panel.addEventListener('toggle', async (e) => {
    const open = e.newState === 'open';
    button.setAttribute('aria-expanded', String(open));
    if (!open) {
      render = null;
      // Esc or a close button inside the panel: back to the bell. A click
      // elsewhere (or a link that navigates) keeps its own focus.
      const active = globalThis.document?.activeElement;
      if (active && (active === panel || panel.contains?.(active))) button.focus?.();
      return;
    }
    const m = await loadPanel();
    render = m.renderPanel(panel, { inbox, api, close: () => panel.hidePopover?.() });
    panel.focus();
  });
  button.setAttribute('aria-expanded', 'false');
  button.setAttribute('aria-controls', panel.id);

  return {
    button, panel, live, inbox, start, stop,
    get available() { return available; },
  };
}
