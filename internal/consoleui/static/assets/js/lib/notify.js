// In-console notifications (contract r8): the vocabulary, validation of
// what the server sends, grouping by day, read state with optimistic
// marking, batched announcements for assistive tech, the "critical toast"
// rule and the preferences merge. Pure logic; ui/bell.js and
// screens/inbox.js draw it.
//
// Nothing here is sent anywhere: the inbox lives on the console server.
// Every field is parsed against a closed list or a pattern before it can
// reach a class name, a link or a request.

import { href, isEventId, isOpaqueId, isSessionId } from './route.js';
import { SEVERITIES, severityRank } from './taxonomy.js';
import { isSectionId } from './settings.js';
import { dayKey, dayLabel } from './format.js';

export const NOTIFICATION_KINDS = Object.freeze(['critical_observation', 'honeytoken_replay', 'agent_canary', 'new_campaign', 'posture_attention', 'account_security', 'assignment']);

// Words for each kind: a short label (list rows, filters), the preference
// toggle's name and its plain-language description, and the glyph (an icon
// beside the word, never colour alone).
export const KIND_META = Object.freeze({
  critical_observation: { label: 'Finding', name: 'High and critical findings', icon: 'warn', describe: 'A rule found something of severity high or critical on a decoy. Repeats of the same rule and source are counted into one notice rather than repeated.' },
  honeytoken_replay: { label: 'Planted credential', name: 'Planted credentials used', icon: 'key', describe: 'A decoy credential came back, on the same sensor or a second one. Only someone who read a decoy can hold it.' },
  agent_canary: { label: 'Agent canary', name: 'Agent canaries', icon: 'flag', describe: 'An agent followed an instruction planted in a decoy. Consistent with automation; never a verdict about who is behind it.' },
  new_campaign: { label: 'Campaign', name: 'New campaigns', icon: 'campaign', describe: 'Several sources were seen following the same steps for the first time. Similar behaviour, not attribution.' },
  posture_attention: { label: 'Posture', name: 'Posture changes', icon: 'posture', describe: 'A configuration check newly needs attention, or an accepted risk expires within 7 days.' },
  account_security: { label: 'Your account', name: 'Your account’s security', icon: 'lock', describe: 'A key was created or revoked for you, your role changed, or someone else signed out one of your sessions. Only you see these. Always on, at any severity.' },
  assignment: { label: 'Assigned to you', name: 'Investigations assigned to you', icon: 'user', describe: 'Someone made you the assignee of an investigation. Only you see these.' },
});

export const isNotificationKind = (v) => NOTIFICATION_KINDS.includes(v);
export const LINK_ROUTES = Object.freeze(['session', 'campaign', 'event', 'posture', 'settings', 'investigation']);

const NTF_ID = /^ntf_[0-9a-f]{16,32}$/;
const CAMPAIGN_ID = /^cmp_[0-9a-z]{4,64}$/;
const RFC3339 = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,9})?(Z|[+-]\d{2}:\d{2})$/;
const UNSAFE = /[\u0000-\u0008\u000b-\u001f\u007f-\u009f​-‏‪-‮⁦-⁩﻿]/g;
export const TITLE_MAX = 200;
// The server marks at most 200 ids per request.
export const READ_BATCH = 200;
export const SUMMARY_MAX = 600;

export const isNotificationId = (v) => typeof v === 'string' && NTF_ID.test(v);

// Plain text: control and bidi characters removed, length capped. The
// result is only ever a Text node.
export function cleanText(v, max) {
  if (typeof v !== 'string') return '';
  const s = Array.from(v.replace(UNSAFE, '').trim());
  return s.length > max ? `${s.slice(0, max - 1).join('')}…` : s.join('');
}

// Where a notification's link goes, or null when the target is not a route
// the console knows (an unknown route, a malformed id).
export function notificationHref(link) {
  if (!link || typeof link !== 'object') return null;
  const { route, id } = link;
  switch (route) {
    case 'session': return isSessionId(id) ? href('sessions', id) : null;
    case 'campaign': return typeof id === 'string' && CAMPAIGN_ID.test(id) ? href('campaigns', id) : null;
    // A forwarded event names its origin node; ids are unique per origin.
    case 'event': return isEventId(id) ? (typeof link.node === 'string' && /^[0-9a-f]{32}$/.test(link.node) ? href('events', id, { node: link.node }) : href('events', id)) : null;
    case 'posture': return href('posture');
    case 'settings': return isSectionId(id) ? href('settings', id) : href('settings');
    case 'investigation': return isOpaqueId(id) ? href('investigations', id) : null;
    default: return null;
  }
}

// One item from the server (or a live event) → a validated item, or null.
export function normalizeNotification(raw) {
  if (!raw || typeof raw !== 'object' || !isNotificationId(raw.id) || !isNotificationKind(raw.kind)) return null;
  const count = Number(raw.group_count);
  return {
    id: raw.id,
    kind: raw.kind,
    severity: SEVERITIES.includes(raw.severity) ? raw.severity : 'info',
    title: cleanText(raw.title, TITLE_MAX) || KIND_META[raw.kind].name,
    summary: cleanText(raw.summary, SUMMARY_MAX),
    created_at: typeof raw.created_at === 'string' && RFC3339.test(raw.created_at) ? raw.created_at : '',
    read: raw.read === true,
    href: notificationHref(raw.link),
    group_count: Number.isInteger(count) && count > 1 ? count : 1,
  };
}

export function normalizeList(body) {
  const items = (Array.isArray(body?.items) ? body.items : []).map(normalizeNotification).filter(Boolean);
  const unread = Number(body?.unread);
  const next = typeof body?.next_cursor === 'string' && body.next_cursor ? body.next_cursor : '';
  return { items, unread: Number.isInteger(unread) && unread >= 0 ? unread : null, next };
}

// Newest first, grouped under a day heading in the chosen zone. Order
// within a day is kept as given.
export function groupByDay(items, now = Date.now()) {
  const out = [];
  let cur = null;
  for (const it of items) {
    const key = dayKey(it.created_at) || 'unknown';
    if (!cur || cur.key !== key) {
      cur = { key, label: it.created_at ? dayLabel(it.created_at, now) : 'Unknown day', items: [] };
      out.push(cur);
    }
    cur.items.push(it);
  }
  return out;
}

// Inbox filters: a kind, a minimum severity, unread only. Values from the
// URL are untrusted and parsed here.
export function normalizeInboxFilters(query) {
  return {
    kind: isNotificationKind(query?.kind) ? query.kind : '',
    severity: SEVERITIES.includes(query?.severity) ? query.severity : '',
    unread: query?.unread === '1',
  };
}

export function matchesInbox(it, f) {
  if (f.kind && it.kind !== f.kind) return false;
  if (f.severity && severityRank(it.severity) < severityRank(f.severity)) return false;
  if (f.unread && it.read) return false;
  return true;
}

// The bell's badge and accessible name.
export const badgeText = (n) => (!Number.isInteger(n) || n <= 0 ? '' : n > 99 ? '99+' : String(n));
export function bellLabel(n) {
  if (!Number.isInteger(n) || n <= 0) return 'Notifications, none unread';
  return `Notifications, ${n > 999 ? 'more than 999' : n} unread`;
}

// ---- Read state ---------------------------------------------------------------

// One store shared by the bell's panel and the Inbox screen. Marking is
// optimistic: the page changes at once, the request runs, and a refusal
// puts everything back and rethrows. The server's unread count wins
// whenever it answers.
export function createInbox({ api, onChange = () => {} } = {}) {
  let items = [];
  let unread = null;
  let next = '';
  const listeners = new Set();
  const emit = () => {
    onChange(state());
    for (const fn of listeners) fn(state());
  };
  const state = () => ({ items, unread, next });
  const byId = (id) => items.find((x) => x.id === id);

  function upsert(list, { prepend = false } = {}) {
    for (const it of list) {
      const i = items.findIndex((x) => x.id === it.id);
      if (i >= 0) {
        // A grouped repeat keeps its place in the list's order unless
        // it arrived live, where it moves to the top as the newest news.
        const merged = { ...items[i], ...it, summary: it.summary || items[i].summary, href: it.href ?? items[i].href };
        if (prepend) { items.splice(i, 1); items.unshift(merged); } else items[i] = merged;
      } else if (prepend) items.unshift(it);
      else items.push(it);
    }
  }

  return {
    state,
    subscribe(fn) { listeners.add(fn); return () => listeners.delete(fn); },
    setUnread(n) {
      if (!Number.isInteger(n) || n < 0 || n === unread) return;
      unread = n;
      emit();
    },
    // Replace with a first page (or append a later one).
    load(body, { append = false } = {}) {
      const page = normalizeList(body);
      if (!append) items = [];
      upsert(page.items);
      if (page.unread !== null) unread = page.unread;
      next = page.next;
      emit();
      return page;
    },
    // A live `notification` event: new (or grouped) and unread.
    live(raw) {
      const it = normalizeNotification({ ...raw, read: false });
      if (!it) return null;
      const was = byId(it.id);
      upsert([it], { prepend: true });
      emit();
      return { item: it, isNew: !was };
    },
    async markRead(ids) {
      const targets = ids.map(byId).filter((x) => x && !x.read);
      if (!targets.length) return unread;
      const before = unread;
      for (const t of targets) t.read = true;
      if (Number.isInteger(unread)) unread = Math.max(0, unread - targets.length);
      emit();
      try {
        const ids = targets.map((t) => t.id);
        let res = null;
        for (let i = 0; i < ids.length; i += READ_BATCH) res = await api.markNotificationsRead({ ids: ids.slice(i, i + READ_BATCH) });
        if (Number.isInteger(res?.unread)) unread = res.unread;
        emit();
        return unread;
      } catch (err) {
        for (const t of targets) t.read = false;
        unread = before;
        emit();
        throw err;
      }
    },
    // Everything up to the newest item the operator has seen: a live item
    // arriving while the request runs stays unread.
    async markAll(nowIso = new Date().toISOString()) {
      const newest = items.reduce((m, x) => (x.created_at > m ? x.created_at : m), '');
      const before = newest && newest < nowIso ? newest : nowIso;
      const changed = items.filter((x) => !x.read && (!x.created_at || x.created_at <= before));
      const prev = unread;
      for (const t of changed) t.read = true;
      unread = 0;
      emit();
      try {
        const res = await api.markNotificationsRead({ all: true, before });
        if (Number.isInteger(res?.unread)) unread = res.unread;
        emit();
        return unread;
      } catch (err) {
        for (const t of changed) t.read = false;
        unread = prev;
        emit();
        throw err;
      }
    },
  };
}

// ---- Announcements ---------------------------------------------------------

// Live arrivals are announced once per quiet spell, never per item: "3 new
// notifications. 14 unread." A burst is held until it settles (quietMs) but
// never longer than maxMs, so a steady trickle still speaks now and then.
// Changes the operator made (marking read) are not announced.
export function createAnnouncer({ say, quietMs = 2000, maxMs = 8000, setTimer = (fn, ms) => setTimeout(fn, ms), clearTimer = (id) => clearTimeout(id), now = () => Date.now() } = {}) {
  let pending = 0;
  let unread = null;
  let timer = null;
  let firstAt = 0;
  const flush = () => {
    timer = null;
    if (!pending) return;
    const n = pending;
    pending = 0;
    say(`${n === 1 ? 'One new notification' : `${n} new notifications`}.${Number.isInteger(unread) ? ` ${unread} unread.` : ''}`);
  };
  return {
    arrived(count = 1, unreadNow = null) {
      if (!pending) firstAt = now();
      pending += count;
      if (Number.isInteger(unreadNow)) unread = unreadNow;
      if (timer !== null) clearTimer(timer);
      const wait = Math.max(0, Math.min(quietMs, firstAt + maxMs - now()));
      timer = setTimer(flush, wait);
    },
    unread(n) {
      if (Number.isInteger(n)) unread = n;
    },
    stop() {
      if (timer !== null) clearTimer(timer);
      timer = null;
      pending = 0;
    },
    get pending() { return pending; },
  };
}

// ---- The one toast ------------------------------------------------------

// Quiet by design: no toast per notification. At most one subtle toast for
// a critical one, only while the tab is visible, only when the operator
// has not turned it off, and at most once a minute.
export const TOAST_GAP_MS = 60000;
export function shouldToast(item, { visible, enabled, lastAt = 0, now = Date.now() } = {}) {
  return Boolean(item && item.severity === 'critical' && visible && enabled && now - lastAt >= TOAST_GAP_MS);
}

// The toast preference lives in this browser (closed values, parsed on read).
export const TOAST_KEY = 'aegismesh.notify-toast';
export function readToastPref(storage) {
  try {
    return storage?.getItem(TOAST_KEY) !== 'off';
  } catch {
    return true;
  }
}
export function writeToastPref(storage, on) {
  try {
    storage?.setItem(TOAST_KEY, on ? 'on' : 'off');
    return true;
  } catch {
    return false;
  }
}

// ---- Preferences --------------------------------------------------------------

export const DEFAULT_MIN_SEVERITY = 'info';
// The minimum severities the server accepts (there is no "low" step: no
// kind is low), and the kind that is always on and never filtered by
// severity: notices about your own account.
export const PREF_SEVERITIES = Object.freeze(['info', 'medium', 'high', 'critical']);
export const ALWAYS_ON = 'account_security';

// Any object → complete preferences: every known kind (missing ones on),
// unknown kinds dropped, an unknown severity replaced by the default, and
// the always-on kind on whatever was sent.
export function parseNotifyPrefs(raw) {
  const kinds = {};
  for (const k of NOTIFICATION_KINDS) kinds[k] = k === ALWAYS_ON || raw?.kinds?.[k] !== false;
  return { kinds, min_severity: PREF_SEVERITIES.includes(raw?.min_severity) ? raw.min_severity : DEFAULT_MIN_SEVERITY };
}

// Merge a patch the way the server does (PUT merges): only known kinds and
// boolean values, a known severity. Returns { prefs, patch } where patch
// holds only what changed (null when nothing did).
export function mergeNotifyPrefs(current, patch) {
  const base = parseNotifyPrefs(current);
  const out = { kinds: { ...base.kinds }, min_severity: base.min_severity };
  const diff = {};
  for (const [k, v] of Object.entries(patch?.kinds || {})) {
    if (!isNotificationKind(k) || k === ALWAYS_ON || typeof v !== 'boolean' || out.kinds[k] === v) continue;
    out.kinds[k] = v;
    (diff.kinds ||= {})[k] = v;
  }
  if (PREF_SEVERITIES.includes(patch?.min_severity) && patch.min_severity !== out.min_severity) {
    out.min_severity = patch.min_severity;
    diff.min_severity = patch.min_severity;
  }
  return { prefs: out, patch: Object.keys(diff).length ? diff : null };
}
