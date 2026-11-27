// Round 8: the in-console notification inbox in the browser. Validation of
// what the server sends, day grouping, read state (optimistic, rolled back
// on refusal, "mark all" bounded by what was seen), the batched
// announcements and the bell's accessible name, the one critical toast,
// and the preferences merge.
import { test } from 'node:test';
import assert from 'node:assert/strict';

const N = await import('../static/assets/js/lib/notify.js');
const { setTimeZone } = await import('../static/assets/js/lib/format.js');

const ID = (n) => `ntf_${String(n).padStart(16, '0')}`;
const raw = (n, o = {}) => ({ id: ID(n), kind: 'critical_observation', severity: 'high', title: `Finding ${n}`, summary: 'PI-001 on web, source 203.0.113.7.', created_at: '2026-11-27T10:00:00Z', read: false, link: { route: 'event', id: 'a'.repeat(32) }, group_count: 1, ...o });

test('a notification is validated: closed kinds, severities and link routes; text only', () => {
  const it = N.normalizeNotification(raw(1, { title: 'Planted key‮ replayed\u0007', group_count: 3 }));
  assert.equal(it.title, 'Planted key replayed', 'bidi and control characters removed');
  assert.equal(it.href, `#/events/${'a'.repeat(32)}`);
  assert.equal(it.group_count, 3);
  assert.equal(N.normalizeNotification(raw(1, { kind: 'phishing' })), null, 'unknown kind dropped');
  assert.equal(N.normalizeNotification(raw(1, { id: 'ntf_<b>' })), null, 'malformed id dropped');
  assert.equal(N.normalizeNotification(raw(1, { severity: 'apocalyptic' })).severity, 'info');
  assert.equal(N.normalizeNotification(raw(1, { created_at: 'yesterday' })).created_at, '');
  assert.equal(N.normalizeNotification(raw(1, { title: 'x'.repeat(500) })).title.length, N.TITLE_MAX);
  assert.equal(N.normalizeNotification(raw(1, { title: '' })).title, 'High and critical findings', 'a missing title falls back to the kind');
});

test('links go only to routes the console knows, with validated ids', () => {
  const H = N.notificationHref;
  assert.equal(H({ route: 'session', id: 'b'.repeat(32) }), `#/sessions/${'b'.repeat(32)}`);
  assert.equal(H({ route: 'campaign', id: 'cmp_23529e45783c' }), '#/campaigns/cmp_23529e45783c');
  assert.equal(H({ route: 'event', id: 'c'.repeat(32), node: 'd'.repeat(32) }), `#/events/${'c'.repeat(32)}?node=${'d'.repeat(32)}`, 'a forwarded event keeps its origin');
  assert.equal(H({ route: 'event', id: 'c'.repeat(32), node: '../x' }), `#/events/${'c'.repeat(32)}`, 'a bad node is ignored');
  assert.equal(H({ route: 'posture', id: 'POS-003' }), '#/posture');
  assert.equal(H({ route: 'settings', id: 'keys' }), '#/settings/keys');
  assert.equal(H({ route: 'settings', id: 'javascript:alert(1)' }), '#/settings');
  assert.equal(H({ route: 'investigation', id: 'inv_821218abae78' }), '#/investigations/inv_821218abae78');
  assert.equal(H({ route: 'investigation', id: '../../x' }), null);
  assert.equal(H({ route: 'event', id: 'not-an-id' }), null);
  assert.equal(H({ route: 'https://example.test', id: 'x' }), null);
  assert.equal(H(null), null);
});

test('grouped by day in the chosen zone: Today, Yesterday, then the date', () => {
  setTimeZone('utc');
  const now = Date.parse('2026-11-27T12:00:00Z');
  const items = [raw(1, { created_at: '2026-11-27T09:00:00Z' }), raw(2, { created_at: '2026-11-27T00:30:00Z' }), raw(3, { created_at: '2026-11-26T23:59:00Z' }), raw(4, { created_at: '2026-11-20T08:00:00Z' }), raw(5, { created_at: '2025-12-31T08:00:00Z' })].map(N.normalizeNotification);
  const groups = N.groupByDay(items, now);
  assert.deepEqual(groups.map((g) => [g.label, g.items.length]), [['Today', 2], ['Yesterday', 1], ['Nov 20', 1], ['Dec 31, 2025', 1]]);
});

function fakeApi({ fail = false, unread } = {}) {
  const calls = [];
  return {
    calls,
    markNotificationsRead: async (body) => {
      calls.push(body);
      if (fail) throw Object.assign(new Error('refused'), { status: 503 });
      return { unread: unread ?? 0 };
    },
  };
}

test('read state: marking one is optimistic, the server count wins, a refusal puts it back', async () => {
  const api = fakeApi({ unread: 1 });
  const inbox = N.createInbox({ api });
  const seen = [];
  inbox.subscribe((s) => seen.push(s.unread));
  inbox.load({ items: [raw(1), raw(2), raw(3, { read: true })], unread: 2, next_cursor: 'c2' });
  assert.equal(inbox.state().next, 'c2');
  const p = inbox.markRead([ID(1), ID(3)]);
  assert.equal(inbox.state().items[0].read, true, 'changes at once');
  assert.equal(inbox.state().unread, 1);
  await p;
  assert.deepEqual(api.calls, [{ ids: [ID(1)] }], 'only unread ids are sent');
  const bad = N.createInbox({ api: fakeApi({ fail: true }) });
  bad.load({ items: [raw(1)], unread: 5 });
  await assert.rejects(bad.markRead([ID(1)]));
  assert.equal(bad.state().items[0].read, false);
  assert.equal(bad.state().unread, 5, 'the count is put back');
  assert.ok(seen.length >= 3);
});

test('read state: ids go in batches of at most 200', async () => {
  const api = fakeApi({ unread: 0 });
  const inbox = N.createInbox({ api });
  inbox.load({ items: Array.from({ length: 450 }, (_, i) => raw(i + 1)), unread: 450 });
  await inbox.markRead(inbox.state().items.map((x) => x.id));
  assert.deepEqual(api.calls.map((c) => c.ids.length), [200, 200, 50]);
});

test('mark all reads everything up to the newest item seen, not what arrives meanwhile', async () => {
  const api = fakeApi({ unread: 1 });
  const inbox = N.createInbox({ api });
  inbox.load({ items: [raw(2, { created_at: '2026-11-27T10:05:00Z' }), raw(1, { created_at: '2026-11-27T10:00:00Z' })], unread: 2 });
  await inbox.markAll('2026-11-27T11:00:00Z');
  assert.deepEqual(api.calls, [{ all: true, before: '2026-11-27T10:05:00Z' }]);
  assert.ok(inbox.state().items.every((x) => x.read));
  assert.equal(inbox.state().unread, 1, 'the server says one arrived meanwhile');
});

test('a live arrival is new once; a grouped repeat updates its row and moves it up', () => {
  const inbox = N.createInbox({ api: fakeApi() });
  inbox.load({ items: [raw(1), raw(2, { read: true })], unread: 1 });
  const first = inbox.live({ id: ID(3), kind: 'honeytoken_replay', severity: 'critical', title: 'Planted key replayed', created_at: '2026-11-27T10:10:00Z' });
  assert.equal(first.isNew, true);
  assert.equal(inbox.state().items[0].id, ID(3));
  const again = inbox.live({ ...raw(2), group_count: 4 });
  assert.equal(again.isNew, false, 'a repeat of a known item is not a new arrival');
  assert.equal(inbox.state().items[0].id, ID(2));
  assert.equal(inbox.state().items[0].group_count, 4);
  assert.equal(inbox.state().items[0].read, false, 'a repeat is unread again');
  assert.equal(inbox.state().items[0].summary, 'PI-001 on web, source 203.0.113.7.');
  assert.equal(inbox.live({ id: 'bad' }), null);
});

test('the bell names its count; the badge caps at 99+', () => {
  assert.equal(N.bellLabel(0), 'Notifications, none unread');
  assert.equal(N.bellLabel(12), 'Notifications, 12 unread');
  assert.equal(N.bellLabel(4000), 'Notifications, more than 999 unread');
  assert.equal(N.badgeText(0), '');
  assert.equal(N.badgeText(7), '7');
  assert.equal(N.badgeText(120), '99+');
});

function clock() {
  let t = 0;
  let seq = 0;
  const timers = new Map();
  return {
    now: () => t,
    setTimer: (fn, ms) => { const id = ++seq; timers.set(id, { at: t + ms, fn }); return id; },
    clearTimer: (id) => timers.delete(id),
    advance(ms) {
      const end = t + ms;
      for (;;) {
        const next = [...timers.entries()].sort((a, b) => a[1].at - b[1].at)[0];
        if (!next || next[1].at > end) break;
        timers.delete(next[0]);
        t = next[1].at;
        next[1].fn();
      }
      t = end;
    },
  };
}

test('announcements are batched: one sentence per quiet spell, never per item', () => {
  const c = clock();
  const said = [];
  const a = N.createAnnouncer({ say: (s) => said.push(s), quietMs: 2000, maxMs: 8000, ...c });
  a.arrived(1, 13);
  c.advance(500);
  a.arrived(1, 14);
  c.advance(500);
  a.arrived(1, 15);
  assert.deepEqual(said, [], 'nothing while the burst goes on');
  c.advance(2000);
  assert.deepEqual(said, ['3 new notifications. 15 unread.']);
  a.arrived(1, 16);
  c.advance(2000);
  assert.deepEqual(said.at(-1), 'One new notification. 16 unread.');
  // A steady trickle still speaks within maxMs.
  for (let i = 0; i < 10; i++) { a.arrived(1); c.advance(1500); }
  assert.ok(said.length >= 3, 'a trickle is announced within the maximum wait');
  a.unread(3);
  const before = said.length;
  c.advance(10000);
  assert.ok(said.length <= before + 1, 'marking read is never announced by itself');
});

test('the one toast: critical only, tab visible, enabled, at most once a minute', () => {
  const crit = { severity: 'critical' };
  assert.equal(N.shouldToast(crit, { visible: true, enabled: true, lastAt: 0, now: 120000 }), true);
  assert.equal(N.shouldToast({ severity: 'high' }, { visible: true, enabled: true, now: 120000 }), false);
  assert.equal(N.shouldToast(crit, { visible: false, enabled: true, now: 120000 }), false);
  assert.equal(N.shouldToast(crit, { visible: true, enabled: false, now: 120000 }), false);
  assert.equal(N.shouldToast(crit, { visible: true, enabled: true, lastAt: 100000, now: 120000 }), false);
  const mem = new Map();
  const storage = { getItem: (k) => mem.get(k) ?? null, setItem: (k, v) => mem.set(k, v) };
  assert.equal(N.readToastPref(storage), true, 'on by default');
  N.writeToastPref(storage, false);
  assert.equal(mem.get(N.TOAST_KEY), 'off');
  assert.equal(N.readToastPref(storage), false);
  assert.equal(N.readToastPref({ getItem() { throw new Error('blocked'); } }), true);
});

test('preferences: parsed against closed lists, merged like the server, account security always on', () => {
  const p = N.parseNotifyPrefs({ kinds: { new_campaign: false, account_security: false, bogus: false }, min_severity: 'low' });
  assert.equal(p.kinds.new_campaign, false);
  assert.equal(p.kinds.account_security, true, 'always on, whatever was sent');
  assert.equal('bogus' in p.kinds, false);
  assert.equal(p.min_severity, 'info', 'no "low" step: back to the default');
  assert.equal(Object.keys(p.kinds).length, N.NOTIFICATION_KINDS.length);
  const m = N.mergeNotifyPrefs(p, { kinds: { new_campaign: true, assignment: false, account_security: false, x: true }, min_severity: 'high' });
  assert.deepEqual(m.patch, { kinds: { new_campaign: true, assignment: false }, min_severity: 'high' }, 'only real changes are sent');
  assert.equal(m.prefs.kinds.account_security, true);
  assert.equal(N.mergeNotifyPrefs(m.prefs, { min_severity: 'high' }).patch, null);
  assert.equal(N.mergeNotifyPrefs(m.prefs, { min_severity: 'low' }).patch, null);
});

test('inbox filters from the URL are parsed and applied', () => {
  const f = N.normalizeInboxFilters({ kind: 'agent_canary', severity: 'high', unread: '1' });
  assert.deepEqual(f, { kind: 'agent_canary', severity: 'high', unread: true });
  assert.deepEqual(N.normalizeInboxFilters({ kind: '<x>', severity: 'loud', unread: 'yes' }), { kind: '', severity: '', unread: false });
  const it = N.normalizeNotification(raw(1, { kind: 'agent_canary', severity: 'high' }));
  assert.equal(N.matchesInbox(it, f), true);
  assert.equal(N.matchesInbox({ ...it, read: true }, f), false);
  assert.equal(N.matchesInbox({ ...it, severity: 'medium' }, f), false);
  assert.equal(N.matchesInbox({ ...it, kind: 'new_campaign' }, f), false);
});
