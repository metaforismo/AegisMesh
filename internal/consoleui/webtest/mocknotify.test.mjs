// Mock contract for round 8 (contract r8 plus the backend's details):
// notifications (list, read, preferences, stream, grouping, the ring),
// the assignee list and PATCH, campaign and session → investigation, the
// workspace fields, and `--round8 off` answering like a round-7 server.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { createNotifications, mergePrefs, defaultPrefs, GROUP_WINDOW_MS } from '../devserver/mock-notify.mjs';
import { memberEvents } from '../devserver/mock-workspace.mjs';

const start = (args) => new Promise((resolve, reject) => {
  const port = 25000 + Math.floor(Math.random() * 1000);
  const proc = spawn(process.execPath, [fileURLToPath(new URL('../devserver/mock-server.mjs', import.meta.url)), '--port', String(port), ...args], { stdio: ['ignore', 'pipe', 'inherit'] });
  const t = setTimeout(() => reject(new Error('mock did not start')), 30000);
  proc.stdout.on('data', (d) => { if (String(d).includes('console mock on')) { clearTimeout(t); resolve({ proc, base: `http://127.0.0.1:${port}` }); } });
});
let on;
let old;
before(async () => { [on, old] = await Promise.all([start([]), start(['--round8', 'off'])]); });
after(() => { on?.proc.kill(); old?.proc.kill(); });

async function login(base, token) {
  const res = await fetch(`${base}/api/v1/session`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ token }) });
  const body = await res.json();
  return { cookie: (res.headers.get('set-cookie') || '').split(';')[0], csrf: body.csrf_token };
}
const call = async (base, who, method, path, body) => {
  const res = await fetch(`${base}/api/v1${path}`, { method, headers: { cookie: who.cookie, 'X-AegisMesh-CSRF': who.csrf || '', ...(body ? { 'Content-Type': 'application/json' } : {}) }, body: body ? JSON.stringify(body) : undefined });
  const text = await res.text();
  let json = null;
  try { json = JSON.parse(text); } catch { /* empty */ }
  return { status: res.status, json };
};

test('store: grouping within 10 minutes, a bounded ring, read cursor and ids', () => {
  let t = Date.parse('2026-11-27T10:00:00Z');
  const s = createNotifications({ clock: () => t, ring: 5 });
  const perms = ['evidence.read'];
  s.add({ kind: 'agent_canary', severity: 'high', title: 'a', key: 'AGT-001|x', at: t });
  const g = s.add({ kind: 'agent_canary', severity: 'high', title: 'a', key: 'AGT-001|x', at: t + GROUP_WINDOW_MS - 1 });
  assert.equal(g.grouped, true);
  assert.equal(g.item.group_count, 2);
  assert.equal(s.add({ kind: 'agent_canary', severity: 'high', title: 'a', key: 'AGT-001|x', at: t + 2 * GROUP_WINDOW_MS + 1 }).grouped, false);
  for (let i = 0; i < 10; i++) s.add({ kind: 'new_campaign', severity: 'medium', title: `c${i}`, at: t + i });
  assert.equal(s.size, 5, 'the ring keeps the newest');
  s.add({ kind: 'account_security', severity: 'high', title: 'mine', for: 'cfg:ana', at: t + 100 });
  assert.equal(s.list('cfg:ada', perms).items.some((x) => x.title === 'mine'), false, 'addressed to one principal');
  assert.equal(s.list('cfg:ana', []).items.map((x) => x.title).join(), 'mine', 'no evidence.read: only your own');
  t += 1000;
  const before = s.unreadCount('cfg:ada', perms);
  const id = s.list('cfg:ada', perms).items[0].id;
  assert.equal(s.markRead('cfg:ada', perms, { ids: [id] }), before - 1);
  assert.equal(s.markRead('cfg:ada', perms, { all: true }), 0);
});

test('preferences merge: known kinds, booleans, account security always on, no "low"', () => {
  const p = defaultPrefs();
  assert.equal(p.min_severity, 'info');
  assert.match(mergePrefs(p, { kinds: { account_security: false } }).error, /cannot be turned off/);
  assert.match(mergePrefs(p, { kinds: { bogus: true } }).error, /unknown notification kind/);
  assert.match(mergePrefs(p, { kinds: { new_campaign: 'no' } }).error, /true or false/);
  assert.match(mergePrefs(p, { min_severity: 'low' }).error, /min_severity/);
  assert.match(mergePrefs(p, { sound: true }).error, /unknown field/);
  assert.equal(mergePrefs(p, { kinds: { new_campaign: false }, min_severity: 'high' }).prefs.kinds.new_campaign, false);
});

test('member events: newest per session first, interleaved, capped, local only', () => {
  const lane = (src, n, node) => Array.from({ length: n }, (_, i) => ({ id: `${src}${i}`, time: new Date(Date.UTC(2026, 10, 27, 10, i)).toISOString(), ...(node ? { node: { id: 'n' } } : {}) }));
  const out = memberEvents([lane('a', 3), lane('b', 2), lane('c', 2, true)], 4);
  assert.deepEqual(out.map((e) => e.id), ['a2', 'b1', 'a1', 'b0']);
});

test('notifications over HTTP: list, filters, read, preferences', async () => {
  const ana = await login(on.base, 'dev-analyst');
  const list = await call(on.base, ana, 'GET', '/notifications?limit=200');
  assert.equal(list.status, 200);
  const { items, unread, next_cursor: next, limits } = list.json;
  assert.ok(items.length > 20 && unread > 0);
  assert.ok(next === null || typeof next === 'string');
  assert.equal(limits.max_items, 2000);
  for (const it of items) {
    assert.match(it.id, /^ntf_[0-9a-f]{16}$/);
    assert.ok(['critical_observation', 'honeytoken_replay', 'agent_canary', 'new_campaign', 'posture_attention', 'account_security', 'assignment'].includes(it.kind));
    assert.ok(['session', 'campaign', 'event', 'posture', 'settings', 'investigation'].includes(it.link.route));
  }
  const kinds = new Set(items.map((x) => x.kind));
  for (const k of ['critical_observation', 'honeytoken_replay', 'agent_canary', 'new_campaign', 'posture_attention', 'account_security', 'assignment']) assert.ok(kinds.has(k), `seeded ${k}`);
  assert.ok(items.some((x) => x.group_count > 1), 'some findings are grouped');
  const only = await call(on.base, ana, 'GET', '/notifications?kind=agent_canary&unread=1');
  assert.ok(only.json.items.every((x) => x.kind === 'agent_canary' && !x.read));
  assert.equal((await call(on.base, ana, 'GET', '/notifications?kind=nope')).status, 400);
  assert.equal((await call(on.base, ana, 'GET', '/notifications?sort=new')).status, 400);
  const unreadIds = items.filter((x) => !x.read).slice(0, 2).map((x) => x.id);
  const r1 = await call(on.base, ana, 'POST', '/notifications/read', { ids: unreadIds });
  assert.equal(r1.json.unread, unread - 2);
  assert.equal((await call(on.base, ana, 'POST', '/notifications/read', { ids: [], all: true })).status, 400, 'exactly one of ids or all');
  assert.equal((await call(on.base, ana, 'POST', '/notifications/read', { ids: Array(201).fill('ntf_0000000000000000') })).status, 400);
  assert.equal((await call(on.base, ana, 'POST', '/notifications/read', { all: true })).json.unread, 0);
  // Another principal's read state is their own.
  const ada = await login(on.base, 'dev-admin');
  assert.ok((await call(on.base, ada, 'GET', '/notifications?limit=1')).json.unread > 0);
  // Preferences: merge and refuse.
  const pr = await call(on.base, ana, 'PUT', '/me/notification-preferences', { kinds: { new_campaign: false }, min_severity: 'high' });
  assert.equal(pr.status, 200);
  assert.equal(pr.json.kinds.new_campaign, false);
  assert.equal(pr.json.kinds.agent_canary, true, 'merged, not replaced');
  assert.equal((await call(on.base, ana, 'PUT', '/me/notification-preferences', { kinds: { account_security: false } })).status, 400);
  const after = await call(on.base, ana, 'GET', '/notifications?limit=200');
  assert.ok(after.json.items.every((x) => x.kind !== 'new_campaign'));
  assert.ok(after.json.items.every((x) => x.kind === 'account_security' || ['high', 'critical'].includes(x.severity)));
});

test('the notification stream opens with the unread count', async () => {
  const vera = await login(on.base, 'dev-viewer');
  const ctl = new AbortController();
  const res = await fetch(`${on.base}/api/v1/notifications/stream`, { headers: { cookie: vera.cookie }, signal: ctl.signal });
  assert.equal(res.headers.get('content-type'), 'text/event-stream');
  const reader = res.body.getReader();
  let text = '';
  while (!/event: unread\ndata: \{"unread":\d+\}/.test(text)) text += new TextDecoder().decode((await reader.read()).value);
  ctl.abort();
  // A raised notification reaches the stream.
  assert.ok((await (await fetch(`${on.base}/__mock/notify?kind=honeytoken_replay&severity=critical`)).json()).sent >= 1);
});

test('assignees and PATCH assignee: only principals that read investigations; the assignee is told', async () => {
  const ada = await login(on.base, 'dev-admin');
  const vera = await login(on.base, 'dev-viewer');
  const list = await call(on.base, ada, 'GET', '/investigations/assignees');
  assert.equal(list.status, 200);
  const ids = list.json.assignees.map((a) => a.id);
  assert.ok(ids.includes('cfg:ana') && ids.includes('cfg:vera'));
  assert.ok(!ids.includes('acc_8r6t2y4ua9'), 'the auditor role cannot read investigations');
  assert.ok(!ids.includes('acc_5w1j8f3ky2'), 'disabled accounts are not offered');
  assert.equal((await call(on.base, vera, 'GET', '/investigations/assignees')).status, 403, 'needs investigations.write');
  const invs = (await call(on.base, ada, 'GET', '/investigations')).json.investigations;
  const target = invs.find((i) => i.title.startsWith('Scanner'));
  assert.equal((await call(on.base, ada, 'PATCH', `/investigations/${target.id}`, { assignee: 'acc_8r6t2y4ua9' })).status, 400);
  const res = await call(on.base, ada, 'PATCH', `/investigations/${target.id}`, { assignee: 'cfg:vera' });
  assert.equal(res.status, 200);
  assert.equal(res.json.assignee, 'cfg:vera');
  assert.equal(res.json.assignee_name, 'vera');
  assert.equal(res.json.activity.at(-1).kind, 'assignee');
  const told = (await call(on.base, vera, 'GET', '/notifications?kind=assignment')).json.items;
  assert.ok(told.some((x) => x.link.id === target.id && !x.read), 'the assignee has an unread assignment');
  assert.ok(told.every((x) => x.severity === 'medium'), 'assignments are medium, so a medium minimum keeps them');
  const mine = (await call(on.base, vera, 'GET', '/investigations?assignee=me')).json.investigations;
  assert.deepEqual(mine.map((i) => i.id), [target.id]);
  const none = (await call(on.base, vera, 'GET', '/investigations?assignee=none')).json.investigations;
  assert.ok(none.every((i) => i.assignee === null));
  assert.equal((await call(on.base, ada, 'PATCH', `/investigations/${target.id}`, { assignee: null })).json.assignee, null);
});

test('campaign and session → investigation: member events attached, origin, first note, summary', async () => {
  const ana = await login(on.base, 'dev-analyst');
  const vera = await login(on.base, 'dev-viewer');
  const cid = (await call(on.base, ana, 'GET', '/campaigns')).json.items[0].id;
  const detail = (await call(on.base, ana, 'GET', `/campaigns/${cid}`)).json;
  assert.ok(Array.isArray(detail.event_ids_sample) && detail.event_ids_sample.length <= 50);
  assert.equal((await call(on.base, vera, 'POST', `/campaigns/${cid}/investigation`, {})).status, 403);
  assert.equal((await call(on.base, ana, 'POST', `/campaigns/${cid}/investigation`, { max_events: 500 })).status, 400);
  const made = await call(on.base, ana, 'POST', `/campaigns/${cid}/investigation`, { priority: 'high', max_events: 10 });
  assert.equal(made.status, 201);
  assert.deepEqual(made.json.origin, { kind: 'campaign', id: cid });
  assert.equal(made.json.event_ids.length, Math.min(10, detail.event_count));
  assert.match(made.json.notes[0].text, /does not prove a shared operator/);
  assert.equal(made.json.priority, 'high');
  assert.ok(made.json.summary.sources >= 2);
  assert.deepEqual(made.json.activity.map((a) => a.kind), ['created', 'attach', 'note']);
  const sid = (await call(on.base, ana, 'GET', '/sessions?window=7d&limit=1')).json.sessions[0].id;
  const s = await call(on.base, ana, 'POST', `/sessions/${sid}/investigation`, { title: 'One session' });
  assert.equal(s.status, 201);
  assert.deepEqual(s.json.origin, { kind: 'session', id: sid });
  assert.equal(s.json.title, 'One session');
  const listed = (await call(on.base, ana, 'GET', '/investigations')).json.investigations.find((i) => i.id === s.json.id);
  assert.equal(listed.event_count, s.json.event_ids.length);
  assert.equal(typeof listed.max_severity, 'string');
  assert.equal('activity' in listed, false, 'activity only on the detail');
});

test('--round8 off answers like a round-7 server', async () => {
  const ana = await login(old.base, 'dev-analyst');
  assert.equal((await call(old.base, ana, 'GET', '/notifications')).status, 404);
  assert.equal((await call(old.base, ana, 'GET', '/me/notification-preferences')).status, 404);
  assert.equal((await call(old.base, ana, 'GET', '/investigations/assignees')).status, 404);
  const cid = (await call(old.base, ana, 'GET', '/campaigns')).json.items[0].id;
  assert.equal('event_ids_sample' in (await call(old.base, ana, 'GET', `/campaigns/${cid}`)).json, false);
  assert.equal((await call(old.base, ana, 'POST', `/campaigns/${cid}/investigation`, {})).status, 404);
  const inv = (await call(old.base, ana, 'GET', '/investigations')).json.investigations[0];
  for (const k of ['assignee', 'origin', 'event_count', 'max_severity']) assert.equal(k in inv, false, `no ${k}`);
  const d = (await call(old.base, ana, 'GET', `/investigations/${inv.id}`)).json;
  for (const k of ['activity', 'summary']) assert.equal(k in d, false, `no ${k}`);
  assert.equal((await call(old.base, ana, 'PATCH', `/investigations/${inv.id}`, { assignee: null })).status, 400, 'unknown field');
});
