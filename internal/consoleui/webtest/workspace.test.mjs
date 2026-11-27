// Round 8: the investigation workspace and opening a case from a campaign
// or a session. Summary (server or computed), evidence grouped by source,
// activity merged with notes in time order, the assignee picker filtered
// by permission, the list's filters and stored default, the prefilled
// draft, and one submission at a time (with the older-server fallback).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createFakeDocument } from './fakedom.mjs';

const doc = createFakeDocument();
globalThis.document = doc;
// Enough of the DOM for a toast: children, classList and dataset.
const proto = Object.getPrototypeOf(doc.createElement('x'));
Object.defineProperty(proto, 'children', { get() { return this.childNodes.filter((n) => n.nodeType === 1); } });
Object.defineProperty(proto, 'dataset', { get() { this._ds ||= {}; return this._ds; } });
Object.defineProperty(proto, 'classList', { get() { const el = this; return { add: (c) => el.setAttribute('class', `${el.getAttribute('class') || ''} ${c}`.trim()), remove() {}, contains: () => false, toggle() {} }; } });
const W = await import('../static/assets/js/lib/workspace.js');
const { openInvestigationFrom, suggestedPriority } = await import('../static/assets/js/ui/open-investigation.js');
const { ApiError } = await import('../static/assets/js/lib/api.js');
const { BUILTIN_PERMS } = await import('../static/assets/js/lib/perms.js');

const ev = (n, o = {}) => ({ id: String(n).padStart(32, '0'), time: `2026-11-27T10:${String(n).padStart(2, '0')}:00Z`, source: '203.0.113.7', sensor: { id: 'web' }, severity: '', rule_ids: [], classification: 'interaction', ...o });

test('summary: the server’s when sent, else computed from the attached events (and said so)', () => {
  const server = W.summaryOf({ summary: { sources: 2, sensors: ['web', 7], first_seen: '2026-11-27T10:00:00Z', last_seen: 'later', max_severity: 'high', rule_ids: ['PI-001', '<b>'] } });
  assert.deepEqual(server, { computed: false, sources: 2, sensors: ['web'], firstSeen: '2026-11-27T10:00:00Z', lastSeen: '', maxSeverity: 'high', ruleIds: ['PI-001'] });
  const computed = W.summaryOf({ events: [ev(3, { severity: 'critical', rule_ids: ['CMD-003'] }), ev(1, { source: '198.51.100.9', sensor: { id: 'mcp' } }), ev(2, { severity: 'low' })] });
  assert.equal(computed.computed, true);
  assert.equal(computed.sources, 2);
  assert.deepEqual(computed.sensors, ['mcp', 'web']);
  assert.equal(computed.firstSeen, '2026-11-27T10:01:00Z');
  assert.equal(computed.lastSeen, '2026-11-27T10:03:00Z');
  assert.equal(computed.maxSeverity, 'critical');
  assert.deepEqual(W.summaryOf({}).sources, 0);
});

test('evidence groups by source: the group with the latest event first, newest first inside', () => {
  const g = W.groupEvidence([ev(1), ev(5, { source: '198.51.100.9', severity: 'high' }), ev(3), ev(2, { source: '198.51.100.9', sensor: { id: 'ssh' } })]);
  assert.deepEqual(g.map((x) => [x.source, x.events.map((e) => Number(e.id))]), [['198.51.100.9', [5, 2]], ['203.0.113.7', [3, 1]]]);
  assert.deepEqual(g[0].sensors, ['ssh', 'web']);
  assert.equal(g[0].maxSeverity, 'high');
  assert.equal(g[0].latest, '2026-11-27T10:05:00Z');
});

test('activity and notes merge oldest first; a note appears once, as the note', () => {
  const activity = [
    { at: '2026-11-27T09:00:00Z', actor_id: 'cfg:ana', actor_name: 'ana', kind: 'created', detail: '' },
    { at: '2026-11-27T09:30:00Z', actor_id: 'cfg:ana', actor_name: 'ana', kind: 'note', detail: '' },
    { at: '2026-11-27T09:30:00Z', actor_id: 'cfg:ada', actor_name: 'ada', kind: 'status', detail: 'open → monitoring' },
    { at: '2026-11-27T11:00:00Z', actor_id: 'cfg:ada', actor_name: 'ada', kind: 'assignee', detail: 'unassigned → ana' },
    { at: 'not a time', actor_name: 'x', kind: 'status' },
    { at: '2026-11-27T11:00:00Z', actor_name: 'x', kind: 'delete_everything' },
  ];
  const notes = [{ time: '2026-11-27T09:30:00Z', author: 'ana', text: 'first look' }, { time: '2026-11-27T10:00:00Z', author: 'ada', text: '<b>second</b>' }];
  const feed = W.mergeFeed(activity, notes);
  assert.deepEqual(feed.map((x) => (x.type === 'note' ? `note:${x.text}` : x.kind)), ['created', 'status', 'note:first look', 'note:<b>second</b>', 'assignee']);
  assert.equal(feed.find((x) => x.kind === 'status').detail, 'open → monitoring');
  // An older server: notes only.
  assert.deepEqual(W.mergeFeed(undefined, notes).map((x) => x.type), ['note', 'note']);
  // A pending note (no server time yet) goes last.
  assert.equal(W.mergeFeed(activity, [...notes, { author: 'me', text: 'saving', pending: true }]).at(-1).text, 'saving');
});

test('the assignee picker: you first, then everyone who may read investigations; the current one kept', () => {
  const opts = W.assigneeOptions({
    assignees: [{ id: 'cfg:ada', name: 'ada' }, { id: 'acc_7k2m9q4wz1', name: 'morgan@soc.example' }, { id: 'cfg:ana', name: 'ana' }, { id: 'bad id!', name: 'x' }],
    meId: 'cfg:ana', meName: 'ana', current: 'acc_gone1234', currentName: 'gone@soc.example',
  });
  assert.deepEqual(opts, [['', 'Unassigned'], ['cfg:ana', 'You (ana)'], ['cfg:ada', 'ada'], ['acc_7k2m9q4wz1', 'morgan@soc.example'], ['acc_gone1234', 'gone@soc.example (no longer eligible)']]);
});

test('fallback eligibility: enabled accounts in the tenant whose role reads investigations', () => {
  const roles = new Map([['role_2b8f04c6e1a7', ['evidence.read', 'audit.read']], ['role_7c1e5a90b3d4', ['investigations.read', 'investigations.write']]]);
  const permsOf = (r) => roles.get(r) || BUILTIN_PERMS[r] || [];
  const accounts = [
    { id: 'cfg:ada', name: 'ada', role: 'admin', tenants: ['default'] },
    { id: 'cfg:vera', name: 'vera', role: 'viewer', tenants: ['default'] },
    { id: 'acc_8r6t2y4ua9', name: 'auditor@soc.example', role: 'role_2b8f04c6e1a7', tenants: ['default'] },
    { id: 'acc_9c4n2h7rb5', name: 'ticket-bridge', role: 'role_7c1e5a90b3d4', tenants: ['default'] },
    { id: 'acc_5w1j8f3ky2', name: 'former', role: 'analyst', tenants: ['default'], status: 'disabled' },
    { id: 'acc_3p8x1d6vt4', name: 'other tenant', role: 'analyst', tenants: ['lisbon'] },
  ];
  assert.deepEqual(W.eligibleAssignees(accounts, permsOf, 'default').map((a) => a.name), ['ada', 'vera', 'ticket-bridge']);
});

test('list filters: closed values, a stored default, applied in the browser', () => {
  const mem = new Map();
  const storage = { getItem: (k) => mem.get(k) ?? null, setItem: (k, v) => mem.set(k, v) };
  assert.equal(W.readListDefault(storage), 'anyone');
  W.writeListDefault(storage, 'me');
  assert.equal(W.readListDefault(storage), 'me');
  assert.deepEqual(W.normalizeInvestigationFilters({}, W.readListDefault(storage)), { status: '', assignee: 'me' }, 'a link without assignee opens with the default');
  assert.deepEqual(W.normalizeInvestigationFilters({ assignee: 'anyone', status: 'open' }, 'me'), { status: 'open', assignee: 'anyone' }, 'the link wins');
  assert.deepEqual(W.normalizeInvestigationFilters({ assignee: '<x>', status: 'burning' }), { status: '', assignee: 'anyone' });
  const list = [{ id: 'a', status: 'open', assignee: 'cfg:ana' }, { id: 'b', status: 'closed', assignee: null }, { id: 'c', status: 'open' }, { id: 'd', status: 'monitoring', assignee: 'cfg:ada' }];
  assert.deepEqual(W.filterInvestigations(list, { assignee: 'me' }, 'cfg:ana').map((i) => i.id), ['a']);
  assert.deepEqual(W.filterInvestigations(list, { assignee: 'unassigned' }).map((i) => i.id), ['b', 'c']);
  assert.deepEqual(W.filterInvestigations(list, { status: 'open', assignee: 'anyone' }).map((i) => i.id), ['a', 'c']);
  assert.deepEqual(W.filterInvestigations(list, { assignee: 'me' }, ''), [], 'no principal id: nothing is "mine"');
  assert.equal(W.eventCountOf({ event_count: 12, event_ids: [] }), 12);
  assert.equal(W.eventCountOf({ event_ids: ['x', 'y'] }), 2);
});

test('the draft: title from the campaign label or the session source; the count capped at 200', () => {
  const c = W.investigationDraft({ kind: 'campaign', label: 'Model listing, then completion probe', id: 'cmp_23529e45783c', eventCount: 33 });
  assert.equal(c.title, 'Campaign: Model listing, then completion probe');
  assert.match(c.sentence, /^33 events will be attached\. A first note records the campaign’s basis and its caveat\.$/);
  const big = W.investigationDraft({ kind: 'campaign', label: '', id: 'cmp_aaaa11112222', eventCount: 950 });
  assert.equal(big.title, 'Campaign: cmp_aaaa11112222');
  assert.equal(big.count, 200);
  assert.match(big.sentence, /the newest 200 of 950, newest per session first/);
  const s = W.investigationDraft({ kind: 'session', source: '2001:db8::1f‮', id: 'f'.repeat(32), eventCount: 1 });
  assert.equal(s.title, 'Session from 2001:db8::1f');
  assert.match(s.sentence, /^One event will be attached/);
  assert.equal(Array.from(W.investigationDraft({ kind: 'session', source: 'x'.repeat(400) }).title).length, 173, 'the source is capped at 160 characters');
});

test('origin and features: only closed shapes; an older server has none of the new fields', () => {
  assert.deepEqual(W.normalizeOrigin({ kind: 'campaign', id: 'cmp_23529e45783c' }), { kind: 'campaign', id: 'cmp_23529e45783c' });
  assert.equal(W.normalizeOrigin({ kind: 'campaign', id: '../x' }), null);
  assert.equal(W.normalizeOrigin({ kind: 'ticket', id: 'x' }), null);
  assert.deepEqual(W.workspaceFeatures({ id: 'inv_1', notes: [] }), { assignee: false, activity: false, summary: false, origin: false });
  assert.deepEqual(W.workspaceFeatures({ assignee: null, activity: [], summary: {}, origin: null }), { assignee: true, activity: true, summary: true, origin: true });
});

test('a submit guard runs one request at a time and can run again after', async () => {
  const g = W.createSubmitGuard();
  let runs = 0;
  let release;
  const fn = () => { runs++; return new Promise((r) => { release = r; }); };
  const a = g.run(fn);
  const b = g.run(fn);
  assert.equal(a, b, 'the second submit shares the first');
  assert.equal(g.busy, true);
  await new Promise((r) => setImmediate(r));
  release('done');
  assert.equal(await a, 'done');
  assert.equal(runs, 1);
  await g.run(() => runs++);
  assert.equal(runs, 2);
});

// A stand-in for openDialog: builds the body, then submits `times` times
// at once (a double click), like a form would.
function fakeOpen({ times = 2, title } = {}) {
  const seen = {};
  const open = async ({ build, onSubmit, title: heading }) => {
    seen.heading = heading;
    const nodes = [build()].flat(3).filter(Boolean);
    const find = (name) => {
      const walk = (n) => (n.getAttribute?.('name') === name ? n : n.childNodes?.map(walk).find(Boolean));
      return nodes.map(walk).find(Boolean);
    };
    const titleInput = find('title');
    seen.prefilled = titleInput.value;
    const form = { elements: { title: { value: title ?? seen.prefilled }, priority: { value: find('priority').childNodes.find((o) => o.getAttribute('selected') !== null)?.getAttribute('value') } } };
    seen.priority = form.elements.priority.value;
    seen.note = nodes.at(-1).textContent;
    const results = await Promise.all(Array.from({ length: times }, () => onSubmit(form)));
    return results[0];
  };
  return { open, seen };
}

function fakeCtx(api) {
  const nav = [];
  const calls = [];
  const wrap = (name, fn) => (...args) => { calls.push([name, ...args]); return fn(...args); };
  return { nav, calls, navigate: (h) => nav.push(h), api: Object.fromEntries(Object.entries(api).map(([k, v]) => [k, wrap(k, v)])) };
}

test('campaign → investigation: prefilled, one request despite a double submit, lands on the case', async () => {
  const ctx = fakeCtx({ openCampaignInvestigation: async (id, body) => ({ id: 'inv_0123456789ab', event_ids: Array(33).fill('x'), origin: { kind: 'campaign', id }, ...body }) });
  const { open, seen } = fakeOpen({ times: 3 });
  const inv = await openInvestigationFrom(ctx, { kind: 'campaign', id: 'cmp_23529e45783c', label: 'Model listing', eventCount: 33, maxSeverity: 'critical' }, { open });
  assert.equal(inv.id, 'inv_0123456789ab');
  assert.equal(seen.prefilled, 'Campaign: Model listing');
  assert.equal(seen.priority, 'high', 'critical evidence suggests high priority');
  assert.match(seen.note, /33 events will be attached/);
  assert.deepEqual(ctx.calls, [['openCampaignInvestigation', 'cmp_23529e45783c', { title: 'Campaign: Model listing', priority: 'high', max_events: 200 }]]);
  assert.deepEqual(ctx.nav, ['#/investigations/inv_0123456789ab']);
});

test('session → investigation on an older server falls back to the plain create with the story’s ids', async () => {
  const missing = new ApiError(404, 'not_found', 'no such endpoint');
  const ctx = fakeCtx({
    openSessionInvestigation: async () => { throw missing; },
    createInvestigation: async (body) => ({ id: 'inv_fallback0001', event_ids: body.event_ids }),
  });
  const ids = Array.from({ length: 250 }, (_, i) => String(i).padStart(32, '0'));
  const { open } = fakeOpen({ times: 2, title: 'Spray from 198.51.100.9' });
  const inv = await openInvestigationFrom(ctx, { kind: 'session', id: 'e'.repeat(32), source: '198.51.100.9', eventCount: 250, fallbackIds: ids }, { open });
  assert.equal(inv.id, 'inv_fallback0001');
  assert.deepEqual(ctx.calls.map((c) => c[0]), ['openSessionInvestigation', 'createInvestigation']);
  assert.equal(ctx.calls[1][1].event_ids.length, 200, 'bounded to 200');
  assert.equal(ctx.calls[1][1].title, 'Spray from 198.51.100.9');
});

test('a campaign has no fallback: a refusal stays a refusal', async () => {
  const ctx = fakeCtx({ openCampaignInvestigation: async () => { throw new ApiError(404, 'not_found', 'campaign is no longer derivable from the index'); } });
  const { open } = fakeOpen({ times: 1 });
  await assert.rejects(openInvestigationFrom(ctx, { kind: 'campaign', id: 'cmp_23529e45783c', eventCount: 3 }, { open }), /no longer derivable/);
  assert.deepEqual(ctx.nav, []);
  assert.equal(suggestedPriority('medium'), 'medium');
  assert.equal(suggestedPriority('high'), 'high');
});
