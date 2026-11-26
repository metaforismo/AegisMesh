// Round 7 polish: folding caveats, page-head action links, the posture
// "acceptable" contract, and the print header.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createFakeDocument } from './fakedom.mjs';

globalThis.document = createFakeDocument();
const mem = new Map();
globalThis.localStorage = { getItem: (k) => (mem.has(k) ? mem.get(k) : null), setItem: (k, v) => mem.set(k, String(v)), removeItem: (k) => mem.delete(k) };
let narrow = false;
globalThis.matchMedia = () => ({ matches: narrow });

const C = await import('../static/assets/js/ui/components.js');
const I = await import('../static/assets/js/lib/insight.js');
const { createAcceptance } = await import('../devserver/mock-roles.mjs');

const cls = (el) => el.getAttribute('class') || '';

test('caveat storage is validated on read', () => {
  assert.deepEqual(C.readCaveats('{"rules-frameworks":"closed","x":"open"}'), { 'rules-frameworks': 'closed', x: 'open' });
  assert.deepEqual(C.readCaveats('{"Bad Id":"closed","a":"maybe","b":1}'), {});
  assert.deepEqual(C.readCaveats('not json'), {});
  assert.deepEqual(C.readCaveats('[1,2]'), {});
  assert.deepEqual(C.readCaveats(null), {});
});

test('a caveat starts open on wide screens, folded on phones, unless the operator chose', () => {
  assert.equal(C.caveatOpen('a', {}, false), true);
  assert.equal(C.caveatOpen('a', {}, true), false);
  assert.equal(C.caveatOpen('a', { a: 'open' }, true), true);
  assert.equal(C.caveatOpen('a', { a: 'closed' }, false), false);
});

test('caveat renders a summary that carries the claim and remembers a toggle', () => {
  mem.clear();
  narrow = true;
  const el = C.caveat({ id: 'techniques-coverage', title: 'Not a coverage claim.', summary: 'Observed means a related rule fired.' }, 'Full text one.', 'Full text two.');
  assert.equal(el.tagName, 'details');
  assert.match(cls(el), /banner banner--info caveat/);
  assert.equal(el.getAttribute('open'), null, 'folded on a phone by default');
  const summary = el.childNodes[0];
  assert.equal(summary.tagName, 'summary');
  assert.match(summary.textContent, /Not a coverage claim\. ?Observed means a related rule fired\./);
  assert.match(el.childNodes[1].textContent, /Full text one\.Full text two\./);
  el.open = true;
  el.dispatch('toggle');
  assert.deepEqual(JSON.parse(mem.get(C.CAVEAT_KEY)), { 'techniques-coverage': 'open' });
  const again = C.caveat({ id: 'techniques-coverage', title: 't', summary: 's' });
  assert.equal(again.getAttribute('open'), '', 'the remembered choice wins over the phone default');
  narrow = false;
  assert.throws(() => C.caveat({ id: 'Bad id', title: 't' }), /caveat id/);
});

test('page-head navigation actions are outlined buttons with an icon', () => {
  const a = C.actionLink('#/events?source=x', 'Events from this source', 'events');
  assert.equal(a.tagName, 'a');
  assert.equal(cls(a), 'btn');
  assert.equal(a.getAttribute('href'), '#/events?source=x');
  assert.equal(a.textContent, 'Events from this source');
  assert.match(cls(a.childNodes[0]), /icon/);
});

test('posture: acceptable comes from the server when it says so', () => {
  const older = I.normalizeCheck({ id: 'POS-1', status: 'attention', accepted: null });
  assert.equal(older.acceptable, true);
  assert.equal(older.serverDecides, false);
  const no = I.normalizeCheck({ id: 'POS-1', status: 'attention', accepted: null, acceptable: false, acceptable_reason: 'editing_disabled' });
  assert.equal(no.acceptable, false);
  assert.equal(no.acceptableReason, 'editing_disabled');
  // An unknown code is not echoed as interface text.
  assert.equal(I.normalizeCheck({ status: 'attention', acceptable: false, acceptable_reason: '<b>x</b>' }).acceptableReason, '');
  assert.match(I.acceptBlockedText('editing_disabled'), /editing is off/);
  assert.match(I.acceptBlockedText('permission_denied', 'Change console settings'), /needs “Change console settings”/);
  assert.match(I.acceptBlockedText('bogus'), /cannot be accepted now/);
  assert.equal(I.acceptBlockedText('not_attention'), '');
});

test('posture: the accept plan hides the button and says why once', () => {
  const n = (o) => I.normalizeCheck({ status: 'attention', accepted: null, ...o });
  // Server says no for every check, one reason: said once, no per-check line.
  const all = [n({ id: 'a', acceptable: false, acceptable_reason: 'editing_disabled' }), n({ id: 'b', acceptable: false, acceptable_reason: 'editing_disabled' })];
  let plan = I.acceptPlan(all, { permitted: true });
  assert.equal(plan.once, 'editing_disabled');
  assert.equal(plan.offer(all[0]), false);
  assert.equal(plan.perCheck(all[0]), '');
  // Mixed: offered where acceptable, the reason beside the others.
  const mixed = [n({ id: 'a', acceptable: true, acceptable_reason: '' }), n({ id: 'b', acceptable: false, acceptable_reason: 'overlay_unavailable' })];
  plan = I.acceptPlan(mixed, { permitted: true });
  assert.equal(plan.once, '');
  assert.equal(plan.offer(mixed[0]), true);
  assert.equal(plan.perCheck(mixed[1]), 'overlay_unavailable');
  // The server's yes wins over a local guess, and its no over a permission.
  assert.equal(I.acceptPlan(mixed, { permitted: false }).offer(mixed[0]), true);
  // Older server: today's behaviour (permission decides, said once).
  const old = [n({ id: 'a' }), n({ id: 'b' })];
  assert.equal(I.acceptPlan(old, { permitted: true }).offer(old[0]), true);
  plan = I.acceptPlan(old, { permitted: false });
  assert.equal(plan.offer(old[0]), false);
  assert.equal(plan.once, 'permission_denied');
  // A server without accepted risk at all: nothing offered, nothing said.
  const none = [I.normalizeCheck({ status: 'attention' })];
  plan = I.acceptPlan(none, { permitted: true });
  assert.equal(plan.offer(none[0]), false);
  assert.equal(plan.once, '');
  assert.equal(plan.perCheck(none[0]), '');
});

test('posture: revoking follows the server too', () => {
  const acc = (o) => I.normalizeCheck({ status: 'accepted', accepted: { by: 'x', until: '2030-01-01T00:00:00Z' }, ...o });
  assert.equal(I.canRevokeAcceptance(acc({ acceptable: false, acceptable_reason: 'already_accepted' }), false), true);
  assert.equal(I.canRevokeAcceptance(acc({ acceptable: false, acceptable_reason: 'editing_disabled' }), true), false);
  assert.equal(I.canRevokeAcceptance(acc({ acceptable: false, acceptable_reason: 'permission_denied' }), true), false);
  assert.equal(I.canRevokeAcceptance(acc({}), true), true);
  assert.equal(I.canRevokeAcceptance(acc({}), false), false);
});

test('mock posture: acceptable with the backend precedence', () => {
  const a = createAcceptance({ startedAt: Date.parse('2026-11-01T00:00:00Z') });
  const body = { checks: [{ id: 'POS-001', status: 'attention' }, { id: 'POS-004', status: 'attention' }, { id: 'POS-009', status: 'ok' }] };
  const admin = a.decorate(body, { canManage: true, editing: true });
  assert.deepEqual(admin.checks.map((c) => [c.id, c.acceptable, c.acceptable_reason]), [
    ['POS-001', true, ''], ['POS-004', false, 'already_accepted'], ['POS-009', false, 'not_attention']]);
  const viewer = a.decorate(body, { canManage: false, editing: false });
  assert.ok(viewer.checks.every((c) => c.acceptable === false && c.acceptable_reason === 'permission_denied'));
  const off = a.decorate(body, { canManage: true, editing: false });
  assert.ok(off.checks.every((c) => c.acceptable_reason === 'editing_disabled'));
  const older = createAcceptance({ acceptableField: false }).decorate(body, { canManage: true, editing: true });
  assert.ok(older.checks.every((c) => !('acceptable' in c)));
});

test('identical recommendations read as one card with a count and all evidence', async () => {
  const { groupRecommendations } = await import('../static/assets/js/screens/recommendations.js');
  const base = { classification: 'canary_invocation', sensor_id: 'ssh-decoy', sensor_kind: 'ssh', summary: 'A canary invocation was observed.', operator_review: 'Confirm.', next_steps: ['Open the evidence.'], false_positive_notes: [], rule_ids: [], conflicts: [] };
  const recs = [
    { ...base, evidence: [{ event_id: 'a'.repeat(32) }], source_resolution: { resolved: 1, unresolved: 0 } },
    { ...base, sensor_id: 'web', sensor_kind: 'http', evidence: [{ event_id: 'b'.repeat(32) }] },
    { ...base, evidence: [{ event_id: 'c'.repeat(32) }] },
    null,
  ];
  const g = groupRecommendations(recs);
  assert.equal(g.length, 2);
  assert.equal(g[0].sensor_id, 'ssh-decoy', 'first appearance keeps its place');
  assert.equal(g[0].count, 2);
  assert.deepEqual(g[0].evidence.map((e) => e.event_id[0]), ['a', 'c']);
  assert.equal(g[0].source_resolution, null, 'a per-proposal figure is not summed into a group');
  assert.equal(g[1].count, 1);
  assert.deepEqual(groupRecommendations(undefined), []);
});

test('seeded events say they are synthetic; observed ones do not', async () => {
  const { eventTable } = await import('../static/assets/js/screens/shared.js');
  const ev = (o) => ({ id: 'a'.repeat(32), time: '2026-11-26T10:00:00Z', sensor: { id: 'web', kind: 'http' }, classification: 'interaction', source: '192.0.2.1', summary: 'GET /', severity: '', rule_ids: [], ...o });
  const el = eventTable([ev({ synthetic: true }), ev({ id: 'b'.repeat(32) }), ev({ id: 'c'.repeat(32), synthetic: 'yes' })], { caption: 'x' });
  const chips = el.querySelectorAll((n) => /chip--synthetic/.test(n.getAttribute?.('class') || ''));
  assert.equal(chips.length, 1, 'only a literal true marks a row');
  assert.equal(chips[0].textContent, 'Synthetic');
});

test('the digest Markdown names the organisation, fenced', async () => {
  const { digestMarkdown } = await import('../static/assets/js/lib/catalogs.js');
  const md = digestMarkdown({ window: '24h', totals: {} }, { organization: 'Example `SOC`' });
  assert.match(md, /^# AegisMesh digest: the last 24 hours\n\nOrganization: `` Example `SOC` ``\n/);
  assert.doesNotMatch(digestMarkdown({ window: '24h' }), /Organization:/);
});
