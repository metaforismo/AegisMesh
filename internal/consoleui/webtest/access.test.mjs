// Round 6 logic: permissions and roles (lib/perms.js), editable settings
// and their history (lib/settings.js), audit details, accepted posture risk
// (lib/insight.js) and the tour's placement (lib/viz.js). Pure functions.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as P from '../static/assets/js/lib/perms.js';
import * as S from '../static/assets/js/lib/settings.js';
import * as I from '../static/assets/js/lib/insight.js';
import { tourPlacement } from '../static/assets/js/lib/viz.js';
import { parseHash } from '../static/assets/js/lib/route.js';
import { NAV } from '../static/assets/js/ui/shell.js';
import { shortcutGroups } from '../static/assets/js/ui/palette.js';

test('built-in roles grant the agreed sets; admin holds the whole catalogue', () => {
  assert.deepEqual(P.BUILTIN_PERMS.viewer, ['evidence.read', 'analysis.read', 'investigations.read', 'fleet.read', 'keys.self']);
  assert.deepEqual([...P.BUILTIN_PERMS.analyst].sort(), [...P.BUILTIN_PERMS.viewer, 'evidence.export', 'reports.download', 'investigations.write'].sort());
  assert.deepEqual([...P.BUILTIN_PERMS.admin].sort(), [...P.PERMISSION_IDS].sort());
  assert.equal(P.PERMISSION_IDS.length, 18);
  for (const id of ['accounts.manage', 'roles.manage', 'settings.manage', 'fleet.manage', 'sessions.manage']) assert.equal(P.CATALOGUE.find((p) => p.id === id).risk, 'high', id);
});

test('permissionsOf: /me.permissions wins; an older server maps the built-in role; a custom role without a list grants nothing', () => {
  assert.deepEqual([...P.permissionsOf({ permissions: ['evidence.read', 'bogus id', 'audit.read'] })], ['evidence.read', 'audit.read']);
  assert.deepEqual([...P.permissionsOf(null, { principal: { role: 'analyst' } })], [...P.BUILTIN_PERMS.analyst]);
  assert.equal(P.permissionsOf(null, { principal: { role: 'role_0123456789ab' } }).size, 0);
  const can = P.toCan(['audit.read']);
  assert.equal(can('audit.read'), true);
  assert.equal(can('audit.export'), false);
  assert.equal(can(''), true, 'no permission needed');
  assert.equal(P.toCan('viewer')('investigations.write'), false);
  assert.equal(P.toCan('analyst')('investigations.write'), true);
});

test('navigation is permission-driven: a screen without its permission leaves the sidebar and the shortcut sheet', () => {
  const ticket = P.toCan(['evidence.read', 'investigations.read', 'investigations.write']);
  const routes = NAV.flatMap((g) => g.items).filter((i) => ticket(P.ROUTE_PERMS[i.route])).map((i) => i.route);
  for (const r of ['digest', 'techniques', 'recommendations', 'posture', 'fleet', 'audit']) assert.ok(!routes.includes(r), r);
  for (const r of ['overview', 'events', 'investigations', 'settings', 'guide']) assert.ok(routes.includes(r), r);
  const sheet = shortcutGroups(ticket).flatMap((g) => g.keys.map((k) => k[1]));
  assert.ok(!sheet.includes('Go to Audit trail'));
  assert.ok(shortcutGroups('admin').flatMap((g) => g.keys.map((k) => k[1])).includes('Go to Audit trail'));
  // The settings pages follow their own permissions.
  const auditor = P.toCan(['evidence.read', 'accounts.read', 'settings.read', 'audit.read', 'audit.export', 'system.read']);
  assert.deepEqual(S.visibleSections({}, auditor).admin.map((s) => s.id), S.ADMIN_SECTIONS.map((s) => s.id));
  assert.deepEqual(S.visibleSections({}, P.toCan(['evidence.read', 'settings.read'])).admin.map((s) => s.id), ['sso', 'security', 'console', 'data', 'detection', 'fleet', 'exports', 'history']);
  assert.deepEqual(S.visibleSections({}, P.toCan('viewer')).admin, []);
});

test('routes: a role page by id or "new"; anything else is not a route', () => {
  assert.equal(parseHash('#/settings/roles/role_0123456789ab').name, 'settings_role');
  assert.equal(parseHash('#/settings/roles/viewer').name, 'settings_role');
  assert.equal(parseHash('#/settings/roles/new').params.id, 'new');
  for (const bad of ['#/settings/roles/role_XYZ', '#/settings/roles/root', '#/settings/roles/role_0123456789abc']) assert.notEqual(parseHash(bad).name, 'settings_role', bad);
  assert.equal(parseHash('#/settings/history?key=console.session_ttl_seconds').params.section, 'history');
});

test('role editor rules: names, descriptions, the dependency rules, diff sentences', () => {
  assert.match(P.validateRoleName(''), /Give the role a name/);
  assert.match(P.validateRoleName('x'.repeat(41)), /40 characters/);
  assert.match(P.validateRoleName('Auditor', ['auditor']), /without case/);
  assert.match(P.validateRoleName('evil‮'), /printable/);
  assert.equal(P.validateRoleName('Incident responder', ['Auditor']), '');
  assert.match(P.validateRoleDescription('d'.repeat(201)), /200/);
  assert.match(P.validateRolePermissions([]), /at least one/);
  assert.deepEqual(P.missingDependencies(['evidence.read', 'roles.manage']), ['accounts.read', 'accounts.manage']);
  assert.deepEqual(P.missingDependencies(['settings.manage', 'accounts.manage', 'accounts.read']), ['settings.read']);
  assert.deepEqual(P.missingDependencies(['sessions.manage']), ['accounts.read']);
  assert.match(P.validateRolePermissions(['evidence.read', 'settings.manage']), /also needs .*Create and change managed accounts.*Read the server/);
  assert.equal(P.validateRolePermissions(['evidence.read', 'settings.manage', 'settings.read', 'accounts.manage', 'accounts.read']), '');
  const d = P.permissionDiff(['evidence.read', 'audit.read'], ['evidence.read', 'audit.export', 'fleet.read']);
  assert.deepEqual(d, { added: ['audit.export', 'fleet.read'], removed: ['audit.read'] }, 'catalogue order');
  assert.equal(P.diffSentence(d, 3), 'Adds 2, removes 1; affects 3 accounts — takes effect on their next request.');
  assert.equal(P.diffSentence({ added: ['x'], removed: [] }, 1), 'Adds 1; affects 1 account — takes effect on their next request.');
  assert.equal(P.diffSentence({ added: [], removed: ['x'] }, 0), 'Removes 1; no account holds this role yet.');
});

test('role wording: summary, counts, risk, names, refusals', () => {
  const s = P.roleSummary(['evidence.read', 'roles.manage', 'future.thing']);
  assert.equal(s.can.length, 2);
  assert.deepEqual(s.high.map((p) => p.id), ['roles.manage']);
  assert.deepEqual(s.unknown, ['future.thing']);
  assert.equal(P.permCountLine(['evidence.read', 'roles.manage', 'accounts.manage']), '3 permissions, 2 high risk');
  assert.equal(P.permCountLine(['evidence.read']), '1 permission');
  assert.deepEqual(P.rolesRisk([{ builtin: true, permissions: ['roles.manage'] }, { builtin: false, permissions: ['fleet.manage'], assigned: { managed: 0 } }, { builtin: false, permissions: ['evidence.read'], assigned: { managed: 2 } }]), { custom: 2, high: 1, unused: 1 });
  assert.equal(P.assignedTotal({ managed: 2, config: 1, oidc: -1 }), 3);
  assert.equal(P.roleNameOf('viewer', [{ id: 'viewer', name: 'viewer' }]), 'Viewer', 'built-ins are said as words');
  assert.equal(P.roleNameOf('role_0123456789ab', [{ id: 'role_0123456789ab', name: 'Auditor' }]), 'Auditor');
  assert.equal(P.roleNameOf('role_0123456789ab', []), 'Custom role');
  assert.equal(P.roleDisplayName({ id: 'admin', name: 'admin', builtin: true }), 'Admin');
  assert.equal(P.riskMeta('nope').label, 'Unknown risk');
  assert.match(S.refusalMessage({ status: 409, reason: 'in_use', message: 'assigned to 2 accounts' }), /still assigned \(assigned to 2 accounts\)/);
  assert.match(S.refusalMessage({ status: 409, reason: 'builtin' }), /Duplicate it/);
  assert.match(S.refusalMessage({ status: 403, reason: 'exceeds_own_permissions' }), /your own role does not include/);
  assert.match(S.refusalMessage({ status: 409, reason: 'editing_disabled' }), /console.settings_editing: off/);
  assert.match(S.refusalMessage({ status: 409, reason: 'not_editable' }), /config file/);
});

test('catalogue from the server: validated, unknown risk kept as unknown, falls back to the built-in copy', () => {
  const c = P.normalizeCatalogue({ items: [{ id: 'evidence.read', group: 'Evidence', label: 'Read', risk: 'low' }, { id: 'BAD', label: 'x' }, { id: 'new.perm', group: '', label: '', risk: 'cosmic' }] });
  assert.deepEqual(c.map((x) => [x.id, x.group, x.risk]), [['evidence.read', 'Evidence', 'low'], ['new.perm', 'Other', 'unknown']]);
  assert.equal(P.normalizeCatalogue(null).length, 18);
  assert.deepEqual(P.groupCatalogue(P.CATALOGUE).map((g) => g.group), ['Evidence', 'Investigations', 'Audit', 'Fleet', 'Access', 'Settings and system']);
});

const TTL = { key: 'console.session_ttl_seconds', constraints: { min: 900, max: 86400, unit: 's', reason_max_len: 200 }, applies: 'live' };
const IDLE = { key: 'console.session_idle_seconds', constraints: { min: 300, max: 86400, unit: 's', allow_zero: true } };
const DAYS = { key: 'console.key_max_days', constraints: { min: 1, max: 365, unit: 'days' } };
const WIN = { key: 'console.default_window', constraints: { enum: ['1h', '24h', '7d'] } };
const ORG = { key: 'console.organization_name', constraints: { max_len: 80, multiline: false } };
const BANNER = { key: 'console.sign_in_banner', constraints: { max_len: 500, multiline: true } };

test('settings: raw values in words, constraints as one sentence', () => {
  assert.equal(S.formatSettingRaw(TTL, '28800'), '8 hours');
  assert.equal(S.formatSettingRaw(TTL, '5400'), '1 hour 30 minutes');
  assert.equal(S.formatSettingRaw(IDLE, '0'), 'off');
  assert.equal(S.formatSettingRaw(DAYS, '1'), '1 day');
  assert.equal(S.formatSettingRaw(WIN, '7d'), '7 days');
  assert.equal(S.formatSettingRaw(ORG, ''), 'not set');
  assert.equal(S.formatSettingRaw({ key: 'console.session_ttl_seconds' }, '3600'), '1 hour', 'inferred from the key when constraints are missing');
  assert.equal(S.constraintText(TTL), '900 to 86,400 seconds (15 minutes to 1 day).');
  assert.equal(S.constraintText(IDLE), '0 turns it off; otherwise 300 to 86,400 seconds (5 minutes to 1 day).');
  assert.equal(S.constraintText(WIN), 'One of 1 hour, 24 hours, 7 days.');
  assert.match(S.constraintText(BANNER), /line breaks kept, at most 500 characters/);
  assert.equal(S.appliesText('live'), 'Applies at once');
  assert.equal(S.appliesText('restart'), 'Applies after a restart');
  assert.match(S.appliesText('none'), /built-in limit/);
  assert.equal(S.settingSourceMeta('console').label, 'Console');
});

test('settings: input parsing against constraints, and the required reason', () => {
  assert.deepEqual(S.parseSettingInput(TTL, '43200'), { value: 43200 }, 'numbers go as JSON numbers');
  assert.match(S.parseSettingInput(TTL, '600').error, /900 to 86,400 seconds/);
  assert.match(S.parseSettingInput(TTL, '1.5').error, /whole number/);
  assert.deepEqual(S.parseSettingInput(IDLE, '0'), { value: 0 });
  assert.match(S.parseSettingInput(IDLE, '120').error, /0 \(off\) or 300/);
  assert.deepEqual(S.parseSettingInput(WIN, '7d'), { value: '7d' });
  assert.match(S.parseSettingInput(WIN, '30d').error, /Choose one of/);
  assert.deepEqual(S.parseSettingInput(ORG, '  Example SOC  '), { value: 'Example SOC' });
  assert.match(S.parseSettingInput(ORG, 'x'.repeat(81)).error, /80 characters or fewer \(now 81\)/);
  assert.match(S.parseSettingInput(ORG, 'a\nb').error, /printable/);
  assert.deepEqual(S.parseSettingInput(BANNER, 'Line one\nLine two'), { value: 'Line one\nLine two' }, 'the banner keeps line breaks');
  assert.match(S.parseSettingInput(BANNER, 'evil‮text').error, /direction/);
  assert.match(S.validateChangeReason(' '), /Say why/);
  assert.match(S.validateChangeReason('r'.repeat(201)), /200/);
  assert.equal(S.validateChangeReason('Night shift works 12-hour rotations.'), '');
});

test('settings: whether a row can be edited, and why not', () => {
  const on = { editing: 'console', editable: true };
  const item = { key: TTL.key, editable: true };
  assert.deepEqual(S.editState(item, on, true), { editable: true, why: '' });
  assert.deepEqual(S.editState(item, on, false), { editable: false, why: 'permission' });
  assert.deepEqual(S.editState({ ...item, editable: false }, { editing: 'off', editable: false }, true), { editable: false, why: 'off' });
  assert.deepEqual(S.editState({ key: 'console.listen', editable: false }, { editing: 'off' }, true), { editable: false, why: '' }, 'not allowlisted: no reason to give');
  assert.deepEqual(S.editState({ key: 'posture.accepted', editable: true }, on, true), { editable: false, why: 'posture' }, 'accepted risk changes on Posture');
  assert.deepEqual(S.editState({ key: TTL.key }, null, true), { editable: false, why: '' }, 'an older server: read-only');
});

test('history: known shape only, newest first; audit details parsed from the server text', () => {
  const h = S.normalizeHistory({ items: [
    { seq: 1, key: 'console.default_window', from: '24h', to: '7d', actor_id: 'cfg:ada', actor_name: 'ada', reason: 'r1', at: '2026-11-20T10:00:00Z' },
    { seq: 2, key: 'BAD KEY', from: 'a', to: 'b', at: '2026-11-21T10:00:00Z' },
    { seq: 3, key: 'console.session_ttl_seconds', from: 28800, to: 43200, actor_id: 'cfg:ada', reason: 'r3', at: '2026-11-22T10:00:00Z' },
  ] });
  assert.deepEqual(h.map((e) => [e.seq, e.from, e.to, e.actor]), [[3, '28800', '43200', 'cfg:ada'], [1, '24h', '7d', 'ada']]);
  assert.deepEqual(S.parseAuditDetail('from="3600" to="7200" seq=4 reason="Night \\"shift\\"\\n12h"'), { from: '3600', to: '7200', seq: '4', reason: 'Night "shift"\n12h' });
  assert.deepEqual(S.parseAuditDetail('name="Auditor" permissions=audit.read,audit.export'), { name: 'Auditor', permissions: 'audit.read,audit.export' });
  assert.deepEqual(S.parseAuditDetail('until=2027-01-01T00:00:00Z reason="Compensating control \\u00e9"'), { until: '2027-01-01T00:00:00Z', reason: 'Compensating control é' });
  assert.deepEqual(S.parseAuditDetail('from="a" to="cut off here'), { from: 'a', to: 'cut off here…' }, 'a detail cut at 256 bytes');
  for (const free of ['', 'key.list', 'Tenant switch to default', 'account.create acc_x', null]) assert.equal(S.parseAuditDetail(free), null, String(free));
});

test('posture: accepted risk is its own status, counted apart, never "looks right"', () => {
  const res = { summary: { attention: 1, accepted: 1, ok: 1, info: 0 }, checks: [
    { id: 'POS-003', area: 'exposure', status: 'attention', title: 'a', accepted: null },
    { id: 'POS-004', area: 'deception', status: 'accepted', title: 'b', accepted: { by: 'cfg:ada', by_name: 'ada', reason: 'why', until: '2027-01-20T00:00:00Z' } },
    { id: 'POS-005', area: 'deception', status: 'ok', title: 'c', accepted: null },
  ] };
  const g = I.postureGroups(res.checks);
  assert.deepEqual(g.attention.map((c) => c.id), ['POS-003']);
  assert.deepEqual(g.accepted.map((c) => c.id), ['POS-004']);
  assert.equal(g.accepted[0].status.label, 'Accepted risk');
  assert.deepEqual(g.accepted[0].accepted, { by: 'cfg:ada', byName: 'ada', reason: 'why', until: '2027-01-20T00:00:00Z' });
  assert.equal(g.groups.find((x) => x.id === 'deception').accepted, 1);
  assert.deepEqual(I.postureCounts(res), { attention: 1, accepted: 1, ok: 1, info: 0 });
  assert.equal(I.postureLine({ attention: 1, accepted: 1, ok: 1 }), 'Configuration review: 1 item needs attention; 1 accepted as a known risk.');
  assert.equal(I.normalizeCheck({ status: 'attention' }).acceptable, false, 'an older server: no accept action');
  assert.equal(I.normalizeCheck(res.checks[0]).acceptable, true);
});

test('posture: accept-until presets, dates and the 180-day limit; the reason is required', () => {
  const now = Date.parse('2026-11-24T12:00:00Z');
  assert.equal(I.acceptUntil(30, now), '2026-12-24T12:00:00Z');
  assert.equal(I.acceptUntil(500, now), '2027-05-23T11:59:00Z', 'clamped under 180 days');
  assert.deepEqual(I.acceptUntilFromDate('2027-01-31', now), { until: '2027-01-31T23:59:59Z' });
  assert.match(I.acceptUntilFromDate('2026-11-23', now).error, /after today/);
  assert.match(I.acceptUntilFromDate('2027-12-31', now).error, /180 days/);
  assert.match(I.acceptUntilFromDate('', now).error, /Choose an end date/);
  assert.match(I.validateAcceptReason(''), /Say why/);
  assert.equal(I.validateAcceptReason('Compensating control'), '');
});

test('tour placement never covers its target or the key content beside it (1440 and 375)', () => {
  const ov = (a, b) => Math.max(0, Math.min(a.right, b.right) - Math.max(a.left, b.left)) * Math.max(0, Math.min(a.bottom, b.bottom) - Math.max(a.top, b.top));
  const rect = (p, box) => ({ left: p.left, top: p.top, right: p.left + box.width, bottom: p.top + box.height });
  const box = { width: 320, height: 204 };
  // 1440: the brief beside its count list, room below once scrolled.
  const brief = { left: 256, top: 120, right: 1032, bottom: 475 };
  const tally = { left: 1065, top: 200, right: 1391, bottom: 458 };
  const p1 = tourPlacement(brief, box, { width: 1440, height: 900 }, [tally]);
  assert.equal(ov(rect(p1, box), brief), 0);
  assert.equal(ov(rect(p1, box), tally), 0);
  assert.equal(p1.side, 'below');
  // The old rule put it right of a tall brief, over the counts.
  const p2 = tourPlacement(tally, box, { width: 1440, height: 900 }, [brief]);
  assert.equal(ov(rect(p2, box), tally) + ov(rect(p2, box), brief), 0);
  // 375: the brief fills the width; the counts come after it.
  const b375 = { left: 16, top: 266, right: 359, bottom: 812 };
  const p3 = tourPlacement(b375, { width: 320, height: 220 }, { width: 375, height: 812 }, [{ left: 16, top: 908, right: 359, bottom: 1166 }]);
  assert.equal(ov(rect(p3, { width: 320, height: 220 }), b375), 0);
  assert.equal(p3.side, 'above');
  for (const p of [p1, p2, p3]) assert.ok(p.left >= 8 && p.top >= 8);
});
