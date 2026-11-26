import { toCan } from '../static/assets/js/lib/perms.js';
// Round 4: campaigns, actor profiles and the posture review. Pure wording
// and layout, then the three screens and the session additions rendered
// into the fake DOM with hostile strings, missing fields and older servers.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createFakeDocument } from './fakedom.mjs';

globalThis.document = createFakeDocument();
const I = await import('../static/assets/js/lib/insight.js');
const { ApiError } = await import('../static/assets/js/lib/api.js');
const { parseHash } = await import('../static/assets/js/lib/route.js');
const { isSafeHref } = await import('../static/assets/js/lib/dom.js');
const { NAV } = await import('../static/assets/js/ui/shell.js');
const { shortcutGroups } = await import('../static/assets/js/ui/palette.js');
const { default: campaigns } = await import('../static/assets/js/screens/campaigns.js');
const { default: campaign } = await import('../static/assets/js/screens/campaign.js');
const { default: posture } = await import('../static/assets/js/screens/posture.js');
const { actorProfileView, actorChip, campaignScoreView } = await import('../static/assets/js/ui/insight.js');
const { roleAtLeast } = await import('../static/assets/js/lib/taxonomy.js');

const HOSTILE = '<img src=x onerror=alert(1)>‮|`x`';
const text = (n) => n.textContent;
const all = (root, pred) => root.querySelectorAll(pred);
const cls = (el) => String(el.getAttribute('class') || '').split(' ');
const hasClass = (c) => (el) => cls(el).includes(c);

function ctx(api, { query = {}, params = {}, role = 'viewer' } = {}) {
  const titles = [];
  return { role, can: toCan(role), route: { query, params }, signal: undefined, navigate() {}, rerender() {}, api, setTitle: (t) => titles.push(t), titles };
}

const ACTOR = {
  assessment: 'possibly_ai_agent',
  summary: 'Machine pace with signs of acting on decoy content.',
  signals: [
    { code: 'human_think_time', label: 'Long pauses', strength: 'moderate', present: false, detail: 'median gap 700 ms' },
    { code: 'sub_second_bursts', label: 'Sub-second bursts', strength: 'moderate', present: true, detail: '7 of 9 gaps under 1 s' },
    { code: 'agent_canary_followed', label: 'Canary followed', strength: 'strong', present: true, detail: 'AGT-001 fired' },
    { code: 'brand_new_signal', label: 'Something new', strength: 'enormous', present: true, detail: '' },
    null,
  ],
};

const SESSION = (id, source, marks) => ({ id, source, first_seen: '2026-11-22T10:00:00Z', last_seen: '2026-11-22T10:00:09Z', duration_ms: 9000, event_count: 8, max_severity: 'high', cadence: { median_gap_ms: 700 }, actor: ACTOR, ...(marks ? { step_marks: marks } : {}) });

const CAMPAIGN = {
  id: 'cmp_3f9a1c2b7d10', label: 'Model listing, then chat completion probe', basis: ['same_step_sequence', 'same_client_family', 'mystery_basis'],
  source_count: 3, sources: ['203.0.113.5', HOSTILE, '2001:db8::1'], sources_truncated: false, session_count: 3, session_ids: [], event_count: 61,
  first_seen: '2026-11-22T08:00:00Z', last_seen: '2026-11-22T11:00:00Z', sensor_kinds: ['http'], rule_ids: ['LLM-001', 'bad rule id!'], max_severity: 'high',
  stages: ['discovery', 'recon'], automation_counts: { likely_automated: 2, inconclusive: 1, someday: 0 },
};
const DETAIL = {
  ...CAMPAIGN,
  steps: [
    { index: 0, sensor_kind: 'http', shape: 'GET /api/tags', stage: 'discovery', sessions: 3 },
    { index: 1, sensor_kind: 'http', shape: HOSTILE, stage: 'recon', sessions: 2 },
  ],
  steps_truncated: false,
  sessions: [
    SESSION('a'.repeat(32), '203.0.113.5', [{ index: 0, offset_ms: 0 }, { index: 1, offset_ms: 1400 }]),
    SESSION('b'.repeat(32), HOSTILE, [{ index: 0, offset_ms: 0 }]),
    SESSION('c'.repeat(32), '2001:db8::1', [{ index: 0, offset_ms: 0 }, { index: 1, offset_ms: 900 }]),
  ],
  caveats: ['Shared behaviour does not prove a shared operator.'],
};
const POSTURE = {
  generated_at: '2026-11-22T12:00:00Z',
  summary: { attention: 2, accepted: 0, ok: 1, info: 1 },
  checks: [
    { id: 'POS-001', area: 'exposure', status: 'ok', title: 'Loopback', detail: 'All loopback.', recommendation: '', doc: 'docs/configuration.md#sensors' },
    { id: 'POS-003', area: 'deception', status: 'attention', title: 'No honeytokens configured', detail: 'None planted.', recommendation: 'Mint one.', doc: 'docs/ai-threat-detection.md#honeytokens' },
    { id: 'POS-009', area: 'evidence', status: 'info', title: 'Index size', detail: 'Half full.', recommendation: 'Nothing to do.', doc: 'https://evil.test/x' },
    { id: 'POS-099', area: 'mystery', status: 'attention', title: HOSTILE, detail: '', recommendation: '', doc: '../../etc/passwd.md' },
  ],
};

test('plural, listJoin and humanize', () => {
  assert.equal(I.plural(1, 'source'), '1 source');
  assert.equal(I.plural(1200, 'source'), '1,200 sources');
  assert.equal(I.plural(2, 'agent canary', 'agent canaries'), '2 agent canaries');
  assert.equal(I.plural('x', 'check'), '0 checks');
  assert.equal(I.listJoin(['a', 'b', 'c']), 'a, b and c');
  assert.equal(I.listJoin(['a']), 'a');
  assert.equal(I.humanize('same_client_family'), 'Same client family');
});

test('older servers: only collection 404/405/501 count as a missing endpoint', () => {
  assert.equal(I.isMissingEndpoint(new ApiError(404, 'not_found')), true);
  assert.equal(I.isMissingEndpoint(new ApiError(405, 'internal')), true);
  assert.equal(I.isMissingEndpoint(new ApiError(503, 'unavailable')), false);
  assert.equal(I.isMissingEndpoint(null), false);
});

test('campaign ids and routes', () => {
  assert.equal(I.isCampaignId('cmp_3f9a1c2b7d10'), true);
  for (const bad of ['cmp_', 'cmp_ABC123', 'cmp_x/y', 'evt_1234', 'cmp_' + 'a'.repeat(65)]) assert.equal(I.isCampaignId(bad), false, bad);
  assert.equal(parseHash('#/campaigns').name, 'campaigns');
  assert.equal(parseHash('#/campaigns/cmp_3f9a1c2b7d10').name, 'campaign');
  assert.equal(parseHash('#/campaigns/cmp_%3Cx%3E').name, 'not_found');
  assert.equal(parseHash('#/posture').name, 'posture');
});

test('actor profile: present first by strength, unknown codes and strengths kept, no number', () => {
  const p = I.actorProfile(ACTOR);
  assert.equal(p.label, 'Possibly an AI agent');
  assert.deepEqual(p.present.map((s) => s.code), ['agent_canary_followed', 'sub_second_bursts', 'brand_new_signal']);
  assert.deepEqual(p.absent.map((s) => s.code), ['human_think_time']);
  assert.equal(p.present[2].strength.label, 'Not rated');
  assert.equal(p.present[2].meta.title, 'Brand new signal');
  assert.equal(p.tally, '3 of 4 signals observed');
  assert.equal(I.actorProfile(null), null);
  assert.equal(I.actorMeta('verdict_bot').label, 'Not assessed');
  for (const a of Object.values(I.ACTORS)) assert.doesNotMatch(`${a.label} ${a.lean}`, /%|\bbot\b|attacker|confirmed/i);
  for (const s of Object.values(I.SIGNALS)) assert.ok(Object.hasOwn(I.LEANS, s.leans));
});

test('actor profile view: checklist with observed and not-observed, server text as text', () => {
  const view = actorProfileView(ACTOR);
  const rows = all(view, hasClass('signal'));
  assert.equal(rows.length, 4);
  assert.equal(all(view, hasClass('signal--present')).length, 3);
  assert.match(text(view), /Not observed/);
  assert.match(text(view), /not a score/);
  assert.doesNotMatch(text(view), /\d+%/);
  assert.equal(all(actorProfileView(ACTOR, { lead: false }), hasClass('profile__summary')).length, 0);
  const chip = actorChip(ACTOR, { compact: true });
  assert.match(text(chip), /Possibly an agent · 3 of 4/);
});

test('campaign wording: basis sentence, mix, span', () => {
  assert.equal(I.basisSentence(CAMPAIGN), '3 sources showed the same sequence of steps, with the same client family and mystery basis.');
  assert.match(I.basisSentence({ source_count: 2 }), /did not say on what basis/);
  assert.deepEqual(I.automationMix(CAMPAIGN.automation_counts).map((r) => [r.key, r.count]), [['likely_automated', 2], ['inconclusive', 1]]);
  assert.equal(I.mixSentence({}), 'No actor profile was reported for these sessions.');
  assert.equal(I.spanText('2026-11-22T08:00:00Z', '2026-11-22T11:00:00Z'), 'over 3 hours');
  assert.equal(I.spanText('2026-11-22T08:00:00Z', '2026-11-22T08:20:00Z'), 'within 20 minutes');
  assert.equal(I.spanText('bad', ''), '');
  const n = I.normalizeCampaign({ id: 'nope', event_count: 'many', sources: [1, 'x'] });
  assert.equal(n.id, '');
  assert.equal(n.eventCount, null);
  assert.deepEqual(n.sources, ['x']);
  assert.deepEqual(I.normalizeCampaign(CAMPAIGN).ruleIds, ['LLM-001']);
});

test('campaign score: exact marks, and honest unknowns without them', () => {
  const exact = I.campaignScore(I.normalizeCampaign(DETAIL));
  assert.equal(exact.exact, true);
  assert.deepEqual(exact.lanes.map((l) => l.cells.map((c) => c.state)), [['performed', 'performed'], ['performed', 'absent'], ['performed', 'performed']]);
  assert.deepEqual(exact.shared, [true, false]);
  assert.equal(exact.lanes[0].cells[1].offset, 1400);
  const bare = I.campaignScore(I.normalizeCampaign({ ...DETAIL, sessions: DETAIL.sessions.map(({ step_marks, ...s }) => s) }));
  assert.equal(bare.exact, false);
  assert.deepEqual(bare.lanes[0].cells.map((c) => c.state), ['performed', 'unknown']);
  const view = campaignScoreView(I.normalizeCampaign(DETAIL), { sessionHref: (id) => `#/sessions/${id}` });
  const shapes = all(view, (el) => hasClass('evidence')(el) && text(el).includes('<img'));
  assert.ok(shapes.length >= 2, 'hostile shape and source render as evidence text');
  assert.match(text(view), /\+1\.4 s/);
});

test('posture: grouping, attention first, counts, doc links only for docs paths', () => {
  const g = I.postureGroups(POSTURE.checks);
  assert.deepEqual(g.groups.map((x) => x.id), ['exposure', 'deception', 'evidence', 'other']);
  assert.deepEqual(g.attention.map((c) => c.id), ['POS-003', 'POS-099']);
  assert.deepEqual(I.postureCounts(POSTURE), { attention: 2, accepted: 0, ok: 1, info: 1 });
  assert.deepEqual(I.postureCounts({ checks: POSTURE.checks }), { attention: 2, accepted: 0, ok: 1, info: 1 });
  assert.equal(I.docHref('docs/ai-threat-detection.md#honeytokens'), 'https://github.com/metaforismo/AegisMesh/blob/master/docs/ai-threat-detection.md#honeytokens');
  for (const bad of ['https://evil.test/x', '../../etc/passwd.md', 'docs/../x.md', 'docs/a.md#<x>', 'docs/a.txt']) assert.equal(I.docHref(bad), '', bad);
  assert.equal(isSafeHref(I.docHref('docs/cli.md#doctor')), true);
  assert.equal(isSafeHref('https://github.com/metaforismo/AegisMesh/blob/master/docs/../x.md'), false);
  assert.equal(I.postureLine({ attention: 1, ok: 3 }), 'Configuration review: 1 item needs attention.');
  assert.equal(I.postureLine({ attention: 0, ok: 1 }), 'Configuration review: nothing needs attention (1 check looks right).');
});

test('navigation: grouped for scanning, every new screen reachable, shortcut sheet from NAV', () => {
  assert.deepEqual(NAV.map((g) => g.group), ['Observe', 'Understand', 'Deception', 'Operate', 'Help']);
  const routes = NAV.flatMap((g) => g.items.map((i) => i.route));
  for (const r of ['campaigns', 'posture', 'sessions', 'digest']) assert.ok(routes.includes(r), r);
  const keys = NAV.flatMap((g) => g.items).filter((i) => i.keys).map((i) => i.keys);
  assert.equal(new Set(keys).size, keys.length, 'g-sequences are unique');
  const viewerGo = shortcutGroups('viewer').find((s) => s.title === 'Go to a screen').keys.map(([k]) => k.join(' '));
  assert.ok(viewerGo.includes('g m') && viewerGo.includes('g p'));
  assert.ok(!viewerGo.includes('g a'), 'the audit shortcut is listed for admins only');
  assert.ok(shortcutGroups('admin').find((s) => s.title === 'Go to a screen').keys.some(([k]) => k.join(' ') === 'g a'));
});

test('campaigns screen: cards with evidence sources; empty; older server', async () => {
  const root = document.createElement('div');
  await campaigns.render(root, ctx({ campaigns: async () => ({ items: [CAMPAIGN], scanned_sessions: 37, truncated: true, generated_at: '2026-11-22T12:00:00Z' }) }));
  assert.equal(all(root, hasClass('ccard')).length, 1);
  assert.match(text(root), /Compared 37 sessions/);
  assert.match(text(root), /scan limit was reached/);
  assert.match(text(root), /not one operator/);
  assert.ok(all(root, (el) => hasClass('evidence')(el) && text(el).includes('<img')).length >= 1);
  const empty = document.createElement('div');
  await campaigns.render(empty, ctx({ campaigns: async () => ({ items: [] }) }));
  assert.match(text(empty), /No campaigns in the indexed events/);
  const old = document.createElement('div');
  await campaigns.render(old, ctx({ campaigns: async () => { throw new ApiError(404, 'not_found', 'no route'); } }));
  assert.match(text(old), /does not provide campaigns yet/);
  await assert.rejects(campaigns.render(document.createElement('div'), ctx({ campaigns: async () => { throw new ApiError(503, 'unavailable', 'down'); } })));
});

test('campaign screen: score, caveats, sessions; unknown id says why', async () => {
  const root = document.createElement('div');
  const c = ctx({ campaign: async () => DETAIL }, { params: { id: 'cmp_3f9a1c2b7d10' } });
  await campaign.render(root, c);
  assert.deepEqual(c.titles, ['Model listing, then chat completion probe']);
  assert.equal(all(root, hasClass('score')).length, 1);
  assert.equal(all(root, hasClass('score__lane')).length, 3);
  assert.match(text(root), /Shared behaviour is not proof of a shared operator/);
  assert.match(text(root), /Server Shared behaviour does not prove/);
  const gone = document.createElement('div');
  await campaign.render(gone, ctx({ campaign: async () => { throw new ApiError(404, 'not_found'); } }, { params: { id: 'cmp_3f9a1c2b7d10' } }));
  assert.match(text(gone), /not in the current comparison/);
  await assert.rejects(campaign.render(document.createElement('div'), ctx({}, { params: { id: 'nope' } })));
});

test('posture screen: header disclaims a guarantee, attention first, filter, older server', async () => {
  const root = document.createElement('div');
  await posture.render(root, ctx({ posture: async () => POSTURE }));
  const t = text(root);
  assert.match(t, /configuration review, not a security guarantee/);
  assert.ok(t.indexOf('No honeytokens configured') < t.indexOf('Loopback'), 'attention before areas');
  const links = all(root, (el) => el.tagName === 'a' && String(el.getAttribute('href')).startsWith('https://'));
  assert.deepEqual(links.map((a) => a.getAttribute('href')), ['https://github.com/metaforismo/AegisMesh/blob/master/docs/ai-threat-detection.md#honeytokens', 'https://github.com/metaforismo/AegisMesh/blob/master/docs/configuration.md#sensors']);
  const only = document.createElement('div');
  await posture.render(only, ctx({ posture: async () => POSTURE }, { query: { show: 'attention' } }));
  assert.equal(all(only, hasClass('parea')).length, 0);
  assert.match(text(only), /2 other checks hidden/);
  const old = document.createElement('div');
  await posture.render(old, ctx({ posture: async () => { throw new ApiError(404, 'not_found'); } }));
  assert.match(text(old), /does not provide a posture review yet/);
});

test('campaignScore divides by the campaign session count when the listed sessions are capped', () => {
  const sessions = Array.from({ length: 50 }, (_, i) => ({ id: `s${i}` }));
  const score = I.campaignScore({ steps: [{ index: 0, sessions: 70 }, { index: 1, sessions: 40 }], sessions, sessionCount: 70 });
  assert.equal(score.total, 70);
  assert.equal(score.lanes[0].cells[0].state, 'performed');
  assert.equal(score.lanes[0].cells[1].state, 'unknown');
});
