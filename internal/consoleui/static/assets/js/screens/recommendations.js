import { h, clear, mount } from '../lib/dom.js';
import { href, isEventId } from '../lib/route.js';
import { pageHead, panel, clsChip, chip, empty, selectField, link, labelFor, kv, banner } from '../ui/components.js';
import { ruleChips } from './shared.js';

const LIMITS = ['20', '100', '1000'];

function list(items, cls = 'bullets') {
  const arr = Array.isArray(items) ? items : [];
  if (!arr.length) return h('p', { class: 'muted' }, 'None');
  return h('ul', { class: cls }, arr.map((t) => h('li', null, t)));
}

function card(r) {
  const evidenceLinks = (r.evidence || []).map((e) => h('li', { class: 'evidence-link' },
    isEventId(e.event_id) ? link(href('events', e.event_id), h('code', null, e.event_id)) : h('code', null, String(e.event_id ?? '')),
    h('span', { class: 'muted' }, ' payload sha256 '), h('code', { class: 'hash' }, String(e.payload_sha256 ?? '')),
    h('span', { class: 'muted' }, ` · ${labelFor(e.verification)} (${labelFor(e.integrity_scope)})`)));
  return h('article', { class: ['banner', 'banner--proposal', 'rec'] },
    h('div', { class: 'rec__body' },
      h('div', { class: 'rec__head' },
        h('p', { class: 'rec__kicker' }, h('span', { class: 'chip' }, 'Proposed · not executed'), clsChip(r.classification), r.sensor_id ? chip(`${r.sensor_id} (${r.sensor_kind || '?'})`, { mono: true }) : null),
        h('h2', { class: 'rec__title' }, r.summary || 'Recommendation'),
        // A card without rule ids shows nothing there, not a lone dash.
        (r.rule_ids || []).length ? ruleChips(r.rule_ids) : null),
      h('div', { class: 'grid grid--2' },
        h('section', null, h('h3', null, 'Operator review'), r.operator_review ? h('p', null, r.operator_review) : h('p', { class: 'muted' }, 'None given')),
        h('section', null, h('h3', null, 'Suggested next steps'), list(r.next_steps))),
      h('section', null, h('h3', null, 'Known false-positive patterns'), list(r.false_positive_notes)),
      (r.conflicts || []).length ? h('section', null, h('h3', null, 'Conflicting signals'),
        h('ul', { class: 'bullets' }, r.conflicts.map((c) => h('li', null, h('code', null, c.code), ` · ${labelFor(c.resolution)} · `, c.note, ' ', ruleChips(c.rule_ids))))) : null,
      r.source_resolution ? kv([['Source events resolved', `${r.source_resolution.resolved} resolved, ${r.source_resolution.unresolved} unresolved`]]) : null,
      h('section', null, h('h3', null, `Evidence (${evidenceLinks.length})`), evidenceLinks.length ? h('ul', { class: 'plain-list' }, evidenceLinks) : h('p', { class: 'muted' }, 'None'))));
}

export default {
  title: 'Recommendations',
  async render(root, ctx) {
    const limit = LIMITS.includes(ctx.route.query.limit) ? ctx.route.query.limit : '20';
    const report = await ctx.api.recommendations(Number(limit), { signal: ctx.signal });
    const recs = Array.isArray(report.recommendations) ? report.recommendations : [];

    mount(root,
      pageHead({
        title: 'Recommendations',
        subtitle: 'Deterministic review suggestions generated from stored signals. They are dry-run proposals: nothing here changes a sensor, a policy or a remote host.',
        hint: 'Review each proposal against its linked evidence; applying anything is your decision, outside AegisMesh.',
        actions: selectField({ label: 'Show', name: 'limit', value: limit, options: LIMITS.map((l) => [l, `Up to ${l}`]), onChange: (l) => ctx.navigate(href('recommendations', { limit: l })) }),
      }),
      banner('info', 'How to read these', h('p', null, `Mode ${labelFor(report.mode || 'dry_run')} · interpretation “${labelFor(report.interpretation || 'signal_not_incident')}”. A recommendation is a prompt for a human to look, not a verdict.`)),
      recs.length ? h('div', { class: 'stack' }, recs.map(card)) : panel({ body: empty('No recommendations', 'No stored signal currently produces a review suggestion.') }));
  },
};
