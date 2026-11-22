// View pieces for attacker sessions and the technique matrix. Words and
// layout come from lib/story.js; API strings stay Text nodes, source keys
// and summaries keep the evidence treatment.

import { h } from '../lib/dom.js';
import { href } from '../lib/route.js';
import { assessmentOf, gapScalePos, formatDurationMs, groupFrameworks, stageMeta } from '../lib/story.js';
import { chip } from './components.js';

// The automation observation: a shape plus words, never a verdict badge.
// filled diamond = consistent; ring = no pattern; dash = too few events.
export function assessmentChip(automation, { compact = false } = {}) {
  const a = assessmentOf(automation);
  return h('span', { class: ['assess', `assess--${a.glyph}`, compact ? 'assess--compact' : ''], title: compact ? a.line : null },
    h('span', { class: 'assess__mark', 'aria-hidden': 'true' }),
    h('span', { class: 'assess__label' }, compact ? a.short : a.label),
    h('span', { class: 'assess__count' }, compact ? ` · ${a.observations}` : ` · ${a.observations} observation${a.observations === 1 ? '' : 's'}`),
    compact ? h('span', { class: 'visually-hidden' }, ` observation${a.observations === 1 ? '' : 's'}`) : null);
}

// A log-scale strip (10 ms … 1 h) with the min-to-p90 range and a median
// tick. Decorative beside the printed median; the numbers are the record.
export function cadenceStrip(c) {
  const range = h('span', { class: 'cstrip__range' });
  const tick = h('span', { class: 'cstrip__median' });
  const lo = gapScalePos(c?.min_gap_ms);
  const hi = Math.max(lo, gapScalePos(c?.p90_gap_ms));
  range.style.left = `${(lo * 100).toFixed(2)}%`;
  range.style.width = `${Math.max(1.5, (hi - lo) * 100).toFixed(2)}%`;
  tick.style.left = `${(gapScalePos(c?.median_gap_ms) * 100).toFixed(2)}%`;
  return h('span', { class: 'cstrip' },
    h('span', { class: 'cstrip__track', 'aria-hidden': 'true' }, range, tick),
    h('span', { class: 'cstrip__value' }, `median ${formatDurationMs(c?.median_gap_ms)}`));
}

// Framework references as chips that open the technique matrix on that
// framework. Editorial "relates to" references: the caption says so.
export function frameworkChips(refs, { link = true } = {}) {
  const groups = groupFrameworks(refs);
  if (!groups.length) return h('span', { class: 'muted' }, '—');
  return h('div', { class: 'fw-groups' }, groups.map((g) => h('div', { class: 'fw-group' },
    h('span', { class: 'fw-group__label' }, g.label),
    h('span', { class: 'chip-row' }, g.refs.map((r) => {
      const c = h('span', { class: ['chip', 'chip--fw'] }, h('code', null, r.id), r.name ? h('span', { class: 'chip__name' }, r.name) : null);
      return link ? h('a', { class: 'fw-link', href: href('techniques', { f: g.framework, t: r.id }), title: `${g.label} ${r.id}: open in the technique matrix` }, c) : c;
    })))));
}

export function stageTag(stage) {
  const m = stageMeta(stage);
  return h('span', { class: ['stage', `stage--${stage in { discovery: 1, credential_access: 1, ai_service_abuse: 1, decoy_credential_replay: 1 } ? stage : 'other'}`], title: m.hint }, h('span', { class: 'stage__mark', 'aria-hidden': 'true' }), m.label);
}

export function kindChips(kinds, { text = false } = {}) {
  const list = Array.isArray(kinds) ? kinds : [];
  if (!list.length) return h('span', { class: 'muted' }, '—');
  return text ? h('span', { class: 'kinds' }, list.map((k) => String(k).toUpperCase()).join(' · ')) : h('span', { class: 'chip-row' }, list.map((k) => chip(String(k).toUpperCase())));
}
