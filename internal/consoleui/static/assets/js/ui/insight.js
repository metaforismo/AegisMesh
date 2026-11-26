// View pieces for campaigns, actor profiles and the posture review. Words
// come from lib/insight.js; every API string stays a Text node, and source
// keys and step shapes keep the evidence treatment.

import { h, svg, mount } from '../lib/dom.js';
import { href } from '../lib/route.js';
import { formatCount } from '../lib/format.js';
import { formatDurationMs } from '../lib/story.js';
import { actorProfile, actorMeta, LEANS, automationMix, campaignScore, plural, statusMeta } from '../lib/insight.js';
import { evidence, timeEl } from './components.js';
import { stageTag } from './story.js';
import { icon } from './icons.js';

// ---- Actor profile ---------------------------------------------------------------

// The reading as a shape plus words. `compact` is for tables: the short
// label and the count of observed signals.
export function actorChip(actor, { compact = false } = {}) {
  const p = actorProfile(actor);
  const m = p || actorMeta('');
  const count = p ? `${p.present.length} of ${p.checked}` : '';
  return h('span', { class: ['actor', `actor--${m.mark}`, compact ? 'actor--compact' : ''], title: compact && p ? `${m.label}. ${p.tally}.` : null },
    h('span', { class: 'actor__mark', 'aria-hidden': 'true' }),
    h('span', { class: 'actor__label' }, compact ? m.short : m.label),
    p && compact ? h('span', { class: 'actor__count' }, ` · ${count}`) : null,
    p && compact ? h('span', { class: 'visually-hidden' }, ' signals observed') : null);
}

// Three bars and a word: how much weight the server gives a signal. Never
// a number.
export function strengthMeter(meta) {
  return h('span', { class: ['strength', `strength--${meta.bars}`] },
    h('span', { class: 'strength__bars', 'aria-hidden': 'true' }, h('i'), h('i'), h('i')),
    h('span', { class: 'strength__label' }, meta.label));
}

function signalRow(s) {
  return h('li', { class: ['signal', s.present ? 'signal--present' : 'signal--absent'] },
    h('span', { class: 'signal__box', 'aria-hidden': 'true' }, s.present ? icon('check', { size: 'xs' }) : null),
    h('div', { class: 'signal__main' },
      h('p', { class: 'signal__title' },
        h('span', { class: 'visually-hidden' }, s.present ? 'Observed: ' : 'Not observed: '),
        s.label),
      s.meta.looked ? h('p', { class: 'signal__looked' }, s.meta.looked) : null,
      s.detail ? h('p', { class: 'signal__detail' }, h('span', { class: 'caps' }, s.present ? 'Measured' : 'Checked'), ' ', s.detail) : null),
    h('div', { class: 'signal__side' },
      s.present ? strengthMeter(s.strength) : h('span', { class: 'signal__absent' }, 'Not observed'),
      s.present ? h('span', { class: ['signal__lean', `signal__lean--${s.meta.leans}`] }, LEANS[s.meta.leans] || LEANS.context) : null));
}

// The profile: the reading in the briefing voice, the server's hedged
// sentence, then the checklist of what was looked for. Present signals
// first (strongest first), then the ones not observed.
// `lead: false` leaves the reading and sentence out where the page already
// shows them (the session hero); the tally stays.
export function actorProfileView(actor, { lead = true } = {}) {
  const p = actorProfile(actor);
  if (!p) return null;
  return h('div', { class: 'profile' },
    h('div', { class: 'profile__lead' },
      lead ? h('p', { class: 'profile__reading' }, actorChip(actor)) : null,
      lead && p.summary ? h('p', { class: 'profile__summary' }, p.summary) : null,
      h('p', { class: 'profile__tally' }, `${p.tally}. `, p.lean ? h('span', { class: 'muted' }, p.lean) : null)),
    p.present.length ? h('section', { class: 'profile__group', 'aria-label': 'Signals observed' },
      h('h3', { class: 'caps profile__head' }, `Observed · ${p.present.length}`),
      h('ul', { class: 'signals' }, p.present.map(signalRow))) : null,
    p.absent.length ? h('section', { class: 'profile__group', 'aria-label': 'Signals looked for and not observed' },
      h('h3', { class: 'caps profile__head' }, `Looked for, not observed · ${p.absent.length}`),
      h('ul', { class: ['signals', 'signals--absent'] }, p.absent.map(signalRow))) : null,
    h('p', { class: 'figures__note' }, 'A reading of the listed signals, not a score. It does not identify who or what is behind the session, and a throttled script can look like a person.'));
}

// ---- Campaigns -----------------------------------------------------------------------

// Automation mix: a proportion bar of shapes plus the words and counts.
export function mixView(counts, { compact = false } = {}) {
  const rows = automationMix(counts);
  if (!rows.length) return h('span', { class: 'muted' }, 'Not reported');
  const total = rows.reduce((n, r) => n + (r.count || 0), 0) || 1;
  const bar = h('span', { class: 'mix__bar', 'aria-hidden': 'true' }, rows.map((r) => {
    const seg = h('span', { class: ['mix__seg', `mix__seg--${r.meta.mark}`] });
    seg.style.flexGrow = String(r.count || 0);
    return seg;
  }));
  return h('span', { class: ['mix', compact ? 'mix--compact' : ''] },
    bar,
    h('span', { class: 'mix__list' }, rows.map((r) => h('span', { class: 'mix__item' },
      h('span', { class: ['actor__mark', `mix__mark--${r.meta.mark}`], 'aria-hidden': 'true' }),
      h('span', { class: 'mix__count' }, formatCount(r.count)), ' ', r.meta.short.toLowerCase(),
      compact ? null : h('span', { class: 'visually-hidden' }, ` of ${total}`)))));
}

// A small decorative "score" for a campaign card: one lane per source (up
// to five), each carrying the same run of stage marks, so sameness reads at
// a glance. Text beside it carries the numbers.
export function miniScore(sourceCount, stages) {
  const lanes = Math.max(2, Math.min(5, Number(sourceCount) || 2));
  const stops = Math.max(3, Math.min(6, (stages?.length || 0) * 2 || 4));
  const W = 132;
  const H = 12 + (lanes - 1) * 12;
  const x = (i) => 10 + (i * (W - 20)) / (stops - 1);
  const out = svg('svg', { class: 'miniscore', viewBox: `0 0 ${W} ${H}`, 'aria-hidden': 'true', focusable: 'false' });
  for (let i = 0; i < stops; i++) out.appendChild(svg('line', { class: 'miniscore__col', x1: x(i), x2: x(i), y1: 2, y2: H - 2 }));
  for (let l = 0; l < lanes; l++) {
    const y = 6 + l * 12;
    out.appendChild(svg('line', { class: 'miniscore__lane', x1: 4, x2: W - 4, y1: y, y2: y }));
    for (let i = 0; i < stops; i++) out.appendChild(svg('circle', { class: 'miniscore__stop', cx: x(i), cy: y, r: 2.4 }));
  }
  return out;
}

// Up to `max` source keys as evidence chips that open each source, and how
// many more exist.
export function sourceChips(sources, { total, truncated = false, max = 4 } = {}) {
  const list = Array.isArray(sources) ? sources : [];
  const shown = list.slice(0, max);
  const more = Math.max(0, (Number(total) || list.length) - shown.length);
  return h('span', { class: 'chip-row source-chips' },
    shown.map((s) => h('a', { class: 'source-chip', href: href('sources', s) }, evidence(s, { max: 28 }))),
    more ? h('span', { class: 'muted' }, `and ${formatCount(more)} more${truncated && list.length < (Number(total) || 0) ? ' (list capped by the server)' : ''}`) : null);
}

function offsetText(ms) {
  if (ms === null || ms === undefined) return '';
  return ms === 0 ? 'start' : `+${formatDurationMs(ms)}`;
}

// The campaign score: an accessible table drawn as lanes. Columns are the
// shared steps (number, stage, shape as evidence, how many sessions took
// it); rows are sessions (source as evidence, start time). A performed step
// is a solid mark on the lane with its offset from the session's start; a
// step not taken is an empty ring; without per-session marks from the
// server, a step only some sessions took is a dotted "?".
// Beyond these, the score folds: the first lanes and steps are drawn and
// one "Show all" per axis draws the rest (no motion; the counts are said).
export const SCORE_LANES = 12;
export const SCORE_STEPS = 12;

export function campaignScoreView(c, { sessionHref, lanes: laneCap = SCORE_LANES, steps: stepCap = SCORE_STEPS } = {}) {
  const score = campaignScore(c);
  if (!score.steps.length || !score.lanes.length) return null;
  let allLanes = score.lanes.length <= laneCap + 2;
  let allSteps = score.steps.length <= stepCap + 2;
  const wrap = h('div', { class: 'score-wrap' });
  const foot = h('div', { class: 'score-more' });
  const root = h('div', { class: 'score-block' }, wrap, foot);
  let laneLinks = [];
  const draw = () => {
    laneLinks = [];
    const nSteps = allSteps ? score.steps.length : stepCap;
    const lanes = allLanes ? score.lanes : score.lanes.slice(0, laneCap);
    const steps = score.steps.slice(0, nSteps);
    const head = h('tr', null,
      h('th', { scope: 'col', class: 'score__corner' }, h('span', { class: 'caps' }, 'Source'), h('span', { class: 'caps score__corner-steps' }, 'Step →')),
      steps.map((st, i) => h('th', { scope: 'col', class: ['score__step', score.shared[i] ? 'is-shared' : ''] },
        h('span', { class: 'score__num' }, String(i + 1)),
        stageTag(st.stage),
        h('span', { class: 'score__shape' }, evidence(st.shape, { max: 26 })),
        h('span', { class: 'score__share' }, st.sessions === null ? '—' : `${formatCount(st.sessions)} of ${formatCount(score.total)}`))));
    const rows = lanes.map((lane) => {
      const s = lane.session;
      const id = typeof s.id === 'string' && /^[0-9a-f]{32}$/.test(s.id) ? s.id : '';
      const who = id ? h('a', { href: sessionHref(id), class: 'score__src' }, evidence(s.source, { max: 22 })) : evidence(s.source, { max: 22 });
      laneLinks.push(id ? who : null);
      return h('tr', { class: 'score__lane' },
        h('th', { scope: 'row', class: 'score__who' },
          who,
          h('span', { class: 'score__when' }, timeEl(s.first_seen, { relative: true }), ' · ', plural(lane.performed, 'step'))),
        lane.cells.slice(0, nSteps).map((cell, i) => h('td', { class: ['score__cell', `score__cell--${cell.state}`, score.shared[i] ? 'is-shared' : ''] },
          h('span', { class: 'score__mark', 'aria-hidden': 'true' }),
          h('span', { class: 'score__t', 'aria-hidden': 'true' }, cell.state === 'performed' ? offsetText(cell.offset) : ''),
          h('span', { class: 'visually-hidden' }, cell.state === 'performed' ? `Performed${cell.offset !== null ? ` at ${offsetText(cell.offset)}` : ''}` : cell.state === 'absent' ? 'Not performed' : 'Not reported per session'))));
    });
    mount(wrap, h('table', { class: 'score' },
      h('caption', { class: 'visually-hidden' }, `Campaign score: one row per session, one column per shared step. ${scoreShownText(lanes.length, score.lanes.length, nSteps, score.steps.length)}`),
      h('thead', null, head),
      h('tbody', null, rows)));
    const buttons = [];
    if (!allLanes) {
      const b = h('button', { class: ['btn', 'btn--sm'], type: 'button' }, `Show all ${formatCount(score.lanes.length)} sessions`);
      // Focus moves to the first lane that was hidden, so reading continues.
      b.addEventListener('click', () => { allLanes = true; draw(); laneLinks[laneCap]?.focus?.(); });
      buttons.push(b);
    }
    if (!allSteps) {
      const b = h('button', { class: ['btn', 'btn--sm'], type: 'button' }, `Show all ${formatCount(score.steps.length)} steps`);
      b.addEventListener('click', () => { allSteps = true; draw(); laneLinks[0]?.focus?.(); });
      buttons.push(b);
    }
    const note = allLanes && allSteps ? '' : scoreShownText(lanes.length, score.lanes.length, nSteps, score.steps.length);
    mount(foot, note ? [h('p', { class: 'muted score-more__note' }, note), h('div', { class: 'btn-row' }, buttons)] : null);
    foot.hidden = !note;
  };
  draw();
  return root;
}

// "Showing 12 of 32 sessions and 12 of 20 steps." (only the folded axes)
export function scoreShownText(lanes, laneTotal, steps, stepTotal) {
  const parts = [];
  if (lanes < laneTotal) parts.push(`${formatCount(lanes)} of ${formatCount(laneTotal)} sessions`);
  if (steps < stepTotal) parts.push(`${formatCount(steps)} of ${formatCount(stepTotal)} steps`);
  return parts.length ? `Showing ${parts.join(' and ')}.` : '';
}

// ---- Posture ---------------------------------------------------------------------------

export function statusChip(status) {
  const m = statusMeta(status?.key ?? status);
  return h('span', { class: ['pstatus', `pstatus--${m.mark}`] },
    h('span', { class: 'pstatus__mark', 'aria-hidden': 'true' }, m.mark === 'ok' ? icon('check', { size: 'xs' }) : m.mark === 'attention' ? '!' : m.mark === 'accepted' ? '–' : 'i'),
    m.label);
}
