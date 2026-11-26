// Technique matrix (GET /coverage): for each framework, the techniques the
// rule catalog relates its rules to, and how many indexed events in the
// window cited one of those rules. It answers "which techniques do our rules
// relate to, and what did we observe": not coverage, completeness,
// compliance, technique execution or attribution. The API's own
// `interpretation` sentence is shown verbatim as interface text.

import { h, mount } from '../lib/dom.js';
import { href, normalizeWindow, normalizeFramework, TECHNIQUE_FRAMEWORKS } from '../lib/route.js';
import { formatCount } from '../lib/format.js';
import { frameworkLabel, boundsNote } from '../lib/story.js';
import { glossaryEntry } from '../lib/glossary.js';
import { pageHead, panel, segmented, timeEl, helpTip, caveat, empty } from '../ui/components.js';
import { icon } from '../ui/icons.js';

const WINDOWS = [['1h', '1h'], ['24h', '24h'], ['7d', '7d']];
const TECH_ID = /^[A-Za-z0-9.]{1,32}$/;
const RULE_ID = /^[A-Za-z0-9_.:-]{1,64}$/;

// Events citing any of the technique's rules. The events filter takes one
// rule; with several, the cell links to the first and lists the others.
function cell(t, since) {
  const rules = (Array.isArray(t.rule_ids) ? t.rule_ids : []).filter((r) => RULE_ID.test(r));
  const n = Number(t.observed_event_count) || 0;
  const observed = n > 0;
  const body = [
    h('span', { class: 'tcell__head' }, h('code', { class: 'tcell__id' }, String(t.id)), observed ? h('span', { class: 'tcell__count' }, formatCount(n)) : h('span', { class: 'tcell__none' }, 'not observed')),
    h('span', { class: 'tcell__name' }, String(t.name || '')),
    h('span', { class: 'tcell__rules' }, rules.map((r) => h('code', null, r))),
    h('span', { class: 'tcell__seen' }, observed ? ['Last seen ', timeEl(t.last_seen, { relative: true })] : 'No event in this window cited these rules'),
  ];
  const cls = ['tcell', observed ? 'tcell--observed' : 'tcell--quiet'];
  const label = `${t.id} ${t.name}: ${observed ? `${formatCount(n)} events` : 'not observed'} in the window; rules ${rules.join(', ') || 'none'}`;
  return observed && rules.length
    ? h('a', { class: cls, href: href('events', { rule: rules[0], since }), 'aria-label': `${label}. Open events citing ${rules[0]}`, 'data-tech': TECH_ID.test(t.id) ? t.id : null }, body)
    : h('div', { class: cls, role: 'group', 'aria-label': label, 'data-tech': TECH_ID.test(t.id) ? t.id : null }, body);
}

export default {
  title: 'Techniques',
  async render(root, ctx) {
    const window = normalizeWindow(ctx.route.query.window);
    const res = await ctx.api.coverage(window, { signal: ctx.signal });
    const frameworks = (Array.isArray(res.frameworks) ? res.frameworks : []).filter((f) => TECHNIQUE_FRAMEWORKS.includes(f?.framework));
    const since = typeof res.since === 'string' ? res.since : '';
    let active = normalizeFramework(ctx.route.query.f);
    const gridSlot = h('div');
    const tabs = h('div', { class: 'tabs', role: 'tablist', 'aria-label': 'Framework' });

    const paint = () => {
      const fw = frameworks.find((f) => f.framework === active) || { techniques: [] };
      const list = Array.isArray(fw.techniques) ? fw.techniques : [];
      const seen = list.filter((t) => Number(t.observed_event_count) > 0).length;
      mount(tabs, TECHNIQUE_FRAMEWORKS.map((f) => {
        const n = (frameworks.find((x) => x.framework === f)?.techniques || []).filter((t) => Number(t.observed_event_count) > 0).length;
        const b = h('button', { class: 'tab', type: 'button', role: 'tab', 'aria-selected': String(f === active), tabindex: f === active ? '0' : '-1', 'aria-controls': 'tech-grid' }, frameworkLabel(f), h('span', { class: 'tab__count' }, ` ${n}`));
        b.addEventListener('click', () => ctx.navigate(href('techniques', { window, f })));
        b.addEventListener('keydown', (e) => {
          const i = TECHNIQUE_FRAMEWORKS.indexOf(active);
          const j = e.key === 'ArrowRight' ? (i + 1) % 3 : e.key === 'ArrowLeft' ? (i + 2) % 3 : -1;
          if (j >= 0) { e.preventDefault(); ctx.navigate(href('techniques', { window, f: TECHNIQUE_FRAMEWORKS[j] })); }
        });
        return b;
      }));
      mount(gridSlot,
        h('p', { class: 'tgrid__summary' }, `${formatCount(seen)} of ${formatCount(list.length)} related techniques had events in the window.`),
        list.length ? h('div', { class: 'tgrid', id: 'tech-grid', role: 'tabpanel' }, list.map((t) => cell(t, since)))
          : empty('No techniques', 'The rule catalog relates no rule to this framework.', null, { icon: 'matrix' }));
      const focus = ctx.route.query.t;
      if (typeof focus === 'string' && TECH_ID.test(focus)) gridSlot.querySelector(`[data-tech="${focus}"]`)?.classList.add('is-target');
    };
    paint();

    mount(root,
      pageHead({
        title: h('span', { class: 'title-help' }, 'Techniques', helpTip(glossaryEntry('mapping'))),
        subtitle: 'The framework techniques the detection and correlation rules relate to, and how many indexed events in the window cited those rules.',
        hint: 'Switch frameworks with the tabs, then open an observed cell to see the events that cited it.',
        actions: segmented({ label: 'Time window', options: WINDOWS, value: window, onChange: (w) => ctx.navigate(href('techniques', { window: w, f: active })) }),
      }),
      caveat({ id: 'techniques-coverage', title: 'Not a coverage claim.', summary: 'Observed means a related rule fired; not observed does not mean absent.' },
        h('p', null, typeof res.interpretation === 'string' && res.interpretation ? res.interpretation : 'Editorial rule relations and retained observations.'),
        h('p', null, 'An unobserved technique means no rule related to it fired in this window, not that the technique was absent or is detectable. An observed one means a related rule fired, not that the technique was used or succeeded.')),
      h('p', { class: 'page-note' }, icon('info', { size: 'sm' }), h('span', null, boundsNote(res.bounds))),
      panel({ primary: true, title: tabs, body: gridSlot }));
    return { update: (r) => { active = normalizeFramework(r.query.f); paint(); } };
  },
};
