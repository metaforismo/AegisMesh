import { h, clear, mount } from '../lib/dom.js';
import { href } from '../lib/route.js';
import { pageHead, panel, table, sevChip, badge, segmented, empty, link, labelFor, helpTip, banner, actionChip, SIGNAL_NO_SEVERITY } from '../ui/components.js';
import { ruleActionMeta } from '../lib/catalogs.js';
import { frameworkChips } from '../ui/story.js';
import { glossaryEntry } from '../lib/glossary.js';

const FAMILIES = [['', 'All'], ['detection', 'Detection'], ['correlation', 'Correlation']];

export default {
  title: 'Rules',
  async render(root, ctx) {
    const res = await ctx.api.rules({ signal: ctx.signal });
    const all = Array.isArray(res.rules) ? res.rules : [];
    const family = FAMILIES.some(([f]) => f === ctx.route.query.family) ? ctx.route.query.family : '';
    const rules = family ? all.filter((r) => r.family === family) : all;

    const grouped = family ? [[family, rules]] : [['detection', all.filter((r) => r.family === 'detection')], ['correlation', all.filter((r) => r.family === 'correlation')]];
    const hasFrameworks = all.some((r) => Array.isArray(r.frameworks));
    // Older servers do not send observe_only, guidance or description.
    const hasAction = all.some((r) => typeof r.observe_only === 'boolean');
    const describe = (r) => {
      const d = typeof r.description === 'string' && r.description ? r.description : '';
      const g = typeof r.guidance === 'string' && r.guidance ? r.guidance : '';
      if (!d && !g) return h('span', { class: 'muted' }, 'No description');
      return h('div', { class: 'rule-prose' },
        d ? h('p', { class: 'rule-prose__desc' }, d) : null,
        g ? h('p', { class: 'rule-prose__next' }, h('span', { class: 'rule-prose__label' }, 'Check next'), g) : null);
    };
    const columns = [
      { label: 'Id', className: 'nowrap', cell: (r) => link(href('events', { rule: r.id }), h('code', null, r.id)) },
      { label: 'Title', className: 'col-title', cell: (r) => r.title || '—' },
      { label: 'Severity', cell: (r) => sevChip(r.severity, SIGNAL_NO_SEVERITY) },
      { label: 'State', cell: (r) => badge(r.enabled ? 'ok' : 'neutral', r.enabled ? 'Enabled' : 'Disabled') },
      ...(hasAction ? [{ label: 'On a match', className: 'nowrap', cell: (r) => actionChip(ruleActionMeta(r)) }] : []),
      ...(hasFrameworks ? [{ label: 'Relates to', cell: (r) => frameworkChips(r.frameworks) }] : []),
      { label: 'What it observes, and what to check next', className: 'col-desc', cell: describe },
    ];
    const FAMILY_META = {
      detection: ['Detection rules', 'Grade one observation at a time and attach a finding with a severity.'],
      correlation: ['Correlation rules', 'Look across observations from one source and write a separate correlation signal. They have no severity of their own.'],
    };
    mount(root,
      pageHead({
        title: 'Rules',
        subtitle: 'The built-in rule catalog. Detection rules grade single observations; correlation rules emit signals across several. Rules are read-only here.',
        hint: 'Read what each rule observes and what to check next, then open the events that cite it.',
        actions: segmented({ label: 'Rule family', options: FAMILIES, value: family, onChange: (f) => ctx.navigate(href('rules', { family: f })) }),
      }),
      hasFrameworks ? banner('info', 'Framework references are editorial',
        h('p', null, 'Each rule lists the MITRE ATT&CK, MITRE ATLAS and OWASP LLM 2025 entries it relates to. These are "relates to" references from the catalog, not coverage, completeness or compliance claims. ', h('a', { href: href('techniques') }, 'Open the technique matrix'), '.'),
        hasAction
          ? h('p', null, '“Observe only” rules never select a response action; every correlation rule and the AI and MCP observation rules are observe-only. “Can select an action” means that, under the configured severity mapping, a match may tag, throttle, isolate or refuse the decoy’s own connection; nothing outside the decoy is touched. Each event shows the action actually recorded.')
          : h('p', null, 'This server does not report per rule whether a match only observes. Each event shows its recorded detection action.')) : null,
      grouped.map(([fam, list]) => panel({
        title: h('span', { class: 'title-help' }, `${(FAMILY_META[fam] || [labelFor(fam)])[0]} · ${list.length}`, helpTip(glossaryEntry(fam === 'correlation' ? 'correlation' : 'finding'))),
        meta: (FAMILY_META[fam] || [])[1] || null,
        flush: true,
        body: list.length ? table({ caption: (FAMILY_META[fam] || [labelFor(fam)])[0], columns, rows: list }) : empty('No rules', 'No rule in this family.'),
      })));
  },
};
