import { h, clear, mount } from '../lib/dom.js';
import { href } from '../lib/route.js';
import { pageHead, panel, table, sevChip, badge, segmented, empty, link, labelFor, helpTip, banner } from '../ui/components.js';
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
    const columns = [
      { label: 'Id', className: 'nowrap', cell: (r) => link(href('events', { rule: r.id }), h('code', null, r.id)) },
      { label: 'Title', className: 'col-title', cell: (r) => r.title || '—' },
      { label: 'Severity', cell: (r) => (r.severity ? sevChip(r.severity) : h('span', { class: 'muted', title: 'Correlation rules emit signals without a severity' }, 'n/a')) },
      { label: 'State', cell: (r) => badge(r.enabled ? 'ok' : 'neutral', r.enabled ? 'Enabled' : 'Disabled') },
      ...(hasFrameworks ? [{ label: 'Relates to', cell: (r) => frameworkChips(r.frameworks) }] : []),
      { label: 'Description', className: 'col-desc', cell: (r) => r.description || h('span', { class: 'muted' }, 'No description') },
    ];
    const FAMILY_META = {
      detection: ['Detection rules', 'Grade one observation at a time and attach a finding with a severity.'],
      correlation: ['Correlation rules', 'Look across observations from one source and write a separate correlation signal. They have no severity of their own.'],
    };
    mount(root,
      pageHead({
        title: 'Rules',
        subtitle: 'The built-in rule catalog. Detection rules grade single observations; correlation rules emit signals across several. Rules are read-only here.',
        actions: segmented({ label: 'Rule family', options: FAMILIES, value: family, onChange: (f) => ctx.navigate(href('rules', { family: f })) }),
      }),
      hasFrameworks ? banner('info', 'Framework references are editorial',
        h('p', null, 'Each rule lists the MITRE ATT&CK, MITRE ATLAS and OWASP LLM 2025 entries it relates to. These are "relates to" references from the catalog, not coverage, completeness or compliance claims. ', h('a', { href: href('techniques') }, 'Open the technique matrix'), '.'),
        h('p', null, 'This list does not say per rule whether a match only observes or also shapes the decoy’s answer: the API does not report it. Each event shows its recorded detection action. The AI-pack rules (LLM-001 to LLM-004, HT-001, AGT-001) are documented as observe-only.')) : null,
      grouped.map(([fam, list]) => panel({
        title: h('span', { class: 'title-help' }, `${(FAMILY_META[fam] || [labelFor(fam)])[0]} · ${list.length}`, helpTip(glossaryEntry(fam === 'correlation' ? 'correlation' : 'finding'))),
        meta: (FAMILY_META[fam] || [])[1] || null,
        flush: true,
        body: list.length ? table({ caption: (FAMILY_META[fam] || [labelFor(fam)])[0], columns, rows: list }) : empty('No rules', 'No rule in this family.'),
      })));
  },
};
