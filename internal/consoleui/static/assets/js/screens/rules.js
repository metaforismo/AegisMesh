import { h, clear, mount } from '../lib/dom.js';
import { href } from '../lib/route.js';
import { pageHead, panel, table, sevChip, badge, segmented, empty, link, labelFor } from '../ui/components.js';

const FAMILIES = [['', 'All'], ['detection', 'Detection'], ['correlation', 'Correlation']];

export default {
  title: 'Rules',
  async render(root, ctx) {
    const res = await ctx.api.rules({ signal: ctx.signal });
    const all = Array.isArray(res.rules) ? res.rules : [];
    const family = FAMILIES.some(([f]) => f === ctx.route.query.family) ? ctx.route.query.family : '';
    const rules = family ? all.filter((r) => r.family === family) : all;

    mount(root,
      pageHead({
        title: 'Rules',
        subtitle: 'The built-in rule catalog. Detection rules grade single observations; correlation rules emit signals across several. Rules are read-only here.',
        actions: segmented({ label: 'Rule family', options: FAMILIES, value: family, onChange: (f) => ctx.navigate(href('rules', { family: f })) }),
      }),
      panel({
        title: `${rules.length} rules`, flush: true,
        body: rules.length ? table({
          caption: 'Rules',
          columns: [
            { label: 'Id', cell: (r) => link(href('events', { rule: r.id }), h('code', null, r.id)) },
            { label: 'Family', cell: (r) => labelFor(r.family) },
            { label: 'Title', cell: (r) => r.title || '—' },
            { label: 'Severity', cell: (r) => (r.severity ? sevChip(r.severity) : h('span', { class: 'muted', title: 'Correlation rules emit signals without a severity' }, 'n/a')) },
            { label: 'State', cell: (r) => badge(r.enabled ? 'ok' : 'neutral', r.enabled ? 'Enabled' : 'Disabled') },
            { label: 'Description', className: 'col-summary', cell: (r) => r.description || h('span', { class: 'muted' }, 'No description') },
          ],
          rows: rules,
        }) : empty('No rules', 'No rule in this family.'),
      }));
  },
};
