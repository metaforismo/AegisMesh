import { h, clear, mount } from '../lib/dom.js';
import { href, isOpaqueId, normalizeStatus } from '../lib/route.js';
import { INVESTIGATION_STATUSES } from '../lib/taxonomy.js';
import { formatCount } from '../lib/format.js';
import { pageHead, panel, table, segmented, timeEl, empty, link, labelFor, toast } from '../ui/components.js';
import { statusBadge, priorityChip, newInvestigationDialog } from './shared.js';

export default {
  title: 'Investigations',
  async render(root, ctx) {
    const status = normalizeStatus(ctx.route.query.status);
    const res = await ctx.api.investigations(status, { signal: ctx.signal });
    const invs = Array.isArray(res.investigations) ? res.investigations : [];

    let create = null;
    if (ctx.can('analyst')) {
      create = h('button', { class: ['btn', 'btn--primary'], type: 'button' }, 'New investigation');
      create.addEventListener('click', async () => {
        const inv = await newInvestigationDialog(ctx);
        if (inv?.id && isOpaqueId(inv.id)) {
          toast('ok', 'Investigation created.');
          ctx.navigate(href('investigations', inv.id));
        }
      });
    }

    mount(root,
      pageHead({
        title: 'Investigations',
        subtitle: 'Operator-authored cases that collect evidence and notes. They are the only state the console writes, and every change is audited.',
        actions: [
          segmented({ label: 'Status', options: [['', 'All'], ...INVESTIGATION_STATUSES.map((s) => [s, labelFor(s)])], value: status, onChange: (s) => ctx.navigate(href('investigations', { status: s })) }),
          create,
        ],
      }),
      panel({
        title: `${formatCount(invs.length)} ${status ? labelFor(status).toLowerCase() : ''} investigations`.replace('  ', ' '),
        flush: true,
        body: invs.length ? table({
          caption: 'Investigations',
          columns: [
            { label: 'Title', className: 'col-summary', cell: (i) => (isOpaqueId(i.id) ? link(href('investigations', i.id), i.title || '(untitled)') : i.title) },
            { label: 'Status', cell: (i) => statusBadge(i.status) },
            { label: 'Priority', cell: (i) => priorityChip(i.priority) },
            { label: 'Evidence', num: true, cell: (i) => formatCount((i.event_ids || []).length) },
            { label: 'Owner', cell: (i) => i.created_by || '—' },
            { label: 'Updated', cell: (i) => timeEl(i.updated_at, { relative: true }) },
          ],
          rows: invs,
        }) : empty(status ? `No ${status} investigations` : 'No investigations yet',
          ctx.can('analyst') ? 'Start one here, or from any event with “Add to investigation”.' : 'Analysts and admins can open investigations.'),
      }));
  },
};
