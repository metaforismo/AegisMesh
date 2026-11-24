import { h, clear, mount } from '../lib/dom.js';
import { href, isOpaqueId, normalizeStatus } from '../lib/route.js';
import { INVESTIGATION_STATUSES, PRIORITIES } from '../lib/taxonomy.js';
import { timeValue } from '../lib/tablesort.js';
import { plural } from '../lib/insight.js';
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
    if (ctx.can('investigations.write')) {
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
        hint: 'Open a case to add notes and evidence, or start a new one from any event.',
        actions: [
          segmented({ label: 'Status', options: [['', 'All'], ...INVESTIGATION_STATUSES.map((s) => [s, labelFor(s)])], value: status, onChange: (s) => ctx.navigate(href('investigations', { status: s })) }),
          create,
        ],
      }),
      panel({
        title: plural(invs.length, status ? `${labelFor(status).toLowerCase()} investigation` : 'investigation'),
        flush: true,
        body: invs.length ? table({
          caption: 'Investigations',
          columns: [
            { label: 'Title', className: 'col-summary', lead: true, sort: (i) => i.title, cell: (i) => (isOpaqueId(i.id) ? link(href('investigations', i.id), i.title || '(untitled)') : i.title) },
            { label: 'Status', sort: (i) => INVESTIGATION_STATUSES.indexOf(i.status), cell: (i) => statusBadge(i.status) },
            { label: 'Priority', sort: (i) => PRIORITIES.indexOf(i.priority), sortFirst: 'desc', cell: (i) => priorityChip(i.priority) },
            { label: 'Evidence', num: true, sort: (i) => (i.event_ids || []).length, cell: (i) => formatCount((i.event_ids || []).length) },
            { label: 'Owner', sort: (i) => i.created_by, cell: (i) => i.created_by || '—' },
            { label: 'Updated', className: 'nowrap', sort: (i) => timeValue(i.updated_at), sortFirst: 'desc', cell: (i) => timeEl(i.updated_at, { relative: true }) },
          ],
          rows: invs,
        }) : empty(status ? `No ${status} investigations` : 'No investigations yet',
          ctx.can('investigations.write') ? 'Start one here, or from any event with “Add to investigation”.' : 'Opening one needs the permission to change investigations, which your role does not include.'),
      }));
  },
};
