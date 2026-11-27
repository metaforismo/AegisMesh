// Investigations: every case in the tenant, filtered by status and by
// assignee (anyone, me, unassigned), with assignee, event count and the
// highest severity of the attached evidence. The list is unpaged, so the
// filters apply in the browser (an older server knows neither the
// assignee filter nor the field, and then the assignee parts are left out).
// "Open with Assigned to me" is a choice kept in this browser.

import { h, mount } from '../lib/dom.js';
import { href, isOpaqueId, withQuery } from '../lib/route.js';
import { INVESTIGATION_STATUSES, PRIORITIES, severityRank } from '../lib/taxonomy.js';
import { timeValue } from '../lib/tablesort.js';
import { formatCount } from '../lib/format.js';
import { normalizeInvestigationFilters, filterInvestigations, readListDefault, writeListDefault, eventCountOf, STATUS_WORDS } from '../lib/workspace.js';
import { pageHead, panel, table, segmented, timeEl, empty, link, toast, sevChip } from '../ui/components.js';
import { statusBadge, priorityChip, newInvestigationDialog } from './shared.js';
import { icon } from '../ui/icons.js';

const storage = () => {
  try {
    return globalThis.localStorage || null;
  } catch {
    return null;
  }
};

const ASSIGNEE_WORDS = { anyone: 'Anyone', me: 'Assigned to me', unassigned: 'Unassigned' };

export default {
  title: 'Investigations',
  async render(root, ctx) {
    const store = storage();
    const f = normalizeInvestigationFilters(ctx.route.query, readListDefault(store));
    const res = await ctx.api.investigations('', { signal: ctx.signal });
    const all = Array.isArray(res.investigations) ? res.investigations : [];
    // Round 8 fields: present on every item from a newer server.
    const assignable = all.some((i) => 'assignee' in i) || (!all.length && Boolean(ctx.me));
    const meId = ctx.me?.id || '';
    const filters = assignable ? f : { ...f, assignee: 'anyone' };
    const invs = filterInvestigations(all, filters, meId);
    const go = (patch) => ctx.navigate(withQuery(ctx.route, patch));

    let create = null;
    if (ctx.can('investigations.write')) {
      create = h('button', { class: ['btn', 'btn--primary'], type: 'button' }, icon('plus', { size: 'sm' }), 'New investigation');
      create.addEventListener('click', async () => {
        const inv = await newInvestigationDialog(ctx);
        if (inv?.id && isOpaqueId(inv.id)) {
          toast('ok', 'Investigation created.');
          ctx.navigate(href('investigations', inv.id));
        }
      });
    }

    // "Open with Assigned to me": the default when a link names no assignee.
    let defaultToggle = null;
    if (assignable && meId) {
      const id = 'inv-default-mine';
      const box = h('input', { type: 'checkbox', id, prop: { checked: readListDefault(store) === 'me' } });
      const said = h('span', { class: 'visually-hidden', role: 'status' });
      box.addEventListener('change', () => {
        const ok = writeListDefault(store, box.checked ? 'me' : 'anyone');
        said.textContent = ok ? `This list now opens with ${box.checked ? 'Assigned to me' : 'Anyone'}.` : 'This browser does not keep the choice.';
        if (!('assignee' in ctx.route.query)) go({ assignee: box.checked ? 'me' : 'anyone' });
      });
      defaultToggle = h('label', { class: ['check', 'inv-default'], for: id }, box, h('span', null, 'Open with “Assigned to me”'), said);
    }

    const people = (i) => (i.assignee ? h('span', { class: 'inv-assignee' }, icon('user', { size: 'xs' }), i.assignee === meId ? 'You' : (i.assignee_name || i.assignee)) : h('span', { class: 'muted' }, 'Unassigned'));
    const columns = [
      { label: 'Title', className: 'col-summary', lead: true, sort: (i) => i.title, cell: (i) => (isOpaqueId(i.id) ? link(href('investigations', i.id), i.title || '(untitled)') : i.title) },
      { label: 'Status', sort: (i) => INVESTIGATION_STATUSES.indexOf(i.status), cell: (i) => statusBadge(i.status) },
      { label: 'Priority', sort: (i) => PRIORITIES.indexOf(i.priority), sortFirst: 'desc', cell: (i) => priorityChip(i.priority) },
      assignable ? { label: 'Assignee', className: 'nowrap', sort: (i) => (i.assignee ? i.assignee_name || i.assignee : ''), cell: people } : null,
      { label: 'Events', num: true, sort: eventCountOf, sortFirst: 'desc', cell: (i) => formatCount(eventCountOf(i)) },
      'max_severity' in (all[0] || {}) ? { label: 'Max severity', sort: (i) => severityRank(i.max_severity), sortFirst: 'desc', cell: (i) => sevChip(i.max_severity) } : null,
      { label: 'Opened by', sort: (i) => i.created_by, cell: (i) => i.created_by || '—' },
      { label: 'Updated', className: 'nowrap', sort: (i) => timeValue(i.updated_at), sortFirst: 'desc', cell: (i) => timeEl(i.updated_at, { relative: true }) },
    ].filter(Boolean);

    const statusWord = filters.status ? STATUS_WORDS[filters.status].label.toLowerCase() : '';
    const who = filters.assignee === 'me' ? ' assigned to you' : filters.assignee === 'unassigned' ? ', unassigned' : '';
    const filtered = Boolean(filters.status) || filters.assignee !== 'anyone';
    const emptyText = filtered
      ? empty(`No ${statusWord ? `${statusWord} ` : ''}investigations${who}`, 'Change a filter to see more.', h('a', { class: 'btn', href: href('investigations', { assignee: 'anyone' }) }, 'Show every investigation'))
      : empty('No investigations yet', ctx.can('investigations.write') ? 'Start one here, from any event with “Add to investigation”, or from a campaign or a session.' : 'Opening one needs the permission to change investigations, which your role does not include.');

    mount(root,
      pageHead({
        title: 'Investigations',
        subtitle: 'Operator-authored cases that collect evidence, notes and who is working on them. Every change is audited.',
        hint: 'Filter by status or by who it is assigned to, then open a case to work on it.',
        actions: [create],
      }),
      h('div', { class: 'inv-filters' },
        segmented({ label: 'Status', options: [['', 'All'], ...INVESTIGATION_STATUSES.map((s) => [s, STATUS_WORDS[s].label])], value: filters.status, onChange: (s) => go({ status: s }) }),
        assignable ? segmented({ label: 'Assignee', options: Object.entries(ASSIGNEE_WORDS), value: filters.assignee, onChange: (a) => go({ assignee: a }) }) : null,
        defaultToggle),
      panel({
        title: `${formatCount(invs.length)} ${statusWord ? `${statusWord} ` : ''}investigation${invs.length === 1 ? '' : 's'}${who}`,
        meta: filtered ? `Of ${formatCount(all.length)} in this tenant` : null,
        flush: true,
        body: invs.length ? table({ caption: 'Investigations', columns, rows: invs }) : emptyText,
      }));
  },
};

