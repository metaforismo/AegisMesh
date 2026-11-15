import { h, clear, mount } from '../lib/dom.js';
import { href, normalizeAuditFilters } from '../lib/route.js';
import { AUDIT_ACTIONS } from '../lib/taxonomy.js';
import { formatDateTime, formatCount, shortId } from '../lib/format.js';
import { pageHead, panel, table, badge, seal, selectField, inputField, empty, pager, banner, labelFor } from '../ui/components.js';

const PAGE = 100;
const OUTCOME = { ok: 'ok', denied: 'warn', error: 'danger' };

export default {
  title: 'Audit trail',
  role: 'admin',
  async render(root, ctx) {
    const filters = normalizeAuditFilters(ctx.route.query);
    const res = await ctx.api.audit(filters, '', PAGE, { signal: ctx.signal });
    const rows = Array.isArray(res.records) ? res.records : [];
    let cursor = res.next_cursor || '';
    const tableSlot = h('div');
    const pagerSlot = h('div');
    const verifySlot = h('div', { class: 'stack' }, h('p', { class: 'muted' }, 'Recompute the hash chain over the whole audit file.'));

    const paint = () => {
      mount(tableSlot, rows.length ? table({
        caption: 'Audit records',
        columns: [
          { label: 'Seq', num: true, cell: (r) => String(r.seq) },
          { label: 'Time (UTC)', className: 'nowrap', cell: (r) => formatDateTime(r.time).replace(' UTC', '') },
          { label: 'Actor', cell: (r) => h('span', null, r.actor || '—', ' ', h('span', { class: 'chip' }, labelFor(r.role || '—'))) },
          { label: 'Action', cell: (r) => h('code', null, r.action) },
          { label: 'Target', cell: (r) => (r.target ? h('code', null, r.target) : '—') },
          { label: 'Outcome', cell: (r) => badge(OUTCOME[r.outcome] || 'neutral', labelFor(r.outcome || 'unknown')) },
          { label: 'Remote', cell: (r) => h('code', null, r.remote || '—') },
          { label: 'Detail', className: 'col-summary', cell: (r) => r.detail || '—' },
          { label: 'Hash', cell: (r) => h('code', { class: 'hash', title: r.hash }, shortId(r.hash, 12)) },
        ],
        rows,
      }) : empty('No audit records', Object.keys(filters).length ? 'Nothing matches these filters.' : 'Nothing has been recorded yet.'));
      mount(pagerSlot, pager({
        shown: rows.length, hasMore: Boolean(cursor),
        onMore: async () => {
          const next = await ctx.api.audit(filters, cursor, PAGE, { signal: ctx.signal });
          rows.push(...(next.records || []));
          cursor = next.next_cursor || '';
          paint();
        },
      }));
    };
    paint();

    const verifyBtn = h('button', { class: 'btn', type: 'button' }, 'Verify chain');
    verifyBtn.addEventListener('click', async () => {
      verifyBtn.disabled = true;
      try {
        const v = await ctx.api.verifyAudit({ signal: ctx.signal });
        mount(verifySlot, v.verified
          ? seal(true, `Chain consistent across ${formatCount(v.records)} records`)
          : seal(false, `Chain broken at record ${v.first_invalid_seq || '?'}`),
        v.verified ? null : h('p', null, v.error || 'No detail returned.'),
        h('p', { class: 'muted' }, 'This proves the file is internally consistent. It does not prove who wrote it: someone with write access to the file can rewrite the whole chain.'));
      } catch (err) {
        mount(verifySlot, banner('danger', 'Verification failed to run', err?.message || ''));
      } finally {
        verifyBtn.disabled = false;
      }
    });

    const form = h('form', { class: 'filters filters--compact' },
      selectField({ label: 'Action', name: 'action', value: filters.action || '', options: [['', 'Any'], ...AUDIT_ACTIONS.map((a) => [a, a])] }),
      inputField({ label: 'Actor', name: 'actor', value: filters.actor || '', mono: true, maxlength: 64 }),
      h('div', { class: ['btn-row', 'filters__actions'] }, h('button', { class: ['btn', 'btn--primary'], type: 'submit' }, 'Apply'), h('a', { class: 'btn', href: '#/audit' }, 'Clear')));
    form.addEventListener('submit', (e) => {
      e.preventDefault();
      ctx.navigate(href('audit', normalizeAuditFilters({ action: form.elements.action.value, actor: form.elements.actor.value.trim() })));
    });

    mount(root,
      pageHead({ title: 'Audit trail', subtitle: 'Append-only, hash-chained record of console logins and investigation changes. Reading it is itself audited.' }),
      panel({ title: 'Chain integrity', actions: verifyBtn, body: verifySlot }),
      panel({ title: 'Filters', body: form }),
      panel({ title: 'Records', meta: 'Newest first', flush: true, body: tableSlot, foot: pagerSlot }));
  },
};
