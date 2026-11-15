import { h, mount } from '../lib/dom.js';
import { href, normalizeAuditFilters } from '../lib/route.js';
import { AUDIT_ACTIONS } from '../lib/taxonomy.js';
import { tenantInfo } from '../lib/tenant.js';
import { formatDateTime, formatCount, shortId } from '../lib/format.js';
import { waveDelays } from '../lib/chart.js';
import { pageHead, panel, table, badge, seal, selectField, inputField, empty, pager, banner, labelFor, copyable, evidence } from '../ui/components.js';
import { icon } from '../ui/icons.js';

const PAGE = 100;
const OUTCOME = { ok: 'ok', denied: 'warn', error: 'danger' };
const CHAIN_LINKS = 32;
const STATE_WORD = { unchecked: 'not checked yet', ok: 'consistent', broken: 'first inconsistent record', beyond: 'after the break, not trusted' };

// The newest records on this page drawn as a chain, oldest to newest. The
// server verifies the whole file in one call; the drawing then reflects its
// single answer link by link (verified, or consistent up to
// first_invalid_seq). It never claims more than the server returned.
function chainView(records) {
  const shown = records.slice(0, CHAIN_LINKS).filter((r) => Number.isFinite(Number(r.seq))).reverse();
  const links = shown.map((r) => {
    const li = h('li', { class: 'chain__link', 'data-state': 'unchecked', title: `Record ${r.seq} · ${shortId(r.hash, 12)}` }, String(r.seq));
    li.setAttribute('aria-label', `Record ${r.seq}: ${STATE_WORD.unchecked}`);
    return { seq: Number(r.seq), li };
  });
  const el = h('ol', { class: 'chain', 'aria-label': `Last ${links.length} records on this page, oldest to newest` }, links.map((l) => l.li));
  return {
    el,
    count: links.length,
    min: links.length ? links[0].seq : 0,
    max: links.length ? links[links.length - 1].seq : 0,
    apply(result) {
      const bad = result.verified ? Infinity : Number(result.first_invalid_seq) || 0;
      const delays = waveDelays(links.length, 520);
      links.forEach(({ seq, li }, i) => {
        const st = result.verified || (bad > 0 && seq < bad) ? 'ok' : seq === bad ? 'broken' : 'beyond';
        li.style.setProperty('--d', `${delays[i]}ms`);
        li.dataset.state = st;
        li.setAttribute('aria-label', `Record ${seq}: ${STATE_WORD[st]}`);
      });
      // Scroll the break into view, if it is drawn.
      const hit = links.find((l) => l.seq === bad)?.li;
      if (hit) el.scrollLeft = Math.max(0, hit.offsetLeft - el.clientWidth / 2);
    },
    reset() {
      for (const { seq, li } of links) {
        li.style.setProperty('--d', '0ms');
        li.dataset.state = 'unchecked';
        li.setAttribute('aria-label', `Record ${seq}: ${STATE_WORD.unchecked}`);
      }
    },
  };
}

// OIDC records carry the provider's stable identity: issuer and subject.
// Both are claims from an external identity provider, so they are shown as
// evidence (mono inset, text only), never as interface text.
function detailCell(r) {
  const issuer = typeof r.issuer === 'string' ? r.issuer : '';
  const subject = typeof r.subject === 'string' ? r.subject : '';
  if (!issuer && !subject) return r.detail || '—';
  return h('div', { class: 'audit-detail' },
    r.detail ? h('span', null, r.detail) : null,
    h('dl', { class: 'audit-claims' },
      issuer ? [h('dt', null, 'Issuer'), h('dd', null, evidence(issuer, { max: 64 }))] : null,
      subject ? [h('dt', null, 'Subject'), h('dd', null, evidence(subject, { max: 48 }))] : null));
}

function chainLegend() {
  return h('p', { class: 'chain-legend' },
    h('span', null, h('i'), 'Not checked'),
    h('span', { class: 'is-ok' }, h('i'), 'Consistent'),
    h('span', { class: 'is-broken' }, h('i'), 'First inconsistent'),
    h('span', { class: 'is-beyond' }, h('i'), 'After the break'));
}

export default {
  title: 'Audit trail',
  role: 'admin',
  async render(root, ctx) {
    const filters = normalizeAuditFilters(ctx.route.query);
    const tenants = tenantInfo(ctx.session);
    const res = await ctx.api.audit(filters, '', PAGE, { signal: ctx.signal });
    const rows = Array.isArray(res.records) ? res.records : [];
    let cursor = res.next_cursor || '';
    const tableSlot = h('div');
    const pagerSlot = h('div');
    const chain = chainView(rows);
    const resultSlot = h('div', { class: 'stack', role: 'status' }, h('p', { class: 'muted' }, 'Recompute the hash chain over the whole audit file. The drawing shows the newest records on this page.'));
    const verifySlot = h('div', { class: 'stack' }, chain.count ? [chain.el, chainLegend()] : null, resultSlot);

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
          { label: 'Detail', className: 'col-summary', cell: detailCell },
          { label: 'Hash', cell: (r) => h('span', { class: 'hash' }, copyable(r.hash, { label: 'record hash', display: shortId(r.hash, 12) })) },
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

    const verifyBtn = h('button', { class: 'btn', type: 'button' }, icon('shield'), 'Verify chain');
    verifyBtn.addEventListener('click', async () => {
      verifyBtn.disabled = true;
      chain.reset();
      mount(resultSlot, h('p', { class: 'btn-row muted' }, h('span', { class: 'spinner', 'aria-hidden': 'true' }), 'Recomputing the chain…'));
      try {
        const v = await ctx.api.verifyAudit({ signal: ctx.signal });
        chain.apply(v);
        const bad = Number(v.first_invalid_seq) || 0;
        let where = null;
        if (!v.verified && chain.count) {
          if (bad && bad < chain.min) where = `Record ${bad} is older than the records drawn here, so every drawn record comes after the break.`;
          else if (bad > chain.max) where = `Record ${bad} is newer than the records drawn here; the drawn records are consistent.`;
        }
        mount(resultSlot, v.verified
          ? seal(true, `Chain consistent across ${formatCount(v.records)} records`)
          : seal(false, `Chain broken at record ${bad || '?'}`),
        v.verified ? null : h('p', null, v.error || 'No detail returned.'),
        where ? h('p', { class: 'muted' }, where) : null,
        h('p', { class: 'muted' }, 'This proves the file is internally consistent. It does not prove who wrote it: someone with write access to the file can rewrite the whole chain.'));
      } catch (err) {
        chain.reset();
        mount(resultSlot, banner('danger', 'Verification failed to run', err?.message || ''));
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
      pageHead({
        title: 'Audit trail',
        subtitle: `Append-only, hash-chained record of console sign-ins, tenant switches, investigation changes and fleet administration. Reading it is itself audited.${tenants.show ? ` Each tenant keeps its own chain; this is the chain of tenant ${tenants.active}.` : ''}`,
      }),
      panel({ title: 'Chain integrity', actions: verifyBtn, body: verifySlot }),
      panel({ title: 'Filters', body: form }),
      panel({ title: 'Records', meta: 'Newest first', flush: true, body: tableSlot, foot: pagerSlot }));
  },
};
