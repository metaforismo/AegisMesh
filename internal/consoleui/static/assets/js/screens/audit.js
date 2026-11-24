import { h, mount } from '../lib/dom.js';
import { href, normalizeAuditFilters } from '../lib/route.js';
import { AUDIT_ACTIONS } from '../lib/taxonomy.js';
import { tenantInfo } from '../lib/tenant.js';
import { formatCount, shortId } from '../lib/format.js';
import { waveDelays } from '../lib/chart.js';
import { pageHead, panel, table, badge, seal, selectField, inputField, empty, pager, banner, labelFor, copyable, evidence, timeEl } from '../ui/components.js';
import { icon } from '../ui/icons.js';
import { parseAuditDetail, formatSettingRaw, settingLabel, isSettingKey } from '../lib/settings.js';
import { permissionLabel, isRoleId, roleNameOf } from '../lib/perms.js';

// Actions grouped for the filter, each with words beside its code.
export const ACTION_GROUPS = [
  ['Sign-in and sessions', { 'session.login': 'Signed in', 'session.login_failed': 'Sign-in failed', 'session.logout': 'Signed out', 'session.oidc_login': 'Signed in with single sign-on', 'session.oidc_denied': 'Single sign-on refused', 'session.tenant_switch': 'Switched tenant', 'session.revoke': 'Revoked a session' }],
  ['Access', { 'account.create': 'Created an account', 'account.update': 'Changed an account', 'key.create': 'Created an API key', 'key.revoke': 'Revoked an API key', 'role.create': 'Created a role', 'role.update': 'Changed a role', 'role.delete': 'Deleted a role', 'authz.denied': 'Refused: not permitted' }],
  ['Settings and posture', { 'settings.update': 'Changed a setting', 'settings.revert': 'Reverted a setting', 'posture.accept': 'Accepted a posture risk', 'posture.unaccept': 'Revoked a risk acceptance', 'preferences.update': 'Changed own preferences' }],
  ['Investigations', { 'investigation.create': 'Opened an investigation', 'investigation.update': 'Changed an investigation', 'investigation.note': 'Added a note', 'investigation.attach': 'Attached evidence', 'investigation.detach': 'Detached evidence' }],
  ['Evidence out', { 'event.read': 'Read an event', 'export.indicators': 'Exported indicators', 'export.events': 'Exported events', 'session.report': 'Downloaded a session report', 'investigation.report': 'Downloaded an investigation report' }],
  ['Audit', { 'audit.read': 'Read the audit trail', 'audit.verify': 'Verified the chain', 'audit.export': 'Exported the audit trail' }],
  ['Fleet', { 'fleet.token.create': 'Created an enrollment token', 'fleet.token.delete': 'Deleted an enrollment token', 'fleet.node.enroll': 'Enrolled a node', 'fleet.node.revoke': 'Revoked a node', 'fleet.node.rejected': 'Refused a node' }],
];
const ACTION_WORDS = Object.assign({}, ...ACTION_GROUPS.map(([, m]) => m));

// A structured detail (round 6) as words: a setting's from → to and its
// reason; a role's name and permissions; an acceptance's end and reason.
// Anything else, or a detail that does not parse, is shown as written.
export function structuredDetail(r) {
  const d = parseAuditDetail(r.detail);
  if (!d) return null;
  if ((r.action === 'settings.update' || r.action === 'settings.revert') && ('from' in d || 'to' in d)) {
    const item = { key: isSettingKey(r.target) ? r.target : '' };
    return h('div', { class: 'audit-change' },
      h('p', { class: 'change' },
        item.key ? h('span', { class: 'change__key' }, `${settingLabel(item.key)}: `) : null,
        h('span', { class: 'change__from' }, formatSettingRaw(item, d.from ?? '')),
        h('span', { class: 'change__arrow', 'aria-hidden': 'true' }, ' → '),
        h('span', { class: 'visually-hidden' }, ' to '),
        h('span', { class: 'change__to' }, formatSettingRaw(item, d.to ?? ''))),
      d.reason ? h('p', { class: 'change__reason' }, h('span', { class: 'caps' }, 'Reason'), ' ', d.reason) : null,
      item.key ? h('a', { class: 'audit-change__link', href: href('settings', 'history', { key: item.key }) }, 'Change history') : null);
  }
  if (r.action?.startsWith('role.') && ('name' in d || 'permissions' in d)) {
    const perms = typeof d.permissions === 'string' && d.permissions ? d.permissions.split(',') : [];
    return h('div', { class: 'audit-change' },
      d.name ? h('p', null, h('span', { class: 'caps' }, 'Role'), ' ', isRoleId(r.target) && r.action !== 'role.delete' ? h('a', { href: href('settings', 'roles', r.target) }, d.name) : d.name) : null,
      perms.length ? h('p', { class: 'muted', title: perms.join(', ') }, `${perms.length} permission${perms.length === 1 ? '' : 's'}: `, perms.slice(0, 4).map((p) => permissionLabel(p).toLowerCase()).join('; '), perms.length > 4 ? `; and ${perms.length - 4} more` : '') : null);
  }
  if (r.action?.startsWith('posture.') && ('until' in d || 'reason' in d)) {
    return h('div', { class: 'audit-change' },
      d.until ? h('p', null, h('span', { class: 'caps' }, 'Until'), ' ', timeEl(d.until)) : null,
      d.reason ? h('p', { class: 'change__reason' }, h('span', { class: 'caps' }, 'Reason'), ' ', d.reason) : null);
  }
  return null;
}

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
  if (!issuer && !subject) return structuredDetail(r) || r.detail || '—';
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

// The action filter, grouped, every action with its words.
function actionSelect(value) {
  const known = new Set(ACTION_GROUPS.flatMap(([, m]) => Object.keys(m)));
  const rest = AUDIT_ACTIONS.filter((a) => !known.has(a));
  return h('div', { class: 'field' },
    h('label', { class: 'field__label', for: 'f-action' }, 'Action'),
    h('select', { class: 'select', id: 'f-action', name: 'action' },
      h('option', { value: '', selected: !value }, 'Any'),
      ACTION_GROUPS.map(([group, m]) => h('optgroup', { label: group }, Object.entries(m).filter(([a]) => AUDIT_ACTIONS.includes(a)).map(([a, w]) => h('option', { value: a, selected: a === value }, `${w} (${a})`)))),
      rest.length ? h('optgroup', { label: 'Other' }, rest.map((a) => h('option', { value: a, selected: a === value }, a))) : null));
}

export default {
  title: 'Audit trail',
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
        // Nine columns do not fit a 1440px column; scroll inside the panel.
        scroll: true,
        columns: [
          { label: 'Seq', num: true, cell: (r) => String(r.seq) },
          { label: 'Time', className: 'nowrap', cell: (r) => timeEl(r.time, { relative: true }) },
          // A custom role's id says nothing to a reader: "Custom role", id in the title.
          { label: 'Actor', cell: (r) => h('span', null, r.actor || '—', ' ', r.role ? h('span', { class: 'chip', title: isRoleId(r.role) ? r.role : null }, roleNameOf(r.role)) : null) },
          { label: 'Action', cell: (r) => h('span', { class: 'stack-tight' }, h('code', null, r.action), ACTION_WORDS[r.action] ? h('span', { class: 'muted' }, ACTION_WORDS[r.action]) : null) },
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
      actionSelect(filters.action || ''),
      inputField({ label: 'Actor', name: 'actor', value: filters.actor || '', mono: true, maxlength: 64 }),
      h('div', { class: ['btn-row', 'filters__actions'] }, h('button', { class: ['btn', 'btn--primary'], type: 'submit' }, 'Apply'), h('a', { class: 'btn', href: '#/audit' }, 'Clear')));
    form.addEventListener('submit', (e) => {
      e.preventDefault();
      ctx.navigate(href('audit', normalizeAuditFilters({ action: form.elements.action.value, actor: form.elements.actor.value.trim() })));
    });

    mount(root,
      pageHead({
        title: 'Audit trail',
        subtitle: `Append-only, hash-chained record of console sign-ins, tenant switches, account, role and setting changes, investigation changes and fleet administration. Reading it is itself audited.${tenants.show ? ` Each tenant keeps its own chain; this is the chain of tenant ${tenants.active}.` : ''}`,
        hint: 'Filter by action or actor to see who did what; verify the chain below the records.',
      }),
      // Who did what comes first; the filters sit on the records they narrow.
      panel({
        title: 'Records', primary: true, flush: true,
        meta: Object.keys(filters).length ? 'Newest first, filtered' : 'Newest first',
        body: h('div', null, h('div', { class: ['panel-toolbar', 'audit-filters'] }, form), tableSlot),
        foot: pagerSlot,
      }),
      panel({ title: 'Chain integrity', actions: verifyBtn, body: verifySlot }));
  },
};
