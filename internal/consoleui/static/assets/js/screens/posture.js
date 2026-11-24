// Posture (GET /posture): a calm review of this node's configuration and of
// what its retained evidence shows. Items that need attention come first,
// each with what was observed, what to change and where it is documented;
// then every area in a fixed order. A configuration review, not a security
// guarantee: "looks right" means the setting matches what the check looks
// for, nothing more.

import { h, mount } from '../lib/dom.js';
import { href } from '../lib/route.js';
import { postureGroups, postureCounts, docHref, plural, isMissingEndpoint, ACCEPT_PRESETS, ACCEPT_MAX_DAYS, acceptUntil, acceptUntilFromDate, validateAcceptReason } from '../lib/insight.js';
import { formatDateTime } from '../lib/format.js';
import { permissionLabel } from '../lib/perms.js';
import { confirmAction, formField, choices, errorSummary, wireForm } from '../ui/settings-kit.js';
import { untilEl } from './settings-account.js';
import { glossaryEntry } from '../lib/glossary.js';
import { pageHead, panel, empty, timeEl, helpTip, segmented, copyable, toast } from '../ui/components.js';
import { statusChip } from '../ui/insight.js';
import { icon } from '../ui/icons.js';
import { olderServer } from './campaigns.js';

const tip = (id) => helpTip(glossaryEntry(id));
const AREA_ICON = { exposure: 'sources', deception: 'decoy', detection: 'rules', evidence: 'shield', access: 'key', other: 'info' };

const head = (actions) => pageHead({
  title: h('span', { class: 'title-help' }, 'Posture', tip('posture')),
  subtitle: 'A review of this node’s configuration and of what its retained evidence shows. It is a configuration review, not a security guarantee: “looks right” means a setting matches what the check looks for.',
  hint: 'Start with what needs attention. Each item says what was observed, what to change and where it is documented.',
  actions,
});

function docLink(doc) {
  if (!doc) return null;
  const url = docHref(doc);
  return h('p', { class: 'pcheck__doc' }, icon('guide', { size: 'sm' }),
    url ? h('a', { href: url }, doc, h('span', { class: 'visually-hidden' }, ' (opens the project documentation)')) : h('code', null, doc));
}

// actions: a node (Accept risk, Revoke acceptance, or why not) or null.
function checkCard(c, { full = true, actions = null } = {}) {
  const a = c.accepted;
  return h('li', { class: ['pcheck', `pcheck--${c.status.mark}`] },
    h('div', { class: 'pcheck__head' },
      statusChip(c.status),
      c.id ? h('code', { class: 'pcheck__id' }, c.id) : null),
    h('p', { class: 'pcheck__title' }, c.title),
    a ? h('div', { class: 'pcheck__accepted' },
      h('p', null, h('span', { class: 'caps' }, 'Accepted'), ' by ', h('strong', null, a.byName || a.by || 'unknown'), a.until ? [' until ', h('time', { datetime: a.until, title: formatDateTime(a.until) }, formatDateTime(a.until)), ' (', untilEl(a.until), ')'] : null, '.'),
      a.reason ? h('p', null, h('span', { class: 'caps' }, 'Reason'), ' ', a.reason) : null,
      h('p', { class: 'muted' }, 'Still present: accepting records a decision, it does not fix anything. It returns to Needs attention when the acceptance ends or is revoked.')) : null,
    c.detail ? h('p', { class: 'pcheck__detail' }, h('span', { class: 'caps' }, 'Observed'), ' ', c.detail) : null,
    full && c.recommendation ? h('p', { class: 'pcheck__rec' }, h('span', { class: 'caps' }, 'Recommended'), ' ', c.recommendation) : null,
    docLink(c.doc),
    actions ? h('div', { class: 'pcheck__actions' }, actions) : null);
}

// The accept-risk dialog: a required reason and an end date (30, 90 or 180
// days, or a date of your choosing, at most 180 days ahead). Resolves to
// true when the server accepted it.
function acceptDialog(ctx, c) {
  return new Promise((resolve) => {
    const summary = errorSummary();
    const reasonInput = h('textarea', { class: 'textarea', rows: 3, maxlength: 200 });
    const reason = formField({ label: 'Why is this acceptable for now?', control: reasonInput, hint: 'Required, at most 200 characters. Kept with the acceptance and in the audit trail.' });
    const dateInput = h('input', { class: 'input', type: 'date', autocomplete: 'off' });
    const dateField = formField({ label: 'End date (UTC)', control: dateInput, hint: `At most ${ACCEPT_MAX_DAYS} days ahead. The acceptance ends at 23:59:59 UTC that day.` });
    dateField.el.hidden = true;
    const ends = h('p', { class: ['field__hint', 'accept__ends'], role: 'status' });
    const until = choices({
      legend: 'Accept until', name: 'accept-until', compact: true, value: '90',
      options: [...ACCEPT_PRESETS.map((d) => [String(d), `${d} days`]), ['date', 'Choose a date']],
      onChange: (v) => { dateField.el.hidden = v !== 'date'; paintEnds(); if (v === 'date') dateInput.focus(); },
    });
    const untilValue = () => (until.value() === 'date' ? acceptUntilFromDate(dateInput.value) : { until: acceptUntil(Number(until.value())) });
    const paintEnds = () => {
      const r = untilValue();
      ends.textContent = r.until ? `Ends ${formatDateTime(r.until)}. Then the check needs attention again, unless it was fixed.` : '';
    };
    dateInput.addEventListener('input', paintEnds);
    paintEnds();
    const submit = h('button', { class: ['btn', 'btn--primary'], type: 'submit' }, 'Accept risk');
    const cancel = h('button', { class: 'btn', type: 'button' }, 'Cancel');
    const form = h('form', { method: 'dialog', novalidate: true });
    const titleId = `accept-${Math.random().toString(36).slice(2, 8)}`;
    const dialog = h('dialog', { class: ['dialog', 'dialog--wide'], 'aria-labelledby': titleId }, form);
    form.append(
      h('div', { class: 'dialog__head' }, h('h2', { id: titleId }, 'Accept this risk for a while')),
      h('div', { class: ['dialog__body', 'form'] },
        summary.el,
        h('dl', { class: 'confirm__target' }, h('dt', null, 'Check'), h('dd', null, h('code', null, c.id), ' ', c.title)),
        h('p', null, 'Accepting records that you know about it and why it is acceptable until a date. Nothing in the configuration changes, and the review keeps showing it, in its own group.'),
        reason.el, until.el, dateField.el, ends),
      h('div', { class: 'dialog__foot' }, cancel, submit));
    let ok = false;
    cancel.addEventListener('click', () => dialog.close());
    wireForm(form, {
      submit, busyLabel: 'Accepting…', summary,
      checks: [
        { field: reason, label: 'Reason', validate: () => validateAcceptReason(reasonInput.value) },
        { field: dateField, label: 'End date', validate: () => untilValue().error || '' },
      ],
      onSubmit: async () => {
        try {
          await ctx.api.acceptPosture(c.id, { reason: reasonInput.value.trim(), until: untilValue().until });
        } catch (err) {
          if (err?.status === 409 && !err.reason) throw Object.assign(new Error('This check no longer needs attention, so there is nothing to accept. Reload the review.'), { status: undefined });
          throw err;
        }
        ok = true;
        dialog.close();
      },
    });
    dialog.addEventListener('close', () => { resolve(ok); setTimeout(() => dialog.remove(), 220); });
    document.body.appendChild(dialog);
    dialog.showModal();
    reasonInput.focus();
  });
}

export default {
  title: 'Posture',
  async render(root, ctx) {
    let res;
    try {
      res = await ctx.api.posture({ signal: ctx.signal });
    } catch (err) {
      if (!isMissingEndpoint(err)) throw err;
      mount(root, head(), olderServer('a posture review',
        'The review arrives with a newer AegisMesh server. Until then, the same checks are a manual read of the configuration; aegismesh doctor validates it.',
        h('code', { class: 'firstrun__cmd' }, 'aegismesh doctor --config mesh.yaml')));
      return;
    }
    const only = ctx.route.query.show === 'attention';
    const counts = postureCounts(res);
    const { groups, attention, accepted, total } = postureGroups(res?.checks);
    // Accepted risk (round 6): offered where the server reports `accepted`
    // on its checks and the role may change settings.
    const supports = (res?.checks || []).some((c) => c && 'accepted' in c);
    const canAccept = supports && ctx.can('settings.manage');
    const denied = supports && !ctx.can('settings.manage')
      ? h('p', { class: ['muted', 'pcheck__why'] }, `Accepting a risk needs “${permissionLabel('settings.manage')}”, which your role does not include.`) : null;
    const acceptBtn = (c) => {
      if (!canAccept) return null;
      const b = h('button', { class: ['btn', 'btn--sm'], type: 'button' }, 'Accept risk…');
      b.addEventListener('click', async () => {
        if (await acceptDialog(ctx, c)) {
          toast('ok', `${c.id} is accepted as a known risk. It stays listed under Accepted risk.`);
          ctx.rerender();
        } else b.focus();
      });
      return b;
    };
    const revokeBtn = (c) => {
      if (!canAccept) return null;
      const b = h('button', { class: ['btn', 'btn--sm'], type: 'button' }, 'Revoke acceptance');
      b.addEventListener('click', async () => {
        const done = await confirmAction({
          title: `Revoke the acceptance of ${c.id}?`,
          consequence: 'The check goes back to Needs attention now. The configuration does not change; the revocation is recorded in the audit trail.',
          targetLabel: 'Check', target: `${c.id} · ${c.title}`,
          danger: false, confirmLabel: 'Revoke acceptance',
          onConfirm: () => ctx.api.unacceptPosture(c.id),
        });
        if (!done) { b.focus(); return; }
        toast('ok', `${c.id} needs attention again.`);
        ctx.rerender();
      });
      return b;
    };
    const filter = segmented({
      label: 'Show', value: only ? 'attention' : 'all',
      options: [['all', 'All checks'], ['attention', `Needs attention (${counts.attention})`]],
      onChange: (v) => ctx.navigate(href('posture', { show: v === 'attention' ? 'attention' : '' })),
    });
    const figure = (key, label, n, mark) => h('div', { class: ['pfig', `pfig--${mark}`] },
      h('dt', null, h('span', { class: 'pstatus__mark', 'aria-hidden': 'true' }, mark === 'ok' ? icon('check', { size: 'xs' }) : mark === 'attention' ? '!' : mark === 'accepted' ? '–' : 'i'), label),
      h('dd', null, String(n)));

    const areaPanels = groups.map((g) => {
      const rest = g.items.filter((c) => c.status.key !== 'attention' && c.status.key !== 'accepted');
      return h('section', { class: 'parea', 'aria-labelledby': `area-${g.id}` },
        h('header', { class: 'parea__head' },
          h('span', { class: 'parea__icon', 'aria-hidden': 'true' }, icon(AREA_ICON[g.id] || 'info')),
          h('div', null,
            h('h2', { class: 'parea__title', id: `area-${g.id}` }, g.label),
            h('p', { class: 'parea__text' }, g.text)),
          h('p', { class: 'parea__count' }, g.attention || g.accepted
            ? [g.attention ? `${g.attention} need${g.attention === 1 ? 's' : ''} attention` : '', g.attention && g.accepted ? ', ' : '', g.accepted ? `${g.accepted} accepted` : '', ' (above)'].join('')
            : plural(g.items.length, 'check'))),
        rest.length ? h('ul', { class: 'pchecks pchecks--quiet' }, rest.map((c) => checkCard(c))) : h('p', { class: 'muted parea__none' }, 'Every check in this area is listed above.'));
    });

    mount(root,
      head(filter),
      h('section', { class: 'psummary', 'aria-label': 'Review summary' },
        h('dl', { class: 'psummary__figs' },
          figure('attention', 'Needs attention', counts.attention, 'attention'),
          supports || counts.accepted ? figure('accepted', 'Accepted risk', counts.accepted, 'accepted') : null,
          figure('info', 'For your information', counts.info, 'info'),
          figure('ok', 'Looks right', counts.ok, 'ok')),
        h('div', { class: 'psummary__side' },
          h('p', { class: 'psummary__line' }, total ? `${plural(total, 'check')} across ${plural(groups.length, 'area')}.` : 'The server returned no checks.', res?.generated_at ? [' Generated ', timeEl(res.generated_at, { relative: true }), '.'] : null),
          res?.scope === 'evidence_only' ? h('p', null, 'This tenant has no local configuration, so only what its retained evidence shows was reviewed.') : null,
          typeof res?.disclaimer === 'string' && res.disclaimer ? h('p', { class: 'psummary__disclaimer' }, h('span', { class: 'caps' }, 'Server'), ' ', res.disclaimer) : null,
          h('p', { class: 'muted' }, 'The same review from the command line: ', copyable('aegismesh posture --config mesh.yaml', { label: 'command' })))),
      attention.length
        ? panel({
          primary: true,
          title: `Needs attention · ${attention.length}`,
          meta: supports ? 'Ordered as the server listed them. Fix the configuration, or accept a risk for a while with a reason.' : 'Ordered as the server listed them. Nothing here was changed: the console cannot edit configuration.',
          body: h('div', null, denied, h('ul', { class: 'pchecks' }, attention.map((c) => checkCard(c, { actions: acceptBtn(c) })))),
        })
        : panel({ primary: true, title: 'Needs attention', body: empty('Nothing needs attention', accepted.length ? 'Every remaining item was accepted as a known risk (below). Accepted is not fixed: those items are still present.' : 'Every check matched what it looks for. That describes the configuration, not whether anyone can get in.', null, { icon: 'shield' }) }),
      accepted.length && !only ? panel({
        title: `Accepted risk · ${accepted.length}`,
        meta: 'Known and still present. Each acceptance has a reason, who decided and when it ends; none of these is fixed.',
        body: h('ul', { class: ['pchecks', 'pchecks--accepted'] }, accepted.map((c) => checkCard(c, { actions: revokeBtn(c) }))),
      }) : null,
      only ? null : areaPanels,
      only && groups.length ? h('p', { class: 'page-note' }, icon('info', { size: 'sm' }), h('span', null, `${plural(total - attention.length, 'other check')} hidden. `, h('a', { href: href('posture') }, 'Show all checks'), '.')) : null);
  },
};
