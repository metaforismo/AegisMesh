// Posture (GET /posture): a calm review of this node's configuration and of
// what its retained evidence shows. Items that need attention come first,
// each with what was observed, what to change and where it is documented;
// then every area in a fixed order. A configuration review, not a security
// guarantee: "looks right" means the setting matches what the check looks
// for, nothing more.

import { h, mount } from '../lib/dom.js';
import { href } from '../lib/route.js';
import { postureGroups, postureCounts, docHref, plural, isMissingEndpoint } from '../lib/insight.js';
import { glossaryEntry } from '../lib/glossary.js';
import { pageHead, panel, empty, timeEl, helpTip, segmented, copyable } from '../ui/components.js';
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

function checkCard(c, { full = true } = {}) {
  return h('li', { class: ['pcheck', `pcheck--${c.status.mark}`] },
    h('div', { class: 'pcheck__head' },
      statusChip(c.status),
      c.id ? h('code', { class: 'pcheck__id' }, c.id) : null),
    h('p', { class: 'pcheck__title' }, c.title),
    c.detail ? h('p', { class: 'pcheck__detail' }, h('span', { class: 'caps' }, 'Observed'), ' ', c.detail) : null,
    full && c.recommendation ? h('p', { class: 'pcheck__rec' }, h('span', { class: 'caps' }, 'Recommended'), ' ', c.recommendation) : null,
    docLink(c.doc));
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
    const { groups, attention, total } = postureGroups(res?.checks);
    const filter = segmented({
      label: 'Show', value: only ? 'attention' : 'all',
      options: [['all', 'All checks'], ['attention', `Needs attention (${counts.attention})`]],
      onChange: (v) => ctx.navigate(href('posture', { show: v === 'attention' ? 'attention' : '' })),
    });
    const figure = (key, label, n, mark) => h('div', { class: ['pfig', `pfig--${mark}`] },
      h('dt', null, h('span', { class: 'pstatus__mark', 'aria-hidden': 'true' }, mark === 'ok' ? icon('check', { size: 'xs' }) : mark === 'attention' ? '!' : 'i'), label),
      h('dd', null, String(n)));

    const areaPanels = groups.map((g) => {
      const rest = g.items.filter((c) => c.status.key !== 'attention');
      return h('section', { class: 'parea', 'aria-labelledby': `area-${g.id}` },
        h('header', { class: 'parea__head' },
          h('span', { class: 'parea__icon', 'aria-hidden': 'true' }, icon(AREA_ICON[g.id] || 'info')),
          h('div', null,
            h('h2', { class: 'parea__title', id: `area-${g.id}` }, g.label),
            h('p', { class: 'parea__text' }, g.text)),
          h('p', { class: 'parea__count' }, g.attention ? `${g.attention} need${g.attention === 1 ? 's' : ''} attention (above)` : plural(g.items.length, 'check'))),
        rest.length ? h('ul', { class: 'pchecks pchecks--quiet' }, rest.map((c) => checkCard(c))) : h('p', { class: 'muted parea__none' }, 'Every check in this area is listed above.'));
    });

    mount(root,
      head(filter),
      h('section', { class: 'psummary', 'aria-label': 'Review summary' },
        h('dl', { class: 'psummary__figs' },
          figure('attention', 'Needs attention', counts.attention, 'attention'),
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
          meta: 'Ordered as the server listed them. Nothing here was changed: the console cannot edit configuration.',
          body: h('ul', { class: 'pchecks' }, attention.map((c) => checkCard(c))),
        })
        : panel({ primary: true, title: 'Needs attention', body: empty('Nothing needs attention', 'Every check matched what it looks for. That describes the configuration, not whether anyone can get in.', null, { icon: 'shield' }) }),
      only ? null : areaPanels,
      only && groups.length ? h('p', { class: 'page-note' }, icon('info', { size: 'sm' }), h('span', null, `${plural(total - attention.length, 'other check')} hidden. `, h('a', { href: href('posture') }, 'Show all checks'), '.')) : null);
  },
};
