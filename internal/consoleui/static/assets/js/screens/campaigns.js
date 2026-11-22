// Campaigns (GET /campaigns): sessions from different sources that followed
// the same steps. Each card says how many sources, on what basis, over what
// span, through which stages, and how the sessions read; a small score
// drawing repeats the same stops on every lane so the sameness is visible.
// A campaign is an observation of similar behaviour, never attribution.

import { h, mount } from '../lib/dom.js';
import { href } from '../lib/route.js';
import { formatCount } from '../lib/format.js';
import { normalizeCampaign, basisSentence, spanText, plural, isMissingEndpoint } from '../lib/insight.js';
import { glossaryEntry } from '../lib/glossary.js';
import { pageHead, panel, empty, sevChip, timeEl, helpTip, banner } from '../ui/components.js';
import { stageTag, kindChips } from '../ui/story.js';
import { mixView, miniScore, sourceChips } from '../ui/insight.js';
import { icon } from '../ui/icons.js';

const tip = (id) => helpTip(glossaryEntry(id));

export const campaignHref = (id) => href('campaigns', id);

const head = (extra = {}) => pageHead({
  title: h('span', { class: 'title-help' }, 'Campaigns', tip('campaign')),
  subtitle: 'Sessions from different sources that followed the same steps. A recurring playbook is worth knowing; it is never proof of one operator.',
  hint: 'Open a campaign to compare its sources step by step, then read any session’s story.',
  ...extra,
});

// The honest state for a server that predates campaigns.
export function olderServer(what, detail, action) {
  return panel({
    body: empty(`This server does not provide ${what} yet`, detail, action, { icon: 'info' }),
  });
}

function card(raw) {
  const c = normalizeCampaign(raw);
  const span = spanText(c.firstSeen, c.lastSeen);
  const title = c.label || `Campaign across ${plural(c.sourceCount, 'source')}`;
  const titleId = `cmp-${c.id || Math.random().toString(36).slice(2, 8)}`;
  return h('article', { class: 'ccard', 'aria-labelledby': titleId },
    h('header', { class: 'ccard__head' },
      h('span', { class: 'ccard__art' }, miniScore(c.sourceCount, c.stages)),
      h('div', { class: 'ccard__title-wrap' },
        h('h2', { class: 'ccard__title', id: titleId }, c.id ? h('a', { href: campaignHref(c.id), 'data-row-link': '' }, title) : title),
        h('p', { class: 'ccard__basis' }, basisSentence(raw))),
      h('div', { class: 'ccard__sev' }, sevChip(c.maxSeverity))),
    h('dl', { class: 'ccard__figures' },
      [['Sources', formatCount(c.sourceCount)], ['Sessions', formatCount(c.sessionCount)], ['Events', c.eventCount === null ? '—' : formatCount(c.eventCount)],
        ['Span', span || '—'], ['Last seen', timeEl(c.lastSeen, { relative: true })]]
        .map(([k, v]) => h('div', { class: 'ccard__fig' }, h('dt', null, k), h('dd', null, v)))),
    h('div', { class: 'ccard__rows' },
      h('div', { class: 'ccard__row' }, h('span', { class: 'ccard__key' }, 'Stages'),
        c.stages.length ? h('span', { class: 'stage-row' }, c.stages.map(stageTag)) : h('span', { class: 'muted' }, '—')),
      h('div', { class: 'ccard__row' }, h('span', { class: 'ccard__key' }, 'Reads as'), mixView(raw?.automation_counts, { compact: true })),
      h('div', { class: 'ccard__row' }, h('span', { class: 'ccard__key' }, 'Surfaces'), kindChips(c.sensorKinds, { text: true })),
      h('div', { class: 'ccard__row' }, h('span', { class: 'ccard__key' }, 'Sources'), sourceChips(c.sources, { total: c.sourceCount, truncated: c.sourcesTruncated }))),
    c.id ? h('footer', { class: 'ccard__foot' },
      h('a', { class: ['btn', 'btn--sm'], href: campaignHref(c.id) }, 'Compare the sources', icon('chevron-right', { size: 'sm' }))) : null);
}

export default {
  title: 'Campaigns',
  async render(root, ctx) {
    let res;
    try {
      res = await ctx.api.campaigns({ signal: ctx.signal });
    } catch (err) {
      if (!isMissingEndpoint(err)) throw err;
      mount(root, head(), olderServer('campaigns',
        'Campaigns arrive with a newer AegisMesh server. Sessions, their stories and automation observations work as before.',
        h('a', { class: 'btn', href: href('sessions') }, icon('story', { size: 'sm' }), 'Read the sessions')));
      return;
    }
    const items = Array.isArray(res?.items) ? res.items : [];
    const sources = new Set(items.flatMap((c) => (Array.isArray(c?.sources) ? c.sources : [])));
    const sessions = items.reduce((n, c) => n + (Number(c?.session_count) || 0), 0);
    const scanned = Number.isFinite(Number(res?.scanned_sessions)) ? Number(res.scanned_sessions) : null;
    mount(root,
      head(),
      h('p', { class: 'page-note' }, icon('info', { size: 'sm' }),
        h('span', null,
          scanned !== null ? `Compared ${plural(scanned, 'session')} from the newest indexed events. ` : 'Compared sessions from the newest indexed events. ',
          res?.truncated ? 'The scan limit was reached, so older sessions are not included. ' : '',
          'A campaign needs at least two different sources. ',
          res?.generated_at ? ['Generated ', timeEl(res.generated_at, { relative: true }), '.'] : null),
        tip('index')),
      items.length ? h('p', { class: 'camp-tally' },
        h('strong', null, plural(items.length, 'campaign')), ` across ${plural(sources.size, 'source')} and ${plural(sessions, 'session')}. `,
        h('span', { class: 'muted' }, 'Newest first.')) : null,
      items.length
        ? h('div', { class: 'campaigns' }, items.map(card))
        : panel({
          body: empty('No campaigns in the indexed events',
            'No two sources followed the same steps in the sessions the server compared. That is a normal state: most contact with decoys is one-off scanning.',
            h('a', { class: 'btn', href: href('sessions', { window: '7d' }) }, icon('story', { size: 'sm' }), 'Sessions in the last 7 days'), { art: true }),
        }),
      items.length ? banner('info', 'Similar behaviour, not one operator',
        'Public tools and copied playbooks produce identical steps, and NAT or relays can make one actor look like many sources. Use a campaign to decide what to watch or harden, not to name who is behind it.') : null);
    // Card click (outside links) opens the campaign, like a table row.
    root.addEventListener('click', (e) => {
      if (e.target.closest?.('a, button')) return;
      if (String(getSelection?.() ?? '')) return;
      e.target.closest?.('.ccard')?.querySelector('[data-row-link]')?.click();
    });
  },
};
