// One campaign (GET /campaigns/{id}): the shared playbook drawn as a score,
// one lane per participating session and one column per step, so it is
// visible which sources took which steps and when. Around it: the basis in
// plain words, figures, stages, rules, how the sessions read, the sessions
// themselves and the server's caveats. Never attribution.

import { h, mount } from '../lib/dom.js';
import { href } from '../lib/route.js';
import { formatCount, formatDateTime } from '../lib/format.js';
import { formatDurationMs } from '../lib/story.js';
import { normalizeCampaign, basisSentence, basisText, spanText, plural, isCampaignId } from '../lib/insight.js';
import { glossaryEntry } from '../lib/glossary.js';
import { pageHead, panel, kv, sevChip, evidence, timeEl, empty, helpTip, table, copyable, link, chip } from '../ui/components.js';
import { stageTag, kindChips } from '../ui/story.js';
import { mixView, campaignScoreView, actorChip, sourceChips } from '../ui/insight.js';
import { icon } from '../ui/icons.js';

const tip = (id) => helpTip(glossaryEntry(id));
const titled = (text, id) => h('span', { class: 'title-help' }, text, tip(id));
const sessionHref = (id) => href('sessions', id);

function legend(exact) {
  const item = (state, text) => h('li', { class: 'score-legend__item' }, h('span', { class: ['score-legend__mark', `score__cell--${state}`] }, h('span', { class: 'score__mark' })), text);
  return h('ul', { class: 'score-legend', 'aria-label': 'Score legend' },
    item('performed', exact ? 'Step taken, with its time from the session’s first event' : 'Step taken by every session'),
    exact ? item('absent', 'Step not taken') : item('unknown', 'Taken by some sessions; the server does not say which'),
    h('li', { class: 'score-legend__item' }, h('span', { class: 'score-legend__band', 'aria-hidden': 'true' }), 'Shaded columns: every session took this step'));
}

function sessionsTable(list) {
  return table({
    caption: 'Sessions in this campaign',
    columns: [
      {
        label: 'Source', className: 'nowrap',
        cell: (s) => h('span', { class: 'stack-tight' },
          /^[0-9a-f]{32}$/.test(s.id) ? h('a', { href: sessionHref(s.id), 'data-row-link': '' }, evidence(s.source, { max: 24 })) : evidence(s.source, { max: 24 }),
          h('span', { class: 'muted' }, 'started ', timeEl(s.first_seen, { relative: true }))),
      },
      { label: 'Duration', num: true, className: 'nowrap', cell: (s) => formatDurationMs(s.duration_ms) },
      { label: 'Events', num: true, cell: (s) => formatCount(s.event_count) },
      { label: 'Median gap', num: true, className: 'nowrap', cell: (s) => formatDurationMs(s.cadence?.median_gap_ms) },
      { label: 'Max severity', cell: (s) => sevChip(s.max_severity) },
      { label: 'Reads as', cell: (s) => (s.actor ? actorChip(s.actor, { compact: true }) : h('span', { class: 'muted' }, 'Not reported')) },
    ],
    rows: list,
  });
}

export default {
  title: 'Campaign',
  async render(root, ctx) {
    const id = ctx.route.params.id;
    if (!isCampaignId(id)) throw new Error('invalid campaign id');
    let raw;
    try {
      raw = await ctx.api.campaign(id, { signal: ctx.signal });
    } catch (err) {
      if (err?.code !== 'not_found') throw err;
      mount(root,
        pageHead({ crumbs: [['Campaigns', href('campaigns')], ['Campaign', null]], title: 'Campaign not found' }),
        panel({
          body: empty('This campaign is not in the current comparison',
            'Campaigns are recomputed from the newest indexed events, so an id can disappear when its sessions age out or the process restarts. Older servers do not provide campaigns at all.',
            h('a', { class: 'btn', href: href('campaigns') }, icon('campaign', { size: 'sm' }), 'All campaigns'), { icon: 'search' }),
        }));
      return;
    }
    const c = normalizeCampaign(raw);
    const title = c.label || `Campaign across ${plural(c.sourceCount, 'source')}`;
    ctx.setTitle?.(title);
    const span = spanText(c.firstSeen, c.lastSeen);
    const score = campaignScoreView(c, { sessionHref });
    const exact = c.sessions.some((s) => Array.isArray(s.step_marks));
    const print = h('button', { class: 'btn', type: 'button' }, icon('print', { size: 'sm' }), 'Print');
    print.addEventListener('click', () => globalThis.print?.());

    mount(root,
      pageHead({
        crumbs: [['Campaigns', href('campaigns')], [title, null]],
        title: h('span', { class: 'campaign-title' }, title),
        subtitle: [basisSentence(raw), span ? ` Seen ${span}, from ${formatDateTime(c.firstSeen)} to ${formatDateTime(c.lastSeen)}.` : ''],
        hint: 'Read the lanes across: each row is one source’s session, each column a step they share. Open a source to read its full story.',
        actions: [print],
      }),
      h('section', { class: 'camp-hero', 'aria-label': 'Campaign at a glance' },
        h('dl', { class: 'camp-hero__figures' },
          [['Sources', formatCount(c.sourceCount)], ['Sessions', formatCount(c.sessionCount)], ['Events', c.eventCount === null ? '—' : formatCount(c.eventCount)],
            ['Shared steps', formatCount(c.steps.length)], ['Max severity', sevChip(c.maxSeverity)]]
            .map(([k, v]) => h('div', null, h('dt', null, k), h('dd', null, v)))),
        h('div', { class: 'camp-hero__rows' },
          h('div', { class: 'camp-hero__row' }, h('span', { class: 'caps' }, 'Basis'),
            c.basis.length ? h('ul', { class: 'basis' }, c.basis.map((b) => h('li', { class: 'basis__item' }, icon('check', { size: 'xs' }), basisText(b)))) : h('span', { class: 'muted' }, 'Not stated by the server')),
          h('div', { class: 'camp-hero__row' }, h('span', { class: 'caps' }, 'Stages'), c.stages.length ? h('span', { class: 'stage-row' }, c.stages.map(stageTag)) : h('span', { class: 'muted' }, '—')),
          h('div', { class: 'camp-hero__row' }, h('span', { class: 'caps' }, 'Reads as'), mixView(raw?.automation_counts)))),
      h('div', { class: ['banner', 'banner--proposal', 'camp-caveat'] },
        icon('info'),
        h('div', null,
          h('p', { class: 'banner__title' }, 'Shared behaviour is not proof of a shared operator'),
          c.caveats.length
            ? h('ul', { class: 'camp-caveat__list' }, c.caveats.map((t) => h('li', null, h('span', { class: 'caps' }, 'Server'), ' ', t)))
            : h('p', null, 'Public tools and copied playbooks produce identical steps; NAT and relays can make one actor look like many sources.'))),
      panel({
        primary: true,
        title: titled('The playbook, source by source', 'campaign'),
        meta: c.stepsTruncated ? `The first ${c.steps.length} shared steps. Steps are normalised from what was sent, so they are shown as evidence.` : 'Steps are normalised from what was sent (request templates, tool names, command classes), so they are shown as evidence.',
        body: score ? [legend(exact), score] : empty('No steps were reported', 'The server sent no step list or no sessions for this campaign.', null, { icon: 'campaign' }),
      }),
      h('div', { class: 'grid grid--2' },
        panel({
          title: 'Rules that fired', meta: 'Across every session in the campaign',
          body: [c.ruleIds.length ? h('span', { class: 'chip-row' }, c.ruleIds.map((r) => h('a', { class: 'rule-link', href: href('events', { rule: r }), title: `Events citing ${r}` }, chip(r, { mono: true })))) : h('span', { class: 'muted' }, 'No rule fired'), h('p', { class: 'figures__note' }, 'Surfaces: ', kindChips(c.sensorKinds, { text: true }))],
        }),
        panel({
          title: 'Sources', meta: c.sourcesTruncated ? 'The server lists up to 20' : 'Source keys as the sensors recorded them, not identities',
          body: sourceChips(c.sources, { total: c.sourceCount, truncated: c.sourcesTruncated, max: 20 }),
        })),
      panel({
        title: titled('Sessions', 'session'), flush: true,
        meta: c.sessions.length < c.sessionCount ? `The first ${formatCount(c.sessions.length)} of ${formatCount(c.sessionCount)}` : 'Oldest first. Open one to read its story',
        body: c.sessions.length ? (() => { const t = sessionsTable(c.sessions); t.setAttribute('class', 'table-wrap table-wrap--scroll'); return t; })() : empty('No sessions listed', 'The server listed none for this campaign.'),
      }),
      panel({
        title: 'Details',
        body: kv([
          ['Campaign id', copyable(c.id, { label: 'campaign id' })],
          ['First seen', timeEl(c.firstSeen)],
          ['Last seen', timeEl(c.lastSeen)],
          ['Stability', h('span', { class: 'kv-note' }, 'Derived on request from the newest indexed events; the id and membership can change as sessions age out.')],
        ]),
      }),
      h('p', { class: 'page-note' }, icon('info', { size: 'sm' }), h('span', null, 'A source key is not an actor identity. ', link(href('campaigns'), 'All campaigns'), '.')));
  },
};
