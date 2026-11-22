// Attacker sessions: consecutive events from one source key, split at idle
// gaps over 30 minutes (GET /sessions). Each row reads as an observation:
// how long, how many events, which surfaces, how regular the pace, and
// whether the pace and rules are consistent with automation, with the
// count of observations behind that reading. Never a verdict.

import { h, mount } from '../lib/dom.js';
import { href, normalizeSessionFilters } from '../lib/route.js';
import { formatCount } from '../lib/format.js';
import { boundsNote, formatDurationMs } from '../lib/story.js';
import { glossaryEntry } from '../lib/glossary.js';
import { pageHead, panel, segmented, sevChip, evidence, table, timeEl, empty, pager, helpTip, filterChip, inputField } from '../ui/components.js';
import { assessmentChip, cadenceStrip, kindChips } from '../ui/story.js';
import { ruleChips } from './shared.js';
import { icon } from '../ui/icons.js';

const PAGE = 50;
const WINDOWS = [['1h', '1h'], ['24h', '24h'], ['7d', '7d']];
const tip = (id) => helpTip(glossaryEntry(id));

export const sessionHref = (s) => href('sessions', s.id);
// Wider than a 1440px column with every field: it scrolls in its panel,
// never the page.
const scrolling = (el) => { el.classList.add('table-wrap--scroll'); return el; };

function columns() {
  return [
    {
      label: 'Source', className: 'nowrap',
      cell: (s) => h('span', { class: 'stack-tight' },
        h('a', { class: 'session-link', href: sessionHref(s), 'data-row-link': '' }, evidence(s.source, { max: 24 })),
        h('span', { class: 'muted' }, 'last seen ', timeEl(s.last_seen, { relative: true }))),
    },
    { label: 'Duration', num: true, className: 'nowrap', cell: (s) => formatDurationMs(s.duration_ms) },
    { label: 'Events', num: true, cell: (s) => formatCount(s.event_count) },
    { label: 'Surfaces', cell: (s) => kindChips(s.sensor_kinds, { text: true }) },
    { label: 'Max severity', cell: (s) => sevChip(s.max_severity) },
    { label: 'Rules', cell: (s) => ruleChips(s.rule_ids) },
    { label: 'Pace', className: 'nowrap', cell: (s) => cadenceStrip(s.cadence) },
    { label: 'Automation', cell: (s) => assessmentChip(s.automation, { compact: true }) },
  ];
}

export default {
  title: 'Sessions',
  async render(root, ctx) {
    const f = normalizeSessionFilters(ctx.route.query);
    const res = await ctx.api.sessions(f.window, f.source || '', '', PAGE, { signal: ctx.signal });
    const rows = Array.isArray(res.sessions) ? [...res.sessions] : [];
    let cursor = res.next_cursor || '';
    const total = Number(res.total_matched) || rows.length;
    const tableSlot = h('div');
    const pagerSlot = h('div');
    const paint = () => {
      mount(tableSlot, rows.length
        ? scrolling(table({ caption: 'Attacker sessions', columns: columns(), rows, rowClass: (s) => (s.automation?.assessment === 'consistent_with_automation' ? 'row--noted' : null) }))
        : empty(f.source ? 'No session from this source in the window' : 'No sessions in this window',
          'A session needs at least one event with a source key. Try a wider window; sessions are built from the newest indexed events only.',
          h('a', { class: 'btn', href: href('sessions', { window: '7d', source: f.source || '' }) }, 'Last 7 days'), { icon: 'story' }));
      mount(pagerSlot, pager({
        shown: rows.length, total, hasMore: Boolean(cursor),
        onMore: async () => {
          const next = await ctx.api.sessions(f.window, f.source || '', cursor, PAGE, { signal: ctx.signal });
          rows.push(...(next.sessions || []));
          cursor = next.next_cursor || '';
          paint();
        },
      }));
    };
    paint();

    // Row click opens the story, like the events list.
    tableSlot.addEventListener('click', (e) => {
      if (e.target.closest?.('a, button')) return;
      if (String(getSelection?.() ?? '')) return;
      e.target.closest?.('tr')?.querySelector('[data-row-link]')?.click();
    });

    const sourceForm = h('form', { class: 'session-filter', 'aria-label': 'Filter sessions by source' },
      inputField({ label: 'Source (exact)', name: 'source', value: f.source || '', mono: true, maxlength: 255, placeholder: 'e.g. 203.0.113.7' }),
      h('button', { class: 'btn', type: 'submit' }, icon('filter', { size: 'sm' }), 'Filter'));
    sourceForm.addEventListener('submit', (e) => {
      e.preventDefault();
      ctx.navigate(href('sessions', { window: f.window, source: sourceForm.elements.source.value.trim() }));
    });
    const automated = rows.filter((s) => s.automation?.assessment === 'consistent_with_automation').length;

    mount(root,
      pageHead({
        title: h('span', { class: 'title-help' }, 'Sessions', tip('session')),
        subtitle: 'Runs of events from one source key, split where it went quiet for more than 30 minutes. Each one reads like a short story: what it touched, how fast, and which rules fired.',
        actions: segmented({ label: 'Time window', options: WINDOWS, value: f.window, onChange: (w) => ctx.navigate(href('sessions', { window: w, source: f.source || '' })) }),
      }),
      h('p', { class: 'page-note' }, icon('info', { size: 'sm' }), h('span', null, boundsNote(res.bounds)), tip('index')),
      panel({
        title: 'Filter',
        body: [sourceForm, f.source ? h('div', { class: 'fchip-row' }, filterChip({ key: 'source', name: 'Source', text: f.source, evidence: true, removeHref: href('sessions', { window: f.window }) })) : null],
      }),
      panel({
        primary: true,
        title: h('span', null, formatCount(total), ` session${total === 1 ? '' : 's'}`),
        meta: rows.length ? `${formatCount(automated)} of the ${formatCount(rows.length)} shown have pace or rules consistent with automation. That is an observation, not a verdict. Sessions overlapping the window; counts include the whole session.` : null,
        flush: true, body: tableSlot, foot: pagerSlot,
      }));
  },
};
