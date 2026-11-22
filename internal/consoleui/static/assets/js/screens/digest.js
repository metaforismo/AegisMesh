// Digest: a periodic briefing computed on demand by GET /digest. Set in the
// briefing serif, it reads like a note to the defender: what changed against
// the window before (neutral ink), new and returning sources, sessions
// consistent with automation, the most cited rules, newly cited techniques,
// planted-marker hits, open work, and the server's limits verbatim. "Copy as
// Markdown" composes the same fields in the browser (lib/catalogs.js), and the
// page prints cleanly. Nothing is scheduled, stored or sent.

import { h, mount } from '../lib/dom.js';
import { href } from '../lib/route.js';
import { formatCount, formatDateTime } from '../lib/format.js';
import { isSeverity } from '../lib/taxonomy.js';
import { normalizeDigestWindow, digestLead, digestFigures, groupTechniques, digestLimits, digestMarkdown } from '../lib/catalogs.js';
import { glossaryEntry } from '../lib/glossary.js';
import { pageHead, segmented, sevChip, empty, helpTip, toast, panel } from '../ui/components.js';
import { icon } from '../ui/icons.js';

const WINDOWS = [['24h', '24h'], ['7d', '7d']];
const TITLE = { '24h': 'The last 24 hours', '7d': 'The last 7 days' };
const WINDOW_MS = { '24h': 86400e3, '7d': 7 * 86400e3 };
const tip = (id) => helpTip(glossaryEntry(id));

function leadNode(sentences) {
  return h('p', { class: 'digest__lead' }, sentences.flatMap((segs, i) => [i ? ' ' : null, ...segs.map((s) => {
    if (s.t === 'num') return h('strong', { class: 'brief__num' }, s.v);
    if (s.t === 'code') return h('code', null, s.v);
    if (s.t === 'title') return h('q', { class: 'digest__qtitle' }, s.v);
    return s.v;
  })]));
}

const section = (id, title, ...body) => h('section', { class: 'digest__section', 'aria-labelledby': `dg-${id}` },
  h('h2', { class: 'digest__h', id: `dg-${id}` }, title), ...body);

function volumeTable(d, w) {
  return h('div', { class: 'table-wrap' }, h('table', { class: ['table', 'digest__table'] },
    h('caption', { class: 'visually-hidden' }, 'Totals in this window and the window before'),
    h('thead', null, h('tr', null,
      h('th', { scope: 'col' }, 'Measure'),
      h('th', { scope: 'col', class: 'num' }, w === '7d' ? 'Last 7 days' : 'Last 24 hours'),
      h('th', { scope: 'col', class: 'num' }, 'Window before'),
      h('th', { scope: 'col', class: 'num' }, 'Change'))),
    h('tbody', null, digestFigures(d).map((f) => h('tr', null,
      h('th', { scope: 'row' }, f.label),
      h('td', { class: 'num' }, f.current === null ? '—' : formatCount(f.current)),
      h('td', { class: 'num' }, f.previous === null ? '—' : formatCount(f.previous)),
      h('td', { class: ['num', 'digest__change'] }, f.change))))));
}

function figure(value, label, target, note) {
  const n = typeof value === 'number' && Number.isFinite(value) ? formatCount(value) : '—';
  const body = [h('span', { class: 'digest__figval' }, n), h('span', { class: 'digest__figlabel' }, label)];
  return h('li', { class: 'digest__fig' },
    target ? h('a', { href: target }, body) : body,
    note ? h('span', { class: 'digest__fignote' }, note) : null);
}

function showMarkdown(md) {
  const area = h('textarea', { class: ['textarea', 'digest__md'], rows: 16, readonly: true, spellcheck: 'false', 'aria-label': 'Digest as Markdown', prop: { value: md } });
  const close = h('button', { class: 'btn', type: 'button' }, 'Close');
  const dialog = h('dialog', { class: ['dialog', 'dialog--wide'], 'aria-labelledby': 'md-title' },
    h('div', { class: 'dialog__head' }, h('h2', { id: 'md-title' }, 'Digest as Markdown')),
    h('div', { class: 'dialog__body' },
      h('p', { class: 'muted' }, 'The browser did not allow clipboard access. The text below is selected: copy it with your keyboard. Server strings are fenced as code.'),
      area),
    h('div', { class: 'dialog__foot' }, close));
  close.addEventListener('click', () => dialog.close());
  dialog.addEventListener('close', () => setTimeout(() => dialog.remove(), 220));
  document.body.appendChild(dialog);
  dialog.showModal();
  area.focus();
  area.select();
}

export default {
  title: 'Digest',
  async render(root, ctx) {
    const w = normalizeDigestWindow(ctx.route.query.window);
    const d = await ctx.api.digest(w, { signal: ctx.signal });
    const asOf = formatDateTime(d?.as_of);
    const end = Date.parse(d?.as_of);
    const since = Number.isFinite(end) ? new Date(end - WINDOW_MS[w]).toISOString().replace(/\.\d+Z$/, 'Z') : '';
    const rules = Array.isArray(d?.top_rules) ? d.top_rules.filter((r) => typeof r?.rule_id === 'string' && r.rule_id) : [];
    const techs = groupTechniques(d?.new_techniques);
    const lead = digestLead(d);
    const empty0 = d?.totals?.events === 0;

    // The copy icon morphs into a check (the same confirmation as every copy
    // button) and a toast says what the clipboard now holds.
    const copyLabel = h('span', null, 'Copy as Markdown');
    const copyBtn = h('button', { class: ['btn', 'btn--sm', 'copy-md'], type: 'button' }, h('span', { class: 'copy-md__icons', 'aria-hidden': 'true' }, icon('copy', { size: 'sm' }), icon('check', { size: 'sm' })), copyLabel);
    let copyTimer = null;
    copyBtn.addEventListener('click', async () => {
      try {
        await navigator.clipboard.writeText(digestMarkdown(d, { asOfText: asOf }));
        copyBtn.classList.add('is-copied');
        copyLabel.textContent = 'Copied';
        toast('ok', 'Digest copied as Markdown. Server strings are fenced as code.');
        clearTimeout(copyTimer);
        copyTimer = setTimeout(() => { copyBtn.classList.remove('is-copied'); copyLabel.textContent = 'Copy as Markdown'; }, 1600);
      } catch {
        // Clipboard refused (permissions, an unfocused page): show the same
        // Markdown in a read-only field, selected, to copy by hand.
        showMarkdown(digestMarkdown(d, { asOfText: asOf }));
      }
    });
    const printBtn = h('button', { class: ['btn', 'btn--sm'], type: 'button' }, icon('print', { size: 'sm' }), 'Print');
    printBtn.addEventListener('click', () => globalThis.print?.());

    const oi = d?.open_investigations;
    mount(root,
      pageHead({
        eyebrow: 'Briefing',
        title: 'Digest',
        subtitle: 'What the decoys recorded, compared with the window before. Computed when you open this page; nothing is scheduled or sent.',
        hint: 'Read the briefing, then follow any figure to the events behind it, copy it as Markdown or print it.',
        actions: [segmented({ label: 'Digest window', options: WINDOWS, value: w, onChange: (x) => ctx.navigate(href('digest', { window: x })) }), copyBtn, printBtn],
      }),
      h('article', { class: 'digest', 'aria-labelledby': 'digest-title' },
        h('header', { class: 'digest__mast' },
          h('p', { class: 'digest__kicker' }, h('span', { class: 'brief__dot', 'aria-hidden': 'true' }), 'AegisMesh digest'),
          h('h2', { class: 'digest__title', id: 'digest-title' }, TITLE[w]),
          h('p', { class: 'digest__asof' }, `As of ${asOf} · observations, not incidents`)),
        leadNode(lead.length ? lead : [[{ t: 'text', v: 'The server reported no figures for this window.' }]]),
        empty0 ? empty('A quiet window', 'Decoys have no legitimate users, so a quiet digest is a normal state. The limits below still apply.', null, { art: 'digest' }) : null,
        section('volume', 'Volume', volumeTable(d, w),
          h('p', { class: 'digest__note' }, 'Changes are printed in neutral ink: more observations are not “worse” and fewer are not “better”.')),
        section('sources', h('span', { class: 'title-help' }, 'Sources and sessions', tip('session')),
          h('ul', { class: 'digest__figs' },
            figure(d?.new_sources, 'new sources', since ? href('sources', { window: w }) : null, 'Absent from the window before'),
            figure(d?.returning_sources, 'returning sources', href('sources', { window: w }), 'Seen in both windows'),
            figure(d?.sessions_consistent_with_automation, 'sessions consistent with automation', href('sessions', { window: w }), 'An observation, not a verdict'))),
        section('rules', 'Most cited rules', rules.length
          ? h('ol', { class: 'digest__rules' }, rules.map((r) => h('li', { class: 'digest__rule' },
            h('a', { class: 'digest__rulelink', href: href('events', { rule: r.rule_id, since }) },
              h('code', null, r.rule_id),
              h('span', { class: 'digest__ruletitle' }, typeof r.title === 'string' && r.title ? r.title : 'Untitled rule')),
            isSeverity(r.severity) ? sevChip(r.severity) : h('span', { class: 'muted digest__nosev' }, 'Signal'),
            h('span', { class: 'digest__count' }, `${formatCount(r.events)} ${r.events === 1 ? 'event' : 'events'}`))))
          : h('p', { class: 'muted' }, 'No rule was cited in this window.')),
        section('techniques', h('span', { class: 'title-help' }, 'Newly observed techniques', tip('mapping')), techs.length
          ? [h('div', { class: 'digest__techs' }, techs.map((g) => h('div', { class: 'digest__techgroup' },
            h('p', { class: 'caps' }, g.label),
            h('p', { class: 'chip-row' }, g.items.map((x) => h('a', { class: 'fw-link', href: href('techniques', { f: g.framework, window: w === '7d' ? '7d' : '24h' }) },
              h('span', { class: ['chip', 'chip--fw'] }, h('code', null, x.id), ` ${x.name}`))))))),
          h('p', { class: 'digest__note' }, 'Cited by a related rule in this window and not in the window before. Editorial “relates to” references: not proof a technique was used.')]
          : h('p', { class: 'muted' }, 'No related technique was cited that the window before did not cite.')),
        section('markers', h('span', { class: 'title-help' }, 'Planted markers and open work', tip('honeytokenhit')),
          h('ul', { class: 'digest__figs' },
            figure(d?.honeytoken_hits, 'decoy credential hits (HT-001)', href('honeytokens', { window: w }), 'A planted fake credential came back'),
            figure(d?.agent_canary_hits, 'agent canary hits (AGT-001)', href('honeytokens', { window: w }), 'A planted instruction marker came back'),
            figure(oi === null ? null : oi, oi === null ? 'open investigations (not available)' : 'open investigations', href('investigations', { status: 'open' }), 'Every case not closed'),
            figure(d?.dry_run_recommendations, 'dry-run recommendations', href('recommendations'), 'Proposed, not executed'))),
        section('limits', 'Limits',
          h('dl', { class: 'digest__limits' }, digestLimits(d).map((l) => [
            h('dt', null, l.label),
            h('dd', null, l.verbatim ? h('q', { class: 'digest__verbatim' }, l.text) : l.text, l.verbatim ? h('span', { class: 'digest__src' }, ' (server text)') : null)])))),
      panel({ body: h('p', { class: 'muted digest__foot' }, icon('info', { size: 'sm' }), ' The digest counts the node’s bounded in-memory index; older evidence stays on disk and is reachable with ', h('code', null, 'aegismesh inspect'), '. The same digest is available from the CLI: ', h('code', null, 'aegismesh digest --since 24h --data-dir ./data --format md'), '.') }));
  },
};
