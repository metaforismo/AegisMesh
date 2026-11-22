// Honeytokens: the planted fake credentials and agent canaries, from
// GET /honeytokens. Ids and kinds are configuration metadata; the values
// never leave the server, so the console cannot show them. Hits count
// events in the window whose detection metadata names the id; sources that
// presented it are attacker-influenced keys (evidence).

import { h, mount } from '../lib/dom.js';
import { href, normalizeWindow } from '../lib/route.js';
import { formatCount } from '../lib/format.js';
import { rankTokens, tokenKindMeta, tokenSummary, catalogBoundsNote, TOKEN_KINDS } from '../lib/catalogs.js';
import { glossaryEntry } from '../lib/glossary.js';
import { pageHead, panel, segmented, empty, link, timeEl, evidence, tokenKindChip, helpTip, banner, stat, copyButton } from '../ui/components.js';
import { icon } from '../ui/icons.js';

const WINDOWS = [['1h', '1h'], ['24h', '24h'], ['7d', '7d']];
const WINDOW_TEXT = { '1h': 'the last hour', '24h': 'the last 24 hours', '7d': 'the last 7 days' };
const WINDOW_MS = { '1h': 3600e3, '24h': 86400e3, '7d': 7 * 86400e3 };
const tip = (id) => helpTip(glossaryEntry(id));
const MINT = [
  ['A decoy credential', 'aegismesh honeytoken new --kind credential --format openai --id planted-key'],
  ['An agent canary', 'aegismesh honeytoken new --kind agent_canary --format generic --id diagnostic-echo'],
];

function meaningPanel() {
  return panel({
    title: h('span', { class: 'title-help' }, 'What a hit means', tip('honeytokenhit')),
    body: h('div', { class: 'meaning' }, Object.entries(TOKEN_KINDS).map(([kind, m]) => h('div', { class: 'meaning__item' },
      h('p', { class: 'meaning__kind' }, tokenKindChip(tokenKindMeta(kind)), h('code', null, m.rule)),
      h('p', null, h('strong', null, 'Means: '), m.means),
      h('p', { class: 'muted' }, h('strong', null, 'Does not mean: '), m.not)))),
  });
}

function mintBlock() {
  return h('div', { class: 'mint' },
    h('p', null, 'Mint a fresh synthetic value with the CLI. It prints a YAML snippet for the configuration’s ', h('code', null, 'honeytokens'), ' list and writes nothing else:'),
    h('ul', { class: 'mint__list' }, MINT.map(([what, cmd]) => h('li', { class: 'mint__item' },
      h('span', { class: 'mint__what' }, what),
      h('span', { class: 'copyable' }, h('code', null, cmd), copyButton(cmd, 'command'))))),
    h('p', { class: 'muted' }, 'Plant the value only in decoy material you own, such as a decoy response or an MCP workspace file. Never use a real credential.'));
}

function tokenRow(t, focus) {
  const kind = tokenKindMeta(t.kind);
  const row = h('tr', { class: [t.hits ? 'is-hit' : '', focus === t.id ? 'is-focus' : ''], 'data-token': t.id },
    h('td', { 'data-label': 'Token' }, h('span', { class: 'token-id' }, icon(kind.shape === 'flag' ? 'flag' : 'key', { size: 'sm' }), h('code', null, t.id))),
    h('td', { 'data-label': 'Kind' }, tokenKindChip(kind)),
    h('td', { 'data-label': 'Planted in' }, t.sensorIds.length
      ? h('span', { class: 'chip-row' }, t.sensorIds.map((s) => h('a', { class: 'cell-chip', href: href('decoys'), title: `Decoy ${s}` }, h('code', null, s))))
      : h('span', { class: 'muted', title: 'Planting is detected only in inline response material' }, 'No planting detected')),
    h('td', { class: 'num', 'data-label': 'Hits' }, t.hits ? h('strong', null, formatCount(t.hits)) : '0'),
    h('td', { 'data-label': 'Last hit' }, t.lastHit ? timeEl(t.lastHit, { relative: true }) : h('span', { class: 'muted' }, 'None in window')),
    h('td', { class: 'col-summary', 'data-label': 'Presented by' }, t.sources.length
      ? h('ul', { class: 'token-sources' }, t.sources.slice(0, 6).map((s) => h('li', null,
        link(href('sources', s), evidence(s, { max: 32 })),
        h('a', { class: 'token-sources__more', href: href('sessions', { source: s, window: '7d' }) }, 'sessions'))),
        t.sources.length > 6 ? h('li', { class: 'muted' }, `and ${formatCount(t.sources.length - 6)} more`) : null)
      : h('span', { class: 'muted' }, '—')));
  return row;
}

export default {
  title: 'Honeytokens',
  async render(root, ctx) {
    const window = normalizeWindow(ctx.route.query.window);
    const res = await ctx.api.honeytokens(window, { signal: ctx.signal });
    const tokens = rankTokens(res?.honeytokens);
    const sum = tokenSummary(res?.honeytokens);
    const since = new Date(Math.floor((Date.now() - WINDOW_MS[window]) / 60000) * 60000).toISOString().replace('.000Z', 'Z');
    const focus = typeof ctx.route.query.t === 'string' ? ctx.route.query.t : '';

    const tableEl = tokens.length ? h('div', { class: ['table-wrap', 'table-wrap--scroll'] },
      h('table', { class: ['table', 'table--stack', 'token-table'] },
        h('caption', { class: 'visually-hidden' }, `Honeytokens and their hits in ${WINDOW_TEXT[window]}`),
        h('thead', null, h('tr', null, ['Token', 'Kind', 'Planted in', 'Hits', 'Last hit', 'Presented by'].map((l, i) => h('th', { scope: 'col', class: i === 3 ? 'num' : null }, l)))),
        h('tbody', null, tokens.map((t) => tokenRow(t, focus))))) : null;

    mount(root,
      pageHead({
        title: 'Honeytokens',
        subtitle: 'Fake credentials and agent canaries planted in decoy material. If one comes back, whoever sent it read a decoy.',
        hint: 'Check which planted ids came back, from which sources, then read those sources’ sessions.',
        actions: segmented({ label: 'Hit window', options: WINDOWS, value: window, onChange: (w) => ctx.navigate(href('honeytokens', { window: w })) }),
      }),
      banner('info', 'Values are never shown', h('p', null, 'The console receives token ids and kinds only. The values stay in the node’s configuration and are scrubbed from stored evidence; nothing here can reveal one.')),
      tokens.length ? h('div', { class: ['grid', 'grid--stats', 'grid--stats-4'] },
        stat({ label: 'Honeytokens', value: formatCount(sum.tokens), note: `${formatCount(sum.credentials)} credential, ${formatCount(sum.canaries)} canary` }),
        stat({ label: 'Came back', value: formatCount(sum.withHits), note: `In ${WINDOW_TEXT[window]}` }),
        stat({ label: 'Hits', value: formatCount(sum.hits), note: 'Events naming a planted id' }),
        stat({ label: 'No planting detected', value: formatCount(sum.unplanted), note: 'Declared, not found inline' })) : null,
      tokens.length
        ? panel({
          title: 'Planted ids', meta: `Hits in ${WINDOW_TEXT[window]}; tokens that came back first`, flush: true,
          actions: link(href('events', { rule: 'HT-001', since }), 'HT-001 events'),
          body: tableEl,
        })
        : panel({ title: 'No honeytokens configured', body: [empty('Nothing is planted yet', 'A honeytoken is a fake value that only exists in your decoys, so any use of it is worth reading.', null, { art: 'tokens' }), mintBlock()] }),
      h('div', { class: 'grid grid--2' },
        meaningPanel(),
        tokens.length ? panel({ title: 'Mint another', body: mintBlock() }) : null),
      h('p', { class: 'page-note' }, icon('info', { size: 'sm' }),
        h('span', null, catalogBoundsNote(res?.bounds, WINDOW_TEXT[window]), ' A source key is not an actor identity: NAT and proxies can combine clients.')));

    // ?t=<id> (from a decoy card) marks the row and brings it into view.
    const mark = (id) => {
      for (const tr of root.querySelectorAll('tr[data-token]')) tr.classList.toggle('is-focus', tr.dataset.token === id);
      const hit = [...root.querySelectorAll('tr[data-token]')].find((tr) => tr.dataset.token === id);
      hit?.scrollIntoView?.({ block: 'center' });
    };
    return {
      mounted: () => { if (focus) mark(focus); },
      update: (route) => mark(typeof route.query.t === 'string' ? route.query.t : ''),
    };
  },
};
