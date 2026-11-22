// Decoys: what the operator has deployed, from GET /decoys. One card per
// configured decoy sensor: kind, listen address, the surface families it
// imitates, its static rules, tools and fake files, the honeytoken ids
// planted in it, and its events in the window. Every value is configuration
// metadata or a count; no body, prompt, file content or token value is ever
// returned by the API, so none can be shown.

import { h, mount } from '../lib/dom.js';
import { href, normalizeWindow } from '../lib/route.js';
import { formatCount } from '../lib/format.js';
import { normalizeDecoy, decoySummary, decoyFigures, activityShare, catalogBoundsNote, kindLabel } from '../lib/catalogs.js';
import { glossaryEntry } from '../lib/glossary.js';
import { pageHead, panel, segmented, empty, link, timeEl, familyChip, helpTip, stat } from '../ui/components.js';
import { icon } from '../ui/icons.js';

const WINDOWS = [['1h', '1h'], ['24h', '24h'], ['7d', '7d']];
const WINDOW_TEXT = { '1h': 'the last hour', '24h': 'the last 24 hours', '7d': 'the last 7 days' };
const WINDOW_MS = { '1h': 3600e3, '24h': 86400e3, '7d': 7 * 86400e3 };
const tip = (id) => helpTip(glossaryEntry(id));

// "What attackers see, and what is real": the one explanation this screen
// exists to make. Fixed interface copy.
function truthPanel() {
  const col = (cls, title, items) => h('div', { class: ['truth__col', cls] },
    h('p', { class: 'truth__title' }, title),
    h('ul', { class: 'truth__list' }, items.map((x) => h('li', null, x))));
  return h('section', { class: 'truth', 'aria-labelledby': 'truth-title' },
    h('h2', { class: 'truth__head', id: 'truth-title' }, 'What attackers see, and what is real'),
    h('div', { class: 'truth__cols' },
      col('truth__col--seen', 'What a client sees', [
        'Listening services that answer like Ollama, OpenAI-compatible APIs, LiteLLM or vLLM, an MCP server, SSH or a TCP service.',
        'An MCP workspace that lists files, reads them, returns environment values and runs lookups.',
        'Credentials and instructions that look usable, because they were planted to be found.',
      ]),
      col('truth__col--real', 'What is actually there', [
        'Nothing behind the decoy. No model runs, no file system or shell is reached, no query touches a database: every answer is static configuration.',
        'Tool calls never execute. A write- or execution-shaped request gets a fixed “not found”.',
        'The only real thing is the record: what was asked, when, and from which source key.',
      ])),
    h('p', { class: 'truth__foot' }, 'The console reads this catalog from the running configuration. It cannot add, change or stop a decoy.'));
}

function card(d, busiest, since) {
  const n = normalizeDecoy(d);
  const share = activityShare(n.events, busiest);
  const fill = h('span', { class: 'activity-mark__fill' });
  fill.style.transform = `scaleX(${share.toFixed(4)})`;
  const figures = decoyFigures(d);
  return h('article', { class: 'decoy', 'aria-labelledby': `decoy-${n.id}` },
    h('header', { class: 'decoy__head' },
      h('span', { class: 'decoy__mark', 'aria-hidden': 'true' }, icon('decoy')),
      h('div', { class: 'decoy__name' },
        h('h2', { class: 'decoy__id', id: `decoy-${n.id}` }, h('code', null, n.id)),
        h('p', { class: 'decoy__listen' }, h('span', { class: 'chip' }, kindLabel(n.kind)), n.listen ? h('code', null, n.listen) : h('span', { class: 'muted' }, 'no listen address'))),
      h('div', { class: 'decoy__activity' },
        h('p', { class: 'decoy__events' }, h('strong', null, formatCount(n.events)), n.events === 1 ? ' event' : ' events'),
        h('span', { class: 'activity-mark', 'aria-hidden': 'true' }, fill),
        h('p', { class: 'decoy__last' }, n.lastActivity ? ['Last ', timeEl(n.lastActivity, { relative: true })] : h('span', { class: 'muted' }, 'No activity in window')))),
    h('div', { class: 'decoy__body' },
      h('div', { class: 'decoy__row' },
        h('p', { class: 'caps' }, 'Imitates'),
        h('p', { class: 'fam-row' }, n.families.length ? n.families.map(familyChip) : h('span', { class: 'muted' }, 'Not reported'))),
      figures.length ? h('dl', { class: 'decoy__figures' }, figures.map((f) => h('div', { class: 'decoy__figure' },
        h('dt', null, f.label), h('dd', null, formatCount(f.value))))) : null,
      h('div', { class: 'decoy__row' },
        h('p', { class: 'caps' }, 'Planted honeytokens'),
        n.honeytokenIds.length
          ? h('p', { class: 'chip-row' }, n.honeytokenIds.map((id) => h('a', { class: 'token-link', href: href('honeytokens', { t: id }) }, icon('key', { size: 'xs' }), h('code', null, id))))
          : h('p', { class: 'muted' }, 'None detected in inline responses'))),
    h('footer', { class: 'decoy__foot' },
      link(href('events', { sensor: n.id, since }), 'View its events'),
      link(href('sensors'), 'Runtime state')));
}

export default {
  title: 'Decoys',
  async render(root, ctx) {
    const window = normalizeWindow(ctx.route.query.window);
    const res = await ctx.api.decoys(window, { signal: ctx.signal });
    const list = Array.isArray(res?.decoys) ? res.decoys : [];
    const sum = decoySummary(list);
    // Round to the minute so the drill-down matches the window counted.
    const since = new Date(Math.floor((Date.now() - WINDOW_MS[window]) / 60000) * 60000).toISOString().replace('.000Z', 'Z');
    const ordered = [...list].sort((a, b) => (Number(b?.events) || 0) - (Number(a?.events) || 0) || String(a?.id).localeCompare(String(b?.id)));

    mount(root,
      pageHead({
        title: 'Decoys',
        subtitle: 'The synthetic surfaces this node runs, as configured. Every one exists only to be found.',
        hint: 'See what each decoy imitates and what is planted in it, then open its events.',
        actions: segmented({ label: 'Activity window', options: WINDOWS, value: window, onChange: (w) => ctx.navigate(href('decoys', { window: w })) }),
      }),
      truthPanel(),
      list.length ? h('div', { class: ['grid', 'grid--stats', 'grid--stats-4'] },
        stat({ label: 'Decoys', value: formatCount(sum.decoys), note: 'Configured on this node' }),
        stat({ label: 'AI-service shapes', value: formatCount(sum.aiServices), note: 'Ollama, OpenAI-compatible, LiteLLM, vLLM' }),
        stat({ label: 'MCP environments', value: formatCount(sum.mcpEnvironments), note: 'Synthetic workspaces' }),
        stat({ label: 'Planted honeytokens', value: formatCount(sum.plantedIds), note: 'Distinct ids found inline' })) : null,
      list.length
        ? h('section', { class: 'decoy-grid', 'aria-label': `Decoys, with events in ${WINDOW_TEXT[window]}` }, ordered.map((d) => card(d, sum.busiest, since)))
        : panel({
          body: empty('No decoys in this catalog', 'Decoys come from the node’s configuration file. Other tenants than the node’s own see an empty catalog. To scaffold AI-service and MCP decoys on loopback:', h('code', { class: 'firstrun__cmd' }, 'aegismesh init --profile ai-decoy --dir ./ai-lab'), { art: 'decoys' }),
        }),
      h('p', { class: 'page-note' }, icon('info', { size: 'sm' }),
        h('span', null, catalogBoundsNote(res?.bounds, WINDOW_TEXT[window]), ' Planting is detected only in inline response material; a token referenced from an external body file is not inferred.'),
        tip('decoy')));
  },
};
