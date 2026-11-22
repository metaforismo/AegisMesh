// Download actions for a session or an investigation: the Markdown
// observation report and indicator exports. Analyst role (the server
// enforces it and audits each download); viewers see why the buttons are
// unavailable instead of buttons that fail.

import { h } from '../lib/dom.js';
import { saveResponse } from '../lib/download.js';
import { describeError } from '../lib/api.js';
import { toast } from './components.js';
import { icon } from './icons.js';

const FORMATS = [
  ['stix', 'STIX 2.1 bundle', 'Low-confidence IP indicators (15/100) with evidence notes'],
  ['csv', 'CSV', 'One row per IP address'],
  ['txt', 'Proposed blocklist', 'Plain IP list. Proposed for review; never applied by AegisMesh'],
];

// scope: { session } | { investigation } | { source } ; report(): Promise<Response> | null
export function downloadActions(ctx, { scope, report, what = 'this session' }) {
  if (!ctx.can('analyst')) {
    return h('div', { class: 'downloads' },
      h('p', { class: 'muted' }, icon('info', { size: 'sm' }), ' Reports and indicator exports need the analyst role: each download is an audited read.'));
  }
  const status = h('p', { class: ['downloads__status', 'muted'], role: 'status' });
  const run = async (btn, fetcher, kind, label) => {
    btn.disabled = true;
    status.textContent = `Preparing ${label}…`;
    try {
      const res = await fetcher();
      const facts = await saveResponse(res, kind);
      const skipped = facts.skippedSources ? ` ${facts.skippedSources} non-IP source${facts.skippedSources === 1 ? ' was' : 's were'} skipped (${facts.skippedEvents} events).` : '';
      const scan = facts.truncated ? ` The scan limit was reached: only the newest ${facts.scanned} events were read.` : '';
      status.textContent = `Saved ${facts.name}.${skipped}${scan}`;
      toast('ok', `Saved ${facts.name}. The download was recorded in the audit trail.`);
    } catch (err) {
      status.textContent = '';
      toast('error', `Could not prepare ${label}: ${describeError(err).detail}`);
    } finally {
      btn.disabled = false;
    }
  };
  const button = (label, iconName, onClick, hint) => {
    const b = h('button', { class: ['btn', 'btn--sm'], type: 'button', title: hint || null }, icon(iconName, { size: 'sm' }), label);
    b.addEventListener('click', () => onClick(b));
    return b;
  };
  const reportBtn = report ? button('Report (Markdown)', 'download', (b) => run(b, report, 'report', 'the report'), `Observation report for ${what}`) : null;
  const exportBtns = FORMATS.map(([fmt, label, hint]) => button(label, fmt === 'txt' ? 'shield' : 'download', (b) => run(b, () => ctx.api.exportIndicators(scope, fmt), fmt, label), hint));
  return h('div', { class: 'downloads' },
    reportBtn ? h('div', { class: 'downloads__group' }, h('p', { class: 'caps' }, 'Report'), h('div', { class: 'btn-row' }, reportBtn)) : null,
    h('div', { class: 'downloads__group' }, h('p', { class: 'caps' }, 'Indicators'), h('div', { class: 'btn-row' }, exportBtns)),
    h('p', { class: 'muted downloads__note' }, 'IP sources only, confidence 15/100: contact with a decoy is an observation, not attribution. The blocklist is proposed, never applied by AegisMesh. Each download is audited.'),
    status);
}
