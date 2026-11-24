// Download actions for a session or an investigation: the Markdown
// observation report and indicator exports. Analyst role (the server
// enforces it and audits each download); viewers see why the buttons are
// unavailable instead of buttons that fail.

import { h } from '../lib/dom.js';
import { saveResponse } from '../lib/download.js';
import { describeError } from '../lib/api.js';
import { toast } from './components.js';
import { icon } from './icons.js';
import { EVENT_FORMATS } from '../lib/catalogs.js';

const FORMATS = [
  ['stix', 'STIX 2.1 bundle', 'Low-confidence IP indicators (15/100) with evidence notes'],
  ['csv', 'CSV', 'One row per IP address'],
  ['txt', 'Proposed blocklist', 'Plain IP list. Proposed for review; never applied by AegisMesh'],
];

// scope: { session } | { investigation } | { source } ; report(): Promise<Response> | null
export function downloadActions(ctx, { scope, report, what = 'this session' }) {
  // Reports need reports.download; indicator and event files need
  // evidence.export. A role may hold one and not the other.
  const canReport = ctx.can('reports.download');
  const canExport = ctx.can('evidence.export');
  if (!canReport && !canExport) {
    return h('div', { class: 'downloads' },
      h('p', { class: 'muted' }, icon('info', { size: 'sm' }), ' Reports, indicator exports and event files need the download permissions, which your role does not include: each download is an audited read.'));
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
  const reportBtn = report && canReport ? button('Report (Markdown)', 'download', (b) => run(b, report, 'report', 'the report'), `Observation report for ${what}`) : null;
  const exportBtns = FORMATS.map(([fmt, label, hint]) => button(label, fmt === 'txt' ? 'shield' : 'download', (b) => run(b, () => ctx.api.exportIndicators(scope, fmt), fmt, label), hint));
  // Local SIEM event files: the observations themselves in a format a SIEM
  // can import. Older servers without the route answer 404, which the status
  // line reports like any other failure.
  const eventBtns = canExport && ctx.api.exportEvents ? EVENT_FORMATS.map((f) => button(f.label, 'download', (b) => run(b, () => ctx.api.exportEvents(scope, f.format), f.format, `the ${f.label} file`), f.hint)) : [];
  return h('div', { class: 'downloads' },
    reportBtn ? h('div', { class: 'downloads__group' }, h('p', { class: 'caps' }, 'Report'), h('div', { class: 'btn-row' }, reportBtn)) : null,
    canExport ? h('div', { class: 'downloads__group' }, h('p', { class: 'caps' }, 'Indicators'), h('div', { class: 'btn-row' }, exportBtns)) : null,
    canExport ? h('p', { class: 'muted downloads__note' }, 'IP sources only, confidence 15/100: contact with a decoy is an observation, not attribution. The blocklist is proposed, never applied by AegisMesh. Each download is audited.') : null,
    !canExport ? h('p', { class: 'muted downloads__note' }, 'Indicator and event files need the export permission, which your role does not include.') : null,
    report && !canReport ? h('p', { class: 'muted downloads__note' }, 'The report needs the report permission, which your role does not include.') : null,
    eventBtns.length ? h('div', { class: 'downloads__group' },
      h('p', { class: 'caps' }, 'Event files for a SIEM'),
      h('div', { class: 'btn-row' }, eventBtns),
      h('p', { class: ['muted', 'downloads__note'] }, 'File formats only: AegisMesh sends nothing and ships no exporter or collector. OTLP JSON is a file you import, not a delivery. Severity is the catalog’s, not an incident rating.')) : null,
    status);
}
