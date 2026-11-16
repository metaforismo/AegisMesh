import { h, mount } from '../lib/dom.js';
import { href, isOpaqueId } from '../lib/route.js';
import { formatDateTime } from '../lib/format.js';
import { jsonTokens, tokensToText } from '../lib/json.js';
import { pageHead, panel, kv, sevChip, clsChip, evidence, seal, table, empty, link, chip, toast, labelFor, banner, copyable } from '../ui/components.js';
import { icon } from '../ui/icons.js';
import { eventTable, ruleChips, statusBadge, attachDialog } from './shared.js';

function jsonViewer(value) {
  const { tokens, truncated } = jsonTokens(value);
  const code = h('pre', { class: 'code', tabindex: '0', 'aria-label': 'Stored envelope JSON' },
    tokens.map((t) => (t.type === 'ws' ? t.text : h('span', { class: `json-${t.type}` }, t.text))));
  const copy = h('button', { class: ['btn', 'btn--sm'], type: 'button' }, icon('copy'), 'Copy JSON');
  copy.addEventListener('click', async () => {
    try {
      await navigator.clipboard.writeText(truncated ? JSON.stringify(value, null, 2) : tokensToText(tokens));
      toast('ok', 'Envelope JSON copied.');
    } catch {
      toast('error', 'The browser blocked clipboard access. Select the text and copy it manually.');
    }
  });
  return { code, copy, truncated };
}

// Renders one event's detail into `root`. Used by the full page and by the
// side panel on the events list (`inDrawer`: no back link, the panel's own
// header carries navigation).
export async function renderEventDetail(root, ctx, id, { inDrawer = false, signal = ctx.signal } = {}) {
    const d = await ctx.api.event(id, { signal });
    const s = d.summary || {};
    const integrity = d.integrity || {};
    const findings = Array.isArray(d.findings) ? d.findings : [];
    const related = Array.isArray(d.related) ? d.related : [];
    const invs = Array.isArray(d.investigations) ? d.investigations : [];
    const viewer = jsonViewer(d.envelope ?? null);
    const isSignal = s.classification === 'correlation_signal';

    const attach = ctx.can('analyst') ? h('button', { class: 'btn', type: 'button' }, 'Add to investigation') : null;
    attach?.addEventListener('click', async () => {
      try {
        const inv = await attachDialog(ctx, id);
        if (inv?.id) {
          toast('ok', 'Evidence attached.');
          ctx.rerender();
        }
      } catch (err) {
        toast('error', err?.message || 'Could not load investigations.');
      }
    });

    mount(root,
      pageHead({
        eyebrow: inDrawer ? null : h('a', { href: '#/events' }, icon('arrow-left', { size: 'xs' }), 'Events'),
        title: h('span', { class: 'event-title' }, evidence(s.summary || '(no summary)')),
        subtitle: h('span', { class: 'btn-row' }, clsChip(s.classification), sevChip(s.severity),
          seal(Boolean(integrity.verified), integrity.verified ? `Payload ${integrity.algorithm || 'hash'} verified` : 'Integrity check failed')),
        actions: attach,
      }),
      integrity.verified ? null : banner('danger', 'Payload hash does not match', h('p', null, 'The stored payload does not match its recorded hash. Treat this envelope as untrustworthy. ', integrity.error ? evidence(integrity.error) : null)),
      h('div', { class: 'grid grid--2' },
        panel({
          title: 'Observation',
          body: kv([
            ['Event id', copyable(s.id, { label: 'event id' })],
            ['Time', formatDateTime(s.time)],
            ['Sequence', String(s.seq ?? '—')],
            ['Sensor', h('span', { class: 'btn-row' }, link(href('events', { sensor: s.sensor?.id }), h('code', null, s.sensor?.id ?? '—')), s.sensor?.kind ? chip(s.sensor.kind) : null)],
            ['Sensor listen', s.sensor?.listen ? h('code', null, s.sensor.listen) : ''],
            ['Source', s.source ? link(href('sources', s.source), evidence(s.source)) : h('span', { class: 'muted' }, 'unknown')],
            ['Detection action', s.action ? chip(s.action, { mono: true }) : ''],
            ['Rules', ruleChips(s.rule_ids)],
          ]),
        }),
        panel({
          title: 'Investigations', meta: 'Cases that cite this event',
          body: invs.length
            ? h('ul', { class: 'plain-list' }, invs.map((i) => h('li', { class: 'btn-row' },
              isOpaqueId(i.id) ? link(href('investigations', i.id), i.title) : i.title, statusBadge(i.status))))
            : empty('Not in any investigation', ctx.can('analyst') ? 'Use “Add to investigation” to collect it as evidence.' : 'An analyst can attach it to an investigation.'),
        })),
      panel({
        title: 'Findings', meta: 'Rule-authored reasons. They never quote the matched input.', flush: true,
        body: findings.length ? table({
          caption: 'Findings',
          columns: [
            { label: 'Rule', cell: (f) => link(href('events', { rule: f.rule_id }), h('code', null, f.rule_id)) },
            { label: 'Severity', cell: (f) => sevChip(f.severity) },
            { label: 'Confidence', cell: (f) => labelFor(f.confidence || '—') },
            { label: 'Reason', className: 'col-summary', cell: (f) => f.reason || '—' },
          ],
          rows: findings,
        }) : empty('No findings', 'No detection rule matched this observation. It is still recorded evidence.'),
      }),
      panel({
        title: isSignal ? 'Source events' : 'Signals citing this event',
        meta: isSignal ? 'The observations this correlation signal was derived from' : 'Correlation signals that list this event as a source',
        flush: true,
        body: related.length ? eventTable(related, { caption: 'Related events' }) : empty(isSignal ? 'No source events indexed' : 'No signal cites this event', isSignal ? 'The source events may have aged out of the index.' : ''),
      }),
      panel({
        title: 'Stored envelope', meta: 'The complete aegismesh.event/v1 envelope, unmodified. Every string in it is untrusted.',
        actions: viewer.copy,
        body: [viewer.truncated ? banner('warn', 'Envelope display truncated', 'The envelope is too large to render fully. Use aegismesh inspect for the complete record.') : null, viewer.code],
      }));
    return d;
}

export default {
  title: 'Event',
  async render(root, ctx) {
    await renderEventDetail(root, ctx, ctx.route.params.id);
  },
};
