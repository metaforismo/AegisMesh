import { h, mount } from '../lib/dom.js';
import { href, isOpaqueId, isSessionId } from '../lib/route.js';
import { formatDateTime } from '../lib/format.js';
import { jsonTokens, tokensToText } from '../lib/json.js';
import { addFilterHref } from '../lib/filters.js';
import { pageHead, panel, kv, sevChip, clsChip, evidence, seal, table, empty, link, chip, toast, labelFor, banner, copyable } from '../ui/components.js';
import { icon } from '../ui/icons.js';
import { describeOrigin, normalizeNodeFilter, LOCAL } from '../lib/origin.js';
import { eventTable, ruleChips, statusBadge, attachDialog, originLabel, originContext } from './shared.js';

// The integrity scope the hub reports for forwarded evidence. The UI words
// it itself and never shows a server-supplied description as interface text.
const HUB_SCOPE = 'hub_payload_hash_consistency';

function integrityView(integrity, forwarded) {
  const verified = integrity.verified === true;
  const scope = typeof integrity.scope === 'string' ? integrity.scope : '';
  const algo = integrity.algorithm || 'hash';
  if (scope === HUB_SCOPE) {
    return {
      seal: seal(verified, verified ? `Payload ${algo} consistent on this hub` : 'Hub integrity check failed'),
      note: verified
        ? 'The hub recomputed the payload hash of the forwarded envelope and it matches. That is consistency, not provenance: it shows the copy was not altered after hashing, not that the content is what the sensor saw. The node id is the origin the hub authenticated when the copy arrived.'
        : 'The hub recomputed the payload hash of the forwarded envelope and it does not match. Treat this copy as untrustworthy and compare it with the node’s own store.',
    };
  }
  return {
    seal: seal(verified, verified ? `Payload ${algo} verified` : 'Integrity check failed'),
    note: scope ? `Integrity scope reported by the server: ${scope}.` : (forwarded ? 'Forwarded copy: the server did not report an integrity scope.' : ''),
  };
}

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
export async function renderEventDetail(root, ctx, id, { node = '', inDrawer = false, signal = ctx.signal } = {}) {
    const [d, origin] = await Promise.all([
      ctx.api.event(id, normalizeNodeFilter(node), { signal }),
      originContext(ctx, signal),
    ]);
    const s = d.summary || {};
    const integrity = d.integrity || {};
    const nodeRef = d.node || s.node || null;
    const o = describeOrigin(nodeRef);
    const forwarded = !o.local;
    const showOrigin = forwarded || origin.accepting;
    const iv = integrityView(integrity, forwarded);
    const findings = Array.isArray(d.findings) ? d.findings : [];
    const related = Array.isArray(d.related) ? d.related : [];
    const invs = Array.isArray(d.investigations) ? d.investigations : [];
    const viewer = jsonViewer(d.envelope ?? null);
    const isSignal = s.classification === 'correlation_signal';
    // The retained analysis session holding this event (newer servers).
    // "" means outside the retained sessions; absent means not reported.
    const sessionId = isSessionId(d.session_id) ? d.session_id : '';
    const sessionRow = typeof d.session_id === 'string'
      ? ['Session', sessionId
        ? h('span', { class: 'btn-row' }, link(href('sessions', sessionId), h('span', null, icon('story', { size: 'sm' }), ' Open the session story')), h('span', { class: 'muted' }, 'this source’s events grouped by idle gaps'))
        : h('span', { class: 'muted' }, 'Not in a retained session (outside the newest analysed events)')]
      : null;

    // Investigations annotate bare event ids, which resolve to local
    // observations only; a forwarded copy cannot be attached.
    const attach = ctx.can('analyst') && !forwarded ? h('button', { class: 'btn', type: 'button' }, 'Add to investigation') : null;
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
        crumbs: inDrawer ? null : [['Events', '#/events'], s.source ? [evidence(s.source, { max: 28 }), href('sources', s.source)] : null, ['Event', null]],
        title: h('span', { class: 'event-title' }, evidence(s.summary || '(no summary)')),
        subtitle: h('span', { class: 'btn-row' }, clsChip(s.classification), sevChip(s.severity), iv.seal,
          forwarded ? h('span', { class: 'chip' }, 'Forwarded') : null),
        actions: [sessionId && !inDrawer ? h('a', { class: 'btn', href: href('sessions', sessionId) }, icon('story', { size: 'sm' }), 'Session story') : null, attach],
      }),
      integrity.verified ? null : banner('danger', 'Payload hash does not match', h('p', null, forwarded ? 'The forwarded payload does not match its recorded hash. Treat this copy as untrustworthy and compare it with the node’s own store. ' : 'The stored payload does not match its recorded hash. Treat this envelope as untrustworthy. ', integrity.error ? evidence(integrity.error) : null)),
      forwarded ? banner('info', 'Forwarded by another node',
        h('p', null, 'Observed by ', originLabel(nodeRef), ' and forwarded to this hub. Forwarding is best effort; that node’s own store is the authoritative record. The hub cannot command the node or fetch anything from it.')) : null,
      h('div', { class: 'grid grid--2' },
        panel({
          title: 'Observation',
          body: kv([
            ...(showOrigin ? [['Origin', h('span', { class: 'btn-row' }, originLabel(nodeRef),
              o.linkable ? link(href('events', { node: o.id }), 'Events from this node') : (o.local ? link(href('events', { node: LOCAL }), 'Events from this node') : null))]] : []),
            ['Event id', copyable(s.id, { label: 'event id' })],
            ['Time', formatDateTime(s.time)],
            ['Sequence', String(s.seq ?? '—')],
            ['Sensor', h('span', { class: 'btn-row' }, link(href('events', { sensor: s.sensor?.id }), h('code', null, s.sensor?.id ?? '—')), s.sensor?.kind ? chip(s.sensor.kind) : null)],
            ['Sensor listen', s.sensor?.listen ? h('code', null, s.sensor.listen) : ''],
            ['Source', s.source ? link(href('sources', s.source), evidence(s.source)) : h('span', { class: 'muted' }, 'unknown')],
            sessionRow,
            ['Detection action', s.action ? chip(s.action, { mono: true }) : ''],
            ['Rules', ruleChips(s.rule_ids)],
            ...(iv.note ? [['Integrity', h('span', { class: 'kv-note' }, iv.note)]] : []),
          ]),
        }),
        panel({
          title: 'Investigations', meta: 'Cases that cite this event',
          body: forwarded
            ? empty('Not available for forwarded evidence', 'Investigations hold this node’s own observations only. Node-scoped annotations are not implemented; investigate on the forwarding node, or note the event id there.')
            : invs.length
            ? h('ul', { class: 'plain-list' }, invs.map((i) => h('li', { class: 'btn-row' },
              isOpaqueId(i.id) ? link(href('investigations', i.id), i.title) : i.title, statusBadge(i.status))))
            : empty('Not in any investigation', ctx.can('analyst') ? 'Use “Add to investigation” to collect it as evidence.' : 'An analyst can attach it to an investigation.'),
        })),
      narrowPanel(s),
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
        body: related.length ? eventTable(related, { caption: 'Related events', origin: origin.accepting || 'auto' }) : empty(isSignal ? 'No source events indexed' : 'No signal cites this event', isSignal ? 'The source events may have aged out of the index.' : ''),
      }),
      panel({
        title: 'Stored envelope', meta: forwarded
          ? 'The aegismesh.event/v1 envelope as the node forwarded it, unmodified. Every string in it is untrusted.'
          : 'The complete aegismesh.event/v1 envelope, unmodified. Every string in it is untrusted.',
        actions: viewer.copy,
        body: [viewer.truncated ? banner('warn', 'Envelope display truncated', 'The envelope is too large to render fully. Use aegismesh inspect for the complete record.') : null, viewer.code],
      }));
    return d;
}

// "Narrow the list": the keyboard path for click-to-filter. Each link opens
// Events filtered to one property of this event. The source key stays
// evidence inside its button.
function narrowPanel(s) {
  const links = [];
  const add = (key, value, label) => {
    const target = addFilterHref({}, key, value);
    if (target) links.push(h('a', { class: ['btn', 'btn--sm'], href: target }, icon('filter', { size: 'sm' }), label));
  };
  if (s.source) add('source', s.source, ['Same source ', evidence(s.source, { max: 24 })]);
  if (s.sensor?.id) add('sensor', s.sensor.id, ['Same sensor ', h('code', null, s.sensor.id)]);
  if (s.classification) add('classification', s.classification, ['Same class: ', clsChip(s.classification)]);
  for (const r of (Array.isArray(s.rule_ids) ? s.rule_ids : []).slice(0, 4)) add('rule', r, ['Rule ', h('code', null, r)]);
  if (!links.length) return null;
  return panel({ title: 'Narrow the list', meta: 'Open Events filtered to one property of this event', body: h('div', { class: 'narrow' }, links) });
}

export default {
  title: 'Event',
  async render(root, ctx) {
    await renderEventDetail(root, ctx, ctx.route.params.id, { node: ctx.route.query.node });
  },
};
