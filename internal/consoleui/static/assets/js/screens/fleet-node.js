import { h, mount } from '../lib/dom.js';
import { ApiError } from '../lib/api.js';
import { href } from '../lib/route.js';
import { formatCount, formatDateTime, formatDuration } from '../lib/format.js';
import { formatFingerprint, idMatchesFingerprint } from '../lib/fleet.js';
import { pageHead, panel, kv, badge, table, empty, banner, toast, openDialog, labelFor, chip, link } from '../ui/components.js';
import { forwardingSummary } from '../lib/fleet.js';
import { fleetStatusBadge, seenCell, countersCell, storageBadge, sensorsCell, hubUnavailable, forwardingRows } from './fleet.js';

const SENSOR_STATE = { running: 'ok', failed: 'danger', stopped: 'neutral' };

function revokeDialog(ctx, node) {
  return openDialog({
    title: `Revoke ${node.name || 'this node'}?`,
    submitLabel: 'Revoke permanently',
    danger: true,
    build: () => [
      banner('danger', 'Revocation is permanent',
        'The hub will refuse every heartbeat from this node from now on. The same key can never enroll again, even with a new token. To bring the machine back, its operator must create a new identity and enroll it with a fresh token.'),
      h('p', null, 'Revoking does not stop, change or reach the node itself: the hub cannot command nodes. It only stops accepting this node’s reports.'),
      h('label', { class: 'check' }, h('input', { type: 'checkbox', name: 'confirm', required: true }), 'I understand this cannot be undone'),
    ],
    onSubmit: async (form) => {
      if (!form.elements.confirm.checked) throw new Error('Tick the box to confirm.');
      return ctx.api.revokeNode(node.id);
    },
  });
}

export default {
  title: 'Fleet node',
  async render(root, ctx) {
    let n;
    let fleet = null;
    try {
      [n, fleet] = await Promise.all([
        ctx.api.fleetNode(ctx.route.params.id, { signal: ctx.signal }),
        ctx.api.fleet ? ctx.api.fleet({ signal: ctx.signal }).catch(() => null) : null,
      ]);
    } catch (err) {
      if (!(err instanceof ApiError && err.code === 'unavailable')) throw err;
      mount(root, pageHead({ eyebrow: h('a', { href: href('fleet') }, '← Fleet'), title: 'Fleet node' }),
        panel({ body: hubUnavailable(err, () => ctx.rerender()) }));
      return;
    }
    const v = n.version || {};
    const sensors = Array.isArray(n.sensors) ? n.sensors : [];
    const fpOk = idMatchesFingerprint(n.id, n.public_key_fingerprint);
    const revoked = n.status === 'revoked';
    const accepting = fleet?.hub?.accept_evidence === true;
    const fwd = forwardingSummary(n.forwarding);
    const receives = accepting && fwd?.enabled;
    const viewEvents = accepting ? h('a', { class: 'btn', href: href('events', { node: n.id }) }, 'View events') : null;

    const copy = h('button', { class: ['btn', 'btn--sm'], type: 'button' }, 'Copy fingerprint');
    copy.addEventListener('click', async () => {
      try {
        await navigator.clipboard.writeText(String(n.public_key_fingerprint || ''));
        toast('ok', 'Fingerprint copied.');
      } catch {
        toast('error', 'The browser blocked clipboard access. Select the fingerprint and copy it manually.');
      }
    });

    let revoke = null;
    if (ctx.can('admin') && !revoked) {
      revoke = h('button', { class: ['btn', 'btn--danger'], type: 'button' }, 'Revoke node');
      revoke.addEventListener('click', async () => {
        const updated = await revokeDialog(ctx, n);
        if (updated) { toast('ok', 'Node revoked.'); ctx.rerender(); }
      });
    }

    mount(root,
      pageHead({
        eyebrow: h('a', { href: href('fleet') }, '← Fleet'),
        title: h('code', null, n.name || '(unnamed)'),
        subtitle: h('span', { class: 'btn-row' }, fleetStatusBadge(n.status), chip('Self-reported'), h('span', { class: 'muted' },
          receives
            ? 'Figures come from the agent’s signed heartbeats. The hub cannot command this node. It receives best-effort copies of this node’s evidence; the node’s own store stays authoritative.'
            : 'Figures come from the agent’s signed heartbeats. The hub cannot command this node, and it is not receiving evidence from it.')),
        actions: viewEvents || revoke ? [viewEvents, revoke] : null,
      }),
      revoked ? banner('danger', 'This node is revoked', 'The hub refuses its heartbeats, and its key can never enroll again. The figures below are the last report accepted before revocation.') : null,
      h('div', { class: 'grid grid--2' },
        panel({
          title: 'Identity',
          body: kv([
            ['Node id', h('code', null, n.id)],
            ['Name', h('code', null, n.name || '—')],
            ['Status', fleetStatusBadge(n.status)],
            ['Enrolled', n.enrolled_at ? `${formatDateTime(n.enrolled_at)} (recorded by the hub)` : ''],
            ['Last seen', seenCell(n.last_seen_at, 'never (no heartbeat yet)')],
          ]),
        }),
        panel({
          title: 'Reported health', meta: 'Signed self-report from the agent, not attestation',
          body: kv([
            ['Version', `${v.version || '—'} (${v.commit || 'unknown commit'}, ${v.go || 'go ?'})`],
            ['Uptime', n.uptime_seconds !== undefined ? formatDuration(n.uptime_seconds) : ''],
            ['Sensors', sensorsCell(sensors)],
            ['Evidence counters', h('span', { class: 'stack-tight' }, countersCell(n.counters), h('span', { class: 'muted' }, 'Local appends since the agent process started'))],
            ['Bus drops', formatCount(n.bus_dropped_events ?? 0)],
            ['Storage', storageBadge(n.storage_healthy)],
          ]),
        })),
      panel({
        title: 'Evidence forwarding', meta: 'Counters, queue and error are self-reported; last receive time and gaps are recorded by the hub',
        actions: accepting ? link(href('events', { node: n.id }), 'Events from this node') : null,
        body: [
          accepting ? null : h('p', { class: 'muted' }, 'This hub does not accept forwarded evidence, so nothing this node forwards is stored here.'),
          kv(forwardingRows(n.forwarding, { lastLabel: 'Last received by the hub' })),
        ],
      }),
      panel({
        title: 'Public key fingerprint', meta: 'Full SHA-256 of the node’s Ed25519 public key. Compare it with the agent’s own record before trusting a match.',
        actions: copy,
        body: [
          h('pre', { class: ['code', 'fingerprint'], tabindex: '0', 'aria-label': 'Public key fingerprint' }, formatFingerprint(n.public_key_fingerprint) || String(n.public_key_fingerprint || '—')),
          fpOk
            ? h('p', { class: 'muted' }, 'The node id is the first 32 hex characters of this fingerprint, as expected.')
            : banner('warn', 'Fingerprint and node id do not match', 'The node id should be the first 32 hex characters of the fingerprint. Treat this record as inconsistent and inspect the hub state.'),
        ],
      }),
      panel({
        title: `Sensors (${sensors.length})`, meta: 'Identifiers and states only. Sensor addresses are never reported to the hub.', flush: true,
        body: sensors.length ? table({
          caption: 'Reported sensors',
          columns: [
            { label: 'Sensor id', cell: (s) => h('code', null, s.id) },
            { label: 'Kind', cell: (s) => chip(s.kind || '?') },
            { label: 'State', cell: (s) => badge(SENSOR_STATE[s.state] || 'neutral', labelFor(s.state || 'unknown')) },
          ],
          rows: sensors,
        }) : empty('No sensors reported', n.last_seen_at ? 'The agent reported zero sensors. A hub-only node can run without sensors.' : 'No heartbeat has arrived yet.'),
      }));
  },
};
