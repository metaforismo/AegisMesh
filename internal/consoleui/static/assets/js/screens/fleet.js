// Experimental fleet inventory (console API, ADR-0018).
//
// What this screen can and cannot claim: node rows are signed self-reports
// from each agent, not attestation. The hub cannot command nodes, and no
// evidence leaves a node. The only writes are enrollment-token management
// and permanent revocation, both admin-only and audited server-side.

import { h, mount } from '../lib/dom.js';
import { href } from '../lib/route.js';
import { ApiError } from '../lib/api.js';
import { CLASSIFICATIONS, classificationMeta } from '../lib/taxonomy.js';
import { formatCount, formatDateTime, formatRelative, shortId } from '../lib/format.js';
import {
  FLEET_STATUSES, fleetStatusMeta, normalizeFleetStatus, sensorSummary, TTL_CHOICES, TOKEN_TTL_DEFAULT,
  validateTokenNote, normalizeExpiry, formatExpiresIn, isTokenId, isNodeId,
} from '../lib/fleet.js';
import {
  pageHead, panel, kv, badge, table, segmented, empty, banner, glyph, link, toast, openDialog, selectField,
  inputField, timeEl, labelFor, errorState,
} from '../ui/components.js';

export const FLEET_SUBTITLE = 'Experimental inventory of nodes enrolled with a fleet hub. Everything shown about a node is self-reported by its agent in signed heartbeats; it is not attestation. The hub cannot start, stop or configure nodes, and no evidence is forwarded to it.';

export function fleetStatusBadge(status) {
  const m = fleetStatusMeta(status);
  return badge(m.badge, m.label);
}

// "2m ago" with the absolute UTC time underneath; "never" before the first heartbeat.
export function seenCell(value, emptyText = 'never') {
  if (!value) return h('span', { class: 'muted' }, emptyText);
  return h('span', { class: 'stack-tight' },
    h('time', { datetime: value, title: formatDateTime(value) }, formatRelative(value)),
    h('span', { class: 'muted' }, formatDateTime(value)));
}

export function sensorsCell(sensors) {
  const s = sensorSummary(sensors);
  if (!s.total) return h('span', { class: 'muted' }, 'none reported');
  return h('span', { class: 'chip-row' },
    `${s.running} of ${s.total} running`,
    s.failed ? badge('danger', `${s.failed} failed`) : null,
    s.stopped ? badge('neutral', `${s.stopped} stopped`) : null);
}

export function countersCell(counters) {
  return h('span', { class: 'counter-row' }, CLASSIFICATIONS.map((c) => h('span', {
    class: 'counter', title: `${classificationMeta(c).label} (since agent process start)`,
  }, glyph(c), h('span', { class: 'visually-hidden' }, `${classificationMeta(c).label}: `), formatCount(counters?.[c] ?? 0))));
}

export function storageBadge(healthy) {
  return healthy ? badge('ok', 'Healthy') : badge('danger', 'Append failure reported');
}

// ---- Role banner -----------------------------------------------------------

function rolePanel(f) {
  const hub = f.hub || {};
  const agent = f.agent || {};
  return panel({
    title: 'This node',
    meta: 'Fleet roles are set in configuration; see docs/configuration.md.',
    body: h('div', { class: 'grid grid--2' },
      h('section', { class: 'role', 'aria-labelledby': 'role-hub' },
        h('h3', { id: 'role-hub', class: 'btn-row' }, 'Hub', hub.enabled ? badge('ok', 'Enabled') : badge('neutral', 'Off')),
        hub.enabled ? kv([
          ['Machine listener', h('code', null, hub.listen || '—')],
          ['TLS', hub.tls ? 'Enabled' : 'Off (loopback development only)'],
        ]) : h('p', { class: 'muted' }, 'This node does not accept enrollments.')),
      h('section', { class: 'role', 'aria-labelledby': 'role-agent' },
        h('h3', { id: 'role-agent', class: 'btn-row' }, 'Agent', agent.enabled ? badge('ok', 'Enabled') : badge('neutral', 'Off')),
        agent.enabled ? kv([
          ['Hub URL', agent.hub_url ? h('code', null, agent.hub_url) : ''],
          ['Node id', agent.node_id ? h('code', { title: agent.node_id }, agent.node_id) : h('span', { class: 'muted' }, 'no identity yet')],
          ['Enrolled', agent.enrolled ? badge('ok', 'Enrolled') : badge('warn', 'Not enrolled')],
          ['Last heartbeat', seenCell(agent.last_heartbeat_at, 'none acknowledged yet')],
          ['Last error', agent.last_error ? h('code', null, agent.last_error) : h('span', { class: 'muted' }, 'none')],
        ]) : h('p', { class: 'muted' }, 'This node does not report to a hub.'))),
  });
}

function teachingState() {
  return panel({
    body: empty('Fleet inventory is not enabled on this node',
      h('span', { class: 'stack' },
        h('span', null, 'Fleet inventory is an experimental way to see many AegisMesh nodes in one list. One node runs as a hub. Other nodes run an agent that enrolls once with a one-time token, then sends signed heartbeats: version, uptime, sensor states, evidence counters and storage health.'),
        h('span', null, 'It is inventory only. The hub cannot command or configure nodes, and evidence never leaves the node that recorded it. Both roles are off by default and are enabled in configuration; see docs/configuration.md.')),
      link('https://github.com/metaforismo/AegisMesh/blob/master/docs/configuration.md', 'Configuration reference')),
  });
}

// ---- Inventory ---------------------------------------------------------------

function nodesTable(nodes) {
  return table({
    caption: 'Fleet nodes',
    columns: [
      { label: 'Status', cell: (n) => fleetStatusBadge(n.status) },
      { label: 'Name', className: 'nowrap', cell: (n) => (isNodeId(n.id) ? link(href('fleet', 'nodes', n.id), h('code', null, n.name || '(unnamed)')) : h('code', null, n.name || '(unnamed)')) },
      { label: 'Node id', className: 'nowrap', cell: (n) => h('code', { class: 'hash', title: n.id }, shortId(n.id, 12)) },
      { label: 'Version', className: 'nowrap', cell: (n) => h('code', null, n.version?.version || '—') },
      { label: 'Last seen', className: 'nowrap', cell: (n) => seenCell(n.last_seen_at, 'never (no heartbeat)') },
      { label: 'Sensors', cell: (n) => sensorsCell(n.sensors) },
      { label: 'Counters', cell: (n) => countersCell(n.counters) },
      { label: 'Bus drops', num: true, cell: (n) => formatCount(n.bus_dropped_events ?? 0) },
      { label: 'Storage', className: 'nowrap', cell: (n) => storageBadge(n.storage_healthy) },
    ],
    rows: nodes,
  });
}

// ---- Enrollment tokens (admin) ---------------------------------------------

// Shows the raw token exactly once. The value lives only in this function's
// closure and one Text node; on close the Text node is emptied and the dialog
// removed, so nothing remains in the DOM, storage, URL or logs.
export function showTokenOnce(minted) {
  return new Promise((resolve) => {
    let value = String(minted?.token ?? '');
    const tokenText = document.createTextNode(value);
    const copy = h('button', { class: ['btn', 'btn--primary'], type: 'button' }, 'Copy token');
    const done = h('button', { class: 'btn', type: 'button' }, 'I have stored it');
    const status = h('p', { class: 'field__hint', role: 'status' });
    const dialog = h('dialog', { class: 'dialog', 'aria-labelledby': 'token-title' },
      h('div', { class: 'dialog__head' }, h('h2', { id: 'token-title' }, 'Enrollment token created')),
      h('div', { class: 'dialog__body' },
        banner('warn', 'This token will not be shown again',
          'Copy it now and hand it to the node operator over a channel you trust. Anyone holding an unused token can enroll a node until it expires. The hub keeps only a hash.'),
        h('pre', { class: ['code', 'token-value'], tabindex: '0', 'aria-label': 'Enrollment token' }, tokenText),
        kv([
          ['Token id', h('code', null, minted?.id ?? '—')],
          ['Expires', `${formatDateTime(normalizeExpiry(minted?.expires_at))} (${formatExpiresIn(minted?.expires_at)})`],
        ]),
        status),
      h('div', { class: 'dialog__foot' }, copy, done));
    copy.addEventListener('click', async () => {
      try {
        await navigator.clipboard.writeText(value);
        status.textContent = 'Copied to the clipboard.';
      } catch {
        status.textContent = 'The browser blocked clipboard access. Select the token and copy it manually.';
      }
    });
    done.addEventListener('click', () => dialog.close());
    dialog.addEventListener('close', () => {
      tokenText.data = '';
      value = '';
      dialog.remove();
      resolve();
    });
    document.body.appendChild(dialog);
    dialog.showModal();
  });
}

function createTokenDialog(ctx) {
  return openDialog({
    title: 'Create enrollment token',
    submitLabel: 'Create token',
    build: () => [
      h('p', null, 'A one-time token lets one new node enroll with this hub. It is consumed on first use and refused after it expires.'),
      selectField({ label: 'Valid for', name: 'ttl', value: String(TOKEN_TTL_DEFAULT), options: TTL_CHOICES.map(([v, t]) => [String(v), t]) }),
      inputField({ label: 'Note (optional)', name: 'note', maxlength: 256, hint: 'Plain ASCII, up to 256 characters, for example which host it is for. Never put secrets here: notes are listed to every admin.' }),
    ],
    onSubmit: async (form) => {
      const note = form.elements.note.value.trim();
      const problem = validateTokenNote(note);
      if (problem) throw new Error(problem);
      const ttl = Number(form.elements.ttl.value);
      return ctx.api.createEnrollmentToken({ ttl_seconds: ttl, ...(note ? { note } : {}) });
    },
  });
}

function tokensPanel(ctx, tokens) {
  const create = h('button', { class: ['btn', 'btn--primary'], type: 'button' }, 'Create enrollment token');
  create.addEventListener('click', async () => {
    let minted = await createTokenDialog(ctx);
    if (!minted) return;
    await showTokenOnce(minted);
    minted = null;
    ctx.rerender();
  });
  const del = (t) => {
    const b = h('button', { class: ['btn', 'btn--sm', 'btn--danger'], type: 'button', 'aria-label': `Delete token ${t.id}` }, 'Delete');
    b.addEventListener('click', async () => {
      const ok = await openDialog({
        title: 'Delete enrollment token?',
        submitLabel: 'Delete token', danger: true,
        build: () => h('p', null, 'The token stops working immediately. Nodes that already enrolled with it are not affected.'),
        onSubmit: () => ctx.api.deleteEnrollmentToken(t.id).then(() => true),
      });
      if (ok) { toast('ok', 'Token deleted.'); ctx.rerender(); }
    });
    return b;
  };
  return panel({
    title: 'Enrollment tokens', meta: 'Outstanding one-time tokens. The raw value is shown only once, when created.',
    actions: create, flush: true,
    body: tokens.length ? table({
      caption: 'Outstanding enrollment tokens',
      columns: [
        { label: 'Token id', cell: (t) => h('code', null, t.id) },
        { label: 'Note', className: 'col-summary', cell: (t) => t.note || h('span', { class: 'muted' }, 'no note') },
        { label: 'Expires', className: 'nowrap', cell: (t) => h('span', { class: 'stack-tight' }, formatExpiresIn(t.expires_at), h('span', { class: 'muted' }, formatDateTime(normalizeExpiry(t.expires_at)))) },
        { label: 'Action', cell: (t) => (isTokenId(t.id) ? del(t) : '—') },
      ],
      rows: tokens,
    }) : empty('No outstanding tokens', 'Create one when you are ready to enroll a node. Tokens expire after at most 24 hours.'),
  });
}

// ---- Screen ----------------------------------------------------------------

export default {
  title: 'Fleet',
  async render(root, ctx) {
    const f = await ctx.api.fleet({ signal: ctx.signal });
    const hubOn = Boolean(f?.hub?.enabled);
    const agentOn = Boolean(f?.agent?.enabled);
    const status = normalizeFleetStatus(ctx.route.query.status);
    const head = pageHead({ title: 'Fleet', eyebrow: h('span', { class: 'chip' }, 'Experimental'), subtitle: FLEET_SUBTITLE });

    if (!hubOn && !agentOn) {
      mount(root, head, teachingState());
      return;
    }

    let inventory = null;
    let tokensBlock = null;
    if (hubOn) {
      const [nodesRes, tokensRes] = await Promise.all([
        ctx.api.fleetNodes(status, { signal: ctx.signal }).catch((err) => ({ error: err })),
        ctx.can('admin') ? ctx.api.enrollmentTokens({ signal: ctx.signal }).catch((err) => ({ error: err })) : null,
      ]);
      const filter = segmented({
        label: 'Node status', value: status,
        options: [['', 'All'], ...FLEET_STATUSES.map((s) => [s, labelFor(s)])],
        onChange: (s) => ctx.navigate(href('fleet', { status: s })),
      });
      if (nodesRes.error) {
        inventory = panel({ title: 'Nodes', body: hubUnavailable(nodesRes.error, () => ctx.rerender()) });
      } else {
        const nodes = Array.isArray(nodesRes.nodes) ? nodesRes.nodes : [];
        inventory = panel({
          title: `${formatCount(nodes.length)} ${status ? labelFor(status).toLowerCase() : ''} nodes`.replace('  ', ' '),
          meta: 'Liveness is computed by the hub: stale after three missed heartbeats, offline after ten. Revoked is permanent.',
          actions: filter, flush: true,
          body: nodes.length ? nodesTable(nodes) : empty(status ? `No ${status} nodes` : 'No nodes enrolled yet',
            ctx.can('admin') ? 'Create an enrollment token below and give it to the operator of the node you want to add.' : 'An admin creates enrollment tokens for new nodes.'),
        });
      }
      if (tokensRes) {
        tokensBlock = tokensRes.error
          ? panel({ title: 'Enrollment tokens', body: hubUnavailable(tokensRes.error, () => ctx.rerender()) })
          : tokensPanel(ctx, Array.isArray(tokensRes.tokens) ? tokensRes.tokens : []);
      }
    } else {
      inventory = banner('info', 'This node is an agent, not a hub',
        'The node inventory lives on the hub this agent reports to. Open that hub’s console to see it.');
    }

    mount(root, head, rolePanel(f), inventory, tokensBlock);
  },
};

export function hubUnavailable(err, retry) {
  if (err instanceof ApiError && err.code === 'unavailable') {
    return h('div', { class: 'stack' },
      banner('warn', 'Hub unavailable', h('p', null, err.message || 'The fleet hub is disabled or stopped accepting writes.'),
        h('p', null, 'If a state write failed, the hub stays unavailable until it is restarted after inspection.')),
      h('button', { class: 'btn', type: 'button', on: { click: retry } }, 'Try again'));
  }
  return errorState(err, retry);
}

