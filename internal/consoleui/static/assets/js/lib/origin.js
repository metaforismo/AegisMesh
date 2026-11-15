// Where an observation came from (console API, experimental forwarded
// evidence additions).
//
// An event without `node` was observed and stored on this node. An event with
// `node: {id, name}` is a best-effort copy that an enrolled node forwarded to
// this hub: the id is the origin the hub authenticated, the name comes from
// the hub's current registry. The forwarding node's own store stays the
// authoritative record. Event ids are unique only within one origin, so the
// console keys rows and links by id plus origin.

export const LOCAL = 'local';
const NODE_ID = /^[0-9a-f]{32}$/;

export const isNodeId = (v) => typeof v === 'string' && NODE_ID.test(v);

// The `node` filter accepts exactly what the contract accepts: "local" or a
// 32-character lowercase hex node id. Anything else is not a filter.
export const isNodeFilter = (v) => v === LOCAL || isNodeId(v);

export function normalizeNodeFilter(value) {
  const v = typeof value === 'string' ? value.trim() : '';
  return isNodeFilter(v) ? v : '';
}

// Origin of one event summary: its node id, or "local" when absent.
export function originOf(ev) {
  const id = ev?.node && typeof ev.node === 'object' ? ev.node.id : undefined;
  return typeof id === 'string' && id !== '' && id !== LOCAL ? id : LOCAL;
}

export const isForwarded = (ev) => originOf(ev) !== LOCAL;

// Browser-side twin of the server's node filter, for the live stream.
export function matchesNodeFilter(ev, filter) {
  return !filter || originOf(ev) === filter;
}

export function shortNodeId(id) {
  return isNodeId(id) ? id.slice(0, 8) : '';
}

// Display parts for an origin. `node` is an EventSummary.node, a by_node
// row, or a FleetNode; null, absent or id "local" mean this node.
export function describeOrigin(node) {
  const id = node && typeof node === 'object' && typeof node.id === 'string' ? node.id : '';
  if (!id || id === LOCAL) return { local: true, id: LOCAL, linkable: false, name: 'This node', named: true, short: '', text: 'This node' };
  const name = typeof node.name === 'string' ? node.name.trim() : '';
  const short = shortNodeId(id);
  const label = name || 'Unnamed node';
  return { local: false, id, linkable: isNodeId(id), name: label, named: Boolean(name), short, text: short ? `${label} (${short})` : label };
}

// Origin is worth a column only on a hub that accepts forwarded evidence, or
// when the data itself says some rows came from elsewhere. A single node
// that never receives evidence keeps its tables as they were.
export function originVisible({ fleet = null, events = [], filter = '' } = {}) {
  if (fleet?.hub?.accept_evidence === true) return true;
  if (filter) return true;
  return (Array.isArray(events) ? events : []).some((ev) => isForwarded(ev));
}

// Overview `by_node` arrives sorted by id. Ranked by events (ties by id) for
// the bar list; malformed rows are dropped rather than guessed at.
export function rankByNode(list) {
  const rows = [];
  for (const r of Array.isArray(list) ? list : []) {
    if (!r || typeof r !== 'object' || !isNodeFilter(r.id)) continue;
    const events = Number(r.events);
    rows.push({ id: r.id, name: typeof r.name === 'string' ? r.name : '', events: Number.isFinite(events) && events > 0 ? events : 0 });
  }
  return rows.sort((a, b) => b.events - a.events || (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
}

// Row identity for tables and the side panel.
export function eventKey(ev) {
  const id = String(ev?.id ?? '');
  const origin = originOf(ev);
  return origin === LOCAL ? id : `${id}@${origin}`;
}

export function parseEventKey(key) {
  const s = String(key ?? '');
  const at = s.indexOf('@');
  if (at < 0) return { id: s, node: '' };
  const node = s.slice(at + 1);
  return { id: s.slice(0, at), node: isNodeId(node) ? node : '' };
}

// Query that pins an event detail request to its origin. Local events send
// nothing: the server prefers a local observation when no node is given.
export function originQuery(ev) {
  const origin = originOf(ev);
  return isNodeId(origin) ? { node: origin } : {};
}

// Options for the Node filter: any, this node, then every enrolled node by
// name. A filter value that is not in the list (a node that left the
// registry, a pasted link) stays selectable rather than silently dropped.
export function nodeFilterOptions(nodes, current = '') {
  const list = (Array.isArray(nodes) ? nodes : [])
    .filter((n) => isNodeId(n?.id))
    .map((n) => {
      const o = describeOrigin(n);
      return [n.id, o.text];
    })
    .sort((a, b) => a[1].localeCompare(b[1]) || (a[0] < b[0] ? -1 : 1));
  const out = [['', 'Any node'], [LOCAL, 'This node'], ...list];
  if (current && !out.some(([v]) => v === current) && isNodeId(current)) out.push([current, `Node ${shortNodeId(current)} (not in the registry)`]);
  return out;
}

// Palette targets for the Node filter, only on a hub that accepts evidence:
// "This node" plus one entry per enrolled node, searchable by name or id.
export function nodeFilterTargets(fleet, nodes) {
  if (fleet?.hub?.accept_evidence !== true) return [];
  const out = [{ node: LOCAL, label: 'This node', hint: 'Events observed here', keywords: ['local', 'origin'] }];
  for (const n of Array.isArray(nodes) ? nodes : []) {
    if (!isNodeId(n?.id)) continue;
    const o = describeOrigin(n);
    out.push({ node: n.id, label: o.name, hint: `Node ${o.short} · events`, keywords: [n.id, 'node', 'origin'] });
  }
  return out;
}
