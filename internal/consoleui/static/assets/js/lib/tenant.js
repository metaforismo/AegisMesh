// Tenant awareness (console API contract, "OIDC and tenant contract").
//
// A session acts in exactly one tenant. Its membership is fixed at sign-in;
// `POST /session/tenant` moves the session to another member tenant and
// rotates both the session cookie and the CSRF token. There is no
// cross-tenant view: another tenant's objects answer 404 exactly like absent
// ones. Isolation is logical (one process, one disk, one encryption
// recipient), not a hard multi-tenant boundary.

import { withQuery } from './route.js';

const DEFAULT_TENANT = 'default';
const MAX_TENANTS = 32; // the contract's declared-tenant ceiling

function tenantName(value) {
  return typeof value === 'string' && value.length > 0 && value.length <= 128 ? value : '';
}

// What the shell shows for a session.
//   active     the tenant this session acts in ('' when the server sent none)
//   tenants    member tenants, in the server's order, deduplicated
//   show       draw tenant UI at all: more than one tenant, or a single
//              tenant with a name other than "default"
//   canSwitch  offer the switcher (menu and palette actions)
export function tenantInfo(session) {
  const active = tenantName(session?.tenant) || tenantName(session?.principal?.tenant);
  const raw = Array.isArray(session?.tenants) ? session.tenants : Array.isArray(session?.principal?.tenants) ? session.principal.tenants : [];
  const tenants = [];
  for (const t of raw) {
    const name = tenantName(t);
    if (name && !tenants.includes(name)) tenants.push(name);
    if (tenants.length >= MAX_TENANTS) break;
  }
  if (active && !tenants.includes(active)) tenants.unshift(active);
  const canSwitch = tenants.length > 1;
  const show = canSwitch || (Boolean(active) && active !== DEFAULT_TENANT);
  return { active, tenants, show, canSwitch };
}

// Tenants the session could switch to (every member except the active one).
export function switchTargets(session) {
  const info = tenantInfo(session);
  return info.canSwitch ? info.tenants.filter((t) => t !== info.active) : [];
}

// Routes that name one object. Ids and source keys belong to the tenant they
// came from; in another tenant they answer 404, so the switch lands on the
// overview instead of on a guaranteed "not found".
const OBJECT_ROUTES = new Set(['event', 'investigation', 'fleet_node', 'source']);
// Query keys on a list that point at an object or a fleet node of the
// departing tenant: the events side panel and the origin filter.
const OBJECT_QUERY_KEYS = { events: ['event', 'event_node', 'node'] };

// Where the console should be after a switch, given the route it is on.
//   hash    the address to show (replaces the current entry)
//   moved   true when it differs from where the operator was
//   reason  'object' (left an object page for the overview), 'cleared'
//           (dropped a side panel or origin filter), or ''
export function routeAfterSwitch(route, currentHash) {
  const name = route?.name || '';
  if (OBJECT_ROUTES.has(name)) return { hash: '#/overview', moved: true, reason: 'object' };
  const drop = (OBJECT_QUERY_KEYS[name] || []).filter((k) => Object.hasOwn(route?.query || {}, k));
  if (drop.length) {
    const hash = withQuery(route, Object.fromEntries(drop.map((k) => [k, null])));
    return { hash, moved: hash !== currentHash, reason: 'cleared' };
  }
  return { hash: currentHash || '#/overview', moved: false, reason: '' };
}

// The request body for a switch, or null when `target` is not a member
// tenant (only names the server itself listed are ever sent).
export function switchBody(session, target) {
  const info = tenantInfo(session);
  if (!info.canSwitch || target === info.active || !info.tenants.includes(target)) return null;
  return { tenant: target };
}
