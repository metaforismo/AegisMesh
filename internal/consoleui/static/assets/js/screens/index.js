// Screen registry: route name → screen descriptor.
//
// Screen modules load on first visit (or on nav hover/focus), so the entry
// graph stays small. Each descriptor carries what the shell needs before the
// module arrives: title, minimum role, skeleton shape, the drawer-aware view
// key, and a data prefetch for hover. Specifiers are string literals; the
// embed test checks each one resolves.

import { h, mount } from '../lib/dom.js';
import { normalizeWindow, normalizeEventFilters, normalizeStatus, normalizeSessionFilters } from '../lib/route.js';
import { normalizeDigestWindow } from '../lib/catalogs.js';
import { pageHead, panel, empty, link } from '../ui/components.js';

function lazy(title, loader, extra = {}) {
  let mod = null;
  const load = () => {
    mod ||= loader().then((m) => m.default, (err) => { mod = null; throw err; });
    return mod;
  };
  return Object.freeze({
    title, skeleton: 'detail', ...extra, load,
    async render(root, ctx) {
      return (await load()).render(root, ctx);
    },
  });
}

export const SCREENS = Object.freeze({
  overview: lazy('Overview', () => import('./overview.js'), {
    skeleton: 'overview',
    prefetch: (api, r) => { api.overview(normalizeWindow(r.query.window)); api.node(); },
  }),
  events: lazy('Events', () => import('./events.js'), {
    skeleton: 'table',
    // The drawer's `event` (and its origin, `event_node`) update the open
    // screen in place.
    viewIgnore: ['event', 'event_node'],
    prefetch: (api, r) => { api.events(normalizeEventFilters(r.query).filters, '', 50); api.sensors(); api.node(); },
  }),
  event: lazy('Event', () => import('./event.js')),
  sources: lazy('Sources', () => import('./sources.js'), {
    skeleton: 'table',
    prefetch: (api, r) => { api.sources(normalizeWindow(r.query.window), r.query.limit === '200' ? 200 : 50); },
  }),
  source: lazy('Source', () => import('./source.js')),
  sensors: lazy('Sensors', () => import('./sensors.js'), { skeleton: 'cards', prefetch: (api) => { api.sensors(); api.overview('24h'); api.node(); } }),
  rules: lazy('Rules', () => import('./rules.js'), { skeleton: 'table', prefetch: (api) => { api.rules(); } }),
  recommendations: lazy('Recommendations', () => import('./recommendations.js'), { skeleton: 'cards' }),
  node: lazy('Node', () => import('./node.js'), { prefetch: (api) => { api.node(); } }),
  investigations: lazy('Investigations', () => import('./investigations.js'), {
    skeleton: 'table',
    prefetch: (api, r) => { api.investigations(normalizeStatus(r.query.status)); },
  }),
  investigation: lazy('Investigation', () => import('./investigation.js')),
  // No prefetch: reading the audit trail is itself an audited action, so it
  // is only ever requested when the operator actually opens the page.
  audit: lazy('Audit trail', () => import('./audit.js'), { role: 'admin', skeleton: 'table' }),
  fleet: lazy('Fleet', () => import('./fleet.js'), { skeleton: 'table' }),
  fleet_node: lazy('Fleet node', () => import('./fleet-node.js')),
  // The guide's `t` (the term in focus) scrolls within the open screen.
  guide: lazy('Guide', () => import('./guide.js'), { viewIgnore: ['t'] }),
  sessions: lazy('Sessions', () => import('./sessions.js'), {
    skeleton: 'table',
    prefetch: (api, r) => { const f = normalizeSessionFilters(r.query); api.sessions(f.window, f.source || '', '', 50); },
  }),
  // The story keeps the event side panel's `event` (and `event_node`) in place.
  attack_session: lazy('Session', () => import('./session.js'), { viewIgnore: ['event', 'event_node'] }),
  techniques: lazy('Techniques', () => import('./techniques.js'), {
    skeleton: 'cards',
    viewIgnore: ['f'],
    prefetch: (api, r) => { api.coverage(normalizeWindow(r.query.window)); },
  }),
  decoys: lazy('Decoys', () => import('./decoys.js'), {
    skeleton: 'cards',
    prefetch: (api, r) => { api.decoys(normalizeWindow(r.query.window)); },
  }),
  // The honeytoken in focus (`t`) is marked within the open screen.
  honeytokens: lazy('Honeytokens', () => import('./honeytokens.js'), {
    skeleton: 'table',
    viewIgnore: ['t'],
    prefetch: (api, r) => { api.honeytokens(normalizeWindow(r.query.window)); api.decoys(normalizeWindow(r.query.window)); },
  }),
  digest: lazy('Digest', () => import('./digest.js'), {
    prefetch: (api, r) => { api.digest(normalizeDigestWindow(r.query.window)); },
  }),
});

export const notFoundScreen = {
  title: 'Not found',
  render(root) {
    mount(root,
      pageHead({ title: 'Page not found' }),
      panel({ body: empty('This address does not match a console page', 'The link may be mistyped, or it points at an id with an invalid format.', link('#/overview', 'Go to the overview'), { icon: 'search' }) }));
  },
};

export const forbiddenScreen = {
  title: 'Not permitted',
  render(root, ctx) {
    mount(root,
      pageHead({ title: 'Not permitted' }),
      panel({ body: empty('Your role cannot open this page', `You are signed in as ${ctx.role || 'unknown'}. The audit trail requires the admin role.`, h('a', { href: '#/overview' }, 'Go to the overview'), { icon: 'shield' }) }));
  },
};
