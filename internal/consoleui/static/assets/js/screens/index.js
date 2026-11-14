// Screen registry: route name → screen module.

import { h, clear, mount } from '../lib/dom.js';
import { pageHead, panel, empty, link } from '../ui/components.js';
import overview from './overview.js';
import events from './events.js';
import event from './event.js';
import sources from './sources.js';
import source from './source.js';
import sensors from './sensors.js';
import rules from './rules.js';
import recommendations from './recommendations.js';
import node from './node.js';
import investigations from './investigations.js';
import investigation from './investigation.js';
import audit from './audit.js';

export const SCREENS = Object.freeze({
  overview, events, event, sources, source, sensors, rules, recommendations, node, investigations, investigation, audit,
});

export const notFoundScreen = {
  title: 'Not found',
  render(root) {
    mount(root,
      pageHead({ title: 'Page not found' }),
      panel({ body: empty('This address does not match a console page', 'The link may be mistyped, or it points at an id with an invalid format.', link('#/overview', 'Go to the overview')) }));
  },
};

export const forbiddenScreen = {
  title: 'Not permitted',
  render(root, ctx) {
    mount(root,
      pageHead({ title: 'Not permitted' }),
      panel({ body: empty('Your role cannot open this page', `You are signed in as ${ctx.role || 'unknown'}. The audit trail requires the admin role.`, h('a', { href: '#/overview' }, 'Go to the overview')) }));
  },
};
