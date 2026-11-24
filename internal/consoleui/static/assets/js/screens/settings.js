// Settings: your account (profile, preferences, sessions, API keys) and, for
// admins, administration (accounts, sessions, the server's effective
// settings, audit export, system). One layout: a sub-navigation on the left
// on desktop; on phones the index is the list and each section its own page.
//
// Showing or hiding administration is a convenience. The server decides
// every request; a 403 or an older server's 404 is answered in place, and a
// 401 ends the session through the API client like everywhere else.

import { h, mount } from '../lib/dom.js';
import { ApiError } from '../lib/api.js';
import { isMissingEndpoint } from '../lib/insight.js';
import { ACCOUNT_SECTIONS, isAdminSection, sectionMeta, visibleSections } from '../lib/settings.js';
import { pageHead } from '../ui/components.js';
import { icon } from '../ui/icons.js';
import { olderServerState, notPermittedState } from '../ui/settings-kit.js';
import { SECTION_PERMS, principalRoleName } from '../lib/perms.js';

function navList(title, items, current, { index }) {
  return h('div', { class: 'settings-nav__group' },
    h('p', { class: 'settings-nav__label', id: `snav-${title.toLowerCase().replace(/\W+/g, '-')}` }, title),
    h('ul', { class: 'settings-nav__list', 'aria-labelledby': `snav-${title.toLowerCase().replace(/\W+/g, '-')}` }, items.map((s) => h('li', null,
      h('a', { class: 'settings-nav__link', href: `#/settings/${s.id}`, 'aria-current': s.id === current ? 'page' : null },
        icon(s.icon),
        h('span', { class: 'settings-nav__text' },
          h('span', { class: 'settings-nav__name' }, s.label),
          h('span', { class: 'settings-nav__hint' }, s.hint)),
        icon('chevron-right', { size: 'sm', className: 'settings-nav__go' }))))));
}

export default {
  title: 'Settings',
  async render(root, ctx) {
    const route = ctx.route;
    const accountId = route.name === 'settings_account' ? route.params.id : '';
    const roleId = route.name === 'settings_role' ? route.params.id : '';
    const requested = accountId ? 'accounts' : roleId ? 'roles' : (route.params.section || '');
    const index = !requested;
    const shown = requested || 'profile';
    const role = ctx.session?.principal?.role || '';

    // Who is signed in, and what the server lets them do.
    let me = null;
    let meMissing = false;
    let meError = null;
    try {
      me = await ctx.api.me({ signal: ctx.signal });
    } catch (err) {
      if (err?.name === 'AbortError' || (err instanceof ApiError && err.status === 401)) throw err;
      if (isMissingEndpoint(err)) meMissing = true;
      else meError = err;
    }
    // Pages appear by permission (round 6) or, on an older server, by the
    // built-in role's fixed set; both come from ctx.can.
    // A server without /me (older than accounts) offers no administration.
    const vis = meMissing ? visibleSections(null) : visibleSections(me, ctx.can);
    const meta = sectionMeta(shown);
    const cleanups = [];
    const roleName = principalRoleName(role, me?.role_name);
    const view = { ctx, me, meMissing, meError, role, roleName, accountId, roleId, cleanups, index };

    let body;
    if (isAdminSection(shown)) {
      const needs = SECTION_PERMS[shown] || '';
      if (meMissing) body = olderServerState();
      else if (needs && !ctx.can(needs)) body = notPermittedState(roleName, `${meta.label.toLowerCase()}`, needs);
      else body = await (await import('./settings-admin.js')).default.render(shown, view);
    } else {
      body = await (await import('./settings-account.js')).default.render(shown, view);
    }
    if (ctx.signal?.aborted) {
      for (const fn of cleanups) fn();
      return null;
    }

    const nav = h('nav', { class: 'settings__nav', 'aria-label': 'Settings' },
      navList('Your account', vis.account, shown, { index }),
      vis.admin.length ? navList('Administration', vis.admin, shown, { index }) : null,
      meMissing ? h('p', { class: 'settings-nav__note' }, 'Administration appears here when the server provides it.') : null);

    const group = ACCOUNT_SECTIONS.some((s) => s.id === shown) ? 'Your account' : 'Administration';
    const detailName = view.detailName || '';
    const head = index
      ? pageHead({ title: 'Settings', subtitle: vis.admin.length ? 'Your account, and the server’s access and configuration.' : 'Your account: profile, preferences, sessions and API keys.', hint: 'Choose a section. Changes to your preferences apply at once.' })
      : pageHead({
        title: detailName || meta.label,
        crumbs: [['Settings', '#/settings'], [group, null], detailName ? [meta.label, `#/settings/${shown}`] : null, [detailName || meta.label]],
        subtitle: view.subtitle || meta.hint,
        hint: view.hint || null,
      });
    if (!index) ctx.setTitle?.(detailName || meta.label);

    mount(root, head,
      h('div', { class: ['settings', index ? 'settings--index' : 'settings--detail'] },
        nav,
        h('div', { class: 'settings__detail' }, body)));
    return { cleanup: () => { for (const fn of cleanups) fn(); } };
  },
};
