// Application frame: navigation, top bar, theme switch.

import { h } from '../lib/dom.js';
import { roleAtLeast, capitalize } from '../lib/taxonomy.js';
import { tenantInfo } from '../lib/tenant.js';
import { authMethodLabel } from '../lib/auth.js';
import { formatDateTime } from '../lib/format.js';
import { icon, brandMark } from './icons.js';

export { brandMark };

export const NAV = [
  { group: 'Observe', items: [
    { route: 'overview', label: 'Overview', href: '#/overview', icon: 'overview', keys: 'g o' },
    { route: 'events', label: 'Events', href: '#/events', also: ['event'], icon: 'events', keys: 'g e' },
    { route: 'sources', label: 'Sources', href: '#/sources', also: ['source'], icon: 'sources', keys: 'g s' },
  ] },
  { group: 'Investigate', items: [
    { route: 'investigations', label: 'Investigations', href: '#/investigations', also: ['investigation'], icon: 'investigations', keys: 'g i' },
    { route: 'recommendations', label: 'Recommendations', href: '#/recommendations', icon: 'recommendations', keys: 'g r' },
  ] },
  { group: 'System', items: [
    { route: 'sensors', label: 'Sensors', href: '#/sensors', icon: 'sensors', keys: 'g n' },
    { route: 'rules', label: 'Rules', href: '#/rules', icon: 'rules' },
    { route: 'node', label: 'Node', href: '#/node', icon: 'node' },
    { route: 'fleet', label: 'Fleet', href: '#/fleet', also: ['fleet_node'], icon: 'fleet', tag: 'Experimental' },
    { route: 'audit', label: 'Audit trail', href: '#/audit', role: 'admin', icon: 'audit', keys: 'g a' },
  ] },
];

export const isApple = () => /Mac|iPhone|iPad/.test(globalThis.navigator?.platform || globalThis.navigator?.userAgent || '');

// ---- Theme ---------------------------------------------------------------

const THEME_KEY = 'aegismesh.theme';
const THEMES = ['system', 'light', 'dark'];
const THEME_ICON = { system: 'monitor', light: 'sun', dark: 'moon' };

function readTheme() {
  try {
    const v = globalThis.localStorage?.getItem(THEME_KEY);
    return THEMES.includes(v) ? v : 'system';
  } catch {
    return 'system';
  }
}

export function applyTheme(theme = readTheme()) {
  const root = document.documentElement;
  if (theme === 'system') root.removeAttribute('data-theme');
  else root.setAttribute('data-theme', theme);
  return theme;
}

const themeListeners = new Set();

export function cycleTheme() {
  const next = THEMES[(THEMES.indexOf(readTheme()) + 1) % THEMES.length];
  try {
    globalThis.localStorage?.setItem(THEME_KEY, next);
  } catch {
    // Storage may be unavailable; the choice still applies to this page.
  }
  applyTheme(next);
  for (const fn of themeListeners) fn(next);
  return next;
}

function themeControl() {
  const btn = h('button', { class: ['btn', 'btn--ghost', 'btn--icon'], type: 'button' });
  const paint = (current) => {
    btn.replaceChildren(icon(THEME_ICON[current]));
    const label = `Color theme: ${capitalize(current)}. Activate to change.`;
    btn.setAttribute('aria-label', label);
    btn.setAttribute('title', `Theme: ${capitalize(current)}`);
  };
  btn.addEventListener('click', () => cycleTheme());
  themeListeners.add(paint);
  paint(readTheme());
  return btn;
}

// ---- Top-bar menus ------------------------------------------------------------

// Native popovers (light dismiss, Esc and the top layer come from the
// platform). They open many times a day, so they never animate. Placement is
// computed geometry, written through CSSOM under the button that opens them.
function anchoredMenu(menu, button, { focusOnOpen } = {}) {
  menu.addEventListener('beforetoggle', (e) => {
    if (e.newState !== 'open') return;
    const r = button.getBoundingClientRect();
    const vw = document.documentElement.clientWidth;
    menu.style.top = `${Math.round(r.bottom + 6)}px`;
    menu.style.right = `${Math.max(8, Math.round(vw - r.right))}px`;
  });
  menu.addEventListener('toggle', (e) => {
    const open = e.newState === 'open';
    button.setAttribute('aria-expanded', String(open));
    if (open) (focusOnOpen?.() || menu).focus();
  });
  button.setAttribute('aria-expanded', 'false');
  button.setAttribute('aria-controls', menu.id);
  return menu;
}

const hideMenu = (menu) => {
  try {
    menu.hidePopover?.();
  } catch {
    // Already closed.
  }
};

// The active tenant beside the principal. With several member tenants it
// opens a switcher; with one tenant named "default" nothing is drawn.
function tenantControl(session, onSwitchTenant) {
  const info = tenantInfo(session);
  if (!info.show) return null;
  if (!info.canSwitch) {
    return h('span', { class: ['top-tenant', 'top-tenant--static'], title: `Tenant: ${info.active}` },
      icon('tenant', { size: 'sm' }),
      h('span', { class: 'visually-hidden' }, 'Tenant: '),
      h('span', { class: 'top-tenant__name' }, info.active));
  }
  const button = h('button', { class: ['btn', 'btn--ghost', 'top-tenant'], type: 'button', popovertarget: 'tenant-menu', title: `Tenant: ${info.active}` },
    icon('tenant', { size: 'sm' }),
    h('span', { class: 'visually-hidden' }, 'Tenant: '),
    h('span', { class: 'top-tenant__name' }, info.active),
    h('span', { class: 'visually-hidden' }, '. Switch tenant'),
    icon('chevron-down', { size: 'xs' }));
  const items = info.tenants.map((t) => {
    const current = t === info.active;
    const item = h('button', { class: 'menu__item', type: 'button', 'aria-current': current ? 'true' : null, 'data-tenant': t },
      h('span', { class: 'menu__check', 'aria-hidden': 'true' }, current ? icon('check', { size: 'sm' }) : null),
      h('span', { class: 'menu__label' }, t),
      current ? h('span', { class: 'menu__hint' }, 'Current') : null);
    item.addEventListener('click', () => {
      hideMenu(menu);
      if (!current) onSwitchTenant?.(t);
    });
    return h('li', null, item);
  });
  const menu = h('div', { class: 'menu', id: 'tenant-menu', popover: 'auto', tabindex: '-1', 'aria-labelledby': 'tenant-menu-title' },
    h('p', { class: 'menu__title', id: 'tenant-menu-title' }, 'Switch tenant'),
    h('ul', { class: 'menu__list' }, items),
    h('p', { class: 'menu__note' }, 'This session acts in one tenant at a time. Switching reloads the current view and closes live streams. Isolation between tenants is logical: one process, one disk.'));
  anchoredMenu(menu, button, { focusOnOpen: () => menu.querySelector('.menu__item[aria-current="true"]') });
  return [button, menu];
}

// The principal's button and its account menu: identity, how the session
// signed in, the active tenant, when it expires, and sign out.
function accountControl(session, meta, onLogout) {
  const p = session?.principal || {};
  const role = p.role || 'unknown';
  const info = tenantInfo(session);
  const name = p.name || 'unknown';
  const button = h('button', { class: ['btn', 'btn--ghost', 'top-user'], type: 'button', popovertarget: 'account-menu', 'aria-label': `Account: ${name}, ${capitalize(role)}` },
    h('span', { class: 'top-user__avatar', 'aria-hidden': 'true' }, String(name).slice(0, 1).toUpperCase()),
    h('span', { class: 'top-user__name', 'aria-hidden': 'true' }, name),
    h('span', { class: 'chip', 'aria-hidden': 'true' }, capitalize(role)));
  const signOut = h('button', { class: ['btn', 'btn--block', 'menu__action'], type: 'button' }, icon('sign-out'), 'Sign out');
  signOut.addEventListener('click', () => { hideMenu(menu); onLogout?.(); });
  const rows = [
    ['Signed in with', authMethodLabel(p.auth_method || 'token', meta)],
    info.show ? ['Tenant', info.active] : null,
    session?.expires_at ? ['Session expires', formatDateTime(session.expires_at)] : null,
  ].filter(Boolean);
  const menu = h('div', { class: 'menu', id: 'account-menu', popover: 'auto', tabindex: '-1', 'aria-labelledby': 'account-menu-title' },
    h('div', { class: 'menu__head' },
      h('span', { class: 'top-user__avatar', 'aria-hidden': 'true' }, String(name).slice(0, 1).toUpperCase()),
      h('div', null,
        h('p', { class: 'menu__name', id: 'account-menu-title' }, name),
        h('p', { class: 'menu__sub' }, capitalize(role)))),
    h('dl', { class: 'menu__kv' }, rows.map(([k, v]) => [h('dt', null, k), h('dd', null, v)])),
    signOut);
  anchoredMenu(menu, button);
  return [button, menu];
}

// ---- Shell -----------------------------------------------------------------

export function createShell({ session, meta, onLogout, onSearch, onSwitchTenant }) {
  const role = session?.principal?.role;
  const links = new Map();
  const indicators = [];

  const groups = NAV.map((g) => {
    const items = g.items.filter((i) => !i.role || roleAtLeast(role, i.role));
    if (!items.length) return null;
    const indicator = h('span', { class: 'nav-indicator', 'aria-hidden': 'true' });
    const list = h('ul', { class: 'nav-list' }, indicator, items.map((i) => {
      const a = h('a', { class: 'nav-link', href: i.href, 'data-route': i.route },
        icon(i.icon),
        h('span', { class: 'nav-link__label' }, i.label),
        i.tag ? h('span', { class: 'nav-link__tag' }, i.tag) : null);
      links.set(i.route, { a, indicator });
      for (const alt of i.also || []) links.set(alt, { a, indicator });
      return h('li', null, a);
    }));
    indicators.push(indicator);
    return h('div', { class: 'nav-group' }, h('p', { class: 'nav-group__label' }, g.group), list);
  });

  const nav = h('nav', { class: 'shell__nav', id: 'primary-nav', 'aria-label': 'Primary' },
    h('a', { class: 'brand', href: '#/overview' }, brandMark(), 'AegisMesh'),
    groups,
    h('div', { class: 'nav-foot' },
      h('p', { class: 'muted' }, 'Times in UTC'),
      h('p', { class: 'muted' }, `Version ${meta?.version || 'unknown'}`),
      h('a', { href: 'https://github.com/metaforismo/AegisMesh/blob/master/docs/architecture/console-api.md' }, 'API contract')));

  const scrim = h('div', { class: 'nav-scrim', 'aria-hidden': 'true' });
  const toggle = h('button', {
    class: ['btn', 'btn--ghost', 'btn--icon', 'nav-toggle'], type: 'button', 'aria-controls': 'primary-nav', 'aria-expanded': 'false', 'aria-label': 'Menu',
  }, icon('menu'));
  const setOpen = (open) => {
    nav.classList.toggle('is-open', open);
    scrim.classList.toggle('is-open', open);
    toggle.setAttribute('aria-expanded', String(open));
    if (open) nav.querySelector('a[aria-current="page"], a')?.focus();
  };
  toggle.addEventListener('click', () => setOpen(!nav.classList.contains('is-open')));
  scrim.addEventListener('click', () => setOpen(false));
  nav.addEventListener('click', (e) => { if (e.target.closest?.('a')) setOpen(false); });
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && nav.classList.contains('is-open')) {
      setOpen(false);
      toggle.focus();
    }
  });

  const searchKey = isApple() ? '⌘K' : 'Ctrl K';
  const search = h('button', { class: ['btn', 'top-search'], type: 'button', 'aria-keyshortcuts': isApple() ? 'Meta+K' : 'Control+K' },
    icon('search'),
    h('span', { class: 'top-search__label' }, 'Search or jump to…'),
    h('kbd', { class: 'top-search__kbd' }, searchKey));
  search.addEventListener('click', () => onSearch?.());

  const liveSlot = h('div', { class: 'top-live', 'aria-live': 'polite' });
  const top = h('header', { class: 'shell__top' },
    toggle,
    search,
    h('div', { class: 'top-spacer' }),
    liveSlot,
    themeControl(),
    tenantControl(session, onSwitchTenant),
    accountControl(session, meta, onLogout));

  const main = h('main', { class: 'shell__main', id: 'main' });
  const root = h('div', { class: 'shell' },
    h('a', { class: 'skip-link', href: '#/skip' }, 'Skip to content'),
    nav, scrim, top, main);
  // The skip link is a hash URL (CSP-friendly) intercepted here.
  root.firstChild.addEventListener('click', (e) => {
    e.preventDefault();
    main.querySelector('#page-title')?.focus();
  });

  let placed = false;
  return {
    root, main, liveSlot, nav,
    setActive(routeName) {
      // A route change (palette, g-sequence, back) closes the top-bar menus.
      for (const m of root.querySelectorAll('.menu')) hideMenu(m);
      for (const { a } of links.values()) a.removeAttribute('aria-current');
      const hit = links.get(routeName);
      hit?.a.setAttribute('aria-current', 'page');
      // One read (offsetTop), then writes: the indicator slides to the link.
      const top = hit ? hit.a.parentElement.offsetTop : 0;
      for (const ind of indicators) {
        const mine = hit?.indicator === ind;
        const wasShown = ind.classList.contains('is-shown');
        // Entering a group (or the first paint) places without sliding.
        ind.classList.toggle('is-placing', !placed || (mine && !wasShown));
        if (mine) ind.style.transform = `translateY(${top}px)`;
        ind.classList.toggle('is-shown', mine);
      }
      requestAnimationFrame(() => { for (const ind of indicators) ind.classList.remove('is-placing'); });
      placed = true;
    },
  };
}
