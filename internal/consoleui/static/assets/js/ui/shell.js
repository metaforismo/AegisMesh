// Application frame: navigation, top bar, theme switch.

import { h, svg } from '../lib/dom.js';
import { roleAtLeast, capitalize } from '../lib/taxonomy.js';

export const NAV = [
  { group: 'Observe', items: [
    { route: 'overview', label: 'Overview', href: '#/overview' },
    { route: 'events', label: 'Events', href: '#/events', also: ['event'] },
    { route: 'sources', label: 'Sources', href: '#/sources', also: ['source'] },
  ] },
  { group: 'Investigate', items: [
    { route: 'investigations', label: 'Investigations', href: '#/investigations', also: ['investigation'] },
    { route: 'recommendations', label: 'Recommendations', href: '#/recommendations' },
  ] },
  { group: 'System', items: [
    { route: 'sensors', label: 'Sensors', href: '#/sensors' },
    { route: 'rules', label: 'Rules', href: '#/rules' },
    { route: 'node', label: 'Node', href: '#/node' },
    { route: 'audit', label: 'Audit trail', href: '#/audit', role: 'admin' },
  ] },
];

export function brandMark() {
  // A shield split by a mesh line: drawn, not fetched.
  return svg('svg', { class: 'brand__mark', viewBox: '0 0 24 24', 'aria-hidden': 'true', focusable: 'false' },
    svg('path', { d: 'M12 2.5 4 5.5v6.2c0 4.6 3.3 8.6 8 9.8 4.7-1.2 8-5.2 8-9.8V5.5z', class: 'brand__shield' }),
    svg('path', { d: 'M7.5 9.5 12 13l4.5-3.5M12 13v5', class: 'brand__mesh' }));
}

// ---- Theme ---------------------------------------------------------------

const THEME_KEY = 'aegismesh.theme';
const THEMES = ['system', 'light', 'dark'];

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

function themeControl() {
  let current = readTheme();
  const btn = h('button', { class: ['btn', 'btn--ghost', 'btn--sm'], type: 'button' });
  const paint = () => {
    btn.textContent = `Theme: ${capitalize(current)}`;
    btn.setAttribute('aria-label', `Color theme: ${current}. Activate to change.`);
  };
  btn.addEventListener('click', () => {
    current = THEMES[(THEMES.indexOf(current) + 1) % THEMES.length];
    try {
      globalThis.localStorage?.setItem(THEME_KEY, current);
    } catch {
      // Storage may be unavailable; the choice still applies to this page.
    }
    applyTheme(current);
    paint();
  });
  paint();
  return btn;
}

// ---- Shell -----------------------------------------------------------------

export function createShell({ session, meta, onLogout }) {
  const role = session?.principal?.role;
  const links = new Map();
  const nav = h('nav', { class: 'shell__nav', id: 'primary-nav', 'aria-label': 'Primary' },
    h('a', { class: 'brand', href: '#/overview' }, brandMark(), 'AegisMesh'),
    NAV.map((g) => {
      const items = g.items.filter((i) => !i.role || roleAtLeast(role, i.role));
      if (!items.length) return null;
      return h('div', { class: 'nav-group' },
        h('p', { class: 'nav-group__label' }, g.group),
        h('ul', { class: 'nav-list' }, items.map((i) => {
          const a = h('a', { class: 'nav-link', href: i.href }, i.label);
          links.set(i.route, a);
          for (const alt of i.also || []) links.set(alt, a);
          return h('li', null, a);
        })));
    }),
    h('div', { class: 'nav-foot' },
      h('p', { class: 'muted' }, `Version ${meta?.version || 'unknown'}`),
      h('a', { href: 'https://github.com/metaforismo/AegisMesh/blob/master/docs/architecture/console-api.md' }, 'API contract')));

  const toggle = h('button', {
    class: ['btn', 'btn--ghost', 'nav-toggle'], type: 'button', 'aria-controls': 'primary-nav', 'aria-expanded': 'false',
  }, 'Menu');
  const setOpen = (open) => {
    nav.classList.toggle('is-open', open);
    toggle.setAttribute('aria-expanded', String(open));
  };
  toggle.addEventListener('click', () => setOpen(!nav.classList.contains('is-open')));
  nav.addEventListener('click', (e) => { if (e.target.closest?.('a')) setOpen(false); });
  document.addEventListener('keydown', (e) => { if (e.key === 'Escape') setOpen(false); });

  const liveSlot = h('div', { class: 'top-live', 'aria-live': 'polite' });
  const logout = h('button', { class: ['btn', 'btn--sm'], type: 'button', on: { click: onLogout } }, 'Sign out');
  const top = h('header', { class: 'shell__top' },
    toggle,
    h('p', { class: 'top-note' }, 'Read-only view of observed evidence · times in UTC'),
    h('div', { class: 'top-spacer' }),
    liveSlot,
    themeControl(),
    h('span', { class: 'top-user' },
      h('span', { class: 'top-user__name' }, session?.principal?.name || 'unknown'),
      h('span', { class: 'chip' }, capitalize(role || 'unknown'))),
    logout);

  const main = h('main', { class: 'shell__main', id: 'main' });
  const root = h('div', { class: 'shell' },
    h('a', { class: 'skip-link', href: '#/skip' }, 'Skip to content'),
    nav, top, main);
  // The skip link is a hash URL (CSP-friendly) intercepted here.
  root.firstChild.addEventListener('click', (e) => {
    e.preventDefault();
    main.querySelector('#page-title')?.focus();
  });

  return {
    root, main, liveSlot,
    setActive(routeName) {
      for (const a of links.values()) a.removeAttribute('aria-current');
      links.get(routeName)?.setAttribute('aria-current', 'page');
    },
  };
}
