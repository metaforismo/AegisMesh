// Application frame: navigation, top bar, theme switch.

import { h } from '../lib/dom.js';
import { roleAtLeast, capitalize } from '../lib/taxonomy.js';
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

// ---- Shell -----------------------------------------------------------------

export function createShell({ session, meta, onLogout, onSearch }) {
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
  const logout = h('button', { class: ['btn', 'btn--ghost', 'btn--icon'], type: 'button', 'aria-label': 'Sign out', title: 'Sign out', on: { click: onLogout } }, icon('sign-out'));
  const top = h('header', { class: 'shell__top' },
    toggle,
    search,
    h('div', { class: 'top-spacer' }),
    liveSlot,
    themeControl(),
    h('span', { class: 'top-user' },
      h('span', { class: 'top-user__avatar', 'aria-hidden': 'true' }, String(session?.principal?.name || '?').slice(0, 1).toUpperCase()),
      h('span', { class: 'top-user__name' }, session?.principal?.name || 'unknown'),
      h('span', { class: 'chip' }, capitalize(role || 'unknown'))),
    logout);

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
