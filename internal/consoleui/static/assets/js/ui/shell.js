// Application frame: navigation, top bar, theme switch.

import { h, mount } from '../lib/dom.js';
import { capitalize } from '../lib/taxonomy.js';
import { toCan, ROUTE_PERMS, principalRoleName } from '../lib/perms.js';
import { tenantInfo } from '../lib/tenant.js';
import { authMethodLabel } from '../lib/auth.js';
import { formatDateTime, setTimeZone, zoneName } from '../lib/format.js';
import { setDefaultWindow } from '../lib/route.js';
import { icon, brandMark } from './icons.js';
import { parseDensity, nextDensity } from '../lib/viz.js';

export { brandMark };

// Navigation is data: a screen appears here and in the palette by adding an
// item (and a route in lib/route.js plus a descriptor in screens/index.js).
// A screen whose permission (lib/perms.js ROUTE_PERMS) the principal lacks
// is left out of the sidebar, the palette and the shortcut sheet.
// Screens for new API endpoints slot into the group they belong to; nothing
// is listed before it exists.
export const NAV = [
  { group: 'Observe', items: [
    { route: 'overview', label: 'Overview', href: '#/overview', icon: 'overview', keys: 'g o' },
    { route: 'digest', label: 'Digest', href: '#/digest', icon: 'digest', keys: 'g b' },
    { route: 'events', label: 'Events', href: '#/events', also: ['event'], icon: 'events', keys: 'g e' },
    { route: 'sources', label: 'Sources', href: '#/sources', also: ['source'], icon: 'sources', keys: 'g s' },
  ] },
  { group: 'Understand', items: [
    { route: 'sessions', label: 'Sessions', href: '#/sessions', also: ['attack_session'], icon: 'story', keys: 'g c' },
    { route: 'campaigns', label: 'Campaigns', href: '#/campaigns', also: ['campaign'], icon: 'campaign', keys: 'g m' },
    { route: 'techniques', label: 'Techniques', href: '#/techniques', icon: 'matrix', keys: 'g t' },
    { route: 'investigations', label: 'Investigations', href: '#/investigations', also: ['investigation'], icon: 'investigations', keys: 'g i' },
    { route: 'recommendations', label: 'Recommendations', href: '#/recommendations', icon: 'recommendations', keys: 'g r' },
  ] },
  { group: 'Deception', items: [
    { route: 'decoys', label: 'Decoys', href: '#/decoys', icon: 'decoy', keys: 'g d' },
    { route: 'honeytokens', label: 'Honeytokens', href: '#/honeytokens', icon: 'key', keys: 'g k' },
    { route: 'sensors', label: 'Sensors', href: '#/sensors', icon: 'sensors', keys: 'g n' },
    { route: 'rules', label: 'Rules', href: '#/rules', icon: 'rules', keys: 'g u' },
  ] },
  { group: 'Operate', items: [
    { route: 'posture', label: 'Posture', href: '#/posture', icon: 'posture', keys: 'g p' },
    { route: 'node', label: 'Node', href: '#/node', icon: 'node' },
    { route: 'fleet', label: 'Fleet', href: '#/fleet', also: ['fleet_node'], icon: 'fleet', tag: 'Experimental' },
    { route: 'audit', label: 'Audit trail', href: '#/audit', icon: 'audit', keys: 'g a' },
    { route: 'settings', label: 'Settings', href: '#/settings', also: ['settings_account', 'settings_role'], icon: 'settings', keys: 'g ,' },
  ] },
  { group: 'Help', items: [
    { route: 'guide', label: 'Guide', href: '#/guide', icon: 'guide', keys: 'g h' },
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
const densityListeners = new Set();
const zoneListeners = new Set();

// Preferences (lib/prefs.js) own the theme, density, time zone, default
// window and motion. The top-bar controls hand a change to the store through
// this sink; the store applies it everywhere through applyPreferences().
let prefsSink = null;
let currentPrefs = { theme: readTheme(), density: 'comfortable', timezone: 'utc', default_window: '24h', reduce_motion: 'system' };
export function setPrefsSink(fn) {
  prefsSink = typeof fn === 'function' ? fn : null;
}

function changePref(patch) {
  if (prefsSink) return prefsSink(patch);
  applyPreferences({ ...currentPrefs, ...patch });
  return null;
}

// Apply a complete, parsed preferences object to the page.
export function applyPreferences(p) {
  currentPrefs = { ...currentPrefs, ...p };
  applyTheme(THEMES.includes(p.theme) ? p.theme : 'system');
  applyDensity(p.density);
  document.documentElement.toggleAttribute('data-reduce-motion', p.reduce_motion === 'on');
  setTimeZone(p.timezone);
  setDefaultWindow(p.default_window);
  for (const fn of themeListeners) fn(currentPrefs.theme);
  for (const fn of densityListeners) fn(parseDensity(currentPrefs.density));
  for (const fn of zoneListeners) fn();
}

// True when motion should be reduced: the operating system asks for it, or
// the operator chose "Always reduce" in Preferences.
export function prefersReducedMotion() {
  return document.documentElement.hasAttribute?.('data-reduce-motion') || Boolean(globalThis.matchMedia?.('(prefers-reduced-motion: reduce)').matches);
}

export function setTheme(next) {
  const theme = THEMES.includes(next) ? next : 'system';
  changePref({ theme });
  return theme;
}

export function cycleTheme() {
  return setTheme(THEMES[(THEMES.indexOf(currentPrefs.theme) + 1) % THEMES.length]);
}

const THEME_LABEL = { system: 'Match the system', light: 'Light', dark: 'Dark' };
const THEME_HINT = { system: 'Follows the operating system', light: 'Always light', dark: 'Always dark' };

// An explicit choice: System, Light or Dark, in a top-bar menu (a native
// popover; it opens many times a day, so it never animates). The current
// choice carries a check and the word "Current".
function themeControl() {
  const btn = h('button', { class: ['btn', 'btn--ghost', 'btn--icon'], type: 'button', popovertarget: 'theme-menu' });
  // References kept here, so painting never queries the DOM.
  const items = THEMES.map((t) => {
    const check = h('span', { class: 'menu__check', 'aria-hidden': 'true' });
    const hint = h('span', { class: 'menu__hint' });
    const button = h('button', { class: 'menu__item', type: 'button', 'data-theme-choice': t },
      check, icon(THEME_ICON[t], { size: 'sm' }), h('span', { class: 'menu__label' }, THEME_LABEL[t]), hint);
    button.addEventListener('click', () => { hideMenu(menu); setTheme(t); btn.focus(); });
    return { t, button, check, hint };
  });
  const menu = h('div', { class: 'menu', id: 'theme-menu', popover: 'auto', tabindex: '-1', 'aria-labelledby': 'theme-menu-title' },
    h('p', { class: 'menu__title', id: 'theme-menu-title' }, 'Color theme'),
    h('ul', { class: 'menu__list' }, items.map((i) => h('li', null, i.button))),
    h('p', { class: 'menu__note' }, 'Also in Settings, Preferences.'));
  let current = currentPrefs.theme;
  const paint = (theme) => {
    current = theme;
    mount(btn, icon(THEME_ICON[theme]));
    btn.setAttribute('aria-label', `Color theme: ${THEME_LABEL[theme]}. Choose a theme.`);
    btn.setAttribute('title', `Theme: ${capitalize(theme)}`);
    for (const i of items) {
      const on = i.t === theme;
      i.button.setAttribute('aria-current', on ? 'true' : 'false');
      mount(i.check, on ? icon('check', { size: 'sm' }) : null);
      i.hint.textContent = on ? 'Current' : THEME_HINT[i.t];
    }
  };
  anchoredMenu(menu, btn, { focusOnOpen: () => items.find((i) => i.t === current)?.button });
  themeListeners.add(paint);
  paint(currentPrefs.theme);
  return [btn, menu];
}

// ---- Row density -----------------------------------------------------------
// Comfortable or compact rows, remembered in this browser (a convenience,
// like the theme). The stored value is parsed against a closed list.

const DENSITY_KEY = 'aegismesh.density';

function readDensity() {
  try {
    return parseDensity(globalThis.localStorage?.getItem(DENSITY_KEY));
  } catch {
    return 'comfortable';
  }
}

export function applyDensity(d = readDensity()) {
  document.documentElement.setAttribute('data-density', parseDensity(d));
}

function densityControl() {
  const btn = h('button', { class: ['btn', 'btn--ghost', 'btn--icon'], type: 'button' });
  const paint = (d) => {
    // A toggle keeps one name; aria-pressed says whether it is on.
    btn.replaceChildren(icon(d === 'compact' ? 'rows-dense' : 'rows-loose'));
    btn.setAttribute('aria-label', 'Compact rows');
    btn.setAttribute('title', d === 'compact' ? 'Rows: compact' : 'Rows: comfortable');
    btn.setAttribute('aria-pressed', String(d === 'compact'));
  };
  btn.addEventListener('click', () => {
    changePref({ density: nextDensity(currentPrefs.density) });
  });
  densityListeners.add(paint);
  paint(parseDensity(currentPrefs.density));
  return btn;
}

// ---- Sidebar rail ------------------------------------------------------------
// A collapsed sidebar shows icons only (labels stay in the accessible name
// and a tooltip). Remembered in this browser; '1' or nothing.

const RAIL_KEY = 'aegismesh.rail';
const readRail = () => {
  try {
    return globalThis.localStorage?.getItem(RAIL_KEY) === '1';
  } catch {
    return false;
  }
};

export function applyRail(on = readRail()) {
  document.documentElement.toggleAttribute('data-rail', Boolean(on));
}

function railToggle() {
  const btn = h('button', { class: ['btn', 'btn--ghost', 'btn--sm', 'rail-toggle'], type: 'button' });
  const paint = (on) => {
    btn.replaceChildren(icon(on ? 'chevron-right' : 'chevron-left', { size: 'sm' }), h('span', { class: 'rail-toggle__label' }, on ? 'Expand' : 'Collapse sidebar'));
    btn.setAttribute('aria-pressed', String(on));
    btn.setAttribute('aria-label', on ? 'Expand the sidebar' : 'Collapse the sidebar to icons');
  };
  btn.addEventListener('click', () => {
    const next = !readRail();
    try {
      globalThis.localStorage?.setItem(RAIL_KEY, next ? '1' : '0');
    } catch {
      // Storage may be unavailable; the choice still applies to this page.
    }
    applyRail(next);
    paint(next);
  });
  paint(readRail());
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
function accountControl(session, meta, onLogout, me) {
  const p = session?.principal || {};
  // A custom role's id is not a name: /me.role_name (round 6) says it.
  const role = p.role ? principalRoleName(p.role, me?.role_name) : 'Unknown role';
  const info = tenantInfo(session);
  const name = p.name || 'unknown';
  const button = h('button', { class: ['btn', 'btn--ghost', 'top-user'], type: 'button', popovertarget: 'account-menu', 'aria-label': `Account: ${name}, ${role}` },
    h('span', { class: 'top-user__avatar', 'aria-hidden': 'true' }, String(name).slice(0, 1).toUpperCase()),
    h('span', { class: 'top-user__name', 'aria-hidden': 'true' }, name),
    h('span', { class: 'chip', 'aria-hidden': 'true' }, role));
  const signOut = h('button', { class: ['btn', 'btn--block', 'menu__action'], type: 'button' }, icon('sign-out'), 'Sign out');
  const go = (href, ico, label) => h('li', null, h('a', { class: 'menu__item', href }, h('span', { class: 'menu__check', 'aria-hidden': 'true' }, icon(ico, { size: 'sm' })), h('span', { class: 'menu__label' }, label)));
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
        h('p', { class: 'menu__sub' }, role))),
    h('dl', { class: 'menu__kv' }, rows.map(([k, v]) => [h('dt', null, k), h('dd', null, v)])),
    h('ul', { class: ['menu__list', 'menu__links'] },
      go('#/settings/profile', 'user', 'Your profile'),
      go('#/settings/preferences', 'settings', 'Preferences'),
      go('#/settings/sessions', 'devices', 'Sessions'),
      go('#/settings/keys', 'key', 'API keys')),
    signOut);
  anchoredMenu(menu, button);
  return [button, menu];
}

// The sidebar's reminder of how times are shown; follows the preference.
function zoneLine() {
  const p = h('p', { class: 'muted nav-foot__meta' });
  const paint = () => { p.textContent = `Times in ${zoneName()}`; };
  zoneListeners.add(paint);
  paint();
  return p;
}

// ---- Shell -----------------------------------------------------------------

// The organisation name (round 6, /meta): plain text, capped, shown in the
// top bar and above the brand in the sidebar on phones.
// The current shell's print-time stamp; one listener for the page.
let printWhenOf = null;
globalThis.addEventListener?.('beforeprint', () => printWhenOf?.());

export function organizationText(v) {
  const s = typeof v === 'string' ? v.replace(/[\u0000-\u001f\u007f\u202a-\u202e\u2066-\u2069]/g, '').trim() : '';
  return Array.from(s).slice(0, 80).join('');
}

export function createShell({ session, meta, me = null, can = null, onLogout, onSearch, onSwitchTenant }) {
  // A rebuilt shell (sign-in, tenant switch) replaces the old controls.
  themeListeners.clear();
  densityListeners.clear();
  zoneListeners.clear();
  const allowed = toCan(can ?? session?.principal?.role);
  const links = new Map();
  const indicators = [];

  const groups = NAV.map((g) => {
    const items = g.items.filter((i) => allowed(ROUTE_PERMS[i.route]));
    if (!items.length) return null;
    const indicator = h('span', { class: 'nav-indicator', 'aria-hidden': 'true' });
    const list = h('ul', { class: 'nav-list' }, indicator, items.map((i) => {
      const a = h('a', { class: 'nav-link', href: i.href, 'data-route': i.route, title: i.label },
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

  const orgTop = h('span', { class: 'top-org', title: 'Organisation' });
  const orgNav = h('p', { class: 'nav-org' });
  // Every printed page (Digest, a session story, a campaign, any screen)
  // opens with who it belongs to and when it was printed. Hidden on screen.
  const printOrg = h('span', { class: 'print-head__org' });
  const printWhen = h('span', { class: 'print-head__when' });
  const tenantName = tenantInfo(session).show ? tenantInfo(session).active : '';
  const printHead = h('div', { class: 'print-head', 'aria-hidden': 'true' },
    printOrg,
    h('span', { class: 'print-head__product' }, brandMark(), 'AegisMesh', tenantName ? ` · tenant ${tenantName}` : ''),
    printWhen);
  const setOrganization = (v) => {
    const text = organizationText(v);
    orgTop.textContent = text;
    orgNav.textContent = text;
    printOrg.textContent = text;
    orgTop.hidden = !text;
    orgNav.hidden = !text;
    printOrg.hidden = !text;
  };
  printWhenOf = () => {
    printWhen.textContent = `Printed ${formatDateTime(new Date().toISOString())}${session?.principal?.name ? ` by ${session.principal.name}` : ''}`;
  };
  printWhenOf();
  setOrganization(meta?.organization_name);

  const nav = h('nav', { class: 'shell__nav', id: 'primary-nav', 'aria-label': 'Primary' },
    h('a', { class: 'brand', href: '#/overview', 'aria-label': 'AegisMesh, go to the overview' }, brandMark(), h('span', { class: 'brand__word' }, 'AegisMesh')),
    orgNav,
    groups,
    h('div', { class: 'nav-foot' },
      railToggle(),
      zoneLine(),
      h('p', { class: 'muted nav-foot__meta' }, `Version ${meta?.version || 'unknown'}`),
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
    orgTop,
    search,
    h('div', { class: 'top-spacer' }),
    liveSlot,
    densityControl(),
    themeControl(),
    tenantControl(session, onSwitchTenant),
    accountControl(session, meta, onLogout, me));

  const main = h('main', { class: 'shell__main', id: 'main' });
  const root = h('div', { class: 'shell' },
    h('a', { class: 'skip-link', href: '#/skip' }, 'Skip to content'),
    printHead, nav, scrim, top, main);
  // The skip link is a hash URL (CSP-friendly) intercepted here.
  root.firstChild.addEventListener('click', (e) => {
    e.preventDefault();
    main.querySelector('#page-title')?.focus();
  });

  // The sign-in banner after sign-in: one dismissible notice above the
  // screen, plain text (a Text node), never a modal.
  let notice = null;
  const showNotice = (text, onDismiss) => {
    notice?.remove();
    const close = h('button', { class: ['btn', 'btn--sm'], type: 'button' }, 'Dismiss');
    notice = h('section', { class: 'notice-bar', 'aria-label': 'Notice from your organisation' },
      icon('info', { size: 'sm' }),
      h('div', { class: 'notice-bar__body' },
        h('p', { class: 'notice-bar__title' }, 'Notice from your organisation'),
        h('p', { class: 'notice-bar__text' }, String(text))),
      close);
    close.addEventListener('click', () => {
      notice?.remove();
      notice = null;
      onDismiss?.();
      main.querySelector('#page-title')?.focus({ preventScroll: true });
    });
    main.prepend(notice);
  };

  let placed = false;
  return {
    root, main, liveSlot, nav, setOrganization, showNotice,
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
