// Console entry point: session bootstrap, hash router, screen lifecycle.
//
// Navigation model:
// - A screen renders into a detached view while the current one stays on
//   screen. If it is not ready within a short grace period, a skeleton shaped
//   like the coming screen takes its place and a thin progress bar runs.
// - The finished view swaps in with a short directional transition (View
//   Transitions API when available, a keyframe otherwise; none under
//   reduced motion, none for in-place refreshes).
// - Read-only GETs go through a small in-memory stale-while-revalidate
//   cache: hover/focus on a link prefetches the screen module and its data,
//   and back/forward navigation shows the last response at once, then
//   refreshes it. Any write clears the cache.

import { createApi, ApiError, screenFailure, describeError } from './lib/api.js';
import { parseHash, viewKey } from './lib/route.js';
import { permissionsOf, toCan, ROUTE_PERMS, BUILTIN_PERMS, principalRoleName } from './lib/perms.js';
import { h, clear } from './lib/dom.js';
import { createSwr, abortable } from './lib/swr.js';
import { chordOf, createSequences, isTypingTarget } from './lib/keys.js';
import { createShell, applyRail, applyPreferences, setPrefsSink, prefersReducedMotion, cycleTheme, isApple, NAV, setFeature, hasFeature } from './ui/shell.js';
import { createBell } from './ui/bell.js';
import { createPrefsStore } from './lib/prefs.js';
import { isMissingEndpoint } from './lib/insight.js';
import { sentence } from './lib/settings.js';
import { failureState, installPeek, toast, pageHead, panel } from './ui/components.js';
import { loginErrorCode, loginErrorMessage } from './lib/auth.js';
import { tenantInfo, switchTargets, routeAfterSwitch, switchBody } from './lib/tenant.js';
import { notFoundInTenant } from './screens/shared.js';
import { skeleton } from './ui/skeletons.js';
import { SCREENS, notFoundScreen, forbiddenScreen } from './screens/index.js';

// Loaded on first use (or when the pointer reaches the search button): the
// palette and shortcut sheet, and the sign-in screen when there is no session.
let paletteModule = null;
const loadPalette = () => {
  paletteModule ||= import('./ui/palette.js').catch((err) => { paletteModule = null; throw err; });
  return paletteModule;
};
const loadLogin = () => import('./screens/login.js');
const toggleShortcuts = () => loadPalette().then((m) => m.toggleShortcuts(state.can));

applyRail();

const appRoot = document.getElementById('app');
const state = {
  session: null,
  meta: null,
  // Who is signed in (`/me`, null on an older server) and what they may do.
  // Drawing the interface from it is a convenience: the server decides.
  me: null,
  can: () => false,
  shell: null,
  // The notification bell of the current shell (round 8), or null.
  bell: null,
  controller: null,
  cleanup: null,
  current: null, // { screen, key, update, hash }
  returnTo: '',
  notice: '',
  firstRender: true,
};

const rawApi = createApi({ onUnauthenticated: () => endSession('Your session ended. Sign in again to continue.') });

// Preferences: applied from the browser copy at once, then from the server
// once signed in (when it stores them). The top-bar theme and density
// controls change them through the same store.
const browserStorage = (() => {
  try {
    return globalThis.localStorage || null;
  } catch {
    return null;
  }
})();
const prefs = createPrefsStore({
  load: () => rawApi.preferences(),
  save: (p) => rawApi.putPreferences(p),
  apply: applyPreferences,
  storage: browserStorage,
  isMissing: isMissingEndpoint,
});
prefs.start();
setPrefsSink((patch) => prefs.update(patch).catch((err) => {
  toast('error', `Could not save the preference: ${sentence(describeError(err).detail)} The previous value is back.`);
}));

// After sign-in: the account's preferences win. A change to how times or
// the default window read redraws the screen on display.
async function syncPrefs() {
  const before = prefs.get();
  try {
    await prefs.sync();
  } catch {
    // Unreachable or refused: keep the browser copy.
  }
  const after = prefs.get();
  if ((before.timezone !== after.timezone || before.default_window !== after.default_window) && state.current) render({ soft: true });
}

// What the signed-in principal may do: `/me.permissions` on a round-6
// server, the built-in role's fixed set on an older one. When `/me` fails
// for another reason and the role is not a built-in, nothing is hidden: the
// server still refuses what the role does not allow, and every screen
// handles that 403.
async function loadAccess() {
  const role = state.session?.principal?.role || '';
  try {
    state.me = await rawApi.me();
    state.can = toCan(permissionsOf(state.me, state.session));
  } catch (err) {
    state.me = null;
    if (err instanceof ApiError && err.status === 401) throw err;
    state.can = isMissingEndpoint(err) || BUILTIN_PERMS[role] ? toCan(permissionsOf(null, state.session)) : () => true;
  }
}

// The organisation name and sign-in banner come from /meta (round 6) and
// can change from Settings; a change there refreshes them.
async function refreshMeta() {
  try {
    state.meta = await rawApi.meta();
  } catch {
    return;
  }
  state.shell?.setOrganization(state.meta?.organization_name);
}

// The sign-in banner, once per console session after sign-in: remembered in
// this tab's session storage under the session's expiry, which a tenant
// switch keeps. Plain text, dismissible.
const BANNER_KEY = 'aegismesh.banner-seen';
function bannerSeenKey() {
  return `${state.session?.principal?.name || ''}|${state.session?.expires_at || ''}`;
}
function maybeShowBanner() {
  const text = typeof state.meta?.sign_in_banner === 'string' ? state.meta.sign_in_banner.trim() : '';
  if (!text || !state.shell) return;
  let seen = '';
  try {
    seen = globalThis.sessionStorage?.getItem(BANNER_KEY) || '';
  } catch {
    // Storage unavailable: show it; dismissing still hides it for this page.
  }
  if (seen === bannerSeenKey()) return;
  state.shell.showNotice(text, () => {
    try {
      globalThis.sessionStorage?.setItem(BANNER_KEY, bannerSeenKey());
    } catch {
      // Not remembered beyond this page.
    }
  });
}

// ---- Cached API ---------------------------------------------------------------

// Read-only GETs safe to cache and prefetch, with their positional arity
// (arguments before the options object). The audit trail is deliberately
// absent: reading it is an audited action and must only happen on request.
const CACHEABLE = {
  overview: 1, events: 3, event: 2, sources: 2, source: 3, sensors: 0, rules: 0, recommendations: 1,
  node: 0, investigations: 1, investigation: 1, fleet: 0, fleetNodes: 1, fleetNode: 1,
  sessions: 2, attackSession: 1, coverage: 1, decoys: 1, honeytokens: 1, digest: 1,
  campaigns: 0, campaign: 1, posture: 0,
};
const CURSOR_ARG = { events: 1, source: 1, sessions: 2 }; // later pages are never cached
// Downloads are audited reads: never cached or prefetched, and not writes.
// Account and administration reads are never cached either: they change
// with every write on the settings screens and must show the server's state.
const PASS = new Set(['request', 'hasCsrf', 'forgetSession', 'meta', 'session', 'switchTenant', 'audit', 'verifyAudit', 'enrollmentTokens',
  'exportIndicators', 'sessionReport', 'investigationReport', 'exportEvents',
  'me', 'preferences', 'mySessions', 'myKeys', 'accounts', 'account', 'allSessions', 'adminSettings', 'system', 'exportAudit',
  'permissions', 'roles', 'role', 'settingsHistory',
  // Round 8: the inbox and its read state are per principal and change
  // with every arrival, so they are never cached; marking read or saving
  // notification preferences changes nothing another screen has cached.
  'notifications', 'markNotificationsRead', 'notificationPrefs', 'putNotificationPrefs', 'assignees']);

const nav = { back: false, used: new Set() };
const swr = createSwr({
  freshMs: 10000,
  staleMs: 120000,
  onUpdate: (key) => {
    // A back-navigation refresh came back different: re-render in place.
    if (nav.used.has(key) && state.current && state.current.hash === location.hash) render({ soft: true });
  },
});

function cacheKey(name, args) {
  return `${name}:${JSON.stringify(args.slice(0, CACHEABLE[name]))}`;
}

function buildApis(raw) {
  const api = {};
  const prefetch = {};
  for (const [name, fn] of Object.entries(raw)) {
    if (typeof fn !== 'function') continue;
    if (name in CACHEABLE) {
      const arity = CACHEABLE[name];
      const pagedPast = (args) => name in CURSOR_ARG && Boolean(args[CURSOR_ARG[name]]);
      api[name] = (...args) => {
        if (pagedPast(args)) return fn(...args);
        const key = cacheKey(name, args);
        nav.used.add(key);
        const params = args.slice(0, arity);
        return abortable(swr.get(key, () => fn(...params), { allowStale: nav.back }), args[arity]?.signal);
      };
      prefetch[name] = (...args) => {
        if (pagedPast(args)) return;
        const params = args.slice(0, arity);
        swr.prefetch(cacheKey(name, args), () => fn(...params));
      };
    } else if (PASS.has(name)) {
      api[name] = fn;
    } else {
      // Every other call writes. Whatever happens, cached reads are dropped.
      api[name] = (...args) => {
        const p = fn(...args);
        p.then(() => swr.invalidate(), () => swr.invalidate());
        return p;
      };
    }
  }
  return { api, prefetch };
}

const { api, prefetch: prefetchApi } = buildApis(rawApi);

function prefetchRoute(hash) {
  if (!state.session) return;
  const route = parseHash(hash);
  const screen = SCREENS[route.name];
  if (!screen || (ROUTE_PERMS[route.name] && !state.can(ROUTE_PERMS[route.name]))) return;
  screen.load().catch(() => {});
  try {
    screen.prefetch?.(prefetchApi, route);
  } catch {
    // A prefetch is a hint; a failure only means the screen fetches normally.
  }
}

// ---- Navigation direction and progress ---------------------------------------

const trail = [];
function direction(hash) {
  if (trail.length >= 2 && trail[trail.length - 2] === hash) {
    trail.pop();
    return 'back';
  }
  if (trail[trail.length - 1] !== hash) trail.push(hash);
  if (trail.length > 50) trail.shift();
  return 'forward';
}

const reducedMotion = () => prefersReducedMotion();

// Navigation the operator drives from the keyboard (g-sequences, the
// palette, Enter on a link) happens many times a day and stays instant;
// the content transition is for pointer navigation only.
let lastInput = { kind: 'pointer', at: 0 };
const keyboardDriven = () => lastInput.kind === 'keyboard' && performance.now() - lastInput.at < 1000;

const progress = (() => {
  const bar = h('div', { class: 'route-progress', 'aria-hidden': 'true' });
  let attached = false;
  return {
    start() {
      if (!attached) { document.body.appendChild(bar); attached = true; }
      bar.classList.remove('is-done');
      void bar.offsetWidth; // restart from 0 (one forced read, only when slow)
      bar.classList.add('is-running');
    },
    done() {
      if (!bar.classList.contains('is-running')) return;
      bar.classList.remove('is-running');
      bar.classList.add('is-done');
    },
  };
})();

// Replace whatever view is on screen with `next`. The current view is looked
// up when the swap actually runs (a View Transition defers it), and any
// other stray view is removed, so a navigation that overtakes another can
// never leave two screens stacked. A running transition is skipped first.
let activeTransition = null;
function swapView(main, next, { animate, dir, fade }) {
  const doSwap = () => {
    const olds = [...main.children].filter((c) => c.classList.contains('view') && c !== next);
    if (olds.length) {
      olds[0].replaceWith(next);
      for (const o of olds.slice(1)) o.remove();
    } else if (next.parentNode !== main) {
      main.appendChild(next);
    }
  };
  try {
    activeTransition?.skipTransition?.();
  } catch {
    // Already finished.
  }
  activeTransition = null;
  const hasPrev = [...main.children].some((c) => c.classList.contains('view'));
  document.documentElement.dataset.navDir = dir === 'back' ? 'back' : 'forward';
  if (animate && hasPrev && typeof document.startViewTransition === 'function') {
    const vt = document.startViewTransition(doSwap);
    // A skipped transition rejects ready; the swap itself still runs, so the rejection is expected.
    vt.ready.catch(() => {});
    activeTransition = vt;
    vt.finished.catch(() => {}).finally(() => { if (activeTransition === vt) activeTransition = null; });
    return vt.updateCallbackDone.catch(() => {});
  }
  doSwap();
  if (animate || fade) {
    next.classList.add(fade ? 'view--fade' : 'view--enter');
    next.addEventListener('animationend', () => next.classList.remove('view--enter', 'view--fade'), { once: true });
  }
  return Promise.resolve();
}

// ---- Screen lifecycle ------------------------------------------------------------

function teardownScreen() {
  state.controller?.abort();
  state.controller = null;
  try {
    state.cleanup?.();
  } catch {
    // A failing cleanup must not block navigation.
  }
  state.cleanup = null;
  state.current = null;
}

function stopBell() {
  state.bell?.stop();
  state.bell = null;
  setFeature('notifications', false);
}

function endSession(notice) {
  teardownScreen();
  stopBell();
  swr.invalidate();
  state.session = null;
  state.shell = null;
  state.me = null;
  state.can = () => false;
  state.notice = notice || '';
  prefs.reset();
  rawApi.forgetSession();
  if (parseHash(location.hash).name !== 'login') state.returnTo = location.hash;
  if (location.hash !== '#/login') location.hash = '#/login';
  else render();
}

async function logout() {
  try {
    await rawApi.logout();
  } catch {
    // The session may already be gone server-side; the local state is cleared regardless.
  }
  state.returnTo = '';
  endSession('You signed out.');
}

async function onLogin(session) {
  state.session = session;
  state.notice = '';
  try {
    await loadAccess();
  } catch {
    return; // 401: the session ended between sign-in and /me.
  }
  const target = state.returnTo && parseHash(state.returnTo).name !== 'login' ? state.returnTo : '#/overview';
  state.returnTo = '';
  state.firstRender = true;
  if (location.hash === target) render();
  else location.hash = target;
  syncPrefs();
}

// Move the session to another member tenant. The live view is torn down
// first, so nothing from the departing tenant (a stream, a late response)
// lands on screen; the server closes the old session's streams anyway.
// Then: new session and CSRF token, an empty read cache, a rebuilt shell,
// and either the same view in the new tenant or the overview when the view
// named an object that cannot exist there.
let switchingTenant = false;
async function switchTenant(target) {
  if (switchingTenant || !state.session) return;
  const body = switchBody(state.session, target);
  if (!body) return;
  switchingTenant = true;
  const from = tenantInfo(state.session).active;
  teardownScreen();
  progress.start();
  let session;
  try {
    session = await rawApi.switchTenant(body.tenant);
  } catch (err) {
    progress.done();
    switchingTenant = false;
    if (err instanceof ApiError && err.status === 401) {
      endSession('Your session ended. Sign in again to continue.');
      return;
    }
    toast('error', `Could not switch to tenant ${target}: ${err?.message || 'request failed'}. You are still in ${from}.`);
    render({ soft: true });
    return;
  }
  progress.done();
  swr.invalidate();
  state.session = session;
  state.shell = null;
  stopBell();
  try {
    await loadAccess();
  } catch {
    switchingTenant = false;
    return;
  }
  state.firstRender = true; // a context change, not a navigation: no transition
  const { hash, reason } = routeAfterSwitch(parseHash(location.hash), location.hash);
  if (hash !== location.hash) history.replaceState(null, '', hash);
  switchingTenant = false;
  await render();
  const now = tenantInfo(state.session).active || target;
  const why = {
    object: ` The page you were on belonged to ${from}, so you are on the overview.`,
    cleared: ` The open event and origin filter belonged to ${from}, so they were cleared.`,
  }[reason] || '';
  toast('ok', `Now in tenant ${now}.${why}`);
  state.shell?.main.querySelector('#page-title')?.focus({ preventScroll: true });
}

async function openPalette() {
  if (!state.session) return;
  const { togglePalette } = await loadPalette();
  togglePalette({
    api,
    can: state.can,
    tenant: tenantInfo(state.session).active || 'default',
    navigate: (target) => { location.hash = target; },
    actions: [
      { label: 'Follow live events', icon: 'live', hint: 'Events in live mode', keywords: ['stream', 'tail'], recentId: 'live', run: (p) => p.navigate('#/events?live=1') },
      { label: 'Switch color theme', icon: 'sun', hint: 'System, light, dark', keywords: ['dark', 'light', 'appearance'], recentId: 'theme', run: () => cycleTheme() },
      { label: 'Keyboard shortcuts', icon: 'keyboard', hint: '?', keywords: ['keys', 'help'], recentId: 'shortcuts', run: () => toggleShortcuts() },
      { label: 'Preferences', icon: 'settings', hint: 'Time zone, default window, density, theme, motion', keywords: ['settings', 'timezone', 'utc', 'local', 'density', 'motion'], recentId: 'preferences', run: (p) => p.navigate('#/settings/preferences') },
      { label: 'Manage API keys', icon: 'key', hint: 'Create or revoke your keys', keywords: ['settings', 'token', 'api key', 'automation'], recentId: 'keys', run: (p) => p.navigate('#/settings/keys') },
      { label: 'Your sessions', icon: 'devices', hint: 'Where your account is signed in', keywords: ['settings', 'sign out', 'revoke', 'devices'], recentId: 'my-sessions', run: (p) => p.navigate('#/settings/sessions') },
      { label: 'Manage accounts', icon: 'users', hint: 'Administration', perm: 'accounts.read', keywords: ['settings', 'users', 'access', 'admin'], recentId: 'accounts', run: (p) => p.navigate('#/settings/accounts') },
      { label: 'Roles and permissions', icon: 'shield', hint: 'Administration', perm: 'accounts.read', keywords: ['settings', 'roles', 'permissions', 'access', 'admin'], recentId: 'roles', run: (p) => p.navigate('#/settings/roles') },
      { label: 'Console settings', icon: 'settings', hint: 'Organisation name, sign-in banner, defaults', perm: 'settings.read', keywords: ['settings', 'organisation', 'organization', 'banner', 'branding'], recentId: 'console-settings', run: (p) => p.navigate('#/settings/console') },
      { label: 'Settings change history', icon: 'audit', hint: 'Who changed which setting, and why', perm: 'settings.read', keywords: ['settings', 'history', 'changes'], recentId: 'settings-history', run: (p) => p.navigate('#/settings/history') },
      { label: 'Export the audit trail', icon: 'audit', hint: 'Administration', perm: 'audit.export', keywords: ['settings', 'audit', 'download', 'csv', 'jsonl'], recentId: 'audit-export', run: (p) => p.navigate('#/settings/audit-export') },
      ...switchTargets(state.session).map((t) => ({
        label: `Switch tenant: ${t}`, icon: 'tenant', hint: `Act in tenant ${t}`, keywords: ['tenant', 'switch', t],
        run: () => switchTenant(t),
      })),
      { label: 'Sign out', icon: 'sign-out', hint: 'End this session', keywords: ['logout', 'log out'], run: () => logout() },
    ],
  });
}

function normalizeResult(result) {
  if (typeof result === 'function') return { cleanup: result };
  if (result && typeof result === 'object') return result;
  return {};
}

async function render({ soft = false } = {}) {
  const route = parseHash(location.hash);

  if (!state.session) {
    teardownScreen();
    if (route.name !== 'login') {
      state.returnTo = location.hash;
      location.replace('#/login');
      return;
    }
    state.shell = null;
    // An OIDC failure comes back as #/login?error=<code>. Read it once, then
    // drop it from the address bar so a reload or a shared link is clean.
    const loginError = loginErrorCode(route.query);
    if (route.query && Object.keys(route.query).length) history.replaceState(null, '', '#/login');
    clear(appRoot);
    document.title = 'Sign in · AegisMesh';
    const controller = new AbortController();
    state.controller = controller;
    const { default: loginScreen } = await loadLogin();
    if (controller.signal.aborted || state.session) return;
    loginScreen.render(appRoot, { api: rawApi, meta: state.meta, notice: state.notice, loginError, onLogin, signal: controller.signal });
    return;
  }

  if (route.name === 'login') {
    // Already signed in (say, a second single sign-on attempt failed in this
    // browser): keep the session and say what happened, once.
    const code = loginErrorCode(route.query);
    if (code) toast('error', `${loginErrorMessage(code).title}. You are still signed in.`);
    location.replace('#/overview');
    return;
  }

  if (!state.shell) {
    teardownScreen();
    stopBell();
    // The bell stays hidden until the server answers /notifications; an
    // older server never shows it and the Inbox leaves the palette.
    const bell = createBell({ api: rawApi, checkSession: () => rawApi.session().then(() => true), storage: browserStorage });
    state.bell = bell;
    bell.start().then((on) => {
      if (state.bell !== bell) return;
      setFeature('notifications', on);
    });
    state.shell = createShell({ session: state.session, meta: state.meta, me: state.me, can: state.can, onLogout: logout, onSearch: openPalette, onSwitchTenant: switchTenant, bell });
    clear(appRoot);
    appRoot.appendChild(state.shell.root);
    const prefetchFrom = (e) => {
      if (e.target.closest?.('.top-search')) loadPalette().catch(() => {});
      const a = e.target.closest?.('a[href^="#/"]');
      if (a) prefetchRoute(a.getAttribute('href'));
    };
    state.shell.root.addEventListener('pointerover', prefetchFrom, { passive: true });
    state.shell.root.addEventListener('focusin', prefetchFrom);
    maybeShowBanner();
  }
  const shell = state.shell;
  const role = state.session.principal?.role;
  let screen = SCREENS[route.name] || notFoundScreen;
  const needed = ROUTE_PERMS[route.name] || '';
  if (needed && !state.can(needed)) screen = forbiddenScreen;

  // Same view, only an overlay parameter changed (e.g. the event drawer).
  const key = viewKey(route, screen.viewIgnore || []);
  if (!soft && state.current?.screen === screen && state.current.key === key && state.current.update) {
    direction(location.hash);
    state.current.hash = location.hash;
    state.current.update(route);
    return;
  }

  const dir = soft ? 'none' : direction(location.hash);
  // User Timing: one measure per screen render ("screen:events"), from the
  // route change to the swapped-in view, visible in the browser's
  // performance tools. Nothing is collected or sent.
  const markStart = `screen-start:${route.name}`;
  performance.mark?.(markStart);
  teardownScreen();
  shell.setActive(route.name);
  clear(shell.liveSlot);
  document.title = `${screen.title} · AegisMesh`;

  const controller = new AbortController();
  state.controller = controller;
  nav.back = dir === 'back';
  nav.used = new Set();
  const main = shell.main;
  const keepY = soft ? window.scrollY : 0;
  drawnWidth = globalThis.innerWidth || drawnWidth;
  const view = h('div', { class: 'view' });

  const ctx = {
    api,
    route,
    session: state.session,
    role,
    roleName: principalRoleName(role, state.me?.role_name),
    me: state.me,
    // can('investigations.write'): what the signed-in principal may do.
    can: state.can,
    needed,
    meta: state.meta,
    refreshMeta,
    signal: controller.signal,
    liveSlot: shell.liveSlot,
    navigate: (target) => { location.hash = target; },
    rerender: () => render({ soft: true }),
    prefs,
    // The shared notification store (the bell's), or null on a server
    // without the inbox.
    inbox: state.bell?.inbox || null,
    notificationsReady: () => state.bell?.available === true,
    // The operator revoked this browser's own session: it is already gone
    // on the server, so only the local state is cleared.
    signedOut: () => {
      state.returnTo = '';
      endSession('You revoked this session, so you are signed out.');
    },
    // A detail screen names itself in the tab ("<name> · Session"). Text
    // only, with control and bidi characters removed and the length capped.
    setTitle: (text) => {
      if (controller.signal.aborted) return;
      const clean = Array.from(String(text ?? '').replace(/[\u0000-\u001f\u007f-\u009f\u200b-\u200f\u202a-\u202e\u2066-\u2069\ufeff]/g, '')).slice(0, 60).join('');
      document.title = clean ? `${clean} · ${screen.title} · AegisMesh` : `${screen.title} · AegisMesh`;
    },
  };

  // Grace period: fast screens swap straight in, slow ones show a skeleton.
  let skeletonShown = false;
  const grace = setTimeout(() => {
    if (controller.signal.aborted) return;
    progress.start();
    if (soft) return;
    skeletonShown = true;
    swapView(main, h('div', { class: 'view' }, skeleton(screen.skeleton, screen.title)), { animate: false, dir });
    window.scrollTo(0, 0);
  }, soft ? 400 : 140);

  try {
    const result = normalizeResult(await screen.render(view, ctx));
    clearTimeout(grace);
    progress.done();
    if (controller.signal.aborted) {
      result.cleanup?.();
      return;
    }
    state.cleanup = result.cleanup || null;
    state.current = { screen, key, update: result.update || null, hash: location.hash };
    const animate = !soft && !state.firstRender && !skeletonShown && !reducedMotion() && !keyboardDriven();
    // An in-place refresh must not replay entrance animations.
    if (soft) view.classList.add('view--static');
    await swapView(main, view, { animate, dir, fade: skeletonShown && !reducedMotion() });
    try {
      performance.measure?.(`screen:${route.name}`, markStart);
      performance.clearMarks?.(markStart);
    } catch {
      // User Timing unavailable: nothing to record.
    }
    window.scrollTo(0, keepY);
    result.mounted?.();
    if (!soft && !state.firstRender) main.querySelector('#page-title')?.focus({ preventScroll: true });
    state.firstRender = false;
  } catch (err) {
    clearTimeout(grace);
    progress.done();
    if (err?.name === 'AbortError' || controller.signal.aborted) return;
    if (err instanceof ApiError && err.status === 401) return; // endSession already ran.
    const first = state.firstRender;
    state.firstRender = false;
    // Another tenant's objects answer 404 exactly like absent ones; with
    // tenants in play the empty state says which tenant was searched.
    const info = tenantInfo(state.session);
    const body = err instanceof ApiError && err.code === 'not_found' && info.show
      ? notFoundInTenant(info)
      : failureState(screenFailure(err, { name: route.name, title: screen.title }), () => render({ soft: true }));
    // The failed screen keeps its heading, so the page still has one h1 and
    // focus lands somewhere meaningful.
    await swapView(main, h('div', { class: 'view' }, pageHead({ title: screen.title }), panel({ body })), { animate: false, dir });
    if (!soft && !first) main.querySelector('#page-title')?.focus({ preventScroll: true });
  }
}

// ---- Global keyboard -----------------------------------------------------------

const sequences = createSequences(Object.fromEntries(NAV.flatMap((g) => g.items).filter((i) => i.keys).map((i) => [i.keys, i.href])));

function onKeydown(e) {
  if (!state.session || !state.shell) return;
  const chord = chordOf(e, { apple: isApple() });
  if (chord === 'mod+k') {
    e.preventDefault();
    openPalette();
    return;
  }
  if (e.defaultPrevented || e.metaKey || e.ctrlKey || e.altKey || isTypingTarget(e.target) || document.querySelector('dialog[open]')) {
    sequences.reset();
    return;
  }
  if (chord === '?') {
    e.preventDefault();
    toggleShortcuts();
    return;
  }
  if (chord === '/') {
    const search = document.querySelector('[data-search]');
    if (search) {
      e.preventDefault();
      search.focus();
      search.select?.();
    }
    return;
  }
  const target = sequences.feed(chord);
  if (target === '#/inbox' && !hasFeature('notifications')) return;
  if (target) {
    e.preventDefault();
    location.hash = target;
  }
}

// Screens drawn at the viewport's width (the Overview chart) redraw in
// place after the window changes width by a quarter or more, so a tick
// drawn for a phone never stretches across a desktop.
let drawnWidth = globalThis.innerWidth || 0;
let resizeTimer = 0;
function onResize() {
  clearTimeout(resizeTimer);
  resizeTimer = setTimeout(() => {
    const w = globalThis.innerWidth || 0;
    if (!drawnWidth || Math.abs(w - drawnWidth) / drawnWidth < 0.25) return;
    drawnWidth = w;
    if (state.current?.screen?.redrawOnResize && !document.querySelector('dialog[open]') && !isTypingTarget(document.activeElement)) render({ soft: true });
  }, 250);
}

async function boot() {
  const [meta, session] = await Promise.allSettled([rawApi.meta(), rawApi.session()]);
  state.meta = meta.status === 'fulfilled' ? meta.value : null;
  if (session.status === 'fulfilled') {
    state.session = session.value;
  } else {
    const err = session.reason;
    state.session = null;
    if (!(err instanceof ApiError && err.status === 401)) {
      state.notice = err instanceof ApiError && err.status === 0
        ? 'The console server could not be reached. Check that AegisMesh is running, then reload.'
        : '';
    }
  }
  if (state.session) {
    try {
      await loadAccess();
    } catch {
      // 401: the API client already ended the session.
    }
    syncPrefs();
  }
  installPeek();
  document.addEventListener('keydown', () => { lastInput = { kind: 'keyboard', at: performance.now() }; }, true);
  document.addEventListener('pointerdown', () => { lastInput = { kind: 'pointer', at: performance.now() }; }, true);
  window.addEventListener('hashchange', () => render());
  window.addEventListener('resize', onResize, { passive: true });
  document.addEventListener('keydown', onKeydown);
  render();
}

boot();
