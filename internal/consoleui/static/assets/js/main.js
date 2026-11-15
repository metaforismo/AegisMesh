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

import { createApi, ApiError } from './lib/api.js';
import { parseHash, viewKey } from './lib/route.js';
import { roleAtLeast } from './lib/taxonomy.js';
import { h, clear } from './lib/dom.js';
import { createSwr, abortable } from './lib/swr.js';
import { chordOf, createSequences, isTypingTarget } from './lib/keys.js';
import { createShell, applyTheme, cycleTheme, isApple, NAV } from './ui/shell.js';
import { errorState, installPeek } from './ui/components.js';
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
const toggleShortcuts = () => loadPalette().then((m) => m.toggleShortcuts());

applyTheme();

const appRoot = document.getElementById('app');
const state = {
  session: null,
  meta: null,
  shell: null,
  controller: null,
  cleanup: null,
  current: null, // { screen, key, update, hash }
  returnTo: '',
  notice: '',
  firstRender: true,
};

const rawApi = createApi({ onUnauthenticated: () => endSession('Your session ended. Sign in again to continue.') });

// ---- Cached API ---------------------------------------------------------------

// Read-only GETs safe to cache and prefetch, with their positional arity
// (arguments before the options object). The audit trail is deliberately
// absent: reading it is an audited action and must only happen on request.
const CACHEABLE = {
  overview: 1, events: 3, event: 1, sources: 2, source: 3, sensors: 0, rules: 0, recommendations: 1,
  node: 0, investigations: 1, investigation: 1, fleet: 0, fleetNodes: 1, fleetNode: 1,
};
const CURSOR_ARG = { events: 1, source: 1 }; // later pages are never cached
const PASS = new Set(['request', 'hasCsrf', 'forgetSession', 'meta', 'session', 'audit', 'verifyAudit', 'enrollmentTokens']);

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
  if (!screen || (screen.role && !roleAtLeast(state.session.principal?.role, screen.role))) return;
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

const reducedMotion = () => globalThis.matchMedia?.('(prefers-reduced-motion: reduce)').matches;

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

function swapView(main, next, { animate, dir, fade }) {
  const prev = [...main.children].find((c) => c.classList.contains('view'));
  const doSwap = () => {
    if (prev) prev.replaceWith(next);
    else main.appendChild(next);
  };
  document.documentElement.dataset.navDir = dir === 'back' ? 'back' : 'forward';
  if (animate && prev && typeof document.startViewTransition === 'function') {
    return document.startViewTransition(doSwap).updateCallbackDone.catch(() => {});
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

function endSession(notice) {
  teardownScreen();
  swr.invalidate();
  state.session = null;
  state.shell = null;
  state.notice = notice || '';
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

function onLogin(session) {
  state.session = session;
  state.notice = '';
  const target = state.returnTo && parseHash(state.returnTo).name !== 'login' ? state.returnTo : '#/overview';
  state.returnTo = '';
  state.firstRender = true;
  if (location.hash === target) render();
  else location.hash = target;
}

async function openPalette() {
  if (!state.session) return;
  const { togglePalette } = await loadPalette();
  togglePalette({
    api,
    role: state.session.principal?.role,
    navigate: (target) => { location.hash = target; },
    actions: [
      { label: 'Follow live events', icon: 'live', hint: 'Events in live mode', keywords: ['stream', 'tail'], run: (p) => p.navigate('#/events?live=1') },
      { label: 'Switch color theme', icon: 'sun', hint: 'System, light, dark', keywords: ['dark', 'light', 'appearance'], run: () => cycleTheme() },
      { label: 'Keyboard shortcuts', icon: 'keyboard', hint: '?', keywords: ['keys', 'help'], run: () => toggleShortcuts() },
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
    clear(appRoot);
    document.title = 'Sign in · AegisMesh';
    const controller = new AbortController();
    state.controller = controller;
    const { default: loginScreen } = await loadLogin();
    if (controller.signal.aborted || state.session) return;
    loginScreen.render(appRoot, { api: rawApi, meta: state.meta, notice: state.notice, onLogin, signal: controller.signal });
    return;
  }

  if (route.name === 'login') {
    location.replace('#/overview');
    return;
  }

  if (!state.shell) {
    teardownScreen();
    state.shell = createShell({ session: state.session, meta: state.meta, onLogout: logout, onSearch: openPalette });
    clear(appRoot);
    appRoot.appendChild(state.shell.root);
    const prefetchFrom = (e) => {
      if (e.target.closest?.('.top-search')) loadPalette().catch(() => {});
      const a = e.target.closest?.('a[href^="#/"]');
      if (a) prefetchRoute(a.getAttribute('href'));
    };
    state.shell.root.addEventListener('pointerover', prefetchFrom, { passive: true });
    state.shell.root.addEventListener('focusin', prefetchFrom);
  }
  const shell = state.shell;
  const role = state.session.principal?.role;
  let screen = SCREENS[route.name] || notFoundScreen;
  if (screen.role && !roleAtLeast(role, screen.role)) screen = forbiddenScreen;

  // Same view, only an overlay parameter changed (e.g. the event drawer).
  const key = viewKey(route, screen.viewIgnore || []);
  if (!soft && state.current?.screen === screen && state.current.key === key && state.current.update) {
    direction(location.hash);
    state.current.hash = location.hash;
    state.current.update(route);
    return;
  }

  const dir = soft ? 'none' : direction(location.hash);
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
  const view = h('div', { class: 'view' });

  const ctx = {
    api,
    route,
    session: state.session,
    role,
    can: (minimum) => roleAtLeast(role, minimum),
    signal: controller.signal,
    liveSlot: shell.liveSlot,
    navigate: (target) => { location.hash = target; },
    rerender: () => render({ soft: true }),
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
    const animate = !soft && !state.firstRender && !skeletonShown && !reducedMotion();
    await swapView(main, view, { animate, dir, fade: skeletonShown && !reducedMotion() });
    window.scrollTo(0, keepY);
    result.mounted?.();
    if (!soft && !state.firstRender) main.querySelector('#page-title')?.focus({ preventScroll: true });
    state.firstRender = false;
  } catch (err) {
    clearTimeout(grace);
    progress.done();
    if (err?.name === 'AbortError' || controller.signal.aborted) return;
    if (err instanceof ApiError && err.status === 401) return; // endSession already ran.
    state.firstRender = false;
    swapView(main, h('div', { class: 'view' }, h('div', { class: 'panel' }, errorState(err, () => render({ soft: true })))), { animate: false, dir });
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
  if (target) {
    e.preventDefault();
    location.hash = target;
  }
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
  installPeek();
  window.addEventListener('hashchange', () => render());
  document.addEventListener('keydown', onKeydown);
  render();
}

boot();
