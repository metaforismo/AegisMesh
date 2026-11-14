// Console entry point: session bootstrap, hash router, screen lifecycle.

import { createApi, ApiError } from './lib/api.js';
import { parseHash } from './lib/route.js';
import { roleAtLeast } from './lib/taxonomy.js';
import { h, clear } from './lib/dom.js';
import { createShell, applyTheme } from './ui/shell.js';
import { errorState, loading } from './ui/components.js';
import { SCREENS, notFoundScreen, forbiddenScreen } from './screens/index.js';
import loginScreen from './screens/login.js';

applyTheme();

const appRoot = document.getElementById('app');
const state = {
  session: null,
  meta: null,
  shell: null,
  controller: null,
  cleanup: null,
  returnTo: '',
  notice: '',
  firstRender: true,
};

const api = createApi({ onUnauthenticated: () => endSession('Your session ended. Sign in again to continue.') });

function teardownScreen() {
  state.controller?.abort();
  state.controller = null;
  try {
    state.cleanup?.();
  } catch {
    // A failing cleanup must not block navigation.
  }
  state.cleanup = null;
}

function endSession(notice) {
  teardownScreen();
  state.session = null;
  state.shell = null;
  state.notice = notice || '';
  api.forgetSession();
  if (parseHash(location.hash).name !== 'login') state.returnTo = location.hash;
  if (location.hash !== '#/login') location.hash = '#/login';
  else render();
}

async function logout() {
  try {
    await api.logout();
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
  location.hash = target;
  render();
}

async function render() {
  teardownScreen();
  const route = parseHash(location.hash);

  if (!state.session) {
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
    loginScreen.render(appRoot, { api, meta: state.meta, notice: state.notice, onLogin, signal: controller.signal });
    return;
  }

  if (route.name === 'login') {
    location.replace('#/overview');
    return;
  }

  if (!state.shell) {
    state.shell = createShell({ session: state.session, meta: state.meta, onLogout: logout });
    clear(appRoot);
    appRoot.appendChild(state.shell.root);
  }
  const shell = state.shell;
  shell.setActive(route.name);
  clear(shell.liveSlot);

  const role = state.session.principal?.role;
  let screen = SCREENS[route.name] || notFoundScreen;
  if (screen.role && !roleAtLeast(role, screen.role)) screen = forbiddenScreen;
  document.title = `${screen.title} · AegisMesh`;

  const controller = new AbortController();
  state.controller = controller;
  const main = shell.main;
  clear(main);
  main.appendChild(loading());

  const ctx = {
    api,
    route,
    session: state.session,
    role,
    can: (minimum) => roleAtLeast(role, minimum),
    signal: controller.signal,
    liveSlot: shell.liveSlot,
    navigate: (target) => { location.hash = target; },
    rerender: () => render(),
  };

  try {
    const cleanup = await screen.render(main, ctx);
    if (controller.signal.aborted) {
      cleanup?.();
      return;
    }
    state.cleanup = typeof cleanup === 'function' ? cleanup : null;
    if (!state.firstRender) main.querySelector('#page-title')?.focus({ preventScroll: false });
    state.firstRender = false;
  } catch (err) {
    if (err?.name === 'AbortError' || controller.signal.aborted) return;
    if (err instanceof ApiError && err.status === 401) return; // endSession already ran.
    clear(main);
    main.appendChild(h('div', { class: 'panel' }, errorState(err, () => render())));
  }
}

async function boot() {
  try {
    state.meta = await api.meta();
  } catch {
    state.meta = null;
  }
  try {
    state.session = await api.session();
  } catch (err) {
    state.session = null;
    if (!(err instanceof ApiError && err.status === 401)) {
      state.notice = err instanceof ApiError && err.status === 0
        ? 'The console server could not be reached. Check that AegisMesh is running, then reload.'
        : '';
    }
  }
  window.addEventListener('hashchange', () => render());
  render();
}

boot();
