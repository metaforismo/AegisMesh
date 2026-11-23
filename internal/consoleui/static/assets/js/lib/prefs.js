// Operator preferences: how times are shown, the default time window, row
// density, color theme and motion. Kept on the server (GET/PUT
// /api/v1/me/preferences) when it offers them, in this browser otherwise.
//
// Every value is parsed against a closed list wherever it comes from (the
// server, browser storage, a form), so nothing read back can become a class
// name, a URL or behaviour. The browser copy also lets the console apply the
// choice before the first request returns, so the page never flashes from one
// theme to another.

export const PREF_VALUES = Object.freeze({
  timezone: Object.freeze(['utc', 'local']),
  default_window: Object.freeze(['1h', '24h', '7d']),
  density: Object.freeze(['comfortable', 'compact']),
  theme: Object.freeze(['system', 'dark', 'light']),
  reduce_motion: Object.freeze(['system', 'on']),
});
export const PREF_KEYS = Object.freeze(Object.keys(PREF_VALUES));
export const PREF_DEFAULTS = Object.freeze({ timezone: 'utc', default_window: '24h', density: 'comfortable', theme: 'system', reduce_motion: 'system' });

// Any object → a complete, valid preferences object. Unknown keys are
// dropped; unknown values fall back to the default for that key.
export function parsePreferences(raw) {
  const out = { ...PREF_DEFAULTS };
  if (!raw || typeof raw !== 'object') return out;
  for (const k of PREF_KEYS) {
    if (PREF_VALUES[k].includes(raw[k])) out[k] = raw[k];
  }
  return out;
}

// A patch with only valid keys and values, or null when nothing is valid.
export function cleanPatch(patch) {
  const out = {};
  for (const [k, v] of Object.entries(patch || {})) {
    if (PREF_KEYS.includes(k) && PREF_VALUES[k].includes(v)) out[k] = v;
  }
  return Object.keys(out).length ? out : null;
}

// Browser keys. Theme and density keep the keys they had before preferences
// existed, so an operator's earlier choice survives the upgrade.
const KEY = { theme: 'aegismesh.theme', density: 'aegismesh.density', rest: 'aegismesh.prefs' };

export function readLocalPrefs(storage) {
  const raw = {};
  try {
    raw.theme = storage?.getItem(KEY.theme);
    raw.density = storage?.getItem(KEY.density);
    const rest = JSON.parse(storage?.getItem(KEY.rest) || '{}');
    if (rest && typeof rest === 'object' && !Array.isArray(rest)) {
      for (const k of ['timezone', 'default_window', 'reduce_motion']) raw[k] = rest[k];
    }
  } catch {
    // Unreadable or malformed storage: defaults.
  }
  return parsePreferences(raw);
}

export function writeLocalPrefs(storage, prefs) {
  const p = parsePreferences(prefs);
  try {
    storage?.setItem(KEY.theme, p.theme);
    storage?.setItem(KEY.density, p.density);
    storage?.setItem(KEY.rest, JSON.stringify({ timezone: p.timezone, default_window: p.default_window, reduce_motion: p.reduce_motion }));
  } catch {
    // Storage may be unavailable; the choice still applies to this page.
  }
}

// Where the preferences live: 'server' (follows the account to any browser)
// or 'browser' (this server does not store them, or could not be reached).
export const PREF_SOURCES = Object.freeze({
  server: 'Saved to your account',
  browser: 'Saved in this browser only',
});

// The store. `load()` and `save(prefs)` talk to the server; `apply(prefs)`
// changes the page; `storage` is the browser copy; `isMissing(err)` tells an
// older server (no endpoint) from a failure. Changes are optimistic: applied
// at once, then saved; a rejected save puts the previous values back,
// re-applies them and rethrows, so the caller can say what happened.
export function createPrefsStore({ load, save, apply, storage, isMissing = () => false }) {
  let current = readLocalPrefs(storage);
  let source = 'browser';
  let pending = Promise.resolve();
  const listeners = new Set();
  const emit = () => { for (const fn of listeners) fn(current, source); };
  const set = (next) => {
    current = parsePreferences(next);
    apply(current);
    writeLocalPrefs(storage, current);
    emit();
  };

  return {
    get: () => current,
    source: () => source,
    subscribe(fn) {
      listeners.add(fn);
      return () => listeners.delete(fn);
    },
    // Apply the browser copy (before the first request).
    start() {
      apply(current);
    },
    // Ask the server once signed in. Its values win over the browser copy.
    async sync() {
      try {
        const remote = await load();
        source = 'server';
        set(remote);
      } catch (err) {
        source = 'browser';
        if (!isMissing(err)) throw err;
        emit();
      }
      return current;
    },
    // Forget the server after sign-out; keep applying the browser copy.
    reset() {
      source = 'browser';
    },
    update(patch) {
      const clean = cleanPatch(patch);
      if (!clean) return Promise.resolve(current);
      const prev = current;
      set({ ...current, ...clean });
      if (source !== 'server') return Promise.resolve(current);
      const wanted = current;
      // Saves are serialised, so a fast second change cannot be overtaken
      // by the first one's answer.
      const run = pending.then(() => save(wanted)).then(
        (saved) => {
          // A later change may already be on screen; keep it.
          if (current === wanted) set(saved || wanted);
          return current;
        },
        (err) => {
          if (current === wanted) set(prev);
          throw err;
        },
      );
      pending = run.catch(() => {});
      return run;
    },
  };
}
