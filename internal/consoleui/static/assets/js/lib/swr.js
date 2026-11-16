// A small stale-while-revalidate cache for read-only GETs.
//
// - Requests in flight are shared, so a hover prefetch and the render that
//   follows it make one request.
// - A response younger than `freshMs` is reused as is.
// - With `allowStale` (back/forward navigation) a response younger than
//   `staleMs` is returned at once and refreshed in the background;
//   `onUpdate(key)` fires if the refreshed value differs.
// - Mutations call invalidate(): nothing written by the operator is ever
//   shown from cache.
//
// Only what the console server already returned is kept, in memory, for the
// life of the page. Nothing goes to storage.

export function createSwr({ freshMs = 10000, staleMs = 120000, maxEntries = 64, now = () => Date.now(), onUpdate = () => {} } = {}) {
  const entries = new Map(); // key → { value, time, inflight, text }
  // Bumped by invalidate(). A request that started before an invalidation
  // (a hover prefetch, say, just before a write or a tenant switch) must not
  // put its now-stale answer back into the cache when it lands.
  let generation = 0;

  function store(key, value) {
    let text = '';
    try {
      text = JSON.stringify(value);
    } catch {
      text = '';
    }
    const prev = entries.get(key);
    const changed = prev && 'value' in prev ? prev.text !== text : false;
    entries.delete(key);
    entries.set(key, { value, time: now(), inflight: null, text });
    while (entries.size > maxEntries) entries.delete(entries.keys().next().value);
    return changed;
  }

  function load(key, fetcher, { background = false } = {}) {
    const e = entries.get(key);
    if (e?.inflight) return e.inflight;
    const gen = generation;
    const p = Promise.resolve().then(fetcher).then(
      (value) => {
        if (gen !== generation) return value;
        const changed = store(key, value);
        if (background && changed) onUpdate(key);
        return value;
      },
      (err) => {
        const cur = gen === generation ? entries.get(key) : null;
        if (cur) {
          cur.inflight = null;
          if (!('value' in cur)) entries.delete(key);
        }
        throw err;
      });
    if (e) e.inflight = p;
    else entries.set(key, { inflight: p, time: 0 });
    return p;
  }

  return {
    get(key, fetcher, { allowStale = false } = {}) {
      const e = entries.get(key);
      const age = e && 'value' in e ? now() - e.time : Infinity;
      if (e?.inflight && !(allowStale && age < staleMs)) return e.inflight;
      if (age < freshMs) return Promise.resolve(e.value);
      if (allowStale && age < staleMs) {
        load(key, fetcher, { background: true }).catch(() => {});
        return Promise.resolve(e.value);
      }
      return load(key, fetcher);
    },
    prefetch(key, fetcher) {
      const e = entries.get(key);
      const age = e && 'value' in e ? now() - e.time : Infinity;
      if (e?.inflight || age < freshMs) return;
      load(key, fetcher).catch(() => {});
    },
    invalidate() {
      generation++;
      entries.clear();
    },
    has(key) {
      return entries.has(key);
    },
    get size() {
      return entries.size;
    },
  };
}

// Reject when `signal` aborts, without cancelling the shared request: other
// callers (a prefetch, a later render) can still use its result.
export function abortable(promise, signal) {
  if (!signal) return promise;
  if (signal.aborted) return Promise.reject(abortError());
  return new Promise((resolve, reject) => {
    const onAbort = () => reject(abortError());
    signal.addEventListener('abort', onAbort, { once: true });
    promise.then(
      (v) => { signal.removeEventListener('abort', onAbort); resolve(v); },
      (e) => { signal.removeEventListener('abort', onAbort); reject(e); });
  });
}

function abortError() {
  const err = new Error('The operation was aborted.');
  err.name = 'AbortError';
  return err;
}
