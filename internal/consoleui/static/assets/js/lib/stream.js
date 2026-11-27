// Live observation stream over Server-Sent Events.
//
// The server filters the stream by origin only (`node=` on the URL, per the
// contract); callers re-apply every other filter locally. A browser
// EventSource cannot report the HTTP status of a failed connection, so on
// every drop we close it ourselves and ask GET /session whether the session
// expired (stop) or the server is merely unreachable (retry with backoff).

export class RingBuffer {
  constructor(capacity) {
    if (!Number.isInteger(capacity) || capacity < 1) throw new RangeError('capacity must be a positive integer');
    this.capacity = capacity;
    this.items = [];
    this.dropped = 0;
  }

  push(item) {
    this.items.push(item);
    if (this.items.length > this.capacity) {
      this.items.shift();
      this.dropped++;
    }
  }

  // Newest first, matching every list in the console.
  newestFirst() {
    return this.items.slice().reverse();
  }

  get size() {
    return this.items.length;
  }

  clear() {
    this.items = [];
    this.dropped = 0;
  }
}

// Exponential backoff with jitter in [50%, 100%] of the capped delay.
export function backoffDelay(attempt, { base = 1000, max = 30000, random = Math.random } = {}) {
  const exp = Math.min(max, base * 2 ** Math.max(0, attempt));
  return Math.round(exp * (0.5 + random() / 2));
}

// Minimal shape check before an observation reaches the UI.
export function parseObservation(data) {
  let ev;
  try {
    ev = JSON.parse(data);
  } catch {
    return null;
  }
  if (!ev || typeof ev !== 'object' || Array.isArray(ev)) return null;
  if (typeof ev.id !== 'string' || typeof ev.time !== 'string') return null;
  return ev;
}

export const STREAM_STATES = Object.freeze(['connecting', 'live', 'checking', 'reconnecting', 'expired', 'stopped']);

export function createLiveStream({
  url = '/api/v1/events/stream',
  EventSourceImpl = globalThis.EventSource,
  checkSession,
  onEvent = () => {},
  // Other named SSE events → handler(raw data string). The notification
  // stream uses this for `notification` and `unread`.
  events = {},
  onState = () => {},
  setTimer = (fn, ms) => setTimeout(fn, ms),
  clearTimer = (id) => clearTimeout(id),
  random = Math.random,
} = {}) {
  let es = null;
  let timer = null;
  let attempt = 0;
  let state = 'stopped';
  let lastHeartbeat = null;
  let generation = 0;

  function setState(next, detail = {}) {
    state = next;
    onState(next, { attempt, lastHeartbeat, ...detail });
  }

  function open() {
    const gen = ++generation;
    setState('connecting');
    es = new EventSourceImpl(url, { withCredentials: true });
    es.addEventListener('open', () => {
      if (gen !== generation) return;
      attempt = 0;
      setState('live');
    });
    es.addEventListener('observation', (msg) => {
      if (gen !== generation) return;
      const ev = parseObservation(msg.data);
      if (ev) onEvent(ev);
    });
    for (const [name, fn] of Object.entries(events)) {
      es.addEventListener(name, (msg) => {
        if (gen !== generation) return;
        fn(msg.data);
      });
    }
    es.addEventListener('heartbeat', (msg) => {
      if (gen !== generation) return;
      lastHeartbeat = safeTime(msg.data) || null;
    });
    es.addEventListener('error', () => {
      if (gen !== generation) return;
      dropped(gen);
    });
  }

  function safeTime(data) {
    try {
      const v = JSON.parse(data);
      return typeof v?.time === 'string' ? v.time : '';
    } catch {
      return '';
    }
  }

  async function dropped(gen) {
    if (es) es.close();
    es = null;
    setState('checking');
    let verdict = 'unavailable';
    try {
      verdict = (await checkSession()) ? 'ok' : 'expired';
    } catch (err) {
      verdict = err?.status === 401 ? 'expired' : 'unavailable';
    }
    if (gen !== generation || state === 'stopped') return;
    if (verdict === 'expired') {
      setState('expired');
      return;
    }
    const delay = backoffDelay(attempt, { random });
    attempt++;
    setState('reconnecting', { delay });
    timer = setTimer(() => {
      timer = null;
      if (gen === generation && state === 'reconnecting') open();
    }, delay);
  }

  return {
    start() {
      if (state !== 'stopped' && state !== 'expired') return;
      attempt = 0;
      open();
    },
    stop() {
      generation++;
      if (timer !== null) clearTimer(timer);
      timer = null;
      if (es) es.close();
      es = null;
      setState('stopped');
    },
    get state() {
      return state;
    },
  };
}
