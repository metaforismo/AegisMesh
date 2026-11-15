// Frame batching for live updates. A burst of stream messages becomes a few
// DOM writes: items queue up and flush once per animation frame, at most
// `perFrame` at a time, so one frame never builds hundreds of rows.

export function createBatcher({
  flush,
  perFrame = 50,
  schedule = (fn) => globalThis.requestAnimationFrame(fn),
  cancel = (id) => globalThis.cancelAnimationFrame(id),
} = {}) {
  if (typeof flush !== 'function') throw new TypeError('flush must be a function');
  let queue = [];
  let handle = null;
  let stopped = false;

  function run() {
    handle = null;
    if (stopped || !queue.length) return;
    const take = queue.slice(0, perFrame);
    queue = queue.slice(take.length);
    flush(take);
    if (queue.length) handle = schedule(run);
  }

  return {
    push(item) {
      if (stopped) return;
      queue.push(item);
      if (handle === null) handle = schedule(run);
    },
    // Drain everything now (e.g. before the view is torn down or re-sorted).
    flushNow() {
      if (handle !== null) cancel(handle);
      handle = null;
      while (!stopped && queue.length) run();
    },
    stop() {
      stopped = true;
      if (handle !== null) cancel(handle);
      handle = null;
      queue = [];
    },
    get size() {
      return queue.length;
    },
  };
}

// Keep a list capped: returns how many items to drop from the tail so that
// `current + incoming` stays within `max`.
export function overflow(current, incoming, max) {
  const total = Math.max(0, current) + Math.max(0, incoming);
  return Math.max(0, total - Math.max(0, max));
}
