// Keyboard helpers: list cursor movement, typing-target detection and
// two-key "go to" sequences. Pure apart from reading element properties.

// Move a cursor within [0, length). -1 means "nothing selected yet": the
// first move down selects 0 and the first move up selects the last item.
export function moveIndex(current, delta, length, { wrap = false } = {}) {
  if (!Number.isInteger(length) || length <= 0) return -1;
  if (current < 0 || current >= length) return delta >= 0 ? 0 : length - 1;
  const next = current + delta;
  if (wrap) return ((next % length) + length) % length;
  return Math.min(length - 1, Math.max(0, next));
}

// True when keystrokes belong to a text field, so single-letter shortcuts
// must not fire.
export function isTypingTarget(el) {
  if (!el || typeof el !== 'object') return false;
  if (el.isContentEditable) return true;
  const tag = String(el.tagName || '').toLowerCase();
  if (tag === 'textarea' || tag === 'select') return true;
  if (tag !== 'input') return false;
  const type = String(el.type || 'text').toLowerCase();
  return !['button', 'checkbox', 'radio', 'submit', 'reset', 'range', 'color', 'file', 'image'].includes(type);
}

// Normalize a KeyboardEvent-like object to a chord string: "mod+k", "?",
// "j", "escape". "mod" is Cmd on Apple platforms and Ctrl elsewhere.
export function chordOf(e, { apple = false } = {}) {
  const key = String(e?.key || '');
  if (!key || key === 'Dead' || key === 'Unidentified') return '';
  const lower = key.length === 1 ? key.toLowerCase() : key.toLowerCase();
  const mod = apple ? e.metaKey : e.ctrlKey;
  const parts = [];
  if (mod) parts.push('mod');
  if (e.altKey) parts.push('alt');
  // Shift is implied by printable characters like "?"; only named keys keep it.
  if (e.shiftKey && key.length > 1) parts.push('shift');
  parts.push(lower);
  return parts.join('+');
}

// Two-key sequences such as "g" then "e". feed() returns the bound action
// when a sequence completes, null otherwise. A prefix waits `timeout` ms.
export function createSequences(bindings, { timeout = 1200, now = () => Date.now() } = {}) {
  let prefix = '';
  let at = 0;
  return {
    feed(chord) {
      const t = now();
      if (prefix && t - at <= timeout) {
        const action = bindings[`${prefix} ${chord}`];
        prefix = '';
        if (action) return action;
      }
      prefix = '';
      if (Object.keys(bindings).some((k) => k.startsWith(`${chord} `))) {
        prefix = chord;
        at = t;
      }
      return null;
    },
    get pending() {
      return prefix && now() - at <= timeout ? prefix : '';
    },
    reset() {
      prefix = '';
    },
  };
}
