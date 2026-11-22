// First-run tour: six short steps over the Overview and the shell. It is a
// non-modal popover (nothing behind it is inert, no dark overlay), every
// step names a real control, Esc or "Skip tour" ends it, and finishing or
// skipping is remembered in this browser. The Guide can start it again.
// All text is interface copy written here.

import { h } from '../lib/dom.js';
import { isApple } from './shell.js';
import { TOUR_KEY, tourStepsFor } from '../lib/viz.js';

const STEPS = [
  { target: '.brief', title: 'Start with the situation', text: 'A few sentences computed from this overview only. Every underlined clause opens the events behind it.' },
  { target: '.grid--stats', title: 'Counts, not alarms', text: 'Changes against the previous window are printed in neutral ink: more observations are not “worse”.' },
  { target: 'a.nav-link[data-route="sessions"]', title: 'Read a session as a story', text: 'Sessions group one source’s events and show the stages, the pace, and an automation reading stated as an observation.' },
  { target: 'a.nav-link[data-route="digest"]', title: 'A briefing on demand', text: 'The Digest compares the last 24 hours or 7 days with the window before, in plain sentences you can copy as Markdown or print.' },
  { target: '.top-search', title: 'Search everything', text: () => `Press ${isApple() ? '⌘' : 'Ctrl'} K to search events, sources, rules, sessions, techniques and the guide.` },
  { target: 'a.nav-link[data-route="guide"]', title: 'Every term, explained', text: 'The Guide explains each word the console uses and its limits. You can restart this tour from there.' },
];

let active = null;

const store = () => {
  try {
    return globalThis.localStorage || null;
  } catch {
    return null;
  }
};

export function tourDone() {
  try {
    return store()?.getItem(TOUR_KEY) === 'done';
  } catch {
    return true;
  }
}

export function resetTour() {
  try {
    store()?.removeItem(TOUR_KEY);
  } catch {
    // Storage unavailable: the tour simply offers itself again.
  }
}

function finish() {
  try {
    store()?.setItem(TOUR_KEY, 'done');
  } catch {
    // Not remembered; it ends for this page anyway.
  }
  active?.close();
}

export function startTour() {
  if (active) return;
  const visible = (sel) => {
    const el = document.querySelector(sel);
    const r = el?.getBoundingClientRect?.();
    return Boolean(r && r.width > 0 && r.height > 0);
  };
  const steps = tourStepsFor(STEPS, visible);
  if (!steps.length) return;
  let i = 0;
  let target = null;
  const title = h('p', { class: 'tour__title', id: 'tour-title', tabindex: '-1' });
  const text = h('p', { class: 'tour__text' });
  const count = h('span', { class: 'tour__count' });
  const back = h('button', { class: ['btn', 'btn--sm', 'btn--ghost'], type: 'button' }, 'Back');
  const next = h('button', { class: ['btn', 'btn--sm', 'btn--primary'], type: 'button' }, 'Next');
  const skip = h('button', { class: ['btn', 'btn--sm', 'btn--ghost', 'tour__skip'], type: 'button' }, 'Skip tour');
  const box = h('div', { class: 'tour', popover: 'manual', role: 'dialog', 'aria-modal': 'false', 'aria-labelledby': 'tour-title' },
    count, title, text, h('div', { class: 'tour__actions' }, skip, h('span', { class: 'top-spacer' }), back, next));
  document.body.appendChild(box);

  const place = () => {
    const r = target.getBoundingClientRect();
    const vw = document.documentElement.clientWidth;
    const vh = window.innerHeight;
    const w = Math.min(box.offsetWidth || 320, vw - 16);
    const hgt = box.offsetHeight || 160;
    let top = r.bottom + 10;
    let left = r.left;
    if (r.right + 12 + w < vw && r.height > 120) { left = r.right + 12; top = r.top; }
    if (top + hgt > vh - 8) top = Math.max(8, r.top - hgt - 10);
    box.style.left = `${Math.round(Math.max(8, Math.min(left, vw - w - 8)))}px`;
    box.style.top = `${Math.round(Math.max(8, top))}px`;
  };
  const show = (k) => {
    target?.classList.remove('tour-target');
    i = k;
    const s = steps[i];
    target = document.querySelector(s.target);
    target.classList.add('tour-target');
    target.scrollIntoView?.({ block: 'nearest' });
    title.textContent = s.title;
    text.textContent = typeof s.text === 'function' ? s.text() : s.text;
    count.textContent = `${i + 1} of ${steps.length}`;
    back.disabled = i === 0;
    next.textContent = i === steps.length - 1 ? 'Done' : 'Next';
    place();
    title.focus({ preventScroll: true });
  };
  const onKey = (e) => { if (e.key === 'Escape') { e.preventDefault(); finish(); } };
  const onResize = () => target && place();
  back.addEventListener('click', () => show(Math.max(0, i - 1)));
  next.addEventListener('click', () => (i === steps.length - 1 ? finish() : show(i + 1)));
  skip.addEventListener('click', finish);
  box.addEventListener('keydown', onKey);
  window.addEventListener('resize', onResize);
  window.addEventListener('hashchange', finish, { once: true });

  active = {
    close() {
      target?.classList.remove('tour-target');
      window.removeEventListener('resize', onResize);
      try {
        box.hidePopover?.();
      } catch {
        // Already hidden.
      }
      box.remove();
      active = null;
    },
  };
  box.showPopover?.();
  show(0);
}
