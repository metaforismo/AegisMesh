// First-run tour: seven short steps over the Overview and the shell. It is a
// non-modal popover (nothing behind it is inert, no dark overlay), every
// step names a real control, Esc or "Skip tour" ends it, and finishing or
// skipping is remembered in this browser. The Guide can start it again.
// All text is interface copy written here.

import { h } from '../lib/dom.js';
import { isApple } from './shell.js';
import { TOUR_KEY, tourStepsFor, tourPlacement } from '../lib/viz.js';

const STEPS = [
  // `avoid`: the step's key content, which the popover must not cover
  // either (the brief sits beside its count list).
  { target: '.brief', avoid: ['.tally'], title: 'Start with the situation', text: 'A few sentences computed from this overview only. Every underlined clause opens the events behind it.' },
  { target: '.tally', avoid: ['.brief'], title: 'Counts, not alarms', text: 'Changes against the previous window are printed in neutral ink: more observations are not “worse”.' },
  { target: 'a.nav-link[data-route="sessions"]', title: 'Read a session as a story', text: 'Sessions group one source’s events and show the stages, the pace, and an automation reading stated as an observation.' },
  { target: 'a.nav-link[data-route="campaigns"]', title: 'Several sources, one playbook', text: 'Campaigns line up sessions from different sources that took the same steps, lane by lane. Similar behaviour, never proof of one operator.' },
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

  // Placed so it never covers the element it describes nor the step's key
  // content (lib/viz.js tourPlacement), at any width.
  let avoidSel = [];
  const place = () => {
    const r = target.getBoundingClientRect();
    const viewport = { width: document.documentElement.clientWidth, height: window.innerHeight };
    const size = { width: box.offsetWidth || 320, height: box.offsetHeight || 160 };
    const avoid = avoidSel.map((sel) => document.querySelector(sel)?.getBoundingClientRect()).filter((a) => a && a.width && a.height);
    const p = tourPlacement(r, size, viewport, avoid);
    box.style.left = `${p.left}px`;
    box.style.top = `${p.top}px`;
    box.dataset.side = p.side;
  };
  const show = (k) => {
    target?.classList.remove('tour-target');
    i = k;
    const s = steps[i];
    target = document.querySelector(s.target);
    avoidSel = Array.isArray(s.avoid) ? s.avoid : [];
    target.classList.add('tour-target');
    title.textContent = s.title;
    text.textContent = typeof s.text === 'function' ? s.text() : s.text;
    count.textContent = `${i + 1} of ${steps.length}`;
    back.disabled = i === 0;
    next.textContent = i === steps.length - 1 ? 'Done' : 'Next';
    target.scrollIntoView?.({ block: 'nearest' });
    // Make room for the popover beneath the target when scrolling can: the
    // page moves up by what is missing, as long as the target stays clear
    // of the top bar. Otherwise tourPlacement finds the least covered spot.
    const r0 = target.getBoundingClientRect();
    const topbar = document.querySelector('.shell__top')?.getBoundingClientRect().bottom || 0;
    const need = r0.bottom + 10 + (box.offsetHeight || 200) + 8 - window.innerHeight;
    if (need > 0 && r0.top - need >= topbar + 8 && target.closest('.shell__main')) window.scrollBy?.(0, need);
    place();
    title.focus({ preventScroll: true });
  };
  const onKey = (e) => { if (e.key === 'Escape') { e.preventDefault(); finish(); } };
  const onResize = () => target && place();
  const onScroll = () => target && place();
  back.addEventListener('click', () => show(Math.max(0, i - 1)));
  next.addEventListener('click', () => (i === steps.length - 1 ? finish() : show(i + 1)));
  skip.addEventListener('click', finish);
  box.addEventListener('keydown', onKey);
  window.addEventListener('resize', onResize);
  window.addEventListener('scroll', onScroll, { passive: true });
  window.addEventListener('hashchange', finish, { once: true });

  active = {
    close() {
      target?.classList.remove('tour-target');
      window.removeEventListener('resize', onResize);
      window.removeEventListener('scroll', onScroll);
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
