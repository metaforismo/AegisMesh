// The Guide: what the console's words mean, from lib/glossary.js. Reachable
// from the nav (g h), the palette, and every "What is this?" tip, which links
// here with ?t=<id>. Everything on this page is interface text.

import { h, mount } from '../lib/dom.js';
import { glossaryGroups, glossaryEntry, isGlossaryId } from '../lib/glossary.js';
import { pageHead, panel, copyable } from '../ui/components.js';
import { icon } from '../ui/icons.js';

function entryPanel(e) {
  return h('section', { class: ['panel', 'guide__entry'], id: `term-${e.id}`, 'aria-labelledby': `term-${e.id}-title`, tabindex: '-1', 'data-term': e.id },
    h('div', { class: 'panel__head' }, h('h3', { class: 'panel__title', id: `term-${e.id}-title` }, e.term)),
    h('div', { class: 'panel__body' },
      h('p', { class: 'guide__short' }, e.short),
      h('div', { class: 'guide__body' }, e.body.map((p) => h('p', null, p))),
      e.cli ? h('p', { class: 'guide__cli' }, icon('keyboard', { size: 'sm' }), 'From the command line:', copyable(e.cli, { label: 'command' })) : null,
      e.see?.length ? h('p', { class: 'guide__see' }, h('span', { class: 'muted' }, 'See also'),
        e.see.map((id) => h('a', { href: `#/guide?t=${id}` }, glossaryEntry(id).term))) : null));
}

export default {
  title: 'Guide',
  async render(root, ctx) {
    const groups = glossaryGroups();
    const tocLinks = new Map();
    const toc = h('nav', { class: 'guide__toc', 'aria-label': 'Guide contents' },
      groups.map((g) => h('div', null,
        h('p', { class: 'caps' }, g.title),
        h('ul', null, g.entries.map((e) => {
          const a = h('a', { href: `#/guide?t=${e.id}` }, e.term);
          tocLinks.set(e.id, a);
          return h('li', null, a);
        })))));

    mount(root,
      pageHead({
        title: 'Guide',
        subtitle: 'What the console shows, in plain words: the terms on every screen, what they do and do not mean, and the limits of what the console can see.',
      }),
      h('div', { class: 'guide' },
        toc,
        h('div', { class: 'guide__entries' },
          groups.map((g) => [
            h('h2', { class: ['caps', 'guide__group'] }, g.title),
            ...g.entries.map(entryPanel),
          ]),
          panel({
            title: 'Keyboard',
            body: h('p', { class: 'guide__body' }, 'Press ', h('kbd', null, '?'), ' anywhere for every shortcut, and ', h('kbd', null, 'Ctrl'), ' ', h('kbd', null, 'K'), ' (', h('kbd', null, '⌘'), ' ', h('kbd', null, 'K'), ' on a Mac) to search events, sources, rules, screens and this guide.'),
          }))));

    let current = '';
    const focusTerm = (route, { scroll }) => {
      const id = isGlossaryId(route.query.t) ? route.query.t : '';
      if (current) {
        root.querySelector(`[data-term="${current}"]`)?.classList.remove('is-target');
        tocLinks.get(current)?.removeAttribute('aria-current');
      }
      current = id;
      if (!id) return;
      const el = root.querySelector(`[data-term="${id}"]`);
      el?.classList.add('is-target');
      tocLinks.get(id)?.setAttribute('aria-current', 'true');
      if (scroll && el) {
        el.scrollIntoView({ block: 'start' });
        el.focus({ preventScroll: true });
      }
    };
    focusTerm(ctx.route, { scroll: false });
    return {
      update: (r) => focusTerm(r, { scroll: true }),
      mounted: () => focusTerm(ctx.route, { scroll: true }),
    };
  },
};
