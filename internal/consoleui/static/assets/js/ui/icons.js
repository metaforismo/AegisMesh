// The console icon set. Every icon is drawn on one 16-unit grid with a
// 1.5 stroke and round caps (styled by .icon in base.css), so icons in the
// nav, buttons, states and statuses share weight and optical size. Paths are
// constants in this file: nothing here is built from API data.

import { svg } from '../lib/dom.js';

const circle = (cx, cy, r) => `M${cx - r} ${cy}a${r} ${r} 0 1 0 ${2 * r} 0a${r} ${r} 0 1 0 ${-2 * r} 0`;
const rrect = (x, y, w, h, r) =>
  `M${x + r} ${y}h${w - 2 * r}a${r} ${r} 0 0 1 ${r} ${r}v${h - 2 * r}a${r} ${r} 0 0 1 ${-r} ${r}h${-(w - 2 * r)}a${r} ${r} 0 0 1 ${-r} ${-r}v${-(h - 2 * r)}a${r} ${r} 0 0 1 ${r} ${-r}z`;

// name → path data (string) or [[d, className], …] for mixed fill/stroke.
const PATHS = {
  overview: `${rrect(2, 2, 5, 5, 1.2)}${rrect(9, 2, 5, 3, 1)}${rrect(9, 7, 5, 7, 1.2)}${rrect(2, 9, 5, 5, 1.2)}`,
  events: 'M1.5 8.5h2.6l1.9-5 3.6 9 1.9-4h3',
  sources: `${circle(8, 8, 5.5)}${circle(8, 8, 1.6)}M8 1v2.5M8 12.5V15M1 8h2.5M12.5 8H15`,
  investigations: 'M1.75 4.25a1 1 0 0 1 1-1h3.1l1.5 1.5h5.9a1 1 0 0 1 1 1v6.5a1 1 0 0 1-1 1H2.75a1 1 0 0 1-1-1zM5.5 9.25h5',
  recommendations: 'M6 13.75h4M6.4 11.75h3.2M8 1.75a4.25 4.25 0 0 0-2.5 7.7c.35.26.5.6.5 1v.55h4v-.55c0-.4.15-.74.5-1A4.25 4.25 0 0 0 8 1.75z',
  sensors: `${circle(8, 8, 1.4)}M5 11a4.25 4.25 0 0 1 0-6M11 5a4.25 4.25 0 0 1 0 6M2.75 13.25a7.4 7.4 0 0 1 0-10.5M13.25 2.75a7.4 7.4 0 0 1 0 10.5`,
  rules: 'M2 4.25l1.25 1.25 2.25-2.25M2 10.75l1.25 1.25 2.25-2.25M8 4.5h6M8 11h6',
  node: `${rrect(2, 2.5, 12, 4.5, 1.2)}${rrect(2, 9, 12, 4.5, 1.2)}M4.75 4.75h.01M4.75 11.25h.01M8 4.75h3.5M8 11.25h3.5`,
  fleet: `${circle(8, 3.25, 1.75)}${circle(3.25, 12.25, 1.75)}${circle(12.75, 12.25, 1.75)}M7.1 4.8l-3 5.9M8.9 4.8l3 5.9M5 12.25h6`,
  audit: 'M6.6 9.4l2.8-2.8M7.2 4.6l1.1-1.1a2.75 2.75 0 0 1 3.9 3.9l-1.1 1.1M8.8 11.4l-1.1 1.1a2.75 2.75 0 0 1-3.9-3.9l1.1-1.1',
  search: `${circle(7, 7, 4.5)}M10.4 10.4L14 14`,
  copy: `${rrect(5.5, 5.5, 8.5, 8.5, 1.5)}M10.5 3.25v-.5a.75.75 0 0 0-.75-.75H2.75a.75.75 0 0 0-.75.75v7a.75.75 0 0 0 .75.75h.5`,
  check: 'M3 8.5l3.25 3.25L13 5',
  close: 'M4 4l8 8M12 4l-8 8',
  'chevron-right': 'M6 3.5L10.5 8 6 12.5',
  'chevron-left': 'M10 3.5L5.5 8l4.5 4.5',
  'chevron-up': 'M3.5 10L8 5.5l4.5 4.5',
  'chevron-down': 'M3.5 6L8 10.5 12.5 6',
  'arrow-left': 'M13 8H3M7 4L3 8l4 4',
  'arrow-up': 'M8 13V3M4 7l4-4 4 4',
  'trend-up': 'M3.5 12.5l9-9M5.5 3.5h7v7',
  'trend-down': 'M3.5 3.5l9 9M12.5 5.5v7h-7',
  'trend-flat': 'M2.5 8h11M10 4.5L13.5 8 10 11.5',
  external: 'M9 2.5h4.5V7M13.5 2.5L7.5 8.5M12 9.5v3a1 1 0 0 1-1 1H3.5a1 1 0 0 1-1-1V5a1 1 0 0 1 1-1h3',
  pause: 'M5.5 3.5v9M10.5 3.5v9',
  play: [['M4.75 3.1v9.8a.5.5 0 0 0 .76.43l7.6-4.9a.5.5 0 0 0 0-.86l-7.6-4.9a.5.5 0 0 0-.76.43z', 'fill']],
  live: `${circle(8, 8, 1.75)}M4.5 11.5a5 5 0 0 1 0-7M11.5 4.5a5 5 0 0 1 0 7`,
  sun: `${circle(8, 8, 3)}M8 1.25v1.5M8 13.25v1.5M1.25 8h1.5M13.25 8h1.5M3.2 3.2l1.05 1.05M11.75 11.75l1.05 1.05M3.2 12.8l1.05-1.05M11.75 4.25l1.05-1.05`,
  moon: 'M13.5 9.6A5.75 5.75 0 0 1 6.4 2.5a5.75 5.75 0 1 0 7.1 7.1z',
  monitor: `${rrect(1.75, 2.5, 12.5, 8.5, 1.25)}M5.5 14h5M8 11v3`,
  'sign-out': 'M6 2.5H3.5a1 1 0 0 0-1 1v9a1 1 0 0 0 1 1H6M10.25 5L13.25 8l-3 3M13.25 8H6',
  filter: 'M2 3.5h12l-4.75 5.25V13l-2.5 1.25v-5.5z',
  keyboard: `${rrect(1.25, 3.75, 13.5, 8.5, 1.5)}M4.25 6.75h.01M6.75 6.75h.01M9.25 6.75h.01M11.75 6.75h.01M5 9.5h6`,
  warn: 'M8 2.25l6.25 11H1.75zM8 6.5v3M8 11.5h.01',
  info: `${circle(8, 8, 6.25)}M8 7.25v4M8 4.75h.01`,
  inbox: 'M1.75 9.25l1.9-5.5h8.7l1.9 5.5v3a1 1 0 0 1-1 1H2.75a1 1 0 0 1-1-1zM1.75 9.25h3.5l1 1.5h3.5l1-1.5h3.5',
  refresh: 'M13.25 2.75v3.5h-3.5M2.75 13.25v-3.5h3.5M12.6 6.25A5 5 0 0 0 3.5 5.6M3.4 9.75a5 5 0 0 0 9.1.65',
  menu: 'M2.5 4h11M2.5 8h11M2.5 12h11',
  // Row density: rows spread apart (comfortable) or packed (compact).
  'rows-loose': 'M3 2.5h10M3 13.5h10M8 5.5v5M6.25 7.25 8 5.5l1.75 1.75M6.25 8.75 8 10.5l1.75-1.75',
  'rows-dense': 'M3 2.5h10M3 5.5h10M3 8h10M3 10.5h10M3 13.5h10',
  shield: 'M8 1.5l5.5 2.1v4.2c0 3.3-2.3 5.9-5.5 6.7-3.2-.8-5.5-3.4-5.5-6.7V3.6zM5.6 8l1.7 1.7 3.2-3.2',
  plus: 'M8 3v10M3 8h10',
  clock: `${circle(8, 8, 6.25)}M8 4.5V8l2.25 1.5`,
  link: 'M6.6 9.4l2.8-2.8M7.2 4.6l1.1-1.1a2.75 2.75 0 0 1 3.9 3.9l-1.1 1.1M8.8 11.4l-1.1 1.1a2.75 2.75 0 0 1-3.9-3.9l1.1-1.1',
  'corner-down': 'M3 3v5.5a1.5 1.5 0 0 0 1.5 1.5H13M10 7l3 3-3 3',
  // Tenant: stacked planes (one process, separate logical views).
  tenant: 'M8 2.25l5.75 2.9L8 8.05 2.25 5.15zM2.25 8.1L8 11l5.75-2.9M2.25 11L8 13.9l5.75-2.9',
  key: `${circle(5, 10.5, 2.75)}M7 8.5l6.25-6.25M10.5 5l1.75 1.75M12.25 3.25l1.25 1.25`,
  'sign-in': 'M10 2.5h2.5a1 1 0 0 1 1 1v9a1 1 0 0 1-1 1H10M5.75 5l3 3-3 3M8.75 8H1.75',
  // "What is this?": a question mark in a ring.
  help: `${circle(8, 8, 6.25)}M6.25 6.25a1.8 1.8 0 0 1 3.5.55c0 1.2-1.75 1.45-1.75 2.6M8 11.4v.1`,
  // The guide: an open book.
  guide: 'M8 4.25C6.9 3.3 5.1 2.9 2.25 3v9.5c2.85-.1 4.65.3 5.75 1.25 1.1-.95 2.9-1.35 5.75-1.25V3C10.9 2.9 9.1 3.3 8 4.25zM8 4.25v9.5',
  // Saved views: a bookmark ribbon.
  bookmark: 'M4.25 2.25h7.5v11.5L8 10.9l-3.75 2.85z',
  // Session story: a vertical spine with three stops.
  story: `${circle(4, 3.5, 1.5)}${circle(4, 8, 1.5)}${circle(4, 12.5, 1.5)}M4 5v1.5M4 9.5V11M7.5 3.5h6M7.5 8h4.5M7.5 12.5h6`,
  // Technique matrix: a 3×3 grid with one cell filled in outline.
  matrix: 'M2 2h3.5v3.5H2zM6.25 2h3.5v3.5h-3.5zM10.5 2H14v3.5h-3.5zM2 6.25h3.5v3.5H2zM6.25 6.25h3.5v3.5h-3.5zM10.5 6.25H14v3.5h-3.5zM2 10.5h3.5V14H2zM6.25 10.5h3.5V14h-3.5zM10.5 10.5H14V14h-3.5z',
  download: 'M8 2v8.5M4.75 7.25 8 10.5l3.25-3.25M2.5 13.5h11',
  // Decoy: a lure (diamond) with a core; nothing real inside.
  decoy: `M8 1.75 14.25 8 8 14.25 1.75 8z${circle(8, 8, 1.6)}`,
  // Digest: a briefing sheet with a headline rule and lines of text.
  digest: `${rrect(3, 1.75, 10, 12.5, 1.25)}M5.5 4.75h5M5.5 7.5h5M5.5 9.75h5M5.5 12h3`,
  // Agent canary: a marker flag.
  flag: 'M3.75 14.25V2.25M3.75 2.75h8.5l-2 3 2 3h-8.5',
  // Print: a printer with a sheet.
  print: `${rrect(1.75, 6, 12.5, 5.5, 1.2)}M4.5 6V2h7v4M4.5 9.5h7V14h-7z`,
  // Cadence: evenly spaced ticks on a baseline.
  cadence: 'M1.75 13h12.5M3.5 13V8M6.5 13V5M9.5 13V8.5M12.5 13V6',
  // Campaign: three lanes that pass through the same two stops.
  campaign: `M1.5 3.5h13M1.5 8h13M1.5 12.5h13${circle(5.5, 3.5, 1.1)}${circle(5.5, 8, 1.1)}${circle(5.5, 12.5, 1.1)}${circle(10.5, 3.5, 1.1)}${circle(10.5, 8, 1.1)}${circle(10.5, 12.5, 1.1)}`,
  // Settings: three sliders, each with its knob.
  settings: `M2 4h6M11 4h3M2 8h2M7 8h7M2 12h8M13 12h1${circle(9.5, 4, 1.5)}${circle(5.5, 8, 1.5)}${circle(11.5, 12, 1.5)}`,
  // Profile: one person.
  user: `${circle(8, 5.25, 2.75)}M2.75 14a5.25 5.25 0 0 1 10.5 0`,
  // Accounts: two people.
  users: `${circle(6, 5.5, 2.4)}M1.5 13.75a4.5 4.5 0 0 1 9 0M10.25 3.4a2.4 2.4 0 0 1 0 4.4M12.25 9.6a4.5 4.5 0 0 1 2.25 4.15`,
  // Sessions: a screen and a phone.
  devices: `${rrect(1.5, 2.75, 9.5, 7, 1)}M4 13.25h4.5M6.25 9.75v3.5${rrect(11.5, 6, 3, 7.25, 0.8)}`,
  // Data and retention: a stack of records.
  database: 'M2.75 4c0-1.1 2.35-2 5.25-2s5.25.9 5.25 2-2.35 2-5.25 2-5.25-.9-5.25-2zM2.75 4v8c0 1.1 2.35 2 5.25 2s5.25-.9 5.25-2V4M2.75 8c0 1.1 2.35 2 5.25 2s5.25-.9 5.25-2',
  // Posture: a clipboard with a checklist.
  posture: `${rrect(3, 2.5, 10, 12, 1.25)}M6 1.5h4v2H6zM5.5 7l1 1 1.75-1.75M5.5 11l1 1 1.75-1.75M9.75 7.5h1.75M9.75 11.5h1.75`,
};

export const ICON_NAMES = Object.freeze(Object.keys(PATHS));

// icon('search') → <svg class="icon"> … ; size: xs | sm | md (default) | lg.
export function icon(name, { size = 'md', className } = {}) {
  const def = PATHS[name];
  if (!def) throw new Error(`unknown icon: ${name}`);
  const parts = typeof def === 'string' ? [[def, null]] : def;
  return svg('svg', {
    class: ['icon', size !== 'md' ? `icon--${size}` : '', `icon--${name}`, className || ''],
    viewBox: '0 0 16 16', 'aria-hidden': 'true', focusable: 'false',
  }, parts.map(([d, cls]) => svg('path', { d, class: cls })));
}

// The brand mark: a net closed around a lure. A diamond perimeter (the
// protective mesh), four links reaching in from its sides, and a solid
// diamond at the centre that the links do not touch (the decoy, held in the
// net). One colour (currentColor), drawn on a 24-unit grid; legible from
// 16px. The same paths are in site/assets/brand/*.svg, the favicons and the
// landing page; webtest/brand.test.mjs keeps them identical.
export const BRAND_PATHS = Object.freeze({
  net: 'M12 2.75 21.25 12 12 21.25 2.75 12z',
  links: 'M7.4 7.4l2.4 2.4M16.6 16.6l-2.4-2.4M16.6 7.4l-2.4 2.4M7.4 16.6l2.4-2.4',
  lure: 'M12 9.6 14.4 12 12 14.4 9.6 12z',
});

export function brandMark() {
  return svg('svg', { class: 'brand__mark', viewBox: '0 0 24 24', 'aria-hidden': 'true', focusable: 'false' },
    svg('path', { class: 'brand__net', d: BRAND_PATHS.net }),
    svg('path', { class: 'brand__links', d: BRAND_PATHS.links }),
    svg('path', { class: 'brand__lure', d: BRAND_PATHS.lure }));
}
