// Measured contrast, from the token file itself. Every pair the design
// system relies on is computed with the WCAG 2 formula in both themes, so a
// token edit that breaks AA fails here instead of in a screenshot review.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

const css = await readFile(new URL('../static/assets/css/tokens.css', import.meta.url), 'utf8');

function block(source, opener) {
  const start = source.indexOf(opener);
  assert.ok(start >= 0, `missing ${opener}`);
  let depth = 0;
  for (let i = source.indexOf('{', start); i < source.length; i++) {
    if (source[i] === '{') depth++;
    else if (source[i] === '}' && --depth === 0) return source.slice(start, i + 1);
  }
  throw new Error(`unterminated ${opener}`);
}

function hexTokens(text) {
  const out = {};
  for (const m of text.matchAll(/(--[a-z0-9-]+):\s*(#[0-9a-f]{6})\b/gi)) out[m[1]] = m[2].toLowerCase();
  return out;
}

const light = hexTokens(block(css, ':root {'));
const dark = hexTokens(block(css, ':root[data-theme="dark"]'));
const darkMedia = hexTokens(block(block(css, '@media screen and (prefers-color-scheme: dark)'), ':root:not([data-theme="light"])'));

function luminance(hex) {
  const n = parseInt(hex.slice(1), 16);
  return [n >> 16, (n >> 8) & 255, n & 255]
    .map((v) => { const c = v / 255; return c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4; })
    .reduce((sum, c, i) => sum + c * [0.2126, 0.7152, 0.0722][i], 0);
}
export function ratio(a, b) {
  const [x, y] = [luminance(a), luminance(b)].sort((p, q) => q - p);
  return (x + 0.05) / (y + 0.05);
}

const TEXT = 4.5;
const UI = 3;
const SURFACES = ['--color-surface', '--color-surface-2', '--color-canvas'];
// [foreground, background(s), minimum, what]
const PAIRS = [
  ...['--color-ink', '--color-ink-2', '--color-ink-3', '--color-accent'].map((fg) => [fg, SURFACES, TEXT, 'text']),
  ['--color-ink-3', ['--color-surface-3', '--color-accent-soft'], TEXT, 'muted text on hover and selected rows'],
  ['--color-accent', ['--color-accent-soft'], TEXT, 'selected palette row'],
  ['--color-accent', ['--color-surface-3', '--color-canvas', '--color-surface'], UI, 'the 1px selection line (sidebar edge, segmented, tab, selected row)'],
  ['--color-accent-ink', ['--color-accent'], TEXT, 'primary button label'],
  ['--color-evidence-ink', ['--color-evidence-bg'], TEXT, 'evidence text'],
  ['--color-ok', ['--color-ok-soft'], TEXT, 'badge'],
  ['--color-warn', ['--color-warn-soft'], TEXT, 'badge'],
  ['--color-danger', ['--color-danger-soft'], TEXT, 'badge'],
  ['--color-info', ['--color-info-soft'], TEXT, 'badge'],
  ['--color-danger', ['--color-surface'], TEXT, 'error text'],
  ['--color-focus', SURFACES, UI, 'focus ring'],
  ['--color-border-strong', SURFACES, UI, 'control edges'],
  ...['info', 'low', 'medium', 'high', 'critical'].map((s) => [`--sev-${s}`, ['--color-surface', '--color-surface-2', '--sev-track'], UI, 'severity meter fill']),
  ...['interaction', 'canary', 'signal'].map((c) => [`--class-${c}`, ['--color-surface', '--color-surface-2'], UI, 'classification glyph and series']),
];

for (const [name, theme] of [['light', light], ['dark', dark]]) {
  test(`contrast (${name}): every relied-on pair meets WCAG AA`, () => {
    const failures = [];
    for (const [fg, bgs, min, what] of PAIRS) {
      for (const bg of bgs) {
        assert.ok(theme[fg] && theme[bg], `${name}: ${fg} or ${bg} is not a hex token`);
        const r = ratio(theme[fg], theme[bg]);
        if (r < min) failures.push(`${fg} on ${bg} (${what}): ${r.toFixed(2)}:1 < ${min}:1`);
      }
    }
    assert.deepEqual(failures, []);
  });
}

test('the media-query dark theme and the explicit dark theme are the same palette', () => {
  assert.deepEqual(darkMedia, dark);
});

test('print never inherits the dark palette', () => {
  // Both dark blocks sit inside screen-only media queries.
  assert.doesNotMatch(css, /@media \(prefers-color-scheme: dark\)/);
  const explicit = css.indexOf(':root[data-theme="dark"]');
  assert.match(css.slice(css.lastIndexOf('@media', explicit), explicit), /^@media screen \{\s*$/);
});

test('ratio matches published reference values', () => {
  assert.equal(ratio('#000000', '#ffffff').toFixed(2), '21.00');
  assert.equal(ratio('#767676', '#ffffff').toFixed(2), '4.54');
});
