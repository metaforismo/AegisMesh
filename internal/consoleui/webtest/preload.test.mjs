// The first screen's module graph is preloaded in full: every module that
// main.js and the Overview import statically (and nothing else) has a
// <link rel="modulepreload"> in index.html, so the browser fetches the
// whole graph in parallel instead of discovering it level by level.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const STATIC = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../static');
const IMPORT = /^import\s[^'"]*?from\s+'(\.[^']+)';/gm;

export function staticGraph(entries) {
  const seen = new Set();
  const walk = (rel) => {
    if (seen.has(rel)) return;
    seen.add(rel);
    const src = readFileSync(path.join(STATIC, rel), 'utf8');
    for (const m of src.matchAll(IMPORT)) walk(path.posix.join(path.posix.dirname(rel), m[1]));
  };
  entries.forEach(walk);
  return seen;
}

test('index.html preloads exactly the first screen module graph', () => {
  const graph = staticGraph(['assets/js/main.js', 'assets/js/screens/overview.js']);
  const html = readFileSync(path.join(STATIC, 'index.html'), 'utf8');
  const preloads = new Set([...html.matchAll(/<link rel="modulepreload" href="([^"]+)">/g)].map((m) => m[1]));
  const missing = [...graph].filter((x) => !preloads.has(x)).sort();
  const extra = [...preloads].filter((x) => !graph.has(x)).sort();
  assert.deepEqual(missing, [], 'modules the first screen imports but index.html does not preload');
  assert.deepEqual(extra, [], 'preloads the first screen never imports');
});

test('heavy screen-only modules stay off the first screen', () => {
  const graph = staticGraph(['assets/js/main.js', 'assets/js/screens/overview.js']);
  for (const m of ['assets/js/lib/catalogs.js', 'assets/js/ui/palette.js', 'assets/js/screens/login.js', 'assets/js/ui/tour.js', 'assets/js/screens/events.js']) {
    assert.ok(!graph.has(m), `${m} is not needed to draw the Overview`);
  }
});
