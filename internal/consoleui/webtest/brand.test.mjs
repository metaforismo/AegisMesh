// The brand mark is drawn once (ui/icons.js BRAND_PATHS) and copied into the
// favicons, the brand files, the landing page and the design-system page.
// Every copy must carry the same three paths, and the old shield must be gone.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile, readdir } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createFakeDocument } from './fakedom.mjs';

globalThis.document = createFakeDocument();
const { BRAND_PATHS, brandMark } = await import('../static/assets/js/ui/icons.js');
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');
const read = (p) => readFile(path.join(ROOT, p), 'utf8');

test('the mark: three paths in one colour, no fixed fill in the console', () => {
  const el = brandMark();
  assert.deepEqual(el.childNodes.map((p) => p.getAttribute('d')), [BRAND_PATHS.net, BRAND_PATHS.links, BRAND_PATHS.lure]);
  assert.ok(el.childNodes.every((p) => p.getAttribute('fill') === null), 'colour comes from CSS (currentColor)');
  assert.equal(el.getAttribute('aria-hidden'), 'true');
});

test('every copy of the mark matches ui/icons.js', async () => {
  const brand = (await readdir(path.join(ROOT, 'site/assets/brand'))).map((f) => `site/assets/brand/${f}`);
  const files = ['internal/consoleui/static/assets/icon.svg', 'site/assets/icon.svg', 'site/index.html', 'site/design-system.html', ...brand];
  assert.ok(brand.length >= 6);
  for (const f of files) {
    const s = await read(f);
    for (const d of Object.values(BRAND_PATHS)) assert.ok(s.includes(`d="${d}"`), `${f} carries ${d}`);
    assert.doesNotMatch(s, /M12 1\.75 3\.75 4\.9|M12 2\.5 4 5\.5v6\.2/, `${f} still has the old shield`);
  }
});
