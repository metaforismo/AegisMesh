import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile, access } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');
const CONSOLE_CSS = path.join(ROOT, 'internal/consoleui/static/assets/css');
const SITE = path.join(ROOT, 'site');

test('shared design-system CSS is byte-identical in the console and the site', async () => {
  for (const name of ['tokens.css', 'base.css', 'components.css']) {
    const a = await readFile(path.join(CONSOLE_CSS, name), 'utf8');
    const b = await readFile(path.join(SITE, 'assets/css', name), 'utf8');
    assert.equal(b, a, `${name} drifted: copy internal/consoleui/static/assets/css/${name} to site/assets/css/`);
  }
});

test('site pages load no scripts and only local or project assets', async () => {
  for (const page of ['index.html', 'design-system.html']) {
    const html = await readFile(path.join(SITE, page), 'utf8');
    assert.doesNotMatch(html, /<script\b/i, `${page} must not load scripts`);
    assert.doesNotMatch(html, /\sstyle\s*=/i, `${page} must not use inline styles`);
    assert.doesNotMatch(html, /\son[a-z]+\s*=/i, `${page} must not use inline handlers`);
    for (const [, ref] of html.matchAll(/(?:href|src)="([^"]+)"/g)) {
      if (ref.startsWith('#') || ref === './') continue;
      if (/^https?:\/\//.test(ref)) {
        assert.ok(ref.startsWith('https://github.com/metaforismo/AegisMesh'), `${page}: unexpected external link ${ref}`);
        continue;
      }
      await access(path.join(SITE, ref.split('#')[0]));
    }
    for (const [, id] of html.matchAll(/href="#([^"]+)"/g)) {
      assert.match(html, new RegExp(`id="${id}"`), `${page}: anchor #${id} has no target`);
    }
  }
});
