import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createFakeDocument } from './fakedom.mjs';

globalThis.document = createFakeDocument();
const { sevChip, clsChip, evidence, table, badge, kv } = await import('../static/assets/js/ui/components.js');
const { SCREENS } = await import('../static/assets/js/screens/index.js');
const { parseHash } = await import('../static/assets/js/lib/route.js');

const cls = (el) => el.getAttribute('class');

test('severity chip: known values get a meter class, anything else is "none"', () => {
  assert.equal(cls(sevChip('high')), 'sev sev--high');
  assert.equal(sevChip('high').textContent, 'High');
  // An unexpected API value never becomes a class name.
  assert.equal(cls(sevChip('high evil')), 'sev sev--none');
  assert.equal(sevChip('').textContent, 'No finding');
});

test('classification chip uses a shape glyph and the word', () => {
  const el = clsChip('canary_invocation');
  assert.equal(el.textContent, 'Canary invocation');
  assert.equal(cls(el.childNodes[0]), 'glyph glyph--canary');
  assert.equal(cls(clsChip('<x>').childNodes[0]), 'glyph');
});

test('evidence is text, truncates by code point and keeps the full value in title', () => {
  const v = `<b>${'a'.repeat(50)}</b>🙂`;
  const el = evidence(v, { max: 10 });
  assert.equal(el.textContent.length <= 10, true);
  assert.equal(el.getAttribute('title'), v);
  assert.equal(evidence('short').getAttribute('title'), null);
  assert.equal(evidence('').textContent, '—');
  assert.equal(evidence('x', { block: true }).tagName, 'pre');
});

test('badges only accept known kinds', () => {
  assert.equal(cls(badge('ok', 'Up')), 'badge badge--ok');
  assert.equal(cls(badge('zzz', 'Up')), 'badge badge--neutral');
});

test('table cells carry interface-text labels for the stacked mobile layout', () => {
  const t = table({ columns: [{ label: 'Source', cell: (r) => r.s }, { label: 'Events', num: true, cell: (r) => String(r.n) }], rows: [{ s: '<i>', n: 3 }] });
  const tds = t.querySelectorAll((n) => n.tagName === 'td');
  assert.deepEqual(tds.map((td) => td.getAttribute('data-label')), ['Source', 'Events']);
  assert.equal(tds[0].textContent, '<i>');
  assert.equal(cls(tds[1]), 'num');
});

test('kv renders an em dash for empty values and skips undefined', () => {
  const dl = kv([['A', ''], ['B', undefined], ['C', 'x']]);
  assert.equal(dl.textContent, 'A—Cx');
});

test('every routable screen except login has a registered module', () => {
  const names = ['overview', 'events', 'event', 'sources', 'source', 'sensors', 'rules', 'recommendations', 'node', 'investigations', 'investigation', 'audit', 'fleet', 'fleet_node', 'guide', 'sessions', 'attack_session', 'techniques'];
  assert.deepEqual(Object.keys(SCREENS).sort(), [...names].sort());
  for (const n of names) assert.equal(typeof SCREENS[n].render, 'function', n);
  assert.equal(SCREENS.audit.role, 'admin');
  assert.equal(parseHash('#/login').name, 'login');
});
