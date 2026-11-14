import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createDom, isSafeHref, UnsafeAttributeError } from '../static/assets/js/lib/dom.js';
import { createFakeDocument } from './fakedom.mjs';

const { h, svg, frag } = createDom(createFakeDocument());

test('children are text nodes, never parsed markup', () => {
  const evil = '<img src=x onerror=alert(1)>';
  const el = h('p', null, evil);
  assert.equal(el.childNodes.length, 1);
  assert.equal(el.childNodes[0].nodeType, 3);
  assert.equal(el.textContent, evil);
});

test('text prop sets textContent', () => {
  assert.equal(h('span', { text: '<b>x</b>' }).textContent, '<b>x</b>');
});

test('disallowed attributes throw', () => {
  for (const name of ['onclick', 'style', 'srcdoc', 'src', 'formaction', 'innerHTML']) {
    assert.throws(() => h('div', { [name]: 'x' }), UnsafeAttributeError, name);
  }
});

test('aria- and data- attributes are allowed', () => {
  const el = h('div', { 'aria-label': 'x', 'data-label': 'Time' });
  assert.equal(el.getAttribute('data-label'), 'Time');
});

test('href accepts in-app routes and the fixed project links only', () => {
  const ok = ['#/events', '#/events/abc?severity=high', '#/sources/2001%3Adb8%3A%3A1', 'https://github.com/metaforismo/AegisMesh'];
  const bad = ['javascript:alert(1)', 'http://evil.test', '//evil.test', '#/x"y', 'data:text/html,1', '#/a b', ' #/x', 'JAVASCRIPT:x'];
  for (const v of ok) assert.ok(isSafeHref(v), v);
  for (const v of bad) {
    assert.ok(!isSafeHref(v), v);
    assert.throws(() => h('a', { href: v }), UnsafeAttributeError);
  }
});

test('class tokens are validated', () => {
  assert.equal(h('i', { class: ['a', 'b-c', ''] }).getAttribute('class'), 'a b-c');
  assert.throws(() => h('i', { class: 'ok "><x' }), UnsafeAttributeError);
});

test('prop only sets form state', () => {
  const el = h('input', { prop: { value: 'v', checked: true } });
  assert.equal(el.value, 'v');
  assert.throws(() => h('div', { prop: { innerHTML: '<b>' } }), UnsafeAttributeError);
});

test('boolean and null attributes', () => {
  const el = h('button', { disabled: true, hidden: false, title: null });
  assert.equal(el.getAttribute('disabled'), '');
  assert.equal(el.getAttribute('hidden'), null);
});

test('svg uses the SVG namespace; fragments flatten', () => {
  assert.equal(svg('rect', { x: 1 }).namespaceURI, 'http://www.w3.org/2000/svg');
  const p = h('p', null, frag('a', ['b', null, false], 'c'));
  assert.equal(p.textContent, 'abc');
});

test('event handlers are functions passed via on, never attributes', () => {
  let hit = 0;
  const b = h('button', { on: { click: () => hit++ } });
  b.dispatch('click');
  assert.equal(hit, 1);
});
