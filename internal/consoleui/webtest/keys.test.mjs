import { test } from 'node:test';
import assert from 'node:assert/strict';
import { moveIndex, isTypingTarget, chordOf, createSequences } from '../static/assets/js/lib/keys.js';

test('moveIndex: first move selects an end, then clamps or wraps', () => {
  assert.equal(moveIndex(-1, 1, 5), 0);
  assert.equal(moveIndex(-1, -1, 5), 4);
  assert.equal(moveIndex(2, 1, 5), 3);
  assert.equal(moveIndex(4, 1, 5), 4);
  assert.equal(moveIndex(0, -1, 5), 0);
  assert.equal(moveIndex(4, 1, 5, { wrap: true }), 0);
  assert.equal(moveIndex(0, -1, 5, { wrap: true }), 4);
  assert.equal(moveIndex(3, 1, 0), -1);
  assert.equal(moveIndex(9, 1, 3), 0, 'a stale cursor restarts from the top');
});

test('isTypingTarget: text fields swallow shortcuts, buttons and checkboxes do not', () => {
  assert.equal(isTypingTarget({ tagName: 'INPUT', type: 'search' }), true);
  assert.equal(isTypingTarget({ tagName: 'INPUT' }), true);
  assert.equal(isTypingTarget({ tagName: 'TEXTAREA' }), true);
  assert.equal(isTypingTarget({ tagName: 'SELECT' }), true);
  assert.equal(isTypingTarget({ tagName: 'DIV', isContentEditable: true }), true);
  assert.equal(isTypingTarget({ tagName: 'INPUT', type: 'checkbox' }), false);
  assert.equal(isTypingTarget({ tagName: 'BUTTON' }), false);
  assert.equal(isTypingTarget(null), false);
});

test('chordOf maps the platform modifier to "mod"', () => {
  assert.equal(chordOf({ key: 'k', metaKey: true }, { apple: true }), 'mod+k');
  assert.equal(chordOf({ key: 'k', ctrlKey: true }, { apple: false }), 'mod+k');
  assert.equal(chordOf({ key: 'k', ctrlKey: true }, { apple: true }), 'k', 'Ctrl is not the Apple modifier');
  assert.equal(chordOf({ key: '?', shiftKey: true }), '?');
  assert.equal(chordOf({ key: 'Escape' }), 'escape');
  assert.equal(chordOf({ key: 'ArrowDown', shiftKey: true }), 'shift+arrowdown');
  assert.equal(chordOf({ key: 'Dead' }), '');
});

test('createSequences completes "g e" within the timeout only', () => {
  let t = 0;
  const seq = createSequences({ 'g e': 'events', 'g o': 'overview' }, { timeout: 1000, now: () => t });
  assert.equal(seq.feed('g'), null);
  assert.equal(seq.pending, 'g');
  assert.equal(seq.feed('e'), 'events');
  assert.equal(seq.pending, '');
  seq.feed('g');
  t = 1500;
  assert.equal(seq.feed('e'), null, 'too slow');
  assert.equal(seq.feed('x'), null);
  seq.feed('g');
  assert.equal(seq.feed('z'), null, 'unknown second key clears the prefix');
  assert.equal(seq.feed('o'), null);
});
