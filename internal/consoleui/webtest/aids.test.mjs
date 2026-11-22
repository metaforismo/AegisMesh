// Rendering of the understanding aids: filter chips, help tips, relative
// times, and the Guide's routing. Evidence must stay text with its class.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createFakeDocument } from './fakedom.mjs';

globalThis.document = createFakeDocument();
const { filterChip, helpTip, timeEl } = await import('../static/assets/js/ui/components.js');
const { activeFilterChips } = await import('../static/assets/js/lib/filters.js');
const { glossaryEntry } = await import('../static/assets/js/lib/glossary.js');
const { parseHash } = await import('../static/assets/js/lib/route.js');
const { SCREENS } = await import('../static/assets/js/screens/index.js');

const cls = (el) => el.getAttribute('class') || '';
const find = (root, pred) => root.querySelectorAll(pred);

test('filter chip: evidence value keeps the evidence class and stays text', () => {
  const [chip] = activeFilterChips({ source: '<img src=x onerror=alert(1)>' });
  const el = filterChip(chip);
  const ev = find(el, (n) => cls(n).split(' ').includes('evidence'));
  assert.equal(ev.length, 1);
  assert.equal(ev[0].textContent, '<img src=x onerror=alert(1)>');
  const remove = find(el, (n) => n.tagName === 'a')[0];
  assert.equal(remove.getAttribute('href'), '#/events');
  assert.equal(remove.getAttribute('aria-label'), 'Remove filter Source');
});

test('filter chip: interface values are not marked as evidence', () => {
  const [chip] = activeFilterChips({ severity: 'high' });
  const el = filterChip(chip);
  assert.equal(find(el, (n) => cls(n).includes('evidence')).length, 0);
  assert.match(el.textContent, /SeverityHigh or higher/);
});

test('help tip: a labelled button tied to a popover that links to the guide', () => {
  const tip = helpTip(glossaryEntry('severity'));
  const btn = find(tip, (n) => n.tagName === 'button')[0];
  const pop = find(tip, (n) => n.getAttribute('popover') === 'auto')[0];
  assert.equal(btn.getAttribute('popovertarget'), pop.getAttribute('id'));
  assert.equal(btn.getAttribute('aria-label'), 'What is “Severity”?');
  assert.equal(find(pop, (n) => n.tagName === 'a')[0].getAttribute('href'), '#/guide?t=severity');
  assert.equal(helpTip(null), null);
});

test('relative time carries the absolute UTC time for hover and assistive tech', () => {
  const now = Date.parse('2026-11-22T12:00:00Z');
  const el = timeEl('2026-11-22T11:00:00Z', { relative: true, now });
  assert.equal(el.getAttribute('title'), '2026-11-22 11:00:00 UTC');
  assert.equal(el.textContent, '1h ago (2026-11-22 11:00:00 UTC)');
  assert.match(cls(el), /reltime/);
});

test('guide route and screen are registered', () => {
  assert.equal(parseHash('#/guide?t=severity').name, 'guide');
  assert.equal(parseHash('#/guide').query.t, undefined);
  assert.deepEqual(SCREENS.guide.viewIgnore, ['t']);
});
