import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createFakeDocument } from './fakedom.mjs';
import { compareValues, sortRows, nextSort, ariaSort, timeValue } from '../static/assets/js/lib/tablesort.js';

globalThis.document = createFakeDocument();
const { table } = await import('../static/assets/js/ui/components.js');

test('compareValues: numbers numerically, words naturally and case-blind', () => {
  assert.ok(compareValues(9, 10) < 0);
  assert.ok(compareValues('node-9', 'node-10') < 0);
  assert.equal(compareValues('Alpha', 'alpha'), 0);
  assert.ok(compareValues(false, true) < 0);
});

test('sortRows: stable, both directions, missing values always last', () => {
  const rows = [{ n: 2, id: 'a' }, { n: null, id: 'b' }, { n: 1, id: 'c' }, { n: 2, id: 'd' }, { n: NaN, id: 'e' }, { n: '', id: 'f' }];
  const ids = (list) => list.map((r) => r.id).join('');
  assert.equal(ids(sortRows(rows, (r) => r.n, 'asc')), 'cadbef');
  assert.equal(ids(sortRows(rows, (r) => r.n, 'desc')), 'adcbef');
  // The input is never reordered in place.
  assert.equal(ids(rows), 'abcdef');
});

test('nextSort and ariaSort', () => {
  assert.deepEqual(nextSort(null, 'Events', 'desc'), { key: 'Events', dir: 'desc' });
  assert.deepEqual(nextSort({ key: 'Events', dir: 'desc' }, 'Events'), { key: 'Events', dir: 'asc' });
  assert.deepEqual(nextSort({ key: 'Events', dir: 'asc' }, 'Name', 'bogus'), { key: 'Name', dir: 'asc' });
  assert.equal(ariaSort({ key: 'Events', dir: 'desc' }, 'Events'), 'descending');
  assert.equal(ariaSort({ key: 'Events', dir: 'asc' }, 'Events'), 'ascending');
  assert.equal(ariaSort({ key: 'Events', dir: 'asc' }, 'Name'), 'none');
  assert.equal(ariaSort(null, 'Name'), 'none');
});

test('timeValue parses RFC 3339 and treats anything else as missing', () => {
  assert.equal(timeValue('2026-11-14T09:00:00Z'), Date.parse('2026-11-14T09:00:00Z'));
  assert.equal(timeValue(''), null);
  assert.equal(timeValue('soon'), null);
  assert.equal(timeValue(42), null);
});

const cls = (el) => el.getAttribute('class') || '';
const find = (root, pred) => root.querySelectorAll(pred);
const bodyText = (wrap) => find(wrap, (n) => n.tagName === 'tbody')[0].childNodes.map((tr) => tr.childNodes[0].textContent);

test('table: sortable headers are buttons with aria-sort, and reorder rows', () => {
  const rows = [{ name: 'beta', n: 3 }, { name: 'alpha', n: 10 }, { name: 'gamma', n: 1 }];
  const wrap = table({
    caption: 'Things',
    columns: [
      { label: 'Name', sort: (r) => r.name, cell: (r) => r.name },
      { label: 'Count', num: true, sort: (r) => r.n, cell: (r) => String(r.n) },
      { label: 'Note', cell: () => '—' },
    ],
    rows,
    sort: { key: 'Count', dir: 'desc' },
  });
  const ths = find(wrap, (n) => n.tagName === 'th');
  assert.equal(ths.length, 3);
  for (const th of ths) assert.equal(th.getAttribute('scope'), 'col');
  assert.equal(ths[0].getAttribute('aria-sort'), 'none');
  assert.equal(ths[1].getAttribute('aria-sort'), 'descending');
  assert.equal(ths[2].getAttribute('aria-sort'), null, 'an unsortable column carries no aria-sort');
  assert.deepEqual(bodyText(wrap), ['alpha', 'beta', 'gamma']);

  const nameBtn = ths[0].childNodes[0];
  assert.equal(nameBtn.tagName, 'button');
  assert.equal(nameBtn.getAttribute('type'), 'button');
  nameBtn.dispatch('click');
  assert.equal(ths[0].getAttribute('aria-sort'), 'ascending');
  assert.equal(ths[1].getAttribute('aria-sort'), 'none');
  assert.deepEqual(bodyText(wrap), ['alpha', 'beta', 'gamma']);
  nameBtn.dispatch('click');
  assert.equal(ths[0].getAttribute('aria-sort'), 'descending');
  assert.deepEqual(bodyText(wrap), ['gamma', 'beta', 'alpha']);
  // A polite status says what happened.
  const status = find(wrap, (n) => n.getAttribute('role') === 'status')[0];
  assert.equal(status.textContent, 'Sorted by name, descending.');

  // A numeric column starts high-to-low.
  ths[1].childNodes[0].dispatch('click');
  assert.equal(ths[1].getAttribute('aria-sort'), 'descending');
  assert.deepEqual(bodyText(wrap), ['alpha', 'beta', 'gamma']);
});

test('table: one row, or no sort getter, gives a plain header', () => {
  const wrap = table({ columns: [{ label: 'Name', sort: (r) => r, cell: (r) => r }], rows: ['only'] });
  const th = find(wrap, (n) => n.tagName === 'th')[0];
  assert.equal(th.textContent, 'Name');
  assert.equal(th.getAttribute('aria-sort'), null);
  assert.match(cls(table({ columns: [], rows: [], scroll: true })), /table-wrap--scroll/);
});
