import { test } from 'node:test';
import assert from 'node:assert/strict';
import { scoreMatch, rankItems, highlightRuns } from '../static/assets/js/lib/palette.js';

test('scoreMatch orders exact > prefix > word start > substring > fuzzy > none', () => {
  const exact = scoreMatch('events', 'Events').score;
  const prefix = scoreMatch('eve', 'Events').score;
  const word = scoreMatch('trail', 'Audit trail').score;
  const sub = scoreMatch('vent', 'Events').score;
  const fuzzy = scoreMatch('adt', 'Audit trail').score;
  assert.ok(exact > prefix && prefix > word && word > sub && sub > fuzzy && fuzzy > 0, JSON.stringify({ exact, prefix, word, sub, fuzzy }));
  assert.equal(scoreMatch('xyz', 'Events').score, 0);
  assert.equal(scoreMatch('ab', '').score, 0);
});

test('scoreMatch is case-insensitive and returns highlight ranges', () => {
  assert.deepEqual(scoreMatch('SEN', 'Sensors').ranges, [[0, 3]]);
  assert.deepEqual(scoreMatch('trail', 'Audit trail').ranges, [[6, 11]]);
  // Fuzzy ranges merge consecutive characters.
  assert.deepEqual(scoreMatch('aud tr', 'Audit trail').ranges, [[0, 3], [6, 8]]);
});

test('word boundaries include punctuation found in ids and source keys', () => {
  const s = scoreMatch('mcp', 'corr:203.0.113.7/mcp-tools');
  assert.ok(s.score >= 600, `got ${s.score}`);
  assert.ok(scoreMatch('113', '203.0.113.7').score > scoreMatch('13', '203.0.113.7').score);
});

test('rankItems keeps input order for ties, applies weight and keywords', () => {
  const items = [
    { label: 'Sources', weight: 50 },
    { label: '198.51.100.23' },
    { label: 'Sensors', weight: 50 },
    { label: 'Node', keywords: ['server', 'storage'] },
  ];
  assert.deepEqual(rankItems(items, '').map((r) => r.item.label), ['Sources', 'Sensors', '198.51.100.23', 'Node']);
  assert.deepEqual(rankItems(items, 'se').map((r) => r.item.label).slice(0, 2), ['Sensors', 'Node'], 'label prefix, then keyword prefix, before a fuzzy label hit');
  const byKeyword = rankItems(items, 'storage');
  assert.equal(byKeyword[0].item.label, 'Node');
  assert.deepEqual(byKeyword[0].ranges, [], 'a keyword hit highlights nothing in the label');
  assert.equal(rankItems(items, 'zzz').length, 0);
  assert.equal(rankItems(items, '', { limit: 2 }).length, 2);
});

test('rankItems: a prefix match on a weighted screen beats fuzzy data hits', () => {
  const items = [{ label: 'investigation: evidence sweep' }, { label: 'Events', weight: 50 }];
  assert.equal(rankItems(items, 'ev')[0].item.label, 'Events');
});

test('highlightRuns splits text into hit and plain runs without touching markup', () => {
  const runs = highlightRuns('<b>Sensors</b>', [[3, 6]]);
  assert.deepEqual(runs, [{ text: '<b>', hit: false }, { text: 'Sen', hit: true }, { text: 'sors</b>', hit: false }]);
  assert.deepEqual(highlightRuns('abc', []), [{ text: 'abc', hit: false }]);
  assert.deepEqual(highlightRuns('abc', [[2, 99]]), [{ text: 'ab', hit: false }, { text: 'c', hit: true }]);
});
