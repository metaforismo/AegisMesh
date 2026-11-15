import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseHash, viewKey, withQuery, normalizeEventFilters, isEventId } from '../static/assets/js/lib/route.js';

const ID = 'ab'.repeat(16);

test('the drawer parameter does not change the events view identity', () => {
  const list = parseHash('#/events?severity=high&live=1');
  const open = parseHash(`#/events?severity=high&live=1&event=${ID}`);
  assert.equal(viewKey(list, ['event']), viewKey(open, ['event']));
  assert.notEqual(viewKey(list), viewKey(open));
  assert.notEqual(viewKey(parseHash('#/events?severity=low'), ['event']), viewKey(list, ['event']));
  // Query order does not matter.
  assert.equal(viewKey(parseHash('#/events?a=1&b=2')), viewKey(parseHash('#/events?b=2&a=1')));
});

test('withQuery opens and closes the drawer while keeping filters', () => {
  const r = parseHash('#/events?severity=high&q=a%20b');
  const opened = withQuery(r, { event: ID });
  const back = parseHash(opened);
  assert.equal(back.name, 'events');
  assert.equal(back.query.event, ID);
  assert.equal(back.query.q, 'a b');
  assert.deepEqual(normalizeEventFilters(back.query).filters, { severity: 'high', q: 'a b' }, 'event is not a filter');
  assert.equal(parseHash(withQuery(back, { event: '' })).query.event, undefined);
  assert.equal(withQuery(parseHash('#/events'), {}), '#/events');
});

test('only a well-formed event id opens the drawer', () => {
  assert.equal(isEventId(ID), true);
  assert.equal(isEventId('../x'), false);
  assert.equal(isEventId(ID.toUpperCase()), false);
});
