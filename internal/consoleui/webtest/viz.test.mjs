// Identity-pass geometry: sparkline marks, sensor mesh, tempo ribbon,
// density, and the "how this session unfolded" sentence.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { sparkMarks, meshLayout, lastBucketActive, tempoLayout, parseDensity, nextDensity } from '../static/assets/js/lib/viz.js';
import { sparkPath } from '../static/assets/js/lib/chart.js';
import { unfoldSentence } from '../static/assets/js/lib/story.js';

test('spark marks: ends always, max and a nonzero min only when interior', () => {
  const values = [2, 9, 0, 3, 1, 4];
  const m = sparkMarks(values, { width: 88, height: 28, pad: 2.5 });
  assert.deepEqual(m.map((x) => x.kind), ['start', 'end', 'max']);
  const p = sparkPath(values, { width: 88, height: 28, pad: 2.5 });
  assert.deepEqual({ x: m[1].x, y: m[1].y }, p.last, 'marks share sparkPath geometry');
  assert.deepEqual(sparkMarks([3, 5, 2, 6]).map((x) => x.kind), ['start', 'end', 'min']);
  assert.deepEqual(sparkMarks([3, 7, 2, 6]).map((x) => x.kind), ['start', 'end', 'max', 'min']);
  assert.deepEqual(sparkMarks([1]), []);
  assert.equal(sparkMarks([0, 0, 0]).length, 2);
});

test('mesh: nodes on a ring from the top, area follows events, quiet nodes stay visible', () => {
  const nodes = meshLayout([{ id: 'a', events: 100 }, { id: 'b', events: 25 }, { id: 'c', events: 0 }, { id: 'd', events: 1 }], { cx: 100, cy: 100, ring: 50 });
  assert.deepEqual([nodes[0].x, nodes[0].y], [100, 50]);
  assert.equal(nodes[0].anchor, 'middle');
  assert.equal(nodes[1].anchor, 'start');
  assert.ok(nodes[0].r > nodes[1].r && nodes[1].r > nodes[3].r && nodes[3].r > nodes[2].r);
  assert.ok(nodes[2].r >= 4);
  assert.equal(lastBucketActive([{ interaction: 0 }, { correlation_signal: 1 }]), true);
  assert.equal(lastBucketActive([{ interaction: 3 }, {}]), false);
  assert.equal(lastBucketActive(undefined), null);
});

test('tempo: spans the axis, compresses gaps, breaks long idles, bands tile', () => {
  const tl = [
    { event_id: 'a', gap_ms: null, classification: 'interaction' },
    { event_id: 'b', gap_ms: 700, classification: 'interaction' },
    { event_id: 'c', gap_ms: 20 * 60 * 1000, classification: 'interaction' },
    { event_id: 'd', gap_ms: 0, classification: 'correlation_signal' },
  ];
  const phases = [{ stage: 'discovery', event_ids: ['a', 'b'] }, { stage: 'decoy_credential_replay', event_ids: ['c', 'd'] }];
  const L = tempoLayout(tl, phases, { width: 200, pad: 10, breakW: 20 });
  assert.equal(L.ticks[0].x, 10);
  assert.equal(L.ticks[3].x, 190);
  assert.equal(L.breaks.length, 1);
  assert.ok(L.ticks[3].x > L.ticks[2].x, 'a zero gap still advances');
  assert.deepEqual(L.bands.map((b) => b.stage), ['discovery', 'decoy_credential_replay']);
  assert.equal(L.bands[0].left, 10);
  assert.equal(L.bands[1].right, 190);
  assert.equal(L.bands[0].right, L.bands[1].left);
  assert.deepEqual(tempoLayout([], []).ticks, []);
});

test('density: closed vocabulary', () => {
  assert.equal(parseDensity('compact'), 'compact');
  assert.equal(parseDensity('x" onload="'), 'comfortable');
  assert.equal(nextDensity('compact'), 'comfortable');
  assert.equal(nextDensity(null), 'compact');
});

test('unfold sentence: built from fields only; the source stays evidence', () => {
  const segs = unfoldSentence({
    source: '<b>203.0.113.66</b>', event_count: 13, duration_ms: 8500, sensors: ['a', 'b'], sensor_kinds: ['http'],
    phases: [{ stage: 'discovery' }, { stage: 'ai_service_abuse' }, { stage: 'discovery' }, { stage: 'decoy_credential_replay' }],
    cadence: { median_gap_ms: 700 },
  });
  assert.deepEqual(segs[0], { t: 'ev', v: '<b>203.0.113.66</b>' });
  const text = segs.slice(1).map((s) => s.v).join('');
  assert.equal(text, ' produced 13 events over 8.5 s on 2 sensors (HTTP): it began with discovery, moved through AI service use, then discovery, and ended with decoy credential replay. The typical gap between events was 700 ms.');
  assert.doesNotMatch(text, /203\.0/);
  assert.deepEqual(unfoldSentence(null), []);
});

test('tour: steps filtered to visible targets; key is fixed', async () => {
  const { tourStepsFor, TOUR_KEY } = await import('../static/assets/js/lib/viz.js');
  const steps = [{ target: '.a' }, { target: '.b' }, null, { target: 3 }];
  assert.deepEqual(tourStepsFor(steps, (s) => s === '.b'), [{ target: '.b' }]);
  assert.equal(TOUR_KEY, 'aegismesh.tour');
});
