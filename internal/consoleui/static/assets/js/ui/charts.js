// SVG charts. Geometry comes from lib/chart.js; this file only draws.
// Identity is never color-alone: a legend with glyph shapes is always
// present, the tooltip names every series, and a table view carries the
// same numbers.

import { h, svg } from '../lib/dom.js';
import { CLASSIFICATIONS, classificationMeta } from '../lib/taxonomy.js';
import { stackedLayout, labelIndices, bucketTotal } from '../lib/chart.js';
import { formatBucketLabel, formatCompact, formatCount, formatDateTime } from '../lib/format.js';
import { glyph, table } from './components.js';

export function legend() {
  return h('ul', { class: 'legend', 'aria-label': 'Series' },
    CLASSIFICATIONS.map((c) => h('li', null, glyph(c), classificationMeta(c).label)));
}

function bucketLabel(b, window) {
  return `${formatDateTime(b.start)}: ${formatCount(bucketTotal(b))} events (` +
    CLASSIFICATIONS.map((c) => `${classificationMeta(c).label} ${formatCount(b[c] || 0)}`).join(', ') + ')';
}

export function stackedBarChart(buckets, window, { title = 'Observations over time' } = {}) {
  const width = 720;
  const height = 200;
  const L = stackedLayout(buckets, { width, height });
  const tip = h('div', { class: 'chart__tip', hidden: true, role: 'presentation' });
  const plot = svg('svg', {
    viewBox: `0 0 ${width} ${height}`, role: 'img', 'aria-label': `${title}, stacked by classification. Use the table view for exact values.`,
    focusable: 'false',
  });

  for (const v of L.scale.values) {
    const y = Math.round(L.yFor(v)) + 0.5;
    plot.appendChild(svg('line', { class: v === 0 ? 'chart__axis' : 'chart__grid', x1: L.plot.x, x2: L.plot.x + L.plot.w, y1: y, y2: y }));
    plot.appendChild(svg('text', { class: 'chart__tick', x: L.plot.x - 6, y, 'text-anchor': 'end', 'dominant-baseline': 'middle' }, formatCompact(v)));
  }
  for (const i of labelIndices(L.bars.length, 6)) {
    const bar = L.bars[i];
    plot.appendChild(svg('text', { class: 'chart__tick', x: bar.x + 1, y: height - 6, 'text-anchor': 'start' }, formatBucketLabel(bar.start, window)));
  }

  const wrap = h('div', { class: 'chart' });
  const show = (bar, evt) => {
    const b = buckets[bar.index];
    tip.replaceChildren(
      h('div', { class: 'chart__tip-head' }, formatDateTime(b.start)),
      ...CLASSIFICATIONS.map((c) => h('div', { class: 'chart__tip-row' }, glyph(c), h('span', null, classificationMeta(c).label), h('span', null, formatCount(b[c] || 0)))),
      h('div', { class: ['chart__tip-row', 'chart__tip-total'] }, h('span', null, 'Total'), h('span', null, formatCount(bar.total))));
    tip.hidden = false;
    const box = wrap.getBoundingClientRect();
    const xRatio = (bar.x + bar.slot / 2) / width;
    const px = xRatio * box.width;
    const wanted = px > box.width * 0.6 ? px - 192 : px + 12;
    const left = Math.min(Math.max(0, wanted), Math.max(0, box.width - 180));
    tip.style.left = `${Math.round(left)}px`;
    tip.style.top = `${Math.round(evt?.offsetY ? Math.max(0, evt.offsetY - 20) : 8)}px`;
  };
  const hide = () => { tip.hidden = true; };

  for (const bar of L.bars) {
    for (const s of bar.segments) {
      // Square top corners on stacked segments; the 2px surface gap between
      // them comes from the layout, not from a stroke.
      plot.appendChild(svg('rect', { class: ['chart__seg', `chart__seg--${s.key}`], x: s.x, y: s.y, width: s.w, height: s.h }));
    }
    const hit = svg('rect', {
      class: 'chart__hit', x: bar.x, y: L.plot.y, width: bar.slot, height: L.plot.h,
      tabindex: '0', role: 'img', 'aria-label': bucketLabel(buckets[bar.index], window),
    });
    hit.addEventListener('mouseenter', (e) => show(bar, e));
    hit.addEventListener('mousemove', (e) => show(bar, e));
    hit.addEventListener('focus', () => show(bar));
    hit.addEventListener('mouseleave', hide);
    hit.addEventListener('blur', hide);
    plot.appendChild(hit);
  }
  wrap.append(plot, tip);

  const tableView = h('details', { class: 'chart__table' },
    h('summary', null, 'Table view'),
    table({
      caption: title,
      stack: false,
      columns: [
        { label: 'Bucket start (UTC)', cell: (b) => formatDateTime(b.start) },
        ...CLASSIFICATIONS.map((c) => ({ label: classificationMeta(c).label, num: true, cell: (b) => formatCount(b[c] || 0) })),
        { label: 'Total', num: true, cell: (b) => formatCount(bucketTotal(b)) },
      ],
      rows: buckets,
    }));

  return h('figure', { class: 'chart-figure' }, legend(), wrap, tableView);
}
