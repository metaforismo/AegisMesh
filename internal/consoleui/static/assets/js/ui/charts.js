// SVG charts. Geometry comes from lib/chart.js; this file only draws.
// Identity is never color-alone: a legend with glyph shapes is always
// present, the tooltip names every series, and a table view carries the
// same numbers.
//
// Interaction (stacked bars): one tab stop for the whole plot, arrow keys
// move between buckets (roving focus), hover or focus shows a dashed
// crosshair and a tooltip that glides between buckets, and click or Enter
// opens the events in that bucket's time range.

import { h, svg } from '../lib/dom.js';
import { CLASSIFICATIONS, SEVERITIES, classificationMeta } from '../lib/taxonomy.js';
import { stackedLayout, labelIndices, bucketTotal, bucketRange, waveDelays } from '../lib/chart.js';
import { moveIndex } from '../lib/keys.js';
import { formatBucketLabel, formatCompact, formatCount, formatDateTime } from '../lib/format.js';
import { glyph, table, sevChip } from './components.js';
import { icon } from './icons.js';

export function legend() {
  return h('ul', { class: 'legend', 'aria-label': 'Series' },
    CLASSIFICATIONS.map((c) => h('li', null, glyph(c), classificationMeta(c).label)));
}

const sumOf = (buckets, key) => buckets.reduce((n, b) => n + (Number(b?.[key]) || 0), 0);

// Readout legend: glyph, series name and a value per series, plus a total.
// At rest it shows the whole window; while a bucket is hovered or focused
// it shows that bucket, so the numbers are readable without the tooltip and
// from the keyboard. It repeats what the focused bar announces, so it is not
// a live region.
function readout(buckets) {
  const window = { head: 'Whole window', values: Object.fromEntries(CLASSIFICATIONS.map((c) => [c, sumOf(buckets, c)])) };
  const head = h('span', { class: 'readout__head' });
  const cells = new Map();
  const total = h('span', { class: 'readout__value' });
  const el = h('div', { class: 'readout' },
    head,
    h('ul', { class: ['legend', 'readout__list'], 'aria-label': 'Series' },
      CLASSIFICATIONS.map((c) => {
        const v = h('span', { class: 'readout__value' });
        cells.set(c, v);
        return h('li', null, glyph(c), h('span', null, classificationMeta(c).label), v);
      }),
      h('li', { class: 'readout__total' }, h('span', null, 'Total'), total)));
  const paint = ({ head: text, values }, active) => {
    head.textContent = text;
    let sum = 0;
    for (const c of CLASSIFICATIONS) {
      const n = Number(values[c]) || 0;
      sum += n;
      cells.get(c).textContent = formatCount(n);
    }
    total.textContent = formatCount(sum);
    el.classList.toggle('is-bucket', active);
  };
  paint(window, false);
  return {
    el,
    show: (b) => paint({ head: formatDateTime(b.start), values: b }, true),
    reset: () => paint(window, false),
  };
}

function bucketLabel(b) {
  return `${formatDateTime(b.start)}: ${formatCount(bucketTotal(b))} events (` +
    CLASSIFICATIONS.map((c) => `${classificationMeta(c).label} ${formatCount(b[c] || 0)}`).join(', ') + ')';
}

// onSelect(range, bucket) opens the bucket; omit it for a read-only chart.
export function stackedBarChart(buckets, window, { title = 'Observations over time', onSelect, end } = {}) {
  // Draw at roughly the size it will be shown, so 10px ticks stay 10px:
  // the content column is the viewport minus the nav (above 960px) and
  // the page and panel padding.
  const vw = globalThis.innerWidth || 1200;
  const width = Math.round(Math.min(1100, Math.max(300, vw >= 960 ? vw - 224 - 100 : vw - 66)));
  const height = width < 600 ? 200 : 240;
  const L = stackedLayout(buckets, { width, height, padLeft: 40, padBottom: 24 });
  const tip = h('div', { class: 'chart__tip', role: 'presentation', 'aria-hidden': 'true' });
  const plot = svg('svg', {
    viewBox: `0 0 ${width} ${height}`, role: 'group', 'aria-label': `${title}, stacked by classification. Arrow keys move between time buckets; the table view lists exact values.`,
    focusable: 'false',
  });

  for (const v of L.scale.values) {
    const y = Math.round(L.yFor(v)) + 0.5;
    plot.appendChild(svg('line', { class: v === 0 ? 'chart__axis' : 'chart__grid', x1: L.plot.x, x2: L.plot.x + L.plot.w, y1: y, y2: y }));
    plot.appendChild(svg('text', { class: 'chart__tick', x: L.plot.x - 8, y, 'text-anchor': 'end', 'dominant-baseline': 'middle' }, formatCompact(v)));
  }
  for (const i of labelIndices(L.bars.length, Math.max(3, Math.floor(width / 140)))) {
    const bar = L.bars[i];
    plot.appendChild(svg('text', { class: 'chart__tick', x: bar.x + 1, y: height - 6, 'text-anchor': 'start' }, formatBucketLabel(bar.start, window)));
  }

  const cross = svg('line', { class: 'chart__cross', x1: 0, x2: 0, y1: L.plot.y, y2: L.plot.y + L.plot.h });
  const read = readout(buckets);
  const wrap = h('div', { class: 'chart' });
  const delays = waveDelays(L.bars.length, 260);
  const groups = [];
  const hits = [];

  for (const bar of L.bars) {
    // Square top corners on stacked segments; the 2px surface gap between
    // them comes from the layout, not from a stroke.
    const g = svg('g', { class: 'chart__bar' },
      bar.segments.map((s) => svg('rect', { class: ['chart__seg', `chart__seg--${s.key}`], x: s.x, y: s.y, width: s.w, height: s.h })));
    g.style.setProperty('--d', `${delays[bar.index]}ms`);
    groups.push(g);
    plot.appendChild(g);
  }
  plot.appendChild(cross);

  let active = -1;
  let tipPlaced = false;

  const placeTip = (bar) => {
    // One layout read for the container, then writes only.
    const box = wrap.getBoundingClientRect();
    const scale = box.width / width;
    const cx = (bar.x + bar.slot / 2) * scale;
    const tw = tip.offsetWidth || 180;
    const th = tip.offsetHeight || 100;
    const right = cx + 14 + tw <= box.width;
    const x = right ? cx + 14 : Math.max(0, cx - 14 - tw);
    // Hug the top of the plot so the tooltip covers the gridlines, not the bars
    // around the crosshair (bars are bottom-anchored).
    const top = Math.max(0, Math.min(L.plot.y * scale, box.height - th - 28));
    tip.classList.toggle('is-placing', !tipPlaced);
    tip.style.transform = `translate(${Math.round(x)}px, ${Math.round(top)}px)`;
    tipPlaced = true;
  };

  const show = (i) => {
    const bar = L.bars[i];
    if (!bar) return;
    const b = buckets[i];
    const range = bucketRange(buckets, i, end);
    tip.replaceChildren(
      h('div', { class: 'chart__tip-head' }, formatDateTime(b.start)),
      ...CLASSIFICATIONS.map((c) => h('div', { class: 'chart__tip-row' }, glyph(c), h('span', null, classificationMeta(c).label), h('span', null, formatCount(b[c] || 0)))),
      h('div', { class: ['chart__tip-row', 'chart__tip-total'] }, h('span', null, 'Total'), h('span', null, formatCount(bar.total))),
      onSelect && range && bar.total ? h('div', { class: 'chart__tip-hint' }, 'Click or press Enter to open these events') : null);
    if (active >= 0 && active !== i) groups[active]?.classList.remove('is-active');
    groups[i].classList.add('is-active');
    cross.classList.toggle('is-placed', active < 0);
    cross.style.transform = `translateX(${bar.x + bar.slot / 2}px)`;
    active = i;
    read.show(b);
    wrap.classList.add('is-active');
    tip.classList.add('is-shown');
    placeTip(bar);
  };

  const hide = () => {
    if (active >= 0) groups[active]?.classList.remove('is-active');
    active = -1;
    tipPlaced = false;
    read.reset();
    wrap.classList.remove('is-active');
    tip.classList.remove('is-shown');
  };

  const select = (i) => {
    const range = bucketRange(buckets, i, end);
    if (onSelect && range && L.bars[i]?.total) onSelect(range, buckets[i]);
  };

  // Roving focus: only one hit target is in the tab order at a time.
  const focusBar = (i) => {
    for (const [j, el] of hits.entries()) el.setAttribute('tabindex', j === i ? '0' : '-1');
    hits[i]?.focus();
  };

  for (const bar of L.bars) {
    const hit = svg('rect', {
      class: 'chart__hit', x: bar.x, y: L.plot.y, width: bar.slot, height: L.plot.h,
      tabindex: bar.index === L.bars.length - 1 ? '0' : '-1', role: onSelect ? 'button' : 'img', 'aria-label': bucketLabel(buckets[bar.index]),
    });
    hit.addEventListener('pointerenter', () => show(bar.index));
    hit.addEventListener('focus', () => show(bar.index));
    hit.addEventListener('click', () => select(bar.index));
    hit.addEventListener('keydown', (e) => {
      let next = -1;
      if (e.key === 'ArrowRight') next = moveIndex(bar.index, 1, L.bars.length);
      else if (e.key === 'ArrowLeft') next = moveIndex(bar.index, -1, L.bars.length);
      else if (e.key === 'Home') next = 0;
      else if (e.key === 'End') next = L.bars.length - 1;
      else if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        select(bar.index);
        return;
      }
      if (next >= 0) {
        e.preventDefault();
        focusBar(next);
      }
    });
    hits.push(hit);
    plot.appendChild(hit);
  }
  plot.addEventListener('pointerleave', () => { if (!plot.contains(document.activeElement)) hide(); });
  plot.addEventListener('focusout', (e) => { if (!plot.contains(e.relatedTarget)) hide(); });
  wrap.append(plot, tip);

  const tableView = h('details', { class: 'chart__table' },
    h('summary', null, icon('chevron-right', { size: 'xs' }), 'Table view'),
    table({
      caption: title,
      stack: false,
      columns: [
        { label: 'Bucket start', cell: (b) => formatDateTime(b.start) },
        ...CLASSIFICATIONS.map((c) => ({ label: classificationMeta(c).label, num: true, cell: (b) => formatCount(b[c] || 0) })),
        { label: 'Total', num: true, cell: (b) => formatCount(bucketTotal(b)) },
      ],
      rows: buckets,
    }));

  return h('figure', { class: 'chart-figure' },
    h('div', { class: 'chart-figure__top' }, read.el,
      onSelect ? h('p', { class: 'chart-figure__hint' }, 'Hover or use the arrow keys to read a bucket; select it to open its events') : null),
    wrap, tableView);
}

// Severity share: one segmented bar (2px surface gaps, fixed severity
// order) and a legend that carries meter, word, count and share, so the bar
// is never the only reading. Rows link to the filtered events list.
// items: [{ key: severity|'none', value, href? }]
export function severityShare(items) {
  const total = items.reduce((a, i) => a + Math.max(0, Number(i.value) || 0), 0);
  const pct = (v) => (total > 0 ? Math.round((v / total) * 1000) / 10 : 0);
  const bar = h('div', { class: 'segbar', 'aria-hidden': 'true' },
    items.filter((i) => Number(i.value) > 0).map((i) => {
      const seg = h('span', { class: ['segbar__seg', `segbar__seg--${i.key}`] });
      seg.style.flexGrow = String(Number(i.value));
      return seg;
    }));
  const rows = items.map((i) => {
    const value = Math.max(0, Number(i.value) || 0);
    const content = [
      sevChip(i.key),
      h('span', { class: 'segleg__count' }, formatCount(value)),
      h('span', { class: 'segleg__pct' }, `${pct(value)}%`),
    ];
    return h('li', null, i.href
      ? h('a', { class: ['segleg__row', `segleg__row--${i.key}`], href: i.href }, content)
      : h('span', { class: ['segleg__row', `segleg__row--${i.key}`] }, content));
  });
  return h('div', { class: 'segshare' }, total ? bar : null, h('ul', { class: 'segleg', 'aria-label': 'Events by highest severity' }, rows));
}

export const SEVERITY_ORDER = [...SEVERITIES].reverse();

// Activity trace: small columns over equal time bins (sensor cards, source
// strip). Bins before `knownFrom` are drawn hatched: the loaded events do not
// reach that far back, so the trace does not claim those bins were quiet.
// The caller prints the totals beside it; this is a shape, aria-hidden.
export function activityTrace(bins, { start, end, knownFrom = -Infinity, height = 32, startLabel, endLabel } = {}) {
  const n = bins.length;
  const w = 240;
  const gap = n > 40 ? 1 : 2;
  const slot = w / Math.max(1, n);
  const max = Math.max(1, ...bins);
  const size = (end - start) / Math.max(1, n);
  const el = svg('svg', { class: 'trace', viewBox: `0 0 ${w} ${height}`, preserveAspectRatio: 'none', 'aria-hidden': 'true', focusable: 'false' },
    svg('line', { class: 'trace__base', x1: 0, x2: w, y1: height - 0.5, y2: height - 0.5 }),
    bins.map((v, i) => {
      const unknown = start + (i + 1) * size <= knownFrom;
      const hgt = unknown ? height - 1 : v > 0 ? Math.max(2, (v / max) * (height - 2)) : 1.5;
      return svg('rect', {
        class: ['trace__bar', unknown ? 'trace__bar--unknown' : v === 0 ? 'trace__bar--zero' : ''],
        x: i * slot + gap / 2, y: height - 1 - hgt, width: Math.max(1, slot - gap), height: hgt, rx: 1,
      });
    }));
  return h('div', { class: 'trace-wrap' }, el,
    startLabel || endLabel ? h('div', { class: 'trace-wrap__meta' }, h('span', null, startLabel || ''), h('span', null, endLabel || '')) : null);
}
