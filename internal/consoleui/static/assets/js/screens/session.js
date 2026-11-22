// The attack story: one attacker session (GET /sessions/{id}) read top to
// bottom. A vertical timeline grouped by the API's phases, with the gap
// before each event and long idles collapsed into a marker; beside it the
// pace, the automation observations, the frameworks the fired rules relate
// to, and the downloads.
//
// Everything attacker-supplied (the source key, summaries) is evidence text.
// Stages describe which rules fired, not intent; the automation reading is
// an observation with its evidence, never a verdict.

import { h, mount, svg } from '../lib/dom.js';
import { tempoLayout } from '../lib/viz.js';
import { href, withQuery, isEventId, isSessionId } from '../lib/route.js';
import { formatCount, formatDateTime, formatClock } from '../lib/format.js';
import { eventKey, parseEventKey, isNodeId } from '../lib/origin.js';
import { moveIndex, isTypingTarget } from '../lib/keys.js';
import { cadence as gapBins } from '../lib/cadence.js';
import {
  assessmentOf, evidenceMeta, storyItems, stageSummary, formatDurationMs, regularityText, boundsNote, unfoldSentence, stageMeta,
} from '../lib/story.js';
import { glossaryEntry } from '../lib/glossary.js';
import { pageHead, panel, kv, sevChip, evidence, chip, empty, banner, helpTip, toast, errorState, link, glyph } from '../ui/components.js';
import { assessmentChip, frameworkChips, stageTag, kindChips } from '../ui/story.js';
import { downloadActions } from '../ui/downloads.js';
import { icon } from '../ui/icons.js';
import { ruleChips, newInvestigationDialog, notFoundInTenant } from './shared.js';
import { createDrawer } from './events.js';
import { renderEventDetail } from './event.js';
import { tenantInfo } from '../lib/tenant.js';

const tip = (id) => helpTip(glossaryEntry(id));
const titled = (text, id) => h('span', { class: 'title-help' }, text, tip(id));

// Milliseconds precision matters at sub-second pace.
function clockMs(t) {
  const ms = Date.parse(t);
  if (!Number.isFinite(ms)) return formatClock(t);
  return `${formatClock(t)}.${String(new Date(ms).getUTCMilliseconds()).padStart(3, '0')}`;
}

const keyOfEntry = (e) => eventKey({ id: e.event_id, node: e.node_id && e.node_id !== 'local' ? { id: e.node_id } : undefined });

function stageRibbon(phases, total) {
  const parts = stageSummary(phases);
  if (!parts.length) return null;
  return h('div', { class: 'ribbon' },
    h('div', { class: 'ribbon__bar', 'aria-hidden': 'true' }, phases.map((p) => {
      const seg = h('span', { class: ['ribbon__seg', `ribbon__seg--${p.stage in { discovery: 1, credential_access: 1, ai_service_abuse: 1, decoy_credential_replay: 1 } ? p.stage : 'other'}`] });
      seg.style.flexGrow = String(Math.max(1, p.event_ids?.length || 0));
      return seg;
    })),
    h('ul', { class: 'ribbon__legend', 'aria-label': 'Stages in this session' }, parts.map((s) => h('li', null,
      stageTag(s.stage), h('span', { class: 'ribbon__count' }, `${formatCount(s.events)} of ${formatCount(total)} event${total === 1 ? '' : 's'}${s.runs > 1 ? `, ${s.runs} runs` : ''}`)))));
}

function timelineView(d, rowHref) {
  const items = storyItems(d.timeline, d.phases);
  if (!items.length) return empty('No events in the timeline', 'The session’s events may have aged out of the index since it was listed.', null, { icon: 'story' });
  return h('ol', { class: 'story', 'aria-label': 'Session timeline, oldest first' }, items.map((it) => {
    if (it.type === 'idle') {
      return h('li', { class: 'story__idle' }, h('span', { class: 'story__idle-line', 'aria-hidden': 'true' }),
        h('span', null, icon('clock', { size: 'xs' }), ` ${formatDurationMs(it.ms)} quiet`));
    }
    if (it.type === 'phase') {
      const same = it.first === it.last;
      return h('li', { class: 'story__phase' },
        stageTag(it.stage),
        h('span', { class: 'story__phase-meta' }, `${formatCount(it.count)} event${it.count === 1 ? '' : 's'} · ${same ? formatClock(it.first) : `${formatClock(it.first)}–${formatClock(it.last)}`} UTC`));
    }
    const ev = it.ev;
    const key = keyOfEntry(ev);
    const signal = ev.classification === 'correlation_signal';
    const summary = isEventId(ev.event_id)
      ? h('a', { class: 'story__summary', href: rowHref(key), 'data-row-link': '', 'data-key': key }, evidence(ev.summary || '(no summary)', { max: 140 }))
      : evidence(ev.summary || '(no summary)', { max: 140 });
    return h('li', { class: ['story__event', signal ? 'story__event--signal' : ''], 'data-key': key },
      h('div', { class: 'story__when' },
        h('time', { datetime: ev.time, title: formatDateTime(ev.time) }, clockMs(ev.time)),
        it.gap === null ? h('span', { class: 'story__gap' }, 'first') : h('span', { class: ['story__gap', it.gap < 1000 ? 'story__gap--fast' : ''] }, `+${formatDurationMs(it.gap)}`)),
      h('span', { class: 'story__node', 'aria-hidden': 'true' }, glyph(ev.classification)),
      h('div', { class: 'story__body' },
        summary,
        h('div', { class: 'story__meta' },
          signal ? chip('Correlation signal') : h('span', { class: 'nowrap' }, h('code', null, ev.sensor || '—'), ev.kind ? [' ', chip(String(ev.kind).toUpperCase())] : null),
          ev.node_id && ev.node_id !== 'local' ? h('span', { class: 'muted' }, `forwarded · ${String(ev.node_id).slice(0, 8)}`) : null,
          (ev.rule_ids || []).length ? ruleChips(ev.rule_ids) : null)));
  }));
}

// The tempo ribbon: every event on one axis, gaps compressed on a log
// scale, quiet stretches over 5 minutes drawn as breaks, phase bands
// underneath. Hover or focus a tick to highlight that event in the list;
// Enter or a click opens it. One tab stop; arrow keys move between ticks.
function tempoView(d, storySlot, rowHref) {
  const timeline = Array.isArray(d.timeline) ? d.timeline : [];
  if (timeline.length < 2) return null;
  const W = 720;
  const H = 64;
  const L = tempoLayout(timeline, d.phases, { width: W, pad: 10 });
  const STAGES = { discovery: 1, credential_access: 1, ai_service_abuse: 1, decoy_credential_replay: 1 };
  const plot = svg('svg', { class: 'tempo', viewBox: `0 0 ${W} ${H}`, role: 'group', 'aria-label': 'Tempo: every event on one compressed time axis. Arrow keys move between events.' });
  for (const b of L.bands) plot.appendChild(svg('rect', { class: ['tempo__band', `tempo__band--${STAGES[b.stage] ? b.stage : 'other'}`], x: b.left, y: 40, width: Math.max(2, b.right - b.left), height: 8, rx: 2 }));
  plot.appendChild(svg('line', { class: 'tempo__axis', x1: 10, x2: W - 10, y1: 34.5, y2: 34.5 }));
  for (const br of L.breaks) {
    plot.appendChild(svg('path', { class: 'tempo__break', d: `M${br.x - 3} 30 l4 9 M${br.x + 1} 30 l4 9` }));
    plot.appendChild(svg('text', { class: 'tempo__label', x: br.x, y: 60, 'text-anchor': 'middle' }, formatDurationMs(br.ms)));
  }
  const groups = [];
  const hot = (i, on) => {
    groups[i]?.classList.toggle('is-hot', on);
    const key = keyOfEntry(timeline[i]);
    storySlot.querySelector(`.story__event[data-key="${key}"]`)?.classList.toggle('is-hot', on);
  };
  L.ticks.forEach((t) => {
    const ev = timeline[t.i];
    const hit = svg('rect', {
      class: 'tempo__hit', x: t.x - 5, y: 8, width: 10, height: 32, tabindex: t.i === 0 ? '0' : '-1', role: 'button',
      'aria-label': `${clockMs(ev.time)} UTC, ${ev.classification === 'correlation_signal' ? 'correlation signal' : ev.sensor || 'event'}${(ev.rule_ids || []).length ? `, rules ${ev.rule_ids.join(' ')}` : ''}`,
    });
    const g = svg('g', null,
      svg('line', { class: ['tempo__tick', `tempo__tick--${ev.classification === 'correlation_signal' ? 'signal' : ev.classification === 'canary_invocation' ? 'canary_invocation' : 'interaction'}`], x1: t.x, x2: t.x, y1: ev.classification === 'correlation_signal' ? 14 : 20, y2: 34 }),
      hit);
    groups.push(g);
    const open = () => { if (isEventId(ev.event_id)) location.hash = rowHref(keyOfEntry(ev)); };
    hit.addEventListener('pointerenter', () => hot(t.i, true));
    hit.addEventListener('pointerleave', () => hot(t.i, false));
    hit.addEventListener('focus', () => hot(t.i, true));
    hit.addEventListener('blur', () => hot(t.i, false));
    hit.addEventListener('click', open);
    hit.addEventListener('keydown', (e) => {
      let j = -1;
      if (e.key === 'ArrowRight') j = Math.min(L.ticks.length - 1, t.i + 1);
      else if (e.key === 'ArrowLeft') j = Math.max(0, t.i - 1);
      else if (e.key === 'Home') j = 0;
      else if (e.key === 'End') j = L.ticks.length - 1;
      else if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); open(); return; }
      if (j >= 0) {
        e.preventDefault();
        groups.forEach((gr, k) => gr.lastChild.setAttribute('tabindex', k === j ? '0' : '-1'));
        groups[j].lastChild.focus();
      }
    });
    plot.appendChild(g);
  });
  plot.appendChild(svg('text', { class: 'tempo__label', x: 10, y: 60 }, clockMs(timeline[0].time)));
  plot.appendChild(svg('text', { class: 'tempo__label', x: W - 10, y: 60, 'text-anchor': 'end' }, clockMs(timeline[timeline.length - 1].time)));
  return h('div', { class: 'tempo-wrap' }, plot,
    h('p', { class: 'tempo-note' }, 'Gaps are compressed (a log scale), so seconds and minutes both stay readable; breaks mark quiet stretches over 5 minutes. Taller ticks are correlation signals. Bands underneath are the stages.'));
}

function cadencePanel(d) {
  const c = d.cadence || {};
  const bins = gapBins((d.timeline || []).map((e) => e.time));
  const max = Math.max(1, ...bins.bins.map((b) => b.count));
  const hist = bins.gaps ? h('ol', { class: ['cadence', 'cadence--compact'], 'aria-label': 'Gaps in each range, from the timeline' }, bins.bins.map((b, i) => {
    const fill = h('span', { class: 'cadence__fill' });
    fill.style.transform = `scaleY(${(b.count / max).toFixed(4)})`;
    return h('li', { class: ['cadence__col', i === bins.peak ? 'is-peak' : ''] },
      h('span', { class: 'cadence__bar', 'aria-hidden': 'true' }, fill),
      h('span', { class: 'cadence__count' }, formatCount(b.count)),
      h('span', { class: 'cadence__label' }, b.label));
  })) : null;
  return panel({
    title: titled('Pace', 'regularity'),
    meta: 'From every event in the session, signals included',
    body: [
      h('dl', { class: 'figures' },
        [['Median gap', formatDurationMs(c.median_gap_ms)], ['90th percentile', formatDurationMs(c.p90_gap_ms)], ['Shortest gap', formatDurationMs(c.min_gap_ms)],
          ['Events per minute', Number.isFinite(c.events_per_minute) ? (Math.round(c.events_per_minute * 10) / 10).toLocaleString('en-US') : '—'], ['Regularity', regularityText(c)]]
          .map(([k, v]) => h('div', { class: 'figures__item' }, h('dt', null, k), h('dd', null, v)))),
      h('p', { class: 'figures__note' }, 'Regularity is the share of gaps within 25% of the median gap (with a zero median, only zero gaps count). The median is the upper median and the 90th percentile is nearest-rank. Zero gaps can be clock precision, not speed.'),
      hist,
      hist ? h('p', { class: 'cadence-caveat' }, `Histogram from the ${formatCount(bins.events)} events in the timeline${d.timeline_truncated ? ' (the first 200 only)' : ''}.`) : null,
    ],
  });
}

function automationPanel(d) {
  const a = assessmentOf(d.automation);
  const items = Array.isArray(d.automation?.evidence) ? d.automation.evidence : [];
  return panel({
    title: titled('Automation observations', 'automation'),
    meta: 'Pace is read from interactions only: correlation signals are excluded so their generated timestamps cannot add evidence',
    body: [
      h('p', { class: 'assess-line' }, assessmentChip(d.automation)),
      items.length ? h('ul', { class: 'obs-list' }, items.map((o) => {
        const m = evidenceMeta(o?.code);
        return h('li', { class: ['obs', o?.code === 'insufficient_events' ? 'obs--quiet' : ''] },
          h('p', { class: 'obs__title' }, m.title, tip(m.guide)),
          m.text ? h('p', { class: 'obs__text' }, m.text) : null,
          o?.detail ? h('p', { class: 'obs__detail' }, h('span', { class: 'caps' }, 'Server'), ' ', String(o.detail)) : null);
      })) : empty('No observations', 'Neither the pace nor the rules that fired established anything here.', null, { icon: 'info' }),
      h('p', { class: 'figures__note' }, a.key === 'consistent_with_automation'
        ? 'At least one observation holds. It describes this run of events; it does not attribute it to an LLM, a tool or a person, and it does not say any technique succeeded.'
        : 'Not establishing automation is not evidence of a person: these are a few selected checks, not a classifier.'),
    ],
  });
}

export default {
  title: 'Session',
  async render(root, ctx) {
    const id = ctx.route.params.id;
    if (!isSessionId(id)) throw new Error('invalid session id');
    const d = await ctx.api.attackSession(id, { signal: ctx.signal });
    let route = ctx.route;
    const timeline = Array.isArray(d.timeline) ? d.timeline : [];
    const keys = timeline.filter((e) => isEventId(e.event_id)).map(keyOfEntry);
    const rowHref = (key) => {
      const { id: evId, node } = parseEventKey(key);
      return withQuery(route, { event: evId, event_node: node });
    };
    const storySlot = h('div', { class: 'story-wrap' }, timelineView(d, rowHref));
    const tempo = tempoView(d, storySlot, rowHref);
    const unfold = unfoldSentence(d).map((seg) => (seg.t === 'ev' ? evidence(seg.v, { max: 40 }) : seg.v));

    // ---- Event side panel (shared with Events) -------------------------------
    let drawer = null;
    let openKey = '';
    let ctl = null;
    let pushed = false;
    const mark = (key) => {
      for (const el of storySlot.querySelectorAll('.story__event.is-open')) el.classList.remove('is-open');
      if (key) storySlot.querySelector(`.story__event[data-key="${key}"]`)?.classList.add('is-open');
    };
    const close = () => {
      if (pushed) history.back();
      else location.replace(withQuery(route, { event: '', event_node: '' }));
    };
    const step = (delta) => {
      const i = keys.indexOf(openKey);
      const j = moveIndex(i, delta, keys.length);
      if (j >= 0 && j !== i) location.replace(rowHref(keys[j]));
    };
    const open = async (key) => {
      if (!drawer) drawer = createDrawer({ onRequestClose: close, onStep: step, onFull: (e) => { e.preventDefault(); const k = parseEventKey(openKey); location.hash = k.node ? href('events', k.id, { node: k.node }) : href('events', k.id); } });
      if (!drawer.dialog.open) { drawer.dialog.showModal(); drawer.focusTitle(); }
      if (key === openKey) return;
      openKey = key;
      mark(key);
      drawer.setNav({ index: keys.indexOf(key), count: keys.length, id: key });
      ctl?.abort();
      ctl = new AbortController();
      const signal = ctl.signal;
      try {
        const next = h('div');
        const ref = parseEventKey(key);
        await renderEventDetail(next, ctx, ref.id, { node: ref.node, inDrawer: true, signal });
        if (signal.aborted) return;
        next.querySelector('#page-title')?.setAttribute('id', 'drawer-event-title');
        mount(drawer.body, ...next.childNodes);
        drawer.scroll.scrollTop = 0;
      } catch (err) {
        if (signal.aborted || err?.name === 'AbortError') return;
        const t = tenantInfo(ctx.session);
        mount(drawer.body, h('div', { class: 'panel' }, err?.code === 'not_found' && t.show ? notFoundInTenant(t) : errorState(err)));
      }
    };
    const shut = () => {
      const last = openKey;
      ctl?.abort();
      openKey = '';
      pushed = false;
      mark('');
      if (drawer?.dialog.open) {
        drawer.dialog.close();
        if (last) storySlot.querySelector(`.story__summary[data-key="${last}"]`)?.focus({ preventScroll: true });
      }
    };
    const sync = (r) => {
      route = r;
      const evId = r.query.event;
      const node = r.query.event_node;
      if (isEventId(evId)) open(isNodeId(node) ? eventKey({ id: evId, node: { id: node } }) : evId);
      else shut();
    };
    storySlot.addEventListener('click', (e) => {
      if (e.metaKey || e.ctrlKey || e.shiftKey) return;
      if (e.target.closest?.('[data-row-link]')) { pushed = true; return; }
      if (e.target.closest?.('a, button')) return;
      if (String(getSelection?.() ?? '')) return;
      e.target.closest?.('.story__event')?.querySelector('[data-row-link]')?.click();
    });
    // j/k step through the story; Enter on a focused summary opens it.
    const onKey = (e) => {
      if (e.defaultPrevented || e.metaKey || e.ctrlKey || e.altKey || isTypingTarget(e.target)) return;
      if (drawer?.dialog.open) {
        if (e.key === 'j' || e.key === 'k') { e.preventDefault(); step(e.key === 'j' ? 1 : -1); }
        return;
      }
      if (document.querySelector('dialog[open]')) return;
      if (e.key !== 'j' && e.key !== 'k') return;
      const links = [...storySlot.querySelectorAll('[data-row-link]')];
      if (!links.length) return;
      e.preventDefault();
      const i = links.indexOf(document.activeElement);
      const j = moveIndex(i, e.key === 'j' ? 1 : -1, links.length);
      links[j < 0 ? 0 : j]?.focus();
      links[j < 0 ? 0 : j]?.scrollIntoView({ block: 'nearest' });
    };
    document.addEventListener('keydown', onKey);

    // ---- Actions ---------------------------------------------------------------
    const localIds = [...new Set(timeline.filter((e) => e.node_id === 'local' && isEventId(e.event_id)).map((e) => e.event_id))].slice(0, 200);
    let investigate = null;
    if (ctx.can('analyst') && localIds.length) {
      investigate = h('button', { class: ['btn', 'btn--primary'], type: 'button' }, icon('investigations', { size: 'sm' }), 'New investigation with these events');
      investigate.addEventListener('click', async () => {
        const inv = await newInvestigationDialog(ctx, { eventIds: localIds });
        if (inv?.id) {
          toast('ok', `Investigation created with ${localIds.length} event${localIds.length === 1 ? '' : 's'}.`);
          ctx.navigate(href('investigations', inv.id));
        }
      });
    }

    const a = assessmentOf(d.automation);
    const total = Number(d.event_count) || timeline.length;
    mount(root,
      pageHead({
        crumbs: [['Sessions', href('sessions')], [evidence(d.source, { max: 28 }), href('sources', d.source)], ['Session', null]],
        hint: 'Read the story in order, open any event in the side panel (j/k to step), then download or start an investigation.',
        title: h('span', { class: 'session-title' }, evidence(d.source)),
        subtitle: `${formatDateTime(d.first_seen)} to ${formatDateTime(d.last_seen)} · ${formatDurationMs(d.duration_ms)} · ${formatCount(total)} event${total === 1 ? '' : 's'}. The source key is what the sensors recorded, not a verified identity.`,
        actions: [investigate, link(href('sources', d.source), 'Source profile'), link(href('events', { source: d.source }), 'All events from this source')],
      }),
      h('section', { class: ['story-hero', `story-hero--${a.glyph}`], 'aria-label': 'Session at a glance' },
        h('div', { class: 'story-hero__lead' },
          h('p', { class: 'caps' }, 'Automation observation'),
          h('p', { class: 'story-hero__assess' }, assessmentChip(d.automation)),
          h('p', { class: 'muted' }, 'An observation from pace and rules, with the evidence listed below. Never a verdict about who or what is behind it.')),
        h('dl', { class: 'story-hero__figures' },
          [['Duration', formatDurationMs(d.duration_ms)], ['Events', formatCount(total)], ['Median gap', formatDurationMs(d.cadence?.median_gap_ms)], ['Max severity', sevChip(d.max_severity)], ['Surfaces', kindChips(d.sensor_kinds)]]
            .map(([k, v]) => h('div', null, h('dt', null, k), h('dd', null, v)))),
        stageRibbon(Array.isArray(d.phases) ? d.phases : [], total)),
      d.timeline_truncated ? banner('warn', 'Timeline shows the first 200 events', `This session has ${formatCount(total)} events. The timeline, its stages and the histogram cover the first 200; counts and pace above cover all of them.`) : null,
      h('div', { class: 'story-layout' },
        panel({
          primary: true,
          title: titled('Timeline', 'session'),
          meta: 'Oldest first, grouped into stages by the rules that fired. Gaps over 5 minutes are collapsed. j and k move between events; Enter opens one.',
          body: [h('p', { class: 'unfold' }, unfold), tempo, storySlot],
        }),
        h('div', { class: 'story-side' },
          automationPanel(d),
          cadencePanel(d),
          panel({
            title: titled('Frameworks', 'mapping'),
            meta: 'Techniques the fired rules relate to (editorial). Not proof a technique was used or succeeded',
            body: [frameworkChips(d.frameworks), h('p', { class: 'figures__note' }, 'Rules: ', ruleChips(d.rule_ids))],
          }),
          panel({ title: 'Downloads', meta: 'Generated by the server from this session', body: downloadActions(ctx, { scope: { session: d.id }, report: () => ctx.api.sessionReport(d.id), what: 'this session' }) }),
          panel({
            title: 'Details',
            body: kv([
              ['Session id', h('code', { class: 'hash' }, d.id)],
              ['Sensors', h('span', { class: 'chip-row' }, (d.sensors || []).map((x) => chip(x, { mono: true })), d.sensors_truncated ? chip('more not listed') : null)],
              ['Classes', h('span', { class: 'chip-row' }, Object.entries(d.classification_counts || {}).map(([k, v]) => chip(`${k.replace(/_/g, ' ')} ${v}`)))],
              ['Bounds', h('span', { class: 'kv-note' }, boundsNote(d.bounds))],
              ['Session id stability', h('span', { class: 'kv-note' }, 'Derived from the first retained event; it can change when that event ages out or the process restarts.')],
            ]),
          }))));

    return {
      cleanup() {
        document.removeEventListener('keydown', onKey);
        ctl?.abort();
        if (drawer) {
          if (drawer.dialog.open) drawer.dialog.close();
          drawer.dialog.remove();
        }
      },
      update: sync,
      mounted: () => sync(route),
    };
  },
};
