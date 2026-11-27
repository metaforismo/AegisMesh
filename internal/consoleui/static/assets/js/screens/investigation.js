// One investigation: the defender's working surface (round 8).
//
// Header: title, the status flow (open → monitoring → closed, what the API
// supports), priority, assignee and where the case came from. Under it a
// summary strip of the attached evidence. Then two columns from 1200px:
// the evidence as a compact timeline grouped by source (detach in place),
// and beside it the activity feed merged with the notes, with the composer
// and its plain-text preview; report and exports in one place.
//
// Edits are optimistic: the page changes at once, the request runs, and on
// failure the change is rolled back and the operator is told why. The
// server's answer (the whole investigation) then redraws the feed and the
// summary. An older server has no assignee, activity, summary or origin:
// the page draws what it has and computes the summary from the events.

import { h, mount } from '../lib/dom.js';
import { href } from '../lib/route.js';
import { PRIORITIES, isSeverity } from '../lib/taxonomy.js';
import { formatCount, formatDateTime } from '../lib/format.js';
import {
  STATUS_FLOW, STATUS_WORDS, MAX_EVIDENCE, normalizeOrigin, workspaceFeatures, summaryOf, groupEvidence, mergeFeed,
  activityWords, assigneeOptions, eligibleAssignees, assigneeName,
} from '../lib/workspace.js';
import { isMissingEndpoint } from '../lib/insight.js';
import { BUILTIN_PERMS } from '../lib/perms.js';
import { pageHead, panel, kv, sevChip, chipList, evidence, glyph, empty, toast, openDialog, inputField, timeEl, labelFor, banner, copyable, segmented } from '../ui/components.js';
import { eventHref } from './shared.js';
import { downloadActions } from '../ui/downloads.js';
import { icon } from '../ui/icons.js';

const NOTE_MAX = 4000;

// Who the case may be assigned to: the server's list (round 8), else, for
// someone who may read accounts, the accounts whose role reads
// investigations; else nobody beyond you and the current assignee.
async function loadAssignees(ctx) {
  try {
    const res = await ctx.api.assignees({ signal: ctx.signal });
    return Array.isArray(res?.assignees) ? res.assignees : [];
  } catch (err) {
    if (err?.name === 'AbortError' || !isMissingEndpoint(err) || !ctx.can('accounts.read')) return [];
  }
  try {
    const [acc, roles] = await Promise.all([ctx.api.accounts({ signal: ctx.signal }), ctx.api.roles({ signal: ctx.signal }).catch(() => null)]);
    const byRole = new Map((roles?.items || []).map((r) => [r.id, r.permissions || []]));
    return eligibleAssignees(acc?.items, (role) => byRole.get(role) || BUILTIN_PERMS[role] || [], ctx.session?.tenant || '');
  } catch {
    return [];
  }
}

function originLine(origin) {
  if (!origin) return null;
  return origin.kind === 'campaign'
    ? h('a', { class: 'ws-origin', href: href('campaigns', origin.id) }, icon('campaign', { size: 'sm' }), 'Opened from a campaign')
    : h('a', { class: 'ws-origin', href: href('sessions', origin.id) }, icon('story', { size: 'sm' }), 'Opened from a session');
}

export default {
  title: 'Investigation',
  async render(root, ctx) {
    const id = ctx.route.params.id;
    let inv = await ctx.api.investigation(id, { signal: ctx.signal });
    ctx.setTitle?.(inv?.title || '');
    const canWrite = ctx.can('investigations.write');
    const has = workspaceFeatures(inv);
    const meId = ctx.me?.id || '';
    const meName = ctx.me?.name || ctx.session?.principal?.name || '';
    const events = Array.isArray(inv.events) ? inv.events : [];
    const indexed = new Set(events.map((e) => e.id));
    let eventIds = [...(inv.event_ids || [])];
    const missing = eventIds.filter((eid) => !indexed.has(eid));
    const state = { title: inv.title || '(untitled)', status: inv.status, priority: inv.priority, assignee: inv.assignee || '' };
    const pendingNotes = [];

    const failed = (err, what) => toast('error', `${what} was not saved and has been undone. ${err?.message || ''}`.trim());

    // ---- Regions redrawn from the server's answers -------------------------------
    const titleText = h('span', null, state.title);
    const updated = h('span', null, timeEl(inv.updated_at));
    const evidenceTitle = h('span', null);
    const paintEvidenceTitle = () => { evidenceTitle.textContent = `Evidence · ${formatCount(eventIds.length)} of ${MAX_EVIDENCE}`; };
    paintEvidenceTitle();
    const summarySlot = h('div');
    const feedSlot = h('div');
    const feedCount = h('span');

    const paintSummary = () => {
      const s = summaryOf(inv);
      const cell = (label, value, note) => h('div', { class: 'ws-sum__cell' }, h('dt', null, label), h('dd', null, value), note ? h('dd', { class: 'ws-sum__note' }, note) : null);
      mount(summarySlot, h('section', { class: 'ws-sum', 'aria-label': 'What the attached evidence covers' },
        h('dl', { class: 'ws-sum__grid' },
          cell('Sources', s.sources === null ? '—' : formatCount(s.sources)),
          cell('Sensors', chipList(s.sensors, { max: 2 })),
          cell('First seen', s.firstSeen ? timeEl(s.firstSeen, { relative: true }) : '—'),
          cell('Last seen', s.lastSeen ? timeEl(s.lastSeen, { relative: true }) : '—'),
          cell('Max severity', sevChip(s.maxSeverity)),
          cell('Rules', chipList(s.ruleIds, { max: 3 }))),
        h('p', { class: 'ws-sum__basis' }, s.computed ? 'From the attached events still in the index, computed in your browser.' : 'From the attached events still in the index, computed by the server.')));
    };

    const feedItem = (x) => {
      if (x.type === 'note') {
        return h('li', { class: ['feed__item', 'feed__item--note', x.pending ? 'is-pending' : ''] },
          h('span', { class: 'feed__mark', 'aria-hidden': 'true' }, icon('digest', { size: 'sm' })),
          h('div', { class: 'feed__body' },
            h('p', { class: 'feed__line' }, h('span', { class: 'feed__who' }, x.author), ' added a note', h('span', { class: 'feed__when' }, x.pending ? 'saving…' : x.at ? timeEl(x.at, { relative: true }) : '')),
            h('p', { class: 'note-text' }, x.text)));
      }
      const w = activityWords(x.kind);
      return h('li', { class: ['feed__item', 'feed__item--activity', `feed__item--${x.kind}`] },
        h('span', { class: 'feed__mark', 'aria-hidden': 'true' }, icon(w.icon, { size: 'xs' })),
        h('div', { class: 'feed__body' },
          h('p', { class: 'feed__line' }, h('span', { class: 'feed__who' }, x.actorName), ` ${w.verb}`, x.detail ? h('span', { class: 'feed__detail' }, `: ${x.detail}`) : null, h('span', { class: 'feed__when' }, timeEl(x.at, { relative: true })))));
    };
    const paintFeed = () => {
      const notes = [...(Array.isArray(inv.notes) ? inv.notes : []), ...pendingNotes];
      const feed = mergeFeed(has.activity ? inv.activity : [], notes);
      const noteCount = notes.length;
      feedCount.textContent = has.activity ? `Activity and notes · ${formatCount(noteCount)} note${noteCount === 1 ? '' : 's'}` : `Notes · ${formatCount(noteCount)}`;
      mount(feedSlot, inv.activity_truncated === true ? h('p', { class: 'feed__truncated' }, icon('history', { size: 'sm' }), 'Older activity is no longer kept here; the audit trail has every change.') : null, feed.length
        ? h('ol', { class: 'feed', 'aria-label': 'Oldest first' }, feed.map(feedItem))
        : empty('No notes yet', canWrite ? 'Record what you checked and what you concluded.' : '', null, { icon: 'investigations' }));
    };
    // The server answers every change with the whole investigation.
    const settle = (res) => {
      if (!res || typeof res !== 'object') return;
      inv = res;
      if (res.updated_at) mount(updated, timeEl(res.updated_at));
      paintSummary();
      paintFeed();
    };

    // ---- Status, priority, assignee ------------------------------------------
    const flowButtons = new Map();
    const flow = h('ol', { class: 'flow', 'aria-label': 'Status' }, STATUS_FLOW.map((s, i) => {
      const words = STATUS_WORDS[s];
      const inner = [h('span', { class: 'flow__num', 'aria-hidden': 'true' }, String(i + 1)), h('span', { class: 'flow__label' }, words.label)];
      const el = canWrite
        ? h('button', { class: 'flow__step', type: 'button', title: words.hint, 'aria-pressed': 'false' }, inner)
        : h('span', { class: 'flow__step', title: words.hint }, inner);
      flowButtons.set(s, el);
      if (canWrite) el.addEventListener('click', () => setField('status', s));
      return h('li', { class: 'flow__item' }, el, i < STATUS_FLOW.length - 1 ? h('span', { class: 'flow__arrow', 'aria-hidden': 'true' }, icon('chevron-right', { size: 'xs' })) : null);
    }));
    const paintFlow = () => {
      const at = STATUS_FLOW.indexOf(state.status);
      for (const [s, el] of flowButtons) {
        const i = STATUS_FLOW.indexOf(s);
        el.classList.toggle('is-current', s === state.status);
        el.classList.toggle('is-done', at >= 0 && i < at);
        if (canWrite) el.setAttribute('aria-pressed', String(s === state.status));
        if (s === state.status) el.setAttribute('aria-current', 'step');
        else el.removeAttribute('aria-current');
      }
    };
    const prioritySlot = h('div', { class: 'ws-field__control' });
    const paintPriority = () => mount(prioritySlot, canWrite
      ? segmented({ label: 'Priority', options: PRIORITIES.map((p) => [p, labelFor(p)]), value: state.priority, onChange: (p) => setField('priority', p) })
      : h('span', { class: 'chip' }, labelFor(state.priority || 'unknown')));

    let options = assigneeOptions({ meId, meName, current: state.assignee || null, currentName: inv.assignee_name || '' });
    const assigneeSlot = h('div', { class: 'ws-field__control' });
    const paintAssignee = () => {
      if (!canWrite) {
        mount(assigneeSlot, state.assignee ? h('span', { class: 'ws-assignee' }, icon('user', { size: 'sm' }), assigneeName({ ...inv, assignee: state.assignee }, options)) : h('span', { class: 'muted' }, 'Unassigned'));
        return;
      }
      const select = h('select', { class: 'select', id: 'ws-assignee', name: 'assignee' }, options.map(([v, label]) => h('option', { value: v, selected: v === state.assignee }, label)));
      select.addEventListener('change', () => setField('assignee', select.value, select));
      mount(assigneeSlot, select);
    };

    const LABEL = { status: 'Status', priority: 'Priority', assignee: 'Assignee' };
    const paintAll = () => { paintFlow(); paintPriority(); paintAssignee(); };
    async function setField(field, value, control) {
      const before = state[field];
      if (value === before) return;
      state[field] = value;
      paintAll();
      try {
        settle(await ctx.api.updateInvestigation(id, { [field]: field === 'assignee' ? (value || null) : value }));
        const said = field === 'assignee'
          ? (value ? `Assigned to ${options.find(([v]) => v === value)?.[1] || value}.` : 'Now unassigned.')
          : `${LABEL[field]} set to ${field === 'status' ? STATUS_WORDS[value]?.label || value : labelFor(value)}.`;
        toast('ok', said);
      } catch (err) {
        state[field] = before;
        paintAll();
        if (control) control.value = before;
        failed(err, `The ${LABEL[field].toLowerCase()} change`);
      }
    }
    paintAll();
    if (has.assignee && canWrite) {
      loadAssignees(ctx).then((list) => {
        if (ctx.signal?.aborted) return;
        options = assigneeOptions({ assignees: list, meId, meName, current: state.assignee || null, currentName: inv.assignee_name || '' });
        paintAssignee();
      });
    }

    let renameBtn = null;
    if (canWrite) {
      renameBtn = h('button', { class: 'btn', type: 'button' }, 'Rename');
      renameBtn.addEventListener('click', async () => {
        let next = '';
        await openDialog({
          title: 'Rename investigation',
          build: () => inputField({ label: 'Title', name: 'title', value: state.title, maxlength: 200, required: true }),
          submitLabel: 'Rename',
          onSubmit: (form) => {
            next = form.elements.title.value.trim();
            if (!next) throw new Error('A title is required.');
            return next;
          },
        });
        if (!next || next === state.title) return;
        const before = state.title;
        state.title = next;
        titleText.textContent = next;
        try {
          settle(await ctx.api.updateInvestigation(id, { title: next }));
          ctx.setTitle?.(next);
          toast('ok', 'Renamed.');
        } catch (err) {
          state.title = before;
          titleText.textContent = before;
          failed(err, 'The new title');
        }
      });
    }

    // ---- Evidence ------------------------------------------------------------
    const detach = async (eid, rowEl) => {
      const index = eventIds.indexOf(eid);
      const parent = rowEl?.parentNode;
      const nextSibling = rowEl?.nextSibling;
      eventIds = eventIds.filter((x) => x !== eid);
      rowEl?.remove();
      paintEvidenceTitle();
      try {
        settle(await ctx.api.detachEvent(id, eid));
        toast('ok', 'Evidence detached. Attach it again from the event if you need it back.');
      } catch (err) {
        eventIds.splice(Math.max(0, index), 0, eid);
        if (parent && rowEl) parent.insertBefore(rowEl, nextSibling);
        paintEvidenceTitle();
        failed(err, 'Detaching the event');
      }
    };
    const detachBtn = (eid, what) => {
      // Neutral, not danger red: detaching is undone by attaching again.
      const b = h('button', { class: ['btn', 'btn--ghost', 'btn--sm', 'ev-row__detach'], type: 'button', 'aria-label': `Detach ${what}` }, 'Detach');
      b.addEventListener('click', () => detach(eid, b.closest('li')));
      return b;
    };
    const evRow = (e) => h('li', { class: 'ev-row' },
      h('span', { class: 'ev-row__when' }, timeEl(e.time, { relative: true })),
      h('span', { class: 'ev-row__cls' }, glyph(e.classification)),
      h('a', { class: 'ev-row__what', href: eventHref(e) }, evidence(e.summary, { max: 140 })),
      h('span', { class: 'ev-row__meta' }, isSeverity(e.severity) ? sevChip(e.severity) : null, e.sensor?.id ? h('code', { class: 'ev-row__sensor' }, e.sensor.id) : null),
      canWrite ? detachBtn(e.id, `event ${e.id}`) : null);
    const groups = groupEvidence(events);
    const evidenceBody = groups.length
      ? h('div', { class: 'ev-groups' }, groups.map((g) => h('section', { class: 'ev-group', 'aria-label': `Events from ${g.source || 'an unknown source'}` },
        h('header', { class: 'ev-group__head' },
          h('span', { class: 'ev-group__source' }, g.source ? h('a', { href: href('sources', g.source), title: 'Source profile' }, evidence(g.source, { max: 48 })) : h('span', { class: 'muted' }, 'No source')),
          h('span', { class: 'ev-group__meta' }, `${formatCount(g.events.length)} event${g.events.length === 1 ? '' : 's'}`, ' · ', sevChip(g.maxSeverity), ' · ', chipList(g.sensors, { max: 2 }))),
        h('ol', { class: 'ev-list' }, g.events.map(evRow)))))
      : empty('No indexed evidence', canWrite ? 'Open an event and choose “Add to investigation”, or open an investigation from a campaign or a session.' : '');

    // ---- Notes composer ------------------------------------------------------
    let composer = null;
    if (canWrite) {
      const area = h('textarea', { class: 'textarea', id: 'note-text', name: 'text', maxlength: NOTE_MAX, rows: 4, 'aria-describedby': 'note-count note-plain' });
      const count = h('span', { class: 'field__hint', id: 'note-count' }, `0 / ${NOTE_MAX}`);
      const preview = h('div', { class: 'note-preview', hidden: true, 'aria-live': 'polite' });
      let mode = 'write';
      const modeSlot = h('div');
      const paintMode = () => {
        mount(modeSlot, segmented({ label: 'Note view', options: [['write', 'Write'], ['preview', 'Preview']], value: mode, onChange: (m) => { mode = m; paintMode(); } }));
        area.hidden = mode !== 'write';
        preview.hidden = mode !== 'preview';
        const t = area.value;
        mount(preview, t.trim() ? h('p', { class: 'note-text' }, t) : h('p', { class: 'muted' }, 'Nothing to preview yet.'));
      };
      const paintCount = () => { count.textContent = `${Array.from(area.value).length} / ${NOTE_MAX}`; };
      area.addEventListener('input', paintCount);
      const submit = h('button', { class: ['btn', 'btn--primary'], type: 'submit' }, 'Add note');
      composer = h('form', { class: ['stack', 'composer'] },
        h('div', { class: 'composer__head' }, h('label', { class: 'field__label', for: 'note-text' }, 'New note'), modeSlot),
        area, preview,
        h('p', { class: 'composer__foot' }, count, h('span', { class: 'muted', id: 'note-plain' }, 'Plain text: what you type is what everyone reads; nothing is formatted. Note bodies are never written to the audit trail.')),
        h('div', { class: 'btn-row' }, submit));
      paintMode();
      let busy = false;
      composer.addEventListener('submit', async (e) => {
        e.preventDefault();
        const t = area.value.trim();
        if (!t || busy) return;
        busy = true;
        const pending = { author: meName || 'you', text: t, time: new Date().toISOString(), pending: true };
        pendingNotes.push(pending);
        paintFeed();
        area.value = '';
        paintCount();
        mode = 'write';
        paintMode();
        submit.disabled = true;
        try {
          const res = await ctx.api.addNote(id, t);
          pendingNotes.splice(pendingNotes.indexOf(pending), 1);
          settle(res);
          toast('ok', 'Note added.');
        } catch (err) {
          pendingNotes.splice(pendingNotes.indexOf(pending), 1);
          paintFeed();
          // Give the text back so nothing typed is lost.
          area.value = t;
          paintCount();
          failed(err, 'The note');
        } finally {
          submit.disabled = false;
          busy = false;
        }
      });
    }

    // ---- Report and exports, in one place -----------------------------------
    const downloadsPanel = panel({ id: 'ws-exports', title: 'Report and exports', meta: 'The report carries the notes and attached events; indicators and event files cover the attached local events', body: downloadActions(ctx, { scope: { investigation: inv.id }, report: () => ctx.api.investigationReport(inv.id), what: 'this investigation' }) });
    const toDownloads = h('button', { class: 'btn', type: 'button' }, icon('download', { size: 'sm' }), 'Report and exports');
    toDownloads.addEventListener('click', () => {
      downloadsPanel.scrollIntoView({ block: 'start' });
      downloadsPanel.querySelector('button, a[href]')?.focus({ preventScroll: true });
    });

    paintSummary();
    paintFeed();
    const origin = normalizeOrigin(inv.origin);
    mount(root,
      pageHead({
        crumbs: [['Investigations', '#/investigations'], ['Investigation', null]],
        actions: [renameBtn, toDownloads],
        hint: canWrite ? 'Move the status along, assign it, read the evidence by source, and write down what you checked.' : 'Read the evidence by source and the activity. Changing it needs the permission to change investigations.',
        title: titleText,
        subtitle: h('span', { class: 'ws-sub' },
          originLine(origin),
          h('span', { class: 'muted' }, `Opened by ${inv.created_by || 'unknown'} · ${formatDateTime(inv.created_at)}`)),
      }),
      h('section', { class: 'ws-head', 'aria-label': 'Case state' },
        h('div', { class: 'ws-field ws-field--flow' }, h('span', { class: 'ws-field__label', 'aria-hidden': 'true' }, 'Status'), flow),
        h('div', { class: 'ws-field' }, h('span', { class: 'ws-field__label', 'aria-hidden': canWrite ? 'true' : null }, 'Priority'), prioritySlot),
        has.assignee ? h('div', { class: 'ws-field' }, canWrite ? h('label', { class: 'ws-field__label', for: 'ws-assignee' }, 'Assignee') : h('span', { class: 'ws-field__label' }, 'Assignee'), assigneeSlot) : null,
        canWrite ? h('p', { class: 'ws-head__note' }, 'Changes apply at once. There is no edit lock: if two people change the same field, the last change wins, and the activity shows both.') : null),
      summarySlot,
      h('div', { class: 'ws-layout' },
        h('div', { class: 'ws-main' },
          panel({
            title: evidenceTitle, primary: true,
            meta: 'Grouped by source, the most recent first; newest first within each',
            body: [
              evidenceBody,
              missing.length ? banner('warn', `${missing.length} attached event${missing.length === 1 ? ' is' : 's are'} no longer indexed`,
                h('p', null, 'They aged out of the in-memory index. The ids stay on the case; read the records with ', h('code', null, 'aegismesh inspect'), '.'),
                h('ul', { class: 'plain-list' }, missing.map((eid) => h('li', { class: 'btn-row' }, copyable(eid, { label: 'event id' }), canWrite ? detachBtn(eid, `event ${eid}`) : null)))) : null,
            ],
          })),
        h('div', { class: 'ws-side' },
          panel({ title: feedCount, meta: has.activity ? 'Oldest first: who changed what, and every note' : 'Oldest first', body: [feedSlot, composer] }),
          downloadsPanel,
          panel({ title: 'Record', body: kv([['Investigation id', copyable(inv.id, { label: 'investigation id' })], ['Last updated', updated], origin ? ['Origin', h('span', null, labelFor(origin.kind), ' ', h('code', null, origin.id))] : null].filter(Boolean)) }))));
  },
};
