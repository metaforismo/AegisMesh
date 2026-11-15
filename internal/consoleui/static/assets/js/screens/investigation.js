import { h, mount } from '../lib/dom.js';
import { INVESTIGATION_STATUSES, PRIORITIES } from '../lib/taxonomy.js';
import { formatDateTime, formatCount } from '../lib/format.js';
import { pageHead, panel, kv, selectField, inputField, empty, toast, openDialog, timeEl, labelFor, banner, copyable } from '../ui/components.js';
import { icon } from '../ui/icons.js';
import { eventTable, statusBadge, priorityChip } from './shared.js';

const NOTE_MAX = 4000;
const MAX_EVIDENCE = 200;

// Edits are optimistic: the page changes at once, the request runs, and on
// failure the change is rolled back and the operator is told why. Nothing is
// re-fetched on success; the server's response is the new truth.
export default {
  title: 'Investigation',
  async render(root, ctx) {
    const id = ctx.route.params.id;
    const inv = await ctx.api.investigation(id, { signal: ctx.signal });
    const canWrite = ctx.can('analyst');
    const events = Array.isArray(inv.events) ? inv.events : [];
    const indexed = new Set(events.map((e) => e.id));
    let eventIds = [...(inv.event_ids || [])];
    const missing = eventIds.filter((eid) => !indexed.has(eid));
    const notes = Array.isArray(inv.notes) ? inv.notes : [];
    const state = { title: inv.title || '(untitled)', status: inv.status, priority: inv.priority };

    // Live pieces of the page that edits update in place.
    const titleText = h('span', null, state.title);
    const statusSlot = h('span', null, statusBadge(state.status));
    const prioritySlot = h('span', null, priorityChip(state.priority));
    const evidenceTitle = h('span', null);
    const updated = h('span', null, timeEl(inv.updated_at));
    const paintEvidenceTitle = () => { evidenceTitle.textContent = `Evidence (${formatCount(eventIds.length)} of ${MAX_EVIDENCE})`; };
    paintEvidenceTitle();
    const settle = (res) => {
      if (res?.updated_at) mount(updated, timeEl(res.updated_at));
    };

    const failed = (err, what) => toast('error', `${what} was not saved and has been undone. ${err?.message || ''}`.trim());

    // ---- Status and priority -------------------------------------------------
    const optimisticField = (field, slot, paint, label) => async (value, select) => {
      const before = state[field];
      if (value === before) return;
      state[field] = value;
      mount(slot, paint(value));
      try {
        settle(await ctx.api.updateInvestigation(id, { [field]: value }));
        toast('ok', `${label} set to ${labelFor(value)}.`);
      } catch (err) {
        state[field] = before;
        mount(slot, paint(before));
        if (select) select.value = before;
        failed(err, `The ${label.toLowerCase()} change`);
      }
    };
    const setStatus = optimisticField('status', statusSlot, statusBadge, 'Status');
    const setPriority = optimisticField('priority', prioritySlot, priorityChip, 'Priority');

    let controls = null;
    if (canWrite) {
      const rename = h('button', { class: 'btn', type: 'button' }, 'Rename');
      rename.addEventListener('click', async () => {
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
          toast('ok', 'Renamed.');
        } catch (err) {
          state.title = before;
          titleText.textContent = before;
          failed(err, 'The new title');
        }
      });
      const statusField = selectField({ label: 'Status', name: 'status', value: state.status, options: INVESTIGATION_STATUSES.map((s) => [s, labelFor(s)]) });
      const priorityField = selectField({ label: 'Priority', name: 'priority', value: state.priority, options: PRIORITIES.map((p) => [p, labelFor(p)]) });
      statusField.querySelector('select').addEventListener('change', (e) => setStatus(e.target.value, e.target));
      priorityField.querySelector('select').addEventListener('change', (e) => setPriority(e.target.value, e.target));
      controls = h('div', { class: 'inv-controls' }, statusField, priorityField, rename);
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
        toast('ok', 'Evidence detached.');
      } catch (err) {
        eventIds.splice(Math.max(0, index), 0, eid);
        if (parent && rowEl) parent.insertBefore(rowEl, nextSibling);
        paintEvidenceTitle();
        failed(err, 'Detaching the event');
      }
    };
    const detachBtn = (eid) => {
      const b = h('button', { class: ['btn', 'btn--sm', 'btn--danger'], type: 'button', 'aria-label': `Detach event ${eid}` }, 'Detach');
      b.addEventListener('click', () => detach(eid, b.closest('tr, li')));
      return b;
    };

    // ---- Notes ---------------------------------------------------------------
    const noteItem = (n, pending = false) => h('li', { class: ['timeline__item', pending ? 'is-pending' : ''] },
      h('span', { class: ['glyph', 'glyph--note'], 'aria-hidden': 'true' }),
      h('p', { class: 'timeline__time' }, n.author || 'unknown', ' · ', pending ? 'saving…' : timeEl(n.time)),
      h('p', { class: 'note-text' }, n.text));
    const noteList = h('ol', { class: 'timeline', hidden: !notes.length }, notes.map((n) => noteItem(n)));
    const notesEmpty = notes.length ? null : empty('No notes yet', canWrite ? 'Record what you checked and what you concluded.' : '', null, { icon: 'investigations' });
    const notesTitle = h('span', null, `Notes (${notes.length})`);
    let noteCount = notes.length;

    let noteForm = null;
    if (canWrite) {
      const area = h('textarea', { class: 'textarea', id: 'note-text', name: 'text', maxlength: NOTE_MAX, rows: 4, 'aria-describedby': 'note-count' });
      const count = h('span', { class: 'field__hint', id: 'note-count' }, `0 / ${NOTE_MAX}`);
      const paintCount = () => { count.textContent = `${Array.from(area.value).length} / ${NOTE_MAX}`; };
      area.addEventListener('input', paintCount);
      const submit = h('button', { class: ['btn', 'btn--primary'], type: 'submit' }, 'Add note');
      noteForm = h('form', { class: 'stack' },
        h('div', { class: 'field' }, h('label', { class: 'field__label', for: 'note-text' }, 'New note'), area, count),
        h('p', { class: 'muted' }, 'Notes are visible to every viewer. Note bodies are never written to the audit trail.'),
        h('div', { class: 'btn-row' }, submit));
      noteForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const text = area.value.trim();
        if (!text) return;
        const pending = noteItem({ author: ctx.session?.principal?.name, text }, true);
        noteList.hidden = false;
        notesEmpty?.remove();
        noteList.appendChild(pending);
        noteCount++;
        notesTitle.textContent = `Notes (${noteCount})`;
        area.value = '';
        paintCount();
        submit.disabled = true;
        try {
          const res = await ctx.api.addNote(id, text);
          const saved = Array.isArray(res?.notes) ? res.notes[res.notes.length - 1] : null;
          pending.replaceWith(noteItem(saved && saved.text === text ? saved : { author: ctx.session?.principal?.name, text, time: new Date().toISOString() }));
          settle(res);
          toast('ok', 'Note added.');
        } catch (err) {
          pending.remove();
          noteCount--;
          notesTitle.textContent = `Notes (${noteCount})`;
          // Give the text back so nothing typed is lost.
          area.value = text;
          paintCount();
          failed(err, 'The note');
        } finally {
          submit.disabled = false;
        }
      });
    }

    mount(root,
      pageHead({
        eyebrow: h('a', { href: '#/investigations' }, icon('arrow-left', { size: 'xs' }), 'Investigations'),
        title: titleText,
        subtitle: h('span', { class: 'btn-row' }, statusSlot, prioritySlot,
          h('span', { class: 'muted' }, `Opened by ${inv.created_by || 'unknown'} · ${formatDateTime(inv.created_at)}`)),
      }),
      canWrite ? panel({ title: 'Case settings', meta: 'Changes apply immediately. There is no edit lock: if two analysts edit at once, the last write wins.', body: controls }) : null,
      panel({
        title: evidenceTitle, flush: true,
        meta: 'Attached events still present in the index, newest first',
        body: [
          events.length ? eventTable(events, { caption: 'Attached evidence', extra: canWrite ? [{ label: 'Action', cell: (ev) => detachBtn(ev.id) }] : [] })
            : empty('No indexed evidence', canWrite ? 'Open an event and choose “Add to investigation”.' : ''),
          missing.length ? h('div', { class: 'panel__body' }, banner('warn', `${missing.length} attached event${missing.length === 1 ? ' is' : 's are'} no longer indexed`,
            h('p', null, 'They aged out of the in-memory index. The ids stay on the case; read the records with ', h('code', null, 'aegismesh inspect'), '.'),
            h('ul', { class: 'plain-list' }, missing.map((eid) => h('li', { class: 'btn-row' }, copyable(eid, { label: 'event id' }), canWrite ? detachBtn(eid) : null))))) : null,
        ],
      }),
      panel({
        title: notesTitle, meta: 'Oldest first',
        body: [noteList, notesEmpty, noteForm],
      }),
      panel({ title: 'Record', body: kv([['Investigation id', copyable(inv.id, { label: 'investigation id' })], ['Last updated', updated]]) }));
  },
};
