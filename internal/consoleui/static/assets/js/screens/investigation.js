import { h, clear, mount } from '../lib/dom.js';
import { INVESTIGATION_STATUSES, PRIORITIES } from '../lib/taxonomy.js';
import { formatDateTime, formatCount } from '../lib/format.js';
import { pageHead, panel, kv, selectField, inputField, empty, toast, openDialog, timeEl, labelFor, banner } from '../ui/components.js';
import { eventTable, statusBadge, priorityChip } from './shared.js';

const NOTE_MAX = 4000;

export default {
  title: 'Investigation',
  async render(root, ctx) {
    const id = ctx.route.params.id;
    const inv = await ctx.api.investigation(id, { signal: ctx.signal });
    const canWrite = ctx.can('analyst');
    const events = Array.isArray(inv.events) ? inv.events : [];
    const indexed = new Set(events.map((e) => e.id));
    const missing = (inv.event_ids || []).filter((eid) => !indexed.has(eid));
    const notes = Array.isArray(inv.notes) ? inv.notes : [];

    const mutate = async (fn, okText) => {
      try {
        await fn();
        toast('ok', okText);
        ctx.rerender();
      } catch (err) {
        toast('error', err?.message || 'The change was not saved.');
      }
    };

    const detachBtn = (eid) => {
      const b = h('button', { class: ['btn', 'btn--sm', 'btn--danger'], type: 'button', 'aria-label': `Detach event ${eid}` }, 'Detach');
      b.addEventListener('click', () => mutate(() => ctx.api.detachEvent(id, eid), 'Evidence detached.'));
      return b;
    };

    let controls = null;
    if (canWrite) {
      const editTitle = h('button', { class: 'btn', type: 'button' }, 'Rename');
      editTitle.addEventListener('click', async () => {
        const updated = await openDialog({
          title: 'Rename investigation',
          build: () => inputField({ label: 'Title', name: 'title', value: inv.title || '', maxlength: 200, required: true }),
          onSubmit: (form) => {
            const title = form.elements.title.value.trim();
            if (!title) throw new Error('A title is required.');
            return ctx.api.updateInvestigation(id, { title });
          },
        });
        if (updated) { toast('ok', 'Renamed.'); ctx.rerender(); }
      });
      controls = h('div', { class: 'inv-controls' },
        selectField({ label: 'Status', name: 'status', value: inv.status, options: INVESTIGATION_STATUSES.map((s) => [s, labelFor(s)]),
          onChange: (v) => mutate(() => ctx.api.updateInvestigation(id, { status: v }), `Status set to ${labelFor(v)}.`) }),
        selectField({ label: 'Priority', name: 'priority', value: inv.priority, options: PRIORITIES.map((p) => [p, labelFor(p)]),
          onChange: (v) => mutate(() => ctx.api.updateInvestigation(id, { priority: v }), `Priority set to ${labelFor(v)}.`) }),
        editTitle);
    }

    let noteForm = null;
    if (canWrite) {
      const area = h('textarea', { class: 'textarea', id: 'note-text', name: 'text', maxlength: NOTE_MAX, rows: 4, 'aria-describedby': 'note-count' });
      const count = h('span', { class: 'field__hint', id: 'note-count' }, `0 / ${NOTE_MAX}`);
      area.addEventListener('input', () => { count.textContent = `${Array.from(area.value).length} / ${NOTE_MAX}`; });
      const submit = h('button', { class: ['btn', 'btn--primary'], type: 'submit' }, 'Add note');
      noteForm = h('form', { class: 'stack' },
        h('div', { class: 'field' }, h('label', { class: 'field__label', for: 'note-text' }, 'New note'), area, count),
        h('p', { class: 'muted' }, 'Notes are visible to every viewer. Note bodies are never written to the audit trail.'),
        h('div', { class: 'btn-row' }, submit));
      noteForm.addEventListener('submit', (e) => {
        e.preventDefault();
        const text = area.value.trim();
        if (!text) return;
        submit.disabled = true;
        mutate(() => ctx.api.addNote(id, text), 'Note added.').finally(() => { submit.disabled = false; });
      });
    }

    mount(root,
      pageHead({
        eyebrow: h('a', { href: '#/investigations' }, '← Investigations'),
        title: inv.title || '(untitled)',
        subtitle: h('span', { class: 'btn-row' }, statusBadge(inv.status), priorityChip(inv.priority),
          h('span', { class: 'muted' }, `Opened by ${inv.created_by || 'unknown'} · ${formatDateTime(inv.created_at)}`)),
      }),
      canWrite ? panel({ title: 'Case settings', meta: 'Changes apply immediately. There is no edit lock: if two analysts edit at once, the last write wins.', body: controls }) : null,
      panel({
        title: `Evidence (${formatCount((inv.event_ids || []).length)} of 200)`, flush: true,
        meta: 'Attached events still present in the index, newest first',
        body: [
          events.length ? eventTable(events, { caption: 'Attached evidence', extra: canWrite ? [{ label: 'Action', cell: (ev) => detachBtn(ev.id) }] : [] })
            : empty('No indexed evidence', canWrite ? 'Open an event and choose “Add to investigation”.' : ''),
          missing.length ? h('div', { class: 'panel__body' }, banner('warn', `${missing.length} attached event${missing.length === 1 ? ' is' : 's are'} no longer indexed`,
            h('p', null, 'They aged out of the in-memory index. The ids stay on the case; read the records with ', h('code', null, 'aegismesh inspect'), '.'),
            h('ul', { class: 'plain-list' }, missing.map((eid) => h('li', { class: 'btn-row' }, h('code', null, eid), canWrite ? detachBtn(eid) : null))))) : null,
        ],
      }),
      panel({
        title: `Notes (${notes.length})`, meta: 'Oldest first',
        body: [
          notes.length ? h('ol', { class: 'timeline' }, notes.map((n) => h('li', { class: 'timeline__item' },
            h('span', { class: ['glyph', 'glyph--note'], 'aria-hidden': 'true' }),
            h('p', { class: 'timeline__time' }, n.author || 'unknown', ' · ', timeEl(n.time)),
            h('p', { class: 'note-text' }, n.text)))) : empty('No notes yet', canWrite ? 'Record what you checked and what you concluded.' : ''),
          noteForm,
        ],
      }),
      panel({ title: 'Record', body: kv([['Investigation id', h('code', null, inv.id)], ['Last updated', timeEl(inv.updated_at)]]) }));
  },
};
