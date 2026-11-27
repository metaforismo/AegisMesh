// "Open an investigation" from a campaign or a session (contract r8,
// section 2): a title prefilled from the campaign's label or the session's
// source, a priority, the number of events that will be attached, one
// submission at a time, then the new investigation.
//
// On a server without the round-8 route, a session falls back to the
// plain create with the story's local event ids (what the console did
// before); a campaign offers the action only when the server sends its
// member event sample, so there is nothing to fall back to.

import { h } from '../lib/dom.js';
import { href, isOpaqueId } from '../lib/route.js';
import { PRIORITIES, severityRank } from '../lib/taxonomy.js';
import { isMissingEndpoint } from '../lib/insight.js';
import { investigationDraft, createSubmitGuard, MAX_EVIDENCE } from '../lib/workspace.js';
import { openDialog, inputField, selectField, labelFor, toast } from './components.js';
import { icon } from './icons.js';

export function suggestedPriority(maxSeverity) {
  return severityRank(maxSeverity) >= severityRank('high') ? 'high' : 'medium';
}

// Returns the created investigation (or null when cancelled). `open` is the
// dialog function (tests pass a stand-in).
export async function openInvestigationFrom(ctx, { kind, id, label = '', source = '', eventCount = null, maxSeverity = '', fallbackIds = [] }, { open = openDialog } = {}) {
  const draft = investigationDraft({ kind, label, source, id, eventCount });
  const guard = createSubmitGuard();
  const create = async (title, priority) => {
    const body = { title, priority, max_events: MAX_EVIDENCE };
    try {
      return kind === 'campaign' ? await ctx.api.openCampaignInvestigation(id, body) : await ctx.api.openSessionInvestigation(id, body);
    } catch (err) {
      if (!isMissingEndpoint(err) || kind !== 'session' || !fallbackIds.length) throw err;
      // An older server: the plain create with the story's own event ids.
      return ctx.api.createInvestigation({ title, priority, event_ids: fallbackIds.slice(0, MAX_EVIDENCE) });
    }
  };
  const inv = await open({
    title: kind === 'campaign' ? 'Open an investigation from this campaign' : 'Open an investigation from this session',
    submitLabel: 'Open investigation',
    build: () => [
      inputField({ label: 'Title', name: 'title', value: draft.title, maxlength: 200, required: true, hint: 'Prefilled; change it to say what you are looking into. Titles appear in lists for every viewer, so avoid pasting secrets.' }),
      selectField({ label: 'Priority', name: 'priority', value: suggestedPriority(maxSeverity), options: PRIORITIES.map((p) => [p, labelFor(p)]) }),
      h('p', { class: 'dialog__note' }, icon('investigations', { size: 'sm' }), h('span', null, draft.sentence)),
    ],
    onSubmit: (form) => guard.run(() => {
      const title = String(form.elements.title.value || '').trim();
      const priority = PRIORITIES.includes(form.elements.priority.value) ? form.elements.priority.value : 'medium';
      if (!title) throw new Error('A title is required.');
      return create(title, priority);
    }),
  });
  if (!inv?.id || !isOpaqueId(inv.id)) return null;
  const n = Array.isArray(inv.event_ids) ? inv.event_ids.length : 0;
  toast('ok', `Investigation opened with ${n === 1 ? 'one event' : `${n} events`} attached.`);
  ctx.navigate(href('investigations', inv.id));
  return inv;
}
