// Editable console settings (contract r6): the /admin/settings renderer
// with edit in place, the "editing is off" explanation, and the change
// history.
//
// Not optimistic on purpose: a setting changes how the console behaves for
// everyone, so the row shows the server's answer after a save, never a
// guess before it. Every value from the server is a Text node.

import { h, mount } from '../lib/dom.js';
import { describeError } from '../lib/api.js';
import { href } from '../lib/route.js';
import {
  settingSourceMeta, settingLabel, formatSettingRaw, constraintText, appliesText, SETTING_EFFECT,
  parseSettingInput, validateChangeReason, editState, durationWords, refusalMessage, normalizeHistory, EDITABLE_KEYS,
} from '../lib/settings.js';
import { permissionLabel } from '../lib/perms.js';
import { copyable, timeEl, toast, banner, empty, table, badge, selectField } from './components.js';
import { confirmAction, formField, choices, errorSummary, wireForm } from './settings-kit.js';
import { icon } from './icons.js';

let seq = 0;
const uid = (p) => `${p}-${++seq}`;

const SRC_KINDS = ['config', 'default', 'env', 'runtime'];

// The source mark: where the effective value comes from. A console
// override is its own mark (an outlined square with the accent line), with
// the word, never colour alone.
function sourceChip(item) {
  if (item.overridden || item.source === 'console') {
    return h('span', { class: ['src-chip', 'src-chip--console'], title: 'Changed in the console. The console stores it; the config file is not written.' },
      h('span', { class: 'src-chip__mark', 'aria-hidden': 'true' }), 'Console');
  }
  const src = settingSourceMeta(item.source);
  return h('span', { class: ['src-chip', `src-chip--${SRC_KINDS.includes(item.source) ? item.source : 'unknown'}`], title: src.hint },
    h('span', { class: 'src-chip__mark', 'aria-hidden': 'true' }), src.label);
}

const valueKind = (it) => (['address', 'text', 'duration', 'count', 'bytes'].includes(it.kind) ? 'num' : '');

// ---- The editor ------------------------------------------------------------------

const UNIT_MULT = { seconds: 1, minutes: 60, hours: 3600 };

// A duration in seconds as a number and a unit (minutes or hours when it
// divides evenly), with the value in words beside it.
function durationControl(item, current) {
  const id = uid('dur');
  const n = Number(current) || 0;
  const unit = n && n % 3600 === 0 ? 'hours' : n && n % 60 === 0 ? 'minutes' : 'seconds';
  const amount = h('input', { class: ['input', 'input--num'], id, type: 'number', inputmode: 'numeric', min: '0', step: '1', autocomplete: 'off', prop: { value: String(n / UNIT_MULT[unit]) } });
  const unitSel = h('select', { class: 'select', 'aria-label': 'Unit' }, Object.keys(UNIT_MULT).map((u) => h('option', { value: u, selected: u === unit }, u)));
  unitSel.value = unit;
  const words = h('span', { class: ['setting-edit__words', 'muted'], 'aria-live': 'polite' });
  const seconds = () => {
    const t = String(amount.value).trim();
    if (!/^\d{1,9}(\.\d+)?$/.test(t)) return t;
    return String(Math.round(Number(t) * UNIT_MULT[unitSel.value]));
  };
  const paint = () => {
    const s = seconds();
    words.textContent = /^\d+$/.test(s) ? `= ${s === '0' && item.constraints?.allow_zero ? 'off' : durationWords(Number(s))} (${Number(s).toLocaleString('en-US')} seconds)` : '';
  };
  amount.addEventListener('input', paint);
  unitSel.addEventListener('change', paint);
  paint();
  return { wrap: (control) => h('div', { class: 'setting-edit__duration' }, control, unitSel, words), control: amount, raw: seconds };
}

function controlFor(item) {
  const c = item.constraints || {};
  const current = item.effective ?? '';
  if (Array.isArray(c.enum) && c.enum.length) {
    const ch = choices({ legend: 'New value', name: uid('enum'), compact: true, value: current, options: c.enum.map((v) => [v, formatSettingRaw(item, v)]) });
    return { field: ch, el: ch.el, raw: () => ch.value(), focus: () => ch.focus(), isFieldset: true };
  }
  if (c.unit === 's') {
    const d = durationControl(item, current);
    const f = formField({ label: 'New value', control: d.control, hint: constraintText(item), wrap: d.wrap });
    return { field: f, el: f.el, raw: d.raw, focus: () => d.control.focus() };
  }
  if (c.unit === 'days' || Number.isFinite(c.min) || Number.isFinite(c.max)) {
    const input = h('input', { class: ['input', 'input--num'], type: 'number', inputmode: 'numeric', min: Number.isFinite(c.min) ? String(c.min) : null, max: Number.isFinite(c.max) ? String(c.max) : null, step: '1', autocomplete: 'off', prop: { value: String(current) } });
    const f = formField({ label: c.unit === 'days' ? 'New value (days)' : 'New value', control: input, hint: constraintText(item) });
    return { field: f, el: f.el, raw: () => input.value, focus: () => input.focus() };
  }
  const multi = c.multiline === true || item.key === 'console.sign_in_banner';
  const max = Number.isFinite(c.max_len) ? c.max_len : null;
  const input = multi
    ? h('textarea', { class: 'textarea', rows: 4, autocomplete: 'off', spellcheck: 'true', prop: { value: String(current) } })
    : h('input', { class: 'input', type: 'text', autocomplete: 'off', spellcheck: 'false', prop: { value: String(current) } });
  const counter = h('span', { class: ['setting-edit__count', 'muted'], 'aria-live': 'polite' });
  const paint = () => {
    const n = Array.from(input.value.trim()).length;
    counter.textContent = max ? `${n} of ${max} characters` : `${n} characters`;
    counter.setAttribute('class', `setting-edit__count muted${max && n > max ? ' is-over' : ''}`);
  };
  input.addEventListener('input', paint);
  paint();
  const f = formField({ label: 'New value', control: input, hint: constraintText(item) });
  f.el.append(counter);
  return { field: f, el: f.el, raw: () => input.value, focus: () => input.focus() };
}

// The inline editor: new value with its constraints, a required reason,
// when it applies, Save and Cancel. Resolves through onSaved(item).
function editor(item, { ctx, onSaved, onCancel }) {
  const summary = errorSummary();
  const ctl = controlFor(item);
  const reasonMax = Number.isInteger(item.constraints?.reason_max_len) && item.constraints.reason_max_len > 0 ? item.constraints.reason_max_len : 200;
  const reasonInput = h('input', { class: 'input', type: 'text', maxlength: reasonMax, autocomplete: 'off', spellcheck: 'true' });
  const reason = formField({ label: 'Reason for change', control: reasonInput, hint: `Required. Kept with the change in the history and the audit trail; at most ${reasonMax} characters.` });
  const submit = h('button', { class: ['btn', 'btn--primary'], type: 'submit' }, 'Save change');
  const cancel = h('button', { class: 'btn', type: 'button' }, 'Cancel');
  cancel.addEventListener('click', () => onCancel());
  const effect = SETTING_EFFECT[item.key];
  const form = h('form', { class: ['form', 'setting-edit'], novalidate: true, 'aria-label': `Change ${settingLabel(item.key, item)}` },
    summary.el,
    ctl.el,
    reason.el,
    h('p', { class: ['setting-edit__applies', 'muted'] }, icon(item.applies === 'live' ? 'live' : 'refresh', { size: 'sm' }),
      h('span', null, `${appliesText(item.applies)}.${effect ? ` ${effect}` : ''}`)),
    h('div', { class: 'form__actions' }, submit, cancel));
  form.addEventListener('keydown', (e) => { if (e.key === 'Escape') { e.preventDefault(); onCancel(); } });
  let parsed = null;
  wireForm(form, {
    submit, summary,
    checks: [
      { field: ctl.field, label: 'New value', validate: () => { const r = parseSettingInput(item, ctl.raw()); parsed = r; return r.error || (String(r.value) === String(item.effective) ? 'This is the value in effect already. Change it, or cancel.' : ''); } },
      { field: reason, label: 'Reason for change', validate: () => validateChangeReason(reasonInput.value) },
    ],
    onSubmit: async () => {
      const saved = await ctx.api.updateSetting(item.key, { value: parsed.value, reason: reasonInput.value.trim() });
      onSaved(saved && typeof saved === 'object' ? saved : null, { from: item.effective, to: String(parsed.value) });
    },
  });
  return { el: form, focus: () => ctl.focus() };
}

// ---- One row ------------------------------------------------------------------------

// A setting: label, effective value and its source; when overridden, the
// file value it overrides; how and when it applies; and, where the server
// and the role allow it, Change and Revert. `state.why` says why not.
function settingRow(initial, ctx, opts) {
  let item = initial;
  const row = h('div', { class: 'setting' });
  const status = h('p', { class: ['setting__status'], role: 'status' });
  let open = false;

  const paint = (focusTarget) => {
    const st = editState(item, opts.body, opts.canManage);
    const label = settingLabel(item.key, item);
    const isPosture = item.key === 'posture.accepted';
    row.setAttribute('class', ['setting', st.editable || EDITABLE_KEYS.includes(item.key) ? 'setting--allow' : '', item.overridden ? 'is-overridden' : '', open ? 'is-editing' : ''].filter(Boolean).join(' '));
    const change = st.editable && !open ? h('button', { class: ['btn', 'btn--sm'], type: 'button', 'aria-label': `Change ${label}` }, icon('settings', { size: 'sm' }), 'Change') : null;
    const revert = st.editable && !open && item.overridden ? h('button', { class: ['btn', 'btn--sm', 'btn--ghost'], type: 'button' }, 'Revert to file value') : null;
    const history = EDITABLE_KEYS.includes(item.key) && !isPosture && opts.history
      ? h('a', { class: 'setting__history', href: href('settings', 'history', { key: item.key }) }, icon('history', { size: 'sm' }), 'History', h('span', { class: 'visually-hidden' }, ` of ${label}`)) : null;
    const why = {
      permission: `Changing it needs “${permissionLabel('settings.manage')}”, which your role does not include.`,
      off: 'Editable here when console editing is on (see above).',
      posture: '',
    }[st.why] || '';
    const fileText = item.overridden ? formatSettingRaw(item, item.file_value) : '';
    // Allowlisted values read in the same words as the file value they
    // override and the history ("12 hours", not "12h" beside "8 hours").
    const valueText = EDITABLE_KEYS.includes(item.key) && !isPosture && typeof item.effective === 'string'
      ? formatSettingRaw(item, item.effective)
      : String(item.value ?? '—');
    const multiline = item.key === 'console.sign_in_banner' && valueText.length > 60;
    const children = [
      h('dt', { class: 'setting__label' }, label,
        st.editable ? h('span', { class: 'setting__tag' }, 'Editable') : null),
      h('dd', { class: 'setting__value' },
        h('span', { class: ['setting__text', valueKind(item), multiline ? 'setting__text--block' : ''] }, valueText),
        sourceChip(item)),
      h('dd', { class: 'setting__how' },
        item.overridden ? h('span', { class: 'setting__override' }, 'Overrides the config file value ', h('strong', null, fileText), '.') : null,
        isPosture ? h('span', { class: 'setting__note' }, 'Accepted and revoked on ', h('a', { href: '#/posture' }, 'Posture'), ', one check at a time, with a reason and an end date.') : null,
        !isPosture && item.note ? h('span', { class: 'setting__note' }, String(item.note)) : null,
        st.editable || (EDITABLE_KEYS.includes(item.key) && !isPosture && item.constraints) ? h('span', { class: ['setting__note', 'muted'] }, [constraintText(item), item.applies ? `${appliesText(item.applies)}.` : ''].filter(Boolean).join(' ')) : null,
        why ? h('span', { class: ['setting__note', 'muted'] }, why) : null,
        change || revert || history ? h('span', { class: ['btn-row', 'setting__actions'] }, change, revert, history) : null,
        typeof item.key === 'string' && item.key ? copyable(item.key, { label: `config key ${item.key}` }) : null,
        status),
    ];
    if (open) {
      const ed = editor(item, {
        ctx,
        onCancel: () => { open = false; paint('change'); },
        onSaved: (next, ch) => {
          open = false;
          const before = item;
          if (next && next.key === item.key) item = next;
          status.textContent = `Saved: ${formatSettingRaw(before, ch.from)} → ${formatSettingRaw(item, item.effective ?? ch.to)}. ${appliesText(item.applies)}.`;
          toast('ok', `${label} changed to ${formatSettingRaw(item, item.effective ?? ch.to)}. Recorded in the change history.`);
          opts.onChanged?.(item);
          paint('change');
        },
      });
      children.push(h('dd', { class: 'setting__editor' }, ed.el));
      mount(row, ...children);
      ed.focus();
      return;
    }
    mount(row, ...children);
    change?.addEventListener('click', () => { open = true; status.textContent = ''; paint(); });
    revert?.addEventListener('click', async () => {
      const next = await confirmAction({
        title: `Revert ${label.toLowerCase()} to the file value?`,
        consequence: `It goes back to ${fileText}, the value in the config file, instead of ${formatSettingRaw(item, item.effective)}. ${appliesText(item.applies)}. The revert is recorded in the change history and the audit trail.`,
        targetLabel: 'Setting', target: item.key,
        danger: false, confirmLabel: 'Revert to file value',
        onConfirm: () => ctx.api.revertSetting(item.key),
      });
      if (!next) { revert.focus(); return; }
      const from = item.effective;
      if (typeof next === 'object' && next.key === item.key) item = next;
      else item = { ...item, overridden: false, effective: item.file_value, value: formatSettingRaw(item, item.file_value) };
      status.textContent = `Reverted: ${formatSettingRaw(item, from)} → ${formatSettingRaw(item, item.effective)} (the config file value).`;
      toast('ok', `${label} is back to the config file value.`);
      opts.onChanged?.(item);
      paint('change');
    });
    if (focusTarget === 'change') (change || history)?.focus?.();
  };
  paint();
  return row;
}

// One /admin/settings section, with edit in place where allowed.
// opts: { body, canManage, history: bool, onChanged(item) }
export function editableSection(section, ctx, opts) {
  const items = Array.isArray(section?.items) ? section.items : [];
  return h('dl', { class: ['setting-list', 'setting-list--edit'] }, items.map((it) => settingRow(it, ctx, opts)));
}

// Whether the server speaks round 6 for settings (items carry `editable`).
export const settingsAreRound6 = (body) => typeof body?.editing === 'string' || (Array.isArray(body?.sections) && body.sections.some((s) => (s.items || []).some((it) => typeof it.editable === 'boolean' && 'effective' in it)));

// Editing is off: why, and how to turn it on. Calm, specific, no
// disabled-looking forms anywhere on the page.
export function editingOffNotice() {
  return h('section', { class: ['panel', 'editing-off'], 'aria-labelledby': 'editing-off-title' },
    h('div', { class: 'panel__body' },
      h('h2', { class: 'editing-off__title', id: 'editing-off-title' }, icon('lock', { size: 'sm' }), 'Console editing is off'),
      h('p', null, 'Every value on this page comes from the config file. That is the default: the file stays the one source of truth, and every change goes through your usual configuration review.'),
      h('p', null, 'To let people with “', permissionLabel('settings.manage'), '” change the allowlisted console settings here (session lifetime and idle timeout, API key lifetimes, organisation name, sign-in banner, default time window, accepted posture risk), set this in the config file and restart:'),
      h('pre', { class: ['code', 'editing-off__code'] }, 'console:\n  settings_editing: console'),
      h('p', { class: 'muted' }, 'Changes made in the console are stored in its state directory and applied over the config file; the file itself is never written. Each change needs a reason and is kept in the change history and the audit trail. Nothing touching sensors, listeners, TLS, evidence storage, detection actions, fleet or tenants can be changed this way.')));
}

// ---- Change history ------------------------------------------------------------------

const ACTION = { update: ['info', 'Changed'], revert: ['neutral', 'Reverted'] };

// The history page. `keys`: the keys the filter offers (from the settings
// body, plus any key in the history).
export function historyView({ entries, keyFilter, labels, constraints = {}, onFilter }) {
  const keys = [...new Set([...Object.keys(labels), ...entries.map((e) => e.key)])].filter((k) => k !== 'posture.accepted');
  const filter = selectField({
    label: 'Setting', name: 'key', value: keyFilter || '',
    options: [['', 'All settings'], ...keys.map((k) => [k, labels[k] || k])],
    onChange: (v) => onFilter(v),
  });
  const shown = keyFilter ? entries.filter((e) => e.key === keyFilter) : entries;
  const item = (e) => ({ key: e.key, constraints: constraints[e.key] });
  const body = shown.length ? table({
    caption: keyFilter ? `Changes to ${labels[keyFilter] || keyFilter}` : 'Setting changes',
    columns: [
      { label: 'When', className: 'nowrap', cell: (e) => (e.at ? timeEl(e.at, { relative: true }) : '—') },
      { label: 'Setting', cell: (e) => h('span', { class: 'stack-tight' }, h('span', null, labels[e.key] || e.key), h('code', { class: 'muted' }, e.key)) },
      { label: 'Change', className: 'col-summary', cell: (e) => h('span', { class: 'change' },
        h('span', { class: 'change__from' }, formatSettingRaw(item(e), e.from)),
        h('span', { class: 'change__arrow', 'aria-hidden': 'true' }, '→'),
        h('span', { class: 'visually-hidden' }, ' to '),
        h('span', { class: 'change__to' }, formatSettingRaw(item(e), e.to))) },
      { label: 'Action', cell: (e) => (ACTION[e.action] ? badge(...ACTION[e.action]) : badge('neutral', 'Recorded')) },
      { label: 'Who', cell: (e) => e.actor },
      { label: 'Reason', className: 'col-summary', cell: (e) => (e.reason ? h('span', { class: 'change__reason' }, e.reason) : h('span', { class: 'muted' }, '—')) },
    ],
    rows: shown,
  }) : empty(keyFilter ? 'No changes to this setting' : 'No setting has been changed here', keyFilter ? 'It still has the value from the config file, or it was changed before the history was kept.' : 'Changes made in the console appear here with who made them, the old and new value, and the reason.', null, { icon: 'history' });
  return { filter, body, count: shown.length };
}

export { normalizeHistory, refusalMessage, describeError, banner };
