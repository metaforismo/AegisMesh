// Settings, administration: roles and permissions (contract r6). The list
// of built-in and custom roles with who holds them and a risk summary; a
// role's page with its permission matrix, a live "can and cannot" summary
// and, for custom roles, the editor with a diff before saving.
//
// Built-in roles are read-only (the server refuses changes); "Duplicate as
// custom role" starts the editor from their permissions. The server checks
// every request; a 403 or an older server's 404 is answered in place.

import { h, mount } from '../lib/dom.js';
import { ApiError, describeError } from '../lib/api.js';
import { isMissingEndpoint, plural } from '../lib/insight.js';
import { href } from '../lib/route.js';
import { formatCount } from '../lib/format.js';
import {
  normalizeCatalogue, groupCatalogue, CATALOGUE, BUILTIN_PERMS, BUILTIN_ROLES, riskMeta, isRoleId,
  validateRoleName, validateRoleDescription, validateRolePermissions, permissionDiff, diffSentence,
  assignedTotal, roleSummary, permCountLine, rolesRisk, permissionLabel, ROLE_NAME_MAX, ROLE_DESCRIPTION_MAX,
  missingDependencies, roleDisplayName,
} from '../lib/perms.js';
import { roleText, sourceMeta, isAccountId, accountStatusMeta, refusalMessage } from '../lib/settings.js';
import { panel, table, badge, timeEl, banner, empty, toast, failureState, kv } from '../ui/components.js';
import { confirmAction, formField, errorSummary, olderServerState, notPermittedState } from '../ui/settings-kit.js';
import { icon } from '../ui/icons.js';

const OLDER = () => ({
  title: 'This server does not provide custom roles yet',
  detail: 'The console is newer than the AegisMesh server answering it. Until the server is updated, accounts use the three built-in roles below, whose permissions are fixed.',
  actions: [h('a', { class: 'btn', href: '#/settings/accounts' }, 'Go to accounts')],
});

// Why a high-risk permission is high risk, in one sentence each.
export const HIGH_RISK_WHY = Object.freeze({
  'accounts.manage': 'Can create managed accounts and give them any role, including this one.',
  'roles.manage': 'Can change what every custom role allows, including its own.',
  'sessions.manage': 'Can sign out anyone, every admin included.',
  'settings.manage': 'Can change session and key lifetimes and the sign-in banner for everyone, and accept posture risk.',
  'fleet.manage': 'Can enroll nodes whose evidence is then trusted here, and revoke nodes.',
});

async function attempt(fn) {
  try {
    return { value: await fn() };
  } catch (err) {
    if (err?.name === 'AbortError') throw err;
    if (err instanceof ApiError && err.status === 401) throw err;
    return { error: err };
  }
}

// The roles the server knows, or the built-ins when it predates roles.
export async function loadRoles(ctx) {
  const r = await attempt(() => ctx.api.roles({ signal: ctx.signal }));
  if (r.value) return { items: Array.isArray(r.value.items) ? r.value.items.filter((x) => x && isRoleId(x.id)) : [], limits: r.value.limits || {}, older: false };
  if (isMissingEndpoint(r.error)) return { items: builtinRoles(), limits: {}, older: true };
  return { error: r.error };
}

export function builtinRoles() {
  return BUILTIN_ROLES.map((id) => ({ id, name: roleText(id).label, description: roleText(id).summary, builtin: true, permissions: [...BUILTIN_PERMS[id]], assigned: null }));
}

async function loadCatalogue(ctx) {
  const r = await attempt(() => ctx.api.permissions({ signal: ctx.signal }));
  return normalizeCatalogue(r.value);
}

// A risk mark: shape and word. High risk is a filled triangle with "!",
// elevated a half-filled square, low a hollow dot.
export function riskMark(risk, { compact = false } = {}) {
  const m = riskMeta(risk);
  return h('span', { class: ['risk', `risk--${m.key}`, compact ? 'risk--compact' : ''], title: m.text },
    h('span', { class: 'risk__mark', 'aria-hidden': 'true' }),
    h('span', { class: compact ? 'visually-hidden' : 'risk__word' }, m.label));
}

const kindBadge = (r) => (r.builtin ? badge('neutral', 'Built in') : badge('info', 'Custom'));

function holdersText(assigned, { inline = false } = {}) {
  if (!assigned) return h('span', { class: 'muted' }, 'not reported');
  const parts = [['managed', 'managed'], ['config', 'configured'], ['oidc', 'single sign-on']]
    .filter(([k]) => assigned[k] > 0).map(([k, w]) => `${formatCount(assigned[k])} ${w}`);
  if (!parts.length) return h('span', { class: 'muted' }, 'nobody');
  return inline ? parts.join(' · ') : h('span', { class: 'holders' }, parts.map((p) => h('span', null, p)));
}

// ---- The list ---------------------------------------------------------------------

export async function rolesPage(v) {
  const { ctx } = v;
  v.hint = 'Open a role to read its permissions. Custom roles can be changed here; built-in roles are fixed and can be duplicated.';
  const [loaded, catalogue] = await Promise.all([loadRoles(ctx), loadCatalogue(ctx)]);
  if (loaded.error) {
    if (loaded.error instanceof ApiError && loaded.error.status === 403) return notPermittedState(v.roleName, 'roles', 'accounts.read');
    return panel({ body: failureState({ ...describeError(loaded.error), retry: true, actions: [] }, () => ctx.rerender()) });
  }
  const { items, limits, older } = loaded;
  const canManage = ctx.can('roles.manage') && !older;
  const risk = rolesRisk(items);
  const create = canManage ? h('a', { class: ['btn', 'btn--primary'], href: href('settings', 'roles', 'new') }, icon('plus', { size: 'sm' }), 'Create role') : null;
  const highOf = (r) => (r.permissions || []).filter((p) => catalogue.find((c) => c.id === p)?.risk === 'high').length;

  const list = table({
    caption: 'Roles',
    columns: [
      { label: 'Role', className: 'col-summary', lead: true, cell: (r) => h('span', { class: 'stack-tight' },
        older ? h('strong', null, roleDisplayName(r)) : h('a', { class: 'role-name', href: href('settings', 'roles', r.id) }, roleDisplayName(r)),
        r.description || r.builtin ? h('span', { class: ['muted', 'role-desc'] }, r.builtin ? roleText(r.id).summary : String(r.description)) : null), sort: (r) => roleDisplayName(r).toLowerCase() },
      { label: 'Kind', cell: kindBadge, sort: (r) => (r.builtin ? 0 : 1) },
      { label: 'Permissions', cell: (r) => h('span', { class: 'role-perms' },
        h('span', null, permCountLine(r.permissions, catalogue)),
        highOf(r) ? riskMark('high', { compact: true }) : null), sort: (r) => (r.permissions || []).length, sortFirst: 'desc' },
      { label: 'Held by', cell: (r) => holdersText(r.assigned), sort: (r) => assignedTotal(r.assigned), sortFirst: 'desc' },
      { label: 'Updated', cell: (r) => (r.updated_at ? timeEl(r.updated_at, { relative: true }) : h('span', { class: 'muted' }, r.builtin ? 'fixed' : '—')), sort: (r) => Date.parse(r.updated_at) || null, sortFirst: 'desc' },
    ],
    rows: items,
  });

  const summary = panel({
    title: 'Risk summary',
    body: h('div', { class: 'roles-risk' },
      h('dl', { class: ['figures', 'figures--roles'] },
        h('div', { class: 'figures__item' }, h('dt', null, 'Custom roles'), h('dd', null, formatCount(risk.custom), limits.max_roles ? h('span', { class: 'muted' }, ` of ${formatCount(limits.max_roles)}`) : null)),
        h('div', { class: 'figures__item' }, h('dt', null, 'With high-risk permissions'), h('dd', null, formatCount(risk.high))),
        h('div', { class: 'figures__item' }, h('dt', null, 'Held by nobody'), h('dd', null, formatCount(risk.unused)))),
      h('ul', { class: 'risk-legend' }, ['high', 'elevated', 'low'].map((k) => h('li', null, riskMark(k), h('span', { class: 'muted' }, riskMeta(k).text)))),
      h('p', { class: 'muted' }, 'Configured operators and single sign-on identities use the built-in roles (set in the config file and the identity provider’s role mapping). Custom roles are for managed accounts.')),
  });

  return h('div', { class: 'stack-lg' },
    older ? olderServerState(OLDER()) : null,
    !older && !canManage ? h('p', { class: ['page-note'] }, icon('info', { size: 'sm' }), h('span', null, `You can read roles. Creating or changing them needs “${permissionLabel('roles.manage', catalogue)}”.`)) : null,
    panel({ title: 'Roles', primary: true, flush: true, meta: `${plural(items.length, 'role')}: ${plural(items.filter((r) => r.builtin).length, 'built-in')}, ${plural(risk.custom, 'custom')}`, actions: create, body: list }),
    summary);
}

// ---- The matrix -------------------------------------------------------------------

// Read mode: every permission with a granted mark or a dash, its label, id
// and risk. Edit mode: the same rows as check boxes.
function matrix(catalogue, { granted, editable, onChange }) {
  const inputs = new Map();
  const groups = groupCatalogue(catalogue).map((g) => {
    const legendId = `perm-g-${g.group.toLowerCase().replace(/\W+/g, '-')}`;
    const count = h('span', { class: ['perm-group__count', 'muted'] });
    const paintCount = () => { count.textContent = `${g.items.filter((p) => granted.has(p.id)).length} of ${g.items.length}`; };
    const rows = g.items.map((p) => {
      const why = p.risk === 'high' ? (HIGH_RISK_WHY[p.id] || riskMeta('high').text) : '';
      const body = h('span', { class: 'perm__body' },
        h('span', { class: 'perm__label' }, p.label),
        h('span', { class: 'perm__meta' }, h('code', { class: 'perm__id' }, p.id), riskMark(p.risk)),
        why ? h('span', { class: 'perm__why' }, why) : null);
      if (editable) {
        const input = h('input', { type: 'checkbox', name: 'permission', value: p.id, prop: { checked: granted.has(p.id) } });
        input.addEventListener('change', () => { if (input.checked) granted.add(p.id); else granted.delete(p.id); paintCount(); onChange?.(); });
        inputs.set(p.id, input);
        return h('li', { class: ['perm', `perm--${p.risk}`] }, h('label', { class: 'perm__row' }, input, body));
      }
      const on = granted.has(p.id);
      return h('li', { class: ['perm', `perm--${p.risk}`, on ? 'perm--on' : 'perm--off'] },
        h('span', { class: 'perm__row' },
          h('span', { class: 'perm__state', 'aria-hidden': 'true' }, on ? icon('check', { size: 'sm' }) : '–'),
          h('span', { class: 'visually-hidden' }, on ? 'Granted: ' : 'Not granted: '),
          body));
    });
    paintCount();
    const content = [h('legend', { class: 'perm-group__title', id: legendId }, g.group, ' ', count), h('ul', { class: 'perm-list' }, rows)];
    return editable ? h('fieldset', { class: 'perm-group' }, content) : h('section', { class: 'perm-group', 'aria-labelledby': legendId }, h('h3', { class: 'perm-group__title', id: legendId }, g.group, ' ', count), h('ul', { class: 'perm-list' }, rows));
  });
  return { el: h('div', { class: 'perm-matrix' }, groups), set: (id, on) => { const i = inputs.get(id); if (i) { i.checked = on; i.dispatchEvent(new Event('change')); } } };
}

// "What this role can and cannot do", redrawn as permissions change; with
// the pending difference against the saved role.
function summaryPanel(catalogue) {
  const body = h('div', { class: 'role-summary' });
  const el = panel({ title: 'What this role can and cannot do', body: h('div', { 'aria-live': 'polite' }, body) });
  el.setAttribute('class', `${el.getAttribute('class') || ''} role-summary-panel`.trim());
  return {
    el,
    paint(perms, { saved = null, affected = 0 } = {}) {
      const s = roleSummary(perms, catalogue);
      const diff = saved ? permissionDiff(saved, perms, catalogue) : null;
      const changed = diff && (diff.added.length || diff.removed.length);
      mount(body,
        h('p', { class: 'role-summary__count' }, permCountLine(perms, catalogue)),
        changed ? h('div', { class: 'role-diff' },
          h('p', { class: 'role-diff__title' }, 'Not saved yet'),
          h('p', null, diffSentence(diff, affected)),
          diffList(diff, catalogue)) : null,
        s.high.length ? h('p', { class: 'role-summary__high' }, riskMark('high'), h('span', null, `It can ${s.high.length === 1 ? 'grant access or change behaviour in one way' : `grant access or change behaviour in ${s.high.length} ways`}: ${s.high.map((p) => p.label.charAt(0).toLowerCase() + p.label.slice(1)).join('; ')}.`)) : null,
        h('div', { class: 'role-lists' },
          h('div', null, h('p', { class: 'caps' }, 'Can'), s.can.length
            ? h('ul', { class: ['role-list', 'role-list--can'] }, s.can.map((p) => h('li', null, icon('check', { size: 'sm' }), h('span', null, p.label))))
            : h('p', { class: 'muted' }, 'Nothing yet. Choose permissions on the left.')),
          s.cannot.length ? h('div', null, h('p', { class: 'caps' }, 'Cannot'), h('ul', { class: ['role-list', 'role-list--cannot'] }, s.cannot.map((p) => h('li', null, icon('close', { size: 'sm' }), h('span', null, p.label))))) : null));
    },
  };
}

function diffList(diff, catalogue) {
  return h('ul', { class: 'role-diff__list' },
    diff.added.map((id) => h('li', { class: 'role-diff__add' }, h('span', { class: 'role-diff__sign', 'aria-hidden': 'true' }, '+'), h('span', { class: 'visually-hidden' }, 'Adds '), permissionLabel(id, catalogue))),
    diff.removed.map((id) => h('li', { class: 'role-diff__remove' }, h('span', { class: 'role-diff__sign', 'aria-hidden': 'true' }, '−'), h('span', { class: 'visually-hidden' }, 'Removes '), permissionLabel(id, catalogue))));
}

// Accounts holding a role, with links.
function holdersPanel(role, accounts) {
  const held = accounts.filter((a) => a.role === role.id);
  const counts = role.assigned;
  return panel({
    title: 'Who holds this role', flush: true,
    meta: counts ? h('span', null, holdersText(counts, { inline: true })) : plural(held.length, 'account'),
    body: held.length ? table({
      caption: `Accounts with the role ${roleDisplayName(role)}`,
      columns: [
        { label: 'Account', className: 'col-summary', cell: (a) => (isAccountId(a.id) ? h('a', { href: href('settings', 'accounts', a.id) }, String(a.name || a.id)) : String(a.name || '—')) },
        { label: 'Source', cell: (a) => sourceMeta(a.source).label },
        { label: 'Status', cell: (a) => { const m = accountStatusMeta(a.status); return badge(m.badge, m.label); } },
      ],
      rows: held,
    }) : empty('Nobody holds this role', role.builtin ? 'No account uses it right now.' : 'Assign it to a managed account from its page under Accounts.', null, { icon: 'users' }),
  });
}

// The refusal for a role still in use: who holds it, with links.
function inUseRefusal(err, role, accounts) {
  const held = accounts.filter((a) => a.role === role.id);
  if (err?.reason !== 'in_use') return '';
  return h('div', null,
    h('p', null, `${role.name} is still assigned to ${plural(held.length || assignedTotal(role.assigned), 'account')}. Move ${held.length === 1 ? 'it' : 'them'} to another role first:`),
    held.length ? h('ul', { class: 'bullets' }, held.map((a) => h('li', null, isAccountId(a.id) ? h('a', { href: href('settings', 'accounts', a.id) }, String(a.name || a.id)) : String(a.name || a.id)))) : null);
}

// ---- One role -----------------------------------------------------------------------

export async function roleEditor(v) {
  const { ctx } = v;
  const id = v.roleId;
  const creating = id === 'new';
  const fromId = creating && isRoleId(ctx.route.query?.from) ? ctx.route.query.from : '';
  const [loaded, catalogue, accts] = await Promise.all([
    loadRoles(ctx),
    loadCatalogue(ctx),
    attempt(() => ctx.api.accounts({ signal: ctx.signal })),
  ]);
  if (loaded.error) {
    if (loaded.error instanceof ApiError && loaded.error.status === 403) return notPermittedState(v.roleName, 'roles', 'accounts.read');
    return panel({ body: failureState({ ...describeError(loaded.error), retry: true, actions: [] }, () => ctx.rerender()) });
  }
  const accounts = Array.isArray(accts.value?.items) ? accts.value.items : [];
  const canManage = ctx.can('roles.manage') && !loaded.older;
  const role = creating ? null : loaded.items.find((r) => r.id === id);
  if (!creating && !role) {
    v.detailName = 'Role not found';
    return panel({ body: empty('Role not found', 'It may have been deleted, or the link is from another server.', h('a', { href: '#/settings/roles' }, 'Go to roles'), { icon: 'search' }) });
  }
  if (creating && !canManage) {
    v.detailName = 'New role';
    return loaded.older ? olderServerState(OLDER()) : notPermittedState(v.roleName, 'to create roles', 'roles.manage');
  }
  const source = creating ? (loaded.items.find((r) => r.id === fromId) || null) : role;
  const editable = canManage && (creating || !role.builtin);
  const sourceName = source ? roleDisplayName(source) : '';
  v.detailName = creating ? (source ? `Copy of ${sourceName}` : 'New role') : roleDisplayName(role);
  v.subtitle = creating ? 'A custom role for managed accounts' : role.builtin ? 'Built-in role: fixed, read-only' : 'Custom role';
  v.hint = editable
    ? 'Choose what the role allows. The summary on the right follows your choices; saving shows the difference first.'
    : role?.builtin ? 'Built-in roles are fixed. Duplicate one to start a custom role from its permissions.' : `Read-only for you: changing roles needs “${permissionLabel('roles.manage', catalogue)}”.`;

  const saved = role ? [...(role.permissions || [])] : [];
  const granted = new Set(source ? source.permissions || [] : ['evidence.read']);
  const affected = role ? (assignedTotal(role.assigned) || accounts.filter((a) => a.role === role.id).length) : 0;
  const others = loaded.items.filter((r) => r.id !== id).map((r) => r.name);
  const summary = summaryPanel(catalogue);
  const coupledBox = h('div', { class: 'perm-coupled', 'aria-live': 'polite' });
  const repaint = () => {
    summary.paint([...granted], { saved: role ? saved : null, affected });
    const msg = validateRolePermissions([...granted]);
    const coupled = msg && granted.size;
    mount(coupledBox, coupled ? h('div', { class: ['banner', 'banner--warn'] },
      icon('warn', { size: 'sm' }),
      h('div', null,
        h('p', null, msg),
        editable ? h('button', { class: ['btn', 'btn--sm'], type: 'button', on: { click: () => { for (const p of missingDependencies([...granted])) mat.set(p, true); } } }, (() => { const n = missingDependencies([...granted]).length; return n === 1 ? 'Also allow it' : `Also allow these ${n}`; })()) : null)) : null);
  };
  const mat = matrix(catalogue, { granted, editable, onChange: repaint });

  // Read-only page: built-in, or no permission to change roles.
  if (!editable) {
    repaint();
    const dup = canManage && role.builtin ? h('a', { class: ['btn', 'btn--primary'], href: href('settings', 'roles', 'new', { from: role.id }) }, icon('copy', { size: 'sm' }), 'Duplicate as custom role') : null;
    return h('div', { class: 'stack-lg' },
      role.builtin ? banner('info', 'Built-in role', 'Built-in roles are fixed so that configured operators and single sign-on mappings always mean the same thing. To adjust one, duplicate it as a custom role and change the copy.') : null,
      h('div', { class: ['grid', 'role-layout'] },
        panel({
          title: 'Permissions', primary: true, meta: permCountLine(role.permissions, catalogue), actions: dup,
          body: h('div', { class: 'stack' },
            role.description ? h('p', { class: 'role-description' }, String(role.description)) : null,
            mat.el),
        }),
        summary.el),
      holdersPanel(role, accounts),
      role.builtin ? null : panel({ title: 'Record', body: kv([['Role id', h('code', null, role.id)], ['Created', role.created_at ? h('span', null, timeEl(role.created_at), role.created_by ? ` by ${role.created_by}` : '') : '—'], ['Updated', role.updated_at ? timeEl(role.updated_at, { relative: true }) : '—']]) }));
  }

  // The editor.
  const errors = errorSummary();
  const nameInput = h('input', { class: 'input', type: 'text', maxlength: ROLE_NAME_MAX, autocomplete: 'off', spellcheck: 'false', prop: { value: creating ? (source ? `${sourceName} (custom)`.slice(0, ROLE_NAME_MAX) : '') : String(role.name || '') } });
  const name = formField({ label: 'Name', control: nameInput, hint: `Shown in the account role picker. 1 to ${ROLE_NAME_MAX} characters, unique.` });
  const descInput = h('textarea', { class: 'textarea', rows: 2, maxlength: ROLE_DESCRIPTION_MAX, prop: { value: creating ? (source?.description && !source.builtin ? String(source.description) : '') : String(role.description || '') } });
  const desc = formField({ label: 'Description', control: descInput, optional: true, hint: 'Who the role is for and why it exists, for the next person who reviews access.' });
  const permField = {
    setError: (m) => { /* the coupled banner and the summary carry it */ if (m) mat.el.setAttribute('aria-invalid', 'true'); else mat.el.removeAttribute('aria-invalid'); },
    focus: () => mat.el.querySelector('input')?.focus(),
  };
  const submit = h('button', { class: ['btn', 'btn--primary'], type: 'submit' }, creating ? 'Create role' : 'Review and save');
  const del = !creating ? h('button', { class: ['btn', 'btn--danger'], type: 'button' }, 'Delete role') : null;
  const cancel = h('a', { class: 'btn', href: creating ? '#/settings/roles' : href('settings', 'roles', role.id) }, creating ? 'Cancel' : 'Discard changes');
  const form = h('form', { class: ['form', 'role-form'], novalidate: true },
    errors.el,
    h('div', { class: 'form__row' }, name.el, desc.el),
    h('div', { class: 'stack' }, h('p', { class: 'field__label' }, 'Permissions'), h('p', { class: ['field__hint'] }, 'Grouped as the server’s catalogue groups them. High-risk permissions can grant access or change how the console behaves; each says why.'), coupledBox, mat.el),
    h('div', { class: 'form__actions' }, submit, cancel, h('span', { class: 'top-spacer' }), del));

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    if (submit.disabled) return;
    const checks = [
      [name, 'Name', validateRoleName(nameInput.value, others)],
      [desc, 'Description', validateRoleDescription(descInput.value)],
      [permField, 'Permissions', validateRolePermissions([...granted])],
    ];
    const problems = [];
    for (const [f, label, msg] of checks) { f.setError(msg); if (msg) problems.push({ field: f, label, message: msg }); }
    if (problems.length) { errors.show(problems); return; }
    errors.clear();
    const perms = catalogue.map((p) => p.id).filter((p) => granted.has(p));
    if (creating) {
      submit.disabled = true;
      submit.textContent = 'Creating…';
      try {
        const made = await ctx.api.createRole({ name: nameInput.value.trim(), description: descInput.value.trim(), permissions: perms });
        toast('ok', `Role created: ${made?.name || nameInput.value.trim()}. Assign it to a managed account from Accounts.`);
        ctx.navigate(isRoleId(made?.id) ? href('settings', 'roles', made.id) : '#/settings/roles');
      } catch (err) {
        errors.serverError(refusalMessage(err, { what: 'this role' }));
      } finally {
        submit.disabled = false;
        submit.textContent = 'Create role';
      }
      return;
    }
    const patch = {};
    if (nameInput.value.trim() !== role.name) patch.name = nameInput.value.trim();
    if (descInput.value.trim() !== (role.description || '')) patch.description = descInput.value.trim();
    const diff = permissionDiff(saved, perms, catalogue);
    if (diff.added.length || diff.removed.length) patch.permissions = perms;
    if (!Object.keys(patch).length) { toast('ok', 'Nothing changed.'); return; }
    const ok = await confirmAction({
      title: `Save ${role.name}?`,
      consequence: patch.permissions ? diffSentence(diff, affected) : `Only the ${[patch.name !== undefined ? 'name' : '', patch.description !== undefined ? 'description' : ''].filter(Boolean).join(' and ')} change${patch.name !== undefined && patch.description !== undefined ? '' : 's'}; what the role allows stays the same.`,
      details: h('div', { class: 'stack' },
        patch.permissions ? diffList(diff, catalogue) : null,
        patch.name !== undefined ? h('p', null, 'Name: ', h('strong', null, role.name), ' → ', h('strong', null, patch.name)) : null,
        patch.permissions && diff.added.some((p) => catalogue.find((c) => c.id === p)?.risk === 'high') ? h('p', { class: 'muted' }, 'It adds a high-risk permission: the accounts holding this role can then grant access or change behaviour.') : null),
      targetLabel: 'Role', target: `${role.name} (${role.id})`,
      danger: false, confirmLabel: 'Save role',
      onConfirm: () => ctx.api.updateRole(role.id, patch),
    });
    if (!ok) return;
    toast('ok', `Saved ${patch.name || role.name}.${patch.permissions && affected ? ` ${plural(affected, 'account')} ${affected === 1 ? 'gets' : 'get'} the change on ${affected === 1 ? 'its' : 'their'} next request.` : ''}`);
    ctx.rerender();
  });

  del?.addEventListener('click', async () => {
    const done = await confirmAction({
      title: `Delete ${role.name}?`,
      consequence: affected
        ? `It is assigned to ${plural(affected, 'account')}, so the server will refuse until they have another role. Nothing else changes.`
        : 'Nobody holds it. The role and its permission list are removed; the audit trail keeps the record.',
      targetLabel: 'Role', target: `${role.name} (${role.id})`,
      typed: String(role.name),
      confirmLabel: 'Delete role',
      onConfirm: () => ctx.api.deleteRole(role.id),
      refuse: (err) => inUseRefusal(err, role, accounts),
    });
    if (!done) return;
    toast('ok', `Role deleted: ${role.name}.`);
    ctx.navigate('#/settings/roles');
  });

  repaint();
  return h('div', { class: 'stack-lg' },
    creating && source ? banner('info', `Starting from ${sourceName}`, `The permissions of ${sourceName} are selected. Name the new role and adjust what it allows; ${sourceName} itself does not change.`) : null,
    h('div', { class: ['grid', 'role-layout'] },
      panel({ title: creating ? 'New custom role' : 'Edit role', primary: true, body: form }),
      summary.el),
    role ? holdersPanel(role, accounts) : null);
}

export { CATALOGUE };
