// Settings, administration: accounts, every session, the server's effective
// settings (read-only, file-driven), audit export and system health.
// Loaded only when the signed-in account may administer; the server still
// decides every request, and its 403 is answered in place.

import { h, mount } from '../lib/dom.js';
import { ApiError, describeError } from '../lib/api.js';
import { isMissingEndpoint, plural } from '../lib/insight.js';
import { formatDuration, formatCount, formatBytes } from '../lib/format.js';
import { href } from '../lib/route.js';
import { glossaryEntry } from '../lib/glossary.js';
import { saveResponse } from '../lib/download.js';
import { ROLES } from '../lib/taxonomy.js';
import {
  ADMIN_SECTIONS, roleText, sourceMeta, kindLabel, accountStatusMeta, validateAccountName, validateTenants,
  isAccountId, groupSettings, healthMeta, COMPONENT_LABEL, keysLine, accountEditable, sentence,
} from '../lib/settings.js';
import { panel, kv, table, badge, chip, timeEl, copyable, banner, empty, toast, helpTip, failureState, segmented } from '../ui/components.js';
import {
  confirmAction, keyReveal, formField, choices, checkSet, errorSummary, wireForm, settingsSection,
  olderServerState, notPermittedState,
} from '../ui/settings-kit.js';
import { sessionsTable, revokeSessionFlow, keysTable, revokeKeyFlow, createKeyForm } from './settings-account.js';
import { icon } from '../ui/icons.js';
import { editableSection, editingOffNotice, settingsAreRound6, historyView } from '../ui/settings-edit.js';
import { rolesPage, roleEditor, loadRoles } from './settings-roles.js';
import { roleNameOf, roleDisplayName, permCountLine, SECTION_PERMS, isRoleId, permissionLabel } from '../lib/perms.js';
import { normalizeHistory, isSettingKey, SETTING_LABELS, EDITABLE_KEYS } from '../lib/settings.js';

// A failure inside a section: an older server, a refusal, or a retryable
// outage. Never a blank panel.
function sectionFailure(v, err, retry, older) {
  if (isMissingEndpoint(err)) return olderServerState(older);
  if (err instanceof ApiError && err.status === 403) return notPermittedState(v.roleName || v.role, 'this page', SECTION_PERMS[v.section] || '');
  return failureState({ ...describeError(err), retry: true, actions: [] }, retry);
}

async function attempt(v, fn) {
  try {
    return { value: await fn() };
  } catch (err) {
    if (err?.name === 'AbortError') throw err;
    if (err instanceof ApiError && err.status === 401) throw err;
    return { error: err };
  }
}

// Source: a mark plus a word, never colour alone.
export function sourceBadge(source) {
  const m = sourceMeta(source);
  return h('span', { class: ['src-badge', `src-badge--${['config', 'oidc', 'managed'].includes(source) ? source : 'unknown'}`], title: m.why },
    h('span', { class: 'src-badge__mark', 'aria-hidden': 'true' }), m.label);
}

const tenantOptions = (v) => {
  const list = v.me?.tenants?.length ? v.me.tenants : (v.ctx.session?.tenants || []);
  return list.map((t) => [t, t]);
};

// ---- Accounts -----------------------------------------------------------------

const SOURCE_FILTERS = [['all', 'All'], ['config', 'Configured'], ['oidc', 'Single sign-on'], ['managed', 'Managed']];

function accountsTable(items, roles = []) {
  return table({
    caption: 'Accounts',
    columns: [
      { label: 'Name', className: 'col-summary', cell: (a) => h('span', { class: 'stack-tight' },
        isAccountId(a.id) ? h('a', { class: 'account-name', href: href('settings', 'accounts', a.id) }, String(a.name || a.id)) : String(a.name || '—'),
        h('span', { class: 'muted' }, kindLabel(a.kind))), sort: (a) => String(a.name || '').toLowerCase() },
      { label: 'Source', cell: (a) => sourceBadge(a.source), sort: (a) => a.source },
      { label: 'Role', cell: (a) => roleNameOf(a.role, roles), sort: (a) => (ROLES.includes(a.role) ? ROLES.indexOf(a.role) : 3), sortFirst: 'desc' },
      { label: 'Tenants', cell: (a) => h('span', { class: 'chip-row' }, (a.tenants || []).map((t) => chip(t, { mono: true }))) },
      { label: 'Status', cell: (a) => { const m = accountStatusMeta(a.status); return badge(m.badge, m.label); }, sort: (a) => a.status },
      { label: 'Last seen', cell: (a) => (a.last_seen_at ? timeEl(a.last_seen_at, { relative: true }) : h('span', { class: 'muted' }, 'never')), sort: (a) => Date.parse(a.last_seen_at) || null, sortFirst: 'desc' },
      { label: 'Keys', num: true, cell: (a) => formatCount(a.active_keys), sort: (a) => Number(a.active_keys) || 0 },
      { label: 'Sessions', num: true, cell: (a) => formatCount(a.active_sessions), sort: (a) => Number(a.active_sessions) || 0 },
    ],
    rows: items,
  });
}

// The create-account dialog. Resolves to the created account or null.
// The role picker: built-in and custom roles, each with what it permits.
// `roles` comes from /admin/roles (or the built-ins on an older server).
function rolePicker(roles, value) {
  const list = roles.length ? roles : ROLES.map((r) => ({ id: r, name: roleText(r).label, builtin: true, description: roleText(r).summary }));
  const sel = h('select', { class: 'select', name: 'role' },
    h('optgroup', { label: 'Built-in roles' }, list.filter((r) => r.builtin).map((r) => h('option', { value: r.id, selected: r.id === value }, roleDisplayName(r)))),
    list.some((r) => !r.builtin) ? h('optgroup', { label: 'Custom roles' }, list.filter((r) => !r.builtin).map((r) => h('option', { value: r.id, selected: r.id === value }, roleDisplayName(r)))) : null);
  if (value && !list.some((r) => r.id === value)) sel.append(h('option', { value, selected: true }, roleNameOf(value, list)));
  const hint = h('span', { class: ['field__hint', 'role-pick'] });
  const paint = () => {
    const r = list.find((x) => x.id === sel.value);
    const text = r ? (r.builtin ? roleText(r.id).summary : String(r.description || 'A custom role.')) : 'A role this console does not know.';
    hint.replaceChildren(h('span', null, text), Array.isArray(r?.permissions) ? h('span', { class: 'role-pick__count' }, ` ${permCountLine(r.permissions)}. `) : ' ', isRoleId(sel.value) && r ? h('a', { href: href('settings', 'roles', sel.value) }, 'What it permits') : null);
  };
  sel.addEventListener('change', paint);
  paint();
  return { sel, hint };
}

function createAccountDialog(v, roles = []) {
  return new Promise((resolve) => {
    const summary = errorSummary();
    const name = formField({ label: 'Name', control: h('input', { class: 'input', type: 'text', name: 'name', maxlength: 64, autocomplete: 'off', spellcheck: 'false' }), hint: 'A person (morgan@soc.example) or what a service does (siem-pull). Shown in the audit trail.' });
    const kind = choices({ legend: 'Kind', name: 'kind', value: 'person', options: [['person', 'Person'], ['service', 'Service']], hint: 'Both sign in with API keys. Service marks automation, such as a SIEM pulling events.' });
    const { sel: roleSel, hint: roleHint } = rolePicker(roles, 'viewer');
    const role = formField({ label: 'Role', control: roleSel });
    const tOpts = tenantOptions(v);
    const tenants = checkSet({ legend: 'Tenants', name: 'tenants', options: tOpts, values: tOpts.length === 1 ? [tOpts[0][0]] : [], hint: 'The tenants this account may act in.' });
    const submit = h('button', { class: ['btn', 'btn--primary'], type: 'submit' }, 'Create account');
    const cancel = h('button', { class: 'btn', type: 'button' }, 'Cancel');
    const form = h('form', { method: 'dialog', novalidate: true });
    const dialog = h('dialog', { class: ['dialog', 'dialog--wide'], 'aria-labelledby': 'acct-create-title' }, form);
    form.append(
      h('div', { class: 'dialog__head' }, h('h2', { id: 'acct-create-title' }, 'Create a managed account')),
      h('div', { class: ['dialog__body', 'form'] },
        summary.el,
        h('p', null, 'A managed account lives in this console. It has no password: it signs in with API keys you create for it next.'),
        name.el, kind.el, h('div', null, role.el, roleHint), tenants.el),
      h('div', { class: 'dialog__foot' }, cancel, submit));
    let result = null;
    cancel.addEventListener('click', () => dialog.close());
    wireForm(form, {
      submit, busyLabel: 'Creating…', summary,
      checks: [
        { field: name, label: 'Name', validate: () => validateAccountName(name.control.value) },
        { field: tenants, label: 'Tenants', validate: () => validateTenants(tenants.values(), tOpts.map(([t]) => t)) },
      ],
      onSubmit: async () => {
        result = await v.ctx.api.createAccount({ name: name.control.value.trim(), kind: kind.value(), role: roleSel.value, tenants: tenants.values() });
        dialog.close();
      },
    });
    dialog.addEventListener('close', () => { resolve(result); setTimeout(() => dialog.remove(), 220); });
    document.body.appendChild(dialog);
    dialog.showModal();
    name.focus();
  });
}

async function accounts(v) {
  const { ctx } = v;
  v.hint = 'Open an account to change its role, tenants or status, or to manage its keys and sessions. Configured and single sign-on accounts are read-only here.';
  const holder = h('div');
  let filter = 'all';
  let roleList = [];
  const load = async () => {
    const [r, rl] = await Promise.all([attempt(v, () => ctx.api.accounts({ signal: ctx.signal })), loadRoles(ctx)]);
    if (r.error) { mount(holder, panel({ body: sectionFailure(v, r.error, load) })); return; }
    roleList = rl.items || [];
    const items = Array.isArray(r.value?.items) ? r.value.items : [];
    const limits = r.value?.limits || {};
    const count = (s) => items.filter((a) => s === 'all' || a.source === s).length;
    const create = ctx.can('accounts.manage') ? h('button', { class: ['btn', 'btn--primary'], type: 'button' }, icon('plus', { size: 'sm' }), 'Create account') : null;
    create?.addEventListener('click', async () => {
      const made = await createAccountDialog(v, roleList);
      if (!made) return;
      toast('ok', `Account created: ${made.name}. Create an API key so it can sign in.`);
      if (isAccountId(made.id)) ctx.navigate(href('settings', 'accounts', made.id, { created: '1' }));
      else load();
    });
    const paint = () => {
      const shown = items.filter((a) => filter === 'all' || a.source === filter);
      mount(holder, h('div', { class: 'stack-lg' },
        panel({
          title: 'Accounts', primary: true, flush: true,
          meta: `${plural(items.length, 'account')}${limits.max_accounts ? ` of at most ${formatCount(limits.max_accounts)}` : ''}${limits.max_keys_per_account ? ` · up to ${limits.max_keys_per_account} active keys each` : ''}`,
          actions: [helpTip(glossaryEntry('account')), create],
          body: h('div', null,
            h('div', { class: 'panel-toolbar' }, segmented({
              label: 'Show accounts from', value: filter,
              options: SOURCE_FILTERS.map(([k, label]) => [k, `${label} ${count(k)}`]),
              onChange: (k) => { filter = k; paint(); },
            })),
            shown.length ? accountsTable(shown, roleList) : empty('No accounts from this source', filter === 'oidc' ? 'Single sign-on identities appear after their first sign-in.' : 'Create a managed account for a person or a service.')),
        }),
        h('div', { class: ['grid', 'grid--3', 'source-notes'] }, ['config', 'oidc', 'managed'].map((s) => h('div', { class: 'source-note' },
          sourceBadge(s), h('p', null, sourceMeta(s).why))))));
    };
    paint();
  };
  await load();
  return holder;
}

// ---- Account detail ------------------------------------------------------------

async function accountDetail(v) {
  const { ctx, accountId } = v;
  if (!isAccountId(accountId)) return panel({ body: empty('This is not an account id', 'Open the account from the list.', h('a', { href: '#/settings/accounts' }, 'Go to accounts')) });
  const holder = h('div');
  const revealSlot = h('div');
  let reveal = null;
  v.cleanups.push(() => reveal?.destroy());
  const [first, listed, rl] = await Promise.all([
    attempt(v, () => ctx.api.account(accountId, { signal: ctx.signal })),
    // Only for the server's key limits (max_key_days, default_key_days).
    attempt(v, () => ctx.api.accounts({ signal: ctx.signal })),
    loadRoles(ctx),
  ]);
  const roleList = rl.items || [];
  const limits = listed.value?.limits || {};
  if (first.error) {
    if (first.error instanceof ApiError && first.error.status === 404) {
      return panel({ body: empty('Account not found', 'It may have been removed, or the link is from another server.', h('a', { href: '#/settings/accounts' }, 'Go to accounts'), { icon: 'search' }) });
    }
    return panel({ body: sectionFailure(v, first.error, () => ctx.rerender()) });
  }
  v.detailName = String(first.value?.name || accountId);
  v.subtitle = `${sourceMeta(first.value?.source).long} · ${kindLabel(first.value?.kind)}`;
  v.hint = accountEditable(first.value) ? 'Change role, tenants or status; create or revoke its keys; sign out its sessions.' : 'Read-only here. You can still revoke its keys and sign out its sessions.';

  const paint = (a) => {
    const src = sourceMeta(a.source);
    // The server's `editable` wins when present (false for configured and
    // single sign-on accounts).
    // Changing it also needs accounts.manage (the server decides).
    const managed = accountEditable(a) && ctx.can('accounts.manage');
    const isSelf = v.me?.id === a.id;
    const keyItems = Array.isArray(a.keys) ? a.keys : [];
    const sessionItems = Array.isArray(a.sessions) ? a.sessions : [];
    const reload = async () => {
      const r = await attempt(v, () => ctx.api.account(accountId, { signal: ctx.signal }));
      if (r.error) { toast('error', `Could not reload the account: ${describeError(r.error).detail}`); return; }
      paint(r.value);
    };

    // Access: role, tenants, name (managed only).
    let access;
    if (managed) {
      const summary = errorSummary();
      const name = formField({ label: 'Name', control: h('input', { class: 'input', type: 'text', name: 'name', maxlength: 64, autocomplete: 'off', spellcheck: 'false', prop: { value: a.name || '' } }) });
      const { sel: roleSel, hint: roleHint } = rolePicker(roleList, a.role);
      const role = formField({ label: 'Role', control: roleSel });
      const tOpts = tenantOptions(v);
      const extra = (a.tenants || []).filter((t) => !tOpts.some(([x]) => x === t)).map((t) => [t, `${t} (not one of yours)`]);
      const tenants = checkSet({ legend: 'Tenants', name: 'tenants', options: [...tOpts, ...extra], values: a.tenants || [] });
      const submit = h('button', { class: ['btn', 'btn--primary'], type: 'submit' }, 'Save changes');
      const form = h('form', { class: 'form', novalidate: true },
        summary.el,
        h('div', { class: 'form__row' }, name.el, h('div', null, role.el, roleHint)),
        tenants.el,
        h('div', { class: 'form__actions' }, submit, h('span', { class: 'field__hint' }, 'Takes effect on the account’s next request. Its keys keep working with the new role.')));
      wireForm(form, {
        submit, summary,
        checks: [
          { field: name, label: 'Name', validate: () => validateAccountName(name.control.value) },
          { field: tenants, label: 'Tenants', validate: () => validateTenants(tenants.values()) },
        ],
        onSubmit: async () => {
          const patch = {};
          if (name.control.value.trim() !== a.name) patch.name = name.control.value.trim();
          if (roleSel.value !== a.role) patch.role = roleSel.value;
          const t = tenants.values();
          if (t.join('\u0000') !== (a.tenants || []).join('\u0000')) patch.tenants = t;
          if (!Object.keys(patch).length) { toast('ok', 'Nothing changed.'); return; }
          await ctx.api.updateAccount(a.id, patch);
          toast('ok', `Saved ${a.name}: ${Object.keys(patch).join(', ')} changed.`);
          await reload();
        },
      });
      access = panel({ title: 'Access', primary: true, body: form });
    } else {
      access = panel({
        title: 'Access', primary: true, meta: 'Read-only here',
        body: h('div', { class: 'stack' },
          accountEditable(a)
            ? banner('info', 'Read-only for you', `Changing accounts needs “${permissionLabel('accounts.manage')}”, which your role does not include.`)
            : banner('info', `${src.long}: changed outside the console`, src.why),
          kv([
            ['Role', isRoleId(a.role) ? h('a', { href: href('settings', 'roles', a.role) }, roleNameOf(a.role, roleList)) : roleNameOf(a.role, roleList)],
            ['Tenants', h('span', { class: 'chip-row' }, (a.tenants || []).map((t) => chip(t, { mono: true })))],
          ])),
      });
    }

    // Status (managed only): disable or enable, with the consequence named.
    const statusMeta = accountStatusMeta(a.status);
    let statusAction = null;
    if (managed) {
      const disabling = a.status === 'active';
      statusAction = h('button', { class: ['btn', disabling ? 'btn--danger' : ''], type: 'button' }, disabling ? 'Disable account' : 'Enable account');
      statusAction.addEventListener('click', async () => {
        const ok = await confirmAction({
          title: disabling ? `Disable ${a.name}?` : `Enable ${a.name}?`,
          consequence: disabling
            ? `It can no longer sign in, and its ${plural(a.active_sessions || 0, 'active session')} end now. Its keys stop working until you enable it again.${isSelf ? ' This is your own account: you will be signed out.' : ''}`
            : 'Its unexpired, unrevoked keys work again from their next request.',
          targetLabel: 'Account', target: `${a.name} (${a.id})`,
          typed: disabling ? String(a.name) : '',
          danger: disabling,
          confirmLabel: disabling ? 'Disable account' : 'Enable account',
          onConfirm: () => ctx.api.updateAccount(a.id, { status: disabling ? 'disabled' : 'active' }),
          refusal: { what: 'this change' },
        });
        if (!ok) return;
        toast('ok', disabling ? `${a.name} is disabled and signed out.` : `${a.name} is enabled.`);
        await reload();
      });
    }
    const overview = panel({
      title: 'Account',
      actions: statusAction,
      body: kv([
        ['Account id', copyable(a.id, { label: 'account id' })],
        ['Source', h('span', { class: 'stack-tight' }, sourceBadge(a.source), h('span', { class: 'muted' }, src.why))],
        ['Kind', kindLabel(a.kind)],
        ['Status', badge(statusMeta.badge, statusMeta.label)],
        ['Created', a.created_at ? h('span', null, timeEl(a.created_at), a.created_by ? h('span', { class: 'muted' }, ` by ${a.created_by}`) : null) : h('span', { class: 'muted' }, a.created_by ? `Not recorded (${a.created_by})` : 'Not recorded')],
        ['Last seen', a.last_seen_at ? timeEl(a.last_seen_at, { relative: true }) : 'never'],
      ]),
    });

    // Keys: create for managed accounts; revoke for any (a leaked key of a
    // configured operator must be stoppable from here).
    const keyPanel = panel({
      title: 'API keys', flush: true, meta: keysLine(keyItems),
      body: h('div', null,
        managed && a.status === 'active' ? h('div', { class: 'panel-inset' }, createKeyForm({
          owner: a.name, limits,
          create: (body) => ctx.api.createAccountKey(a.id, body),
          onMinted: (minted) => {
            reveal?.destroy();
            reveal = keyReveal(minted, { owner: a.name, onDone: () => { reveal = null; toast('ok', 'The key is no longer shown on this page.'); } });
            mount(revealSlot, reveal.el);
            reveal.focus();
            reload();
          },
        })) : null,
        managed && a.status !== 'active' ? h('p', { class: ['panel-inset', 'muted'] }, 'Enable the account to create keys for it.') : null,
        !managed ? h('p', { class: ['panel-inset', 'muted'] }, a.source === 'config' ? 'A configured operator creates its own keys in its Settings. You can revoke them here.' : 'Single sign-on identities do not use API keys on this server.') : null,
        keyItems.length ? keysTable(keyItems, {
          caption: `API keys of ${a.name}`,
          onRevoke: !ctx.can('accounts.manage') ? null : (k) => revokeKeyFlow(k, { revoke: (id) => ctx.api.revokeAccountKey(a.id, id), after: reload, owner: a.name }),
        }) : empty('No keys', managed ? 'This account cannot sign in until it has a key.' : 'This account has no API keys.', null, { icon: 'key' })),
    });

    const sessionPanel = panel({
      title: 'Sessions', flush: true, meta: plural(sessionItems.length, 'signed-in session'),
      body: sessionItems.length ? sessionsTable(sessionItems, {
        onRevoke: !ctx.can('sessions.manage') ? null : (s) => revokeSessionFlow(ctx, s, { revoke: (handle) => ctx.api.revokeAnySession(handle), after: reload, who: a.name }),
      }) : empty('No sessions', 'This account is not signed in anywhere right now.', null, { icon: 'devices' }),
    });

    mount(holder, h('div', { class: 'stack-lg' },
      ctx.route.query?.created === '1' && managed && !keyItems.length ? banner('info', 'Account created', 'It cannot sign in yet. Create its first API key below, then hand the key over through a channel you trust.') : null,
      a.status === 'disabled' ? (a.source === 'config'
        ? banner('warn', 'Token sign-in is off on this server', 'Configured operators (and managed accounts\u2019 API keys) cannot sign in while console.token_login is false. Change it in the config file and restart.')
        : banner('warn', 'This account is disabled', 'It cannot sign in and its keys are refused until it is enabled again.')) : null,
      revealSlot,
      h('div', { class: ['grid', 'grid--2'] }, access, overview),
      keyPanel,
      sessionPanel));
  };
  paint(first.value);
  return holder;
}

// ---- Every session --------------------------------------------------------------

async function activeSessions(v) {
  const { ctx } = v;
  v.hint = 'Sign out a session you do not recognise. Revoking your own session here signs you out.';
  const holder = h('div');
  const load = async () => {
    const r = await attempt(v, () => ctx.api.allSessions({ signal: ctx.signal }));
    if (r.error) { mount(holder, panel({ body: sectionFailure(v, r.error, load) })); return; }
    const items = Array.isArray(r.value?.items) ? r.value.items : [];
    const accountsSeen = new Set(items.map((s) => s.account_id)).size;
    mount(holder, panel({
      title: 'Active sessions', primary: true, flush: true,
      meta: `${plural(items.length, 'session')} across ${plural(accountsSeen, 'account')}. Sessions end when they expire, idle out or are revoked.`,
      body: items.length ? sessionsTable(items, {
        showAccount: true,
        accountCell: (s) => (isAccountId(s.account_id)
          ? h('a', { href: href('settings', 'accounts', s.account_id) }, String(s.account_name || s.account_id))
          : String(s.account_name || 'unknown')),
        onRevoke: !ctx.can('sessions.manage') ? null : (s) => revokeSessionFlow(ctx, s, { revoke: (handle) => ctx.api.revokeAnySession(handle), after: load, who: s.account_name || 'that account' }),
      }) : empty('No sessions', 'Nobody is signed in, which only happens right after a restart.'),
    }));
  };
  await load();
  return holder;
}

// ---- Effective settings (read-only) -------------------------------------------------

const FILE_NOTE = 'Read-only in the console. These are the values the server is running with: change them in the config file (or the environment, where marked) and restart. Copy a key to find it in the file.';

async function configPage(v, page) {
  const { ctx } = v;
  v.hint = 'Read the values in effect, where each comes from and how to change it.';
  const r = await attempt(v, () => ctx.api.adminSettings({ signal: ctx.signal }));
  if (r.error) return panel({ body: sectionFailure(v, r.error, () => ctx.rerender()) });
  const body = r.value || {};
  const { byId } = groupSettings(body);
  const sections = (page.settings || []).map((id) => byId.get(id)).filter(Boolean);
  const generated = body.generated_at;
  const round6 = settingsAreRound6(body);
  const canManage = ctx.can('settings.manage');
  const hasAllowlisted = sections.some((sec) => (sec.items || []).some((it) => EDITABLE_KEYS.includes(it.key) && it.key !== 'posture.accepted'));
  const editingOff = round6 && body.editing === 'off';
  const anyEditable = round6 && sections.some((sec) => (sec.items || []).some((it) => it.editable && it.key !== 'posture.accepted'));
  if (anyEditable && canManage) v.hint = 'Change a value marked Editable: give a reason, save, and read the server’s answer. Everything else comes from the config file.';
  // Organisation name and banner live in /meta too: refresh the top bar.
  const onChanged = (item) => { if (['console.organization_name', 'console.sign_in_banner'].includes(item.key)) ctx.refreshMeta?.(); };
  const note = typeof body.note === 'string' && body.note ? `${sentence(body.note)} Copy a key to find it in the file.` : FILE_NOTE;
  let lead;
  if (!round6) lead = banner('info', 'File-driven settings', note);
  else if (editingOff && hasAllowlisted) lead = editingOffNotice();
  else if (editingOff) lead = banner('info', 'File-driven settings', note);
  else if (hasAllowlisted && !canManage) lead = banner('info', 'Some values can be changed in the console', `They are marked Editable for people with “${permissionLabel('settings.manage')}”, which your role does not include. The rest come from the config file.`);
  else if (hasAllowlisted) lead = banner('info', 'Some values can be changed here', 'Values marked Editable can be changed with a reason; the console stores the change and the config file is never written. Everything else comes from the config file: change it there and restart.');
  else lead = banner('info', 'File-driven settings', note);
  return h('div', { class: 'stack-lg' },
    lead,
    page.id === 'sso' ? ssoGuide(byId.get('sso')) : null,
    page.id === 'console' && !sections.length ? olderServerState({ title: 'This server does not provide console settings yet', detail: 'The organisation name, sign-in banner and default window arrive with a newer AegisMesh server. Until then, the console shows no organisation name and no banner.' }) : null,
    sections.length ? sections.map((sec, i) => panel({
      title: String(sec.title || sec.id), primary: i === 0,
      meta: generated ? h('span', null, 'Effective values, read ', timeEl(generated, { relative: true })) : 'Effective values',
      body: round6 ? editableSection(sec, ctx, { body, canManage, history: ctx.can('settings.read'), onChanged }) : settingsSection(sec),
    })) : page.id === 'console' ? null : panel({ body: empty('This server does not report these settings', 'It may be older than the console, or the section is not enabled. Check the config file directly.', null, { icon: 'info' }) }));
}

// ---- Change history -------------------------------------------------------------------

async function historyPage(v) {
  const { ctx } = v;
  v.hint = 'Read who changed which console setting, from what to what, and why. Filter by setting; each setting links here.';
  const keyFilter = isSettingKey(ctx.route.query?.key) ? ctx.route.query.key : '';
  const [hist, set] = await Promise.all([
    attempt(v, () => ctx.api.settingsHistory('', { signal: ctx.signal })),
    attempt(v, () => ctx.api.adminSettings({ signal: ctx.signal })),
  ]);
  if (hist.error) {
    return panel({ body: sectionFailure(v, hist.error, () => ctx.rerender(), { title: 'This server does not record setting changes yet', detail: 'Settings on this server come only from the config file, so there is no change history in the console. Your configuration repository’s history is the record.' }) });
  }
  const entries = normalizeHistory(hist.value);
  const labels = { ...SETTING_LABELS };
  const constraints = {};
  for (const sec of Array.isArray(set.value?.sections) ? set.value.sections : []) {
    for (const it of sec.items || []) {
      if (EDITABLE_KEYS.includes(it.key)) { labels[it.key] = String(it.label || labels[it.key] || it.key); constraints[it.key] = it.constraints; }
    }
  }
  const holder = h('div');
  const paint = (k) => {
    const view = historyView({ entries, keyFilter: k, labels, constraints, onFilter: (next) => ctx.navigate(href('settings', 'history', next ? { key: next } : {})) });
    mount(holder, panel({
      title: 'Change history', primary: true, flush: true,
      meta: `${plural(view.count, 'change')}${k ? '' : ', newest first'}. The server keeps a bounded history; the audit trail keeps every record.`,
      actions: ctx.can('audit.read') ? h('a', { class: 'btn', href: href('audit', { action: 'settings.update' }) }, 'In the audit trail') : null,
      body: h('div', null, h('div', { class: ['panel-toolbar', 'history-filter'] }, view.filter), view.body),
    }));
  };
  paint(keyFilter);
  return holder;
}

function ssoGuide(section) {
  const enabled = (section?.items || []).some((it) => it.key === 'console.oidc.enabled' && /^(enabled|on|true)$/i.test(String(it.value)));
  if (enabled) return null;
  return banner('info', 'Single sign-on is not configured',
    h('p', null, 'Operators sign in with configured tokens and managed API keys. To add OpenID Connect, set the console.oidc section of the config file and restart; the console never stores the client secret. '),
    h('a', { href: 'https://github.com/metaforismo/AegisMesh/blob/master/docs/configuration.md' }, 'Configuration reference'));
}

// ---- Audit export ------------------------------------------------------------------

const SINCE = [['', 'Everything'], ['24h', 'Last 24 hours'], ['7d', 'Last 7 days'], ['30d', 'Last 30 days']];
const SINCE_MS = { '24h': 86400e3, '7d': 7 * 86400e3, '30d': 30 * 86400e3 };

export function sinceValue(key, now = Date.now()) {
  return SINCE_MS[key] ? new Date(now - SINCE_MS[key]).toISOString().replace(/\.\d+Z$/, 'Z') : '';
}

function auditExport(v) {
  const { ctx } = v;
  v.hint = 'Download the audit chain for review or archive. The download is itself recorded in the audit trail.';
  const summary = errorSummary();
  const format = choices({ legend: 'Format', name: 'format', value: 'jsonl', options: [['jsonl', 'JSON Lines', 'One record per line, with the hash-chain fields'], ['csv', 'CSV', 'For a spreadsheet']] });
  const since = choices({ legend: 'Records', name: 'since', value: '', options: SINCE });
  const status = h('p', { class: 'field__hint', role: 'status' });
  const submit = h('button', { class: ['btn', 'btn--primary'], type: 'submit' }, icon('download', { size: 'sm' }), 'Download');
  const form = h('form', { class: 'form', novalidate: true },
    summary.el, format.el, since.el,
    h('div', { class: 'form__actions' }, submit, status));
  wireForm(form, {
    submit, busyLabel: 'Preparing…', summary,
    onSubmit: async () => {
      const f = format.value() === 'csv' ? 'csv' : 'jsonl';
      const res = await ctx.api.exportAudit(f, sinceValue(since.value()) || undefined, { signal: ctx.signal });
      const saved = await saveResponse(res, `audit-${f}`);
      status.textContent = `Saved ${saved.name} (${formatBytes(saved.bytes)}).`;
      toast('ok', `Audit export saved as ${saved.name}. The export is recorded in the audit trail.`);
    },
  });
  return h('div', { class: ['grid', 'grid--2'] },
    panel({ title: 'Export the audit trail', primary: true, body: form }),
    panel({
      title: 'What the file holds',
      actions: helpTip(glossaryEntry('audit')),
      body: h('ul', { class: 'bullets' },
        h('li', null, 'The audit chain of the tenant you are in, oldest first, at most 10,000 records: who did what, when, from where, and the outcome. For a longer chain, export a shorter period.'),
        h('li', null, 'Each record carries its hash and the previous record’s hash, so a copy can be checked against the chain later. It shows the chain was not altered after the fact; it cannot show what was never recorded.'),
        h('li', null, 'No secrets: tokens, keys and session cookies are never written to the audit trail.'),
        h('li', null, h('a', { href: '#/audit' }, 'Read the audit trail in the console'))),
    }));
}

// ---- System ------------------------------------------------------------------------

async function system(v) {
  const { ctx } = v;
  v.hint = 'Check the version and the health of each component. Support asks for these first.';
  const [sys, set] = await Promise.all([
    attempt(v, () => ctx.api.system({ signal: ctx.signal })),
    attempt(v, () => ctx.api.adminSettings({ signal: ctx.signal })),
  ]);
  if (sys.error) return panel({ body: sectionFailure(v, sys.error, () => ctx.rerender()) });
  const s = sys.value || {};
  const comps = Array.isArray(s.components) ? s.components : [];
  const other = set.value ? groupSettings(set.value).other : [];
  return h('div', { class: 'stack-lg' },
    h('div', { class: ['grid', 'grid--2'] },
      panel({
        title: 'Build', primary: true,
        body: kv([
          ['Version', h('strong', null, String(s.version || '—'))],
          ['Commit', s.commit ? copyable(String(s.commit), { label: 'commit' }) : '—'],
          ['Built', s.build_date ? timeEl(s.build_date) : '—'],
          ['Go', String(s.go_version || '—')],
          ['Config schema', String(s.config_schema || '—')],
          ['Started', s.started_at ? timeEl(s.started_at, { relative: true }) : '—'],
          ['Uptime', formatDuration(s.uptime_seconds)],
          // The server has no licence page (licenses_url is empty); the
          // release's LICENSE and NOTICE files list them.
          ['Licences', h('span', { class: 'muted' }, 'Apache-2.0; third-party notices are in the release’s NOTICE file')],
        ]),
      }),
      panel({
        title: 'Components', flush: true,
        meta: `${comps.filter((c) => c.status === 'ok').length} of ${comps.length} working`,
        body: comps.length ? table({
          caption: 'Component health',
          columns: [
            { label: 'Component', cell: (c) => COMPONENT_LABEL[c.id] || String(c.id || '—') },
            { label: 'Status', cell: (c) => { const m = healthMeta(c.status); return badge(m.badge, m.label); } },
            { label: 'Detail', className: 'col-summary', cell: (c) => String(c.detail || '—') },
          ],
          rows: comps,
        }) : empty('No components reported', 'This server does not report component health.'),
      })),
    other.length ? other.map((sec) => panel({ title: String(sec.title || sec.id), meta: 'Other settings (read-only)', body: settingsSection(sec) })) : null);
}

const RENDER = {
  accounts: (v) => (v.accountId ? accountDetail(v) : accounts(v)),
  roles: (v) => (v.roleId ? roleEditor(v) : rolesPage(v)),
  history: historyPage,
  'active-sessions': activeSessions,
  'audit-export': auditExport,
  system,
};

export default {
  async render(id, v) {
    const page = ADMIN_SECTIONS.find((s) => s.id === id);
    if (!page) return notPermittedState(v.role);
    v.section = id;
    if (RENDER[id]) return RENDER[id](v);
    return configPage(v, page);
  },
};
