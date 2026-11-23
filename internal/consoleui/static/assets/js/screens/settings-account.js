// Settings, your account: profile, preferences, sessions and API keys.

import { h, mount } from '../lib/dom.js';
import { ApiError, describeError } from '../lib/api.js';
import { isMissingEndpoint } from '../lib/insight.js';
import { formatDateTime, formatDurationMs } from '../lib/format.js';
import { glossaryEntry } from '../lib/glossary.js';
import { PREF_SOURCES } from '../lib/prefs.js';
import {
  roleText, sourceMeta, kindLabel, authLabel, keyStatusMeta, EXPIRY_PRESETS, EXPIRY_DEFAULT, expiryLabel,
  validateKeyLabel, isSessionHandle, isKeyId, keysLine,
} from '../lib/settings.js';
import { panel, kv, table, badge, chip, timeEl, copyable, banner, empty, toast, helpTip, failureState } from '../ui/components.js';
import { confirmAction, keyReveal, formField, choices, errorSummary, wireForm, olderServerState } from '../ui/settings-kit.js';
import { icon } from '../ui/icons.js';

// "in 3 h" / "expired" for times ahead (sessions, keys).
export function formatUntil(value, now = Date.now()) {
  const t = Date.parse(value);
  if (Number.isNaN(t)) return '—';
  if (t <= now) return 'expired';
  return `in ${formatDurationMs(t - now)}`;
}

export function untilEl(value) {
  const full = formatDateTime(value);
  if (full === '—') return h('span', { class: 'muted' }, '—');
  return h('time', { class: 'reltime', datetime: value, title: full }, formatUntil(value), h('span', { class: 'visually-hidden' }, ` (${full})`));
}

const sectionError = (err, retry) => failureState({ ...describeError(err), retry: true, actions: [] }, retry);

// ---- Profile -----------------------------------------------------------------

function profile(v) {
  const { me, ctx } = v;
  const p = ctx.session?.principal || {};
  const who = me || { name: p.name, role: p.role, auth_method: p.auth_method, tenant: ctx.session?.tenant, tenants: ctx.session?.tenants || [] };
  const rt = roleText(who.role);
  const src = me ? sourceMeta(me.source) : null;
  const tenants = Array.isArray(who.tenants) ? who.tenants : [];
  v.hint = 'Read who you are signed in as and what your role allows. Your role and tenants are set by an admin, the config file or the identity provider.';
  const account = panel({
    title: 'Account', primary: true,
    actions: helpTip(glossaryEntry('account')),
    body: kv([
      ['Name', who.name || '—'],
      me ? ['Account id', copyable(me.id, { label: 'account id' })] : null,
      me ? ['Kind', kindLabel(me.kind)] : null,
      ['Role', h('strong', null, rt.label)],
      ['Tenants', tenants.length ? h('span', { class: 'chip-row' }, tenants.map((t) => chip(t, { mono: true }))) : '—'],
      ['Active tenant', who.tenant ? h('code', null, who.tenant) : '—'],
      ['Signed in with', authLabel(who.auth_method || 'token')],
      src ? ['Account source', h('span', { class: 'stack-tight' }, h('span', null, src.long), h('span', { class: 'muted' }, src.why))] : null,
      me ? ['Created', me.created_at ? timeEl(me.created_at) : h('span', { class: 'muted' }, 'Not recorded (configured in the file)')] : null,
      me ? ['Last seen', me.last_seen_at ? timeEl(me.last_seen_at, { relative: true }) : '—'] : null,
      ctx.session?.expires_at ? ['This session expires', untilEl(ctx.session.expires_at)] : null,
    ]),
  });
  const rolePanel = panel({
    title: `What the ${rt.label.toLowerCase()} role can do`,
    meta: rt.summary,
    body: h('div', { class: 'role-lists' },
      h('div', null, h('p', { class: 'caps' }, 'Can'), h('ul', { class: ['role-list', 'role-list--can'] }, rt.can.map((t) => h('li', null, icon('check', { size: 'sm' }), h('span', null, t))))),
      rt.cannot.length ? h('div', null, h('p', { class: 'caps' }, 'Cannot'), h('ul', { class: ['role-list', 'role-list--cannot'] }, rt.cannot.map((t) => h('li', null, icon('close', { size: 'sm' }), h('span', null, t))))) : null,
      h('p', { class: 'muted' }, 'The server checks every request against your role; this list explains it, it does not grant anything.')),
  });
  return h('div', { class: 'stack-lg' },
    v.meMissing ? banner('info', 'This server does not provide account management yet', 'What is shown comes from your sign-in session. Update the server to see your account id, source and history, and to manage sessions and API keys.') : null,
    v.meError ? banner('warn', 'Your account details could not be loaded', `${describeError(v.meError).detail} What is shown comes from your sign-in session.`) : null,
    h('div', { class: ['grid', 'grid--2'] }, account, rolePanel));
}

// ---- Preferences ----------------------------------------------------------------

const PREF_ROWS = [
  { key: 'timezone', legend: 'Time zone', options: [['utc', 'UTC'], ['local', 'Local time']],
    hint: 'How every absolute time is printed. UTC matches logs from other machines; local time adds the offset to each time, so a copied time stays unambiguous.' },
  { key: 'default_window', legend: 'Default time window', options: [['1h', '1 hour'], ['24h', '24 hours'], ['7d', '7 days']],
    hint: 'The window Overview, Sources, Sessions and the catalogs open with when a link names none.' },
  { key: 'density', legend: 'Row density', options: [['comfortable', 'Comfortable'], ['compact', 'Compact']],
    hint: 'Compact fits more rows of a table on screen.' },
  { key: 'theme', legend: 'Color theme', options: [['system', 'Match the system'], ['light', 'Light'], ['dark', 'Dark']],
    hint: 'Printing always uses the light palette.' },
  { key: 'reduce_motion', legend: 'Motion', options: [['system', 'Follow the system'], ['on', 'Always reduce']],
    hint: 'Reduce turns off view transitions, sliding indicators and other movement, even if the operating system does not ask for it.' },
];

function preferences(v) {
  const { ctx } = v;
  const store = ctx.prefs;
  v.hint = 'Changes apply at once and are saved as you make them.';
  const status = h('p', { class: ['pref-status'], role: 'status', 'aria-live': 'polite' });
  const sourceLine = h('span', null);
  const example = h('span', { class: 'num' });
  const paintSource = () => {
    sourceLine.textContent = store.source() === 'server'
      ? `${PREF_SOURCES.server}: they follow you to any browser you sign in from.`
      : `${PREF_SOURCES.browser}${v.meMissing ? ': this server does not store preferences yet.' : '.'}`;
    example.textContent = formatDateTime(new Date().toISOString());
  };
  const groups = new Map();
  const rows = PREF_ROWS.map((row) => {
    const group = choices({
      legend: row.legend, name: `pref-${row.key}`, options: row.options, value: store.get()[row.key], hint: row.hint,
      onChange: (value) => {
        const prev = store.get()[row.key];
        status.textContent = 'Saving…';
        store.update({ [row.key]: value }).then(() => {
          status.textContent = `${row.legend}: ${row.options.find(([x]) => x === value)?.[1] || value}. ${store.source() === 'server' ? 'Saved to your account.' : 'Saved in this browser.'}`;
          paintSource();
        }, (err) => {
          group.set(prev);
          status.textContent = `${row.legend} was not saved, so the previous value is back. ${describeError(err).detail}`;
          toast('error', `Could not save ${row.legend.toLowerCase()}: ${describeError(err).detail} The previous value is back.`);
        });
      },
    });
    groups.set(row.key, group);
    return h('div', { class: 'pref-row' }, group.el,
      row.key === 'timezone' ? h('p', { class: 'pref-row__example' }, 'Now: ', example) : null);
  });
  // The top-bar theme and density controls change the same store.
  v.cleanups.push(store.subscribe((p) => {
    for (const [k, g] of groups) g.set(p[k]);
    paintSource();
  }));
  paintSource();
  return panel({
    title: 'Display and time', primary: true,
    meta: sourceLine,
    body: h('div', { class: 'pref-list' }, rows, status),
  });
}

// ---- Sessions ---------------------------------------------------------------------

export function sessionsTable(items, { onRevoke, showAccount = false, accountCell } = {}) {
  return table({
    caption: 'Signed-in sessions',
    columns: [
      showAccount ? { label: 'Account', cell: (s) => accountCell(s) } : null,
      { label: 'Client', cell: (s) => h('span', { class: 'stack-tight' }, h('span', { class: 'session-client' }, icon('devices', { size: 'sm' }), String(s.client || 'Unknown client')), s.current ? badge('info', 'This browser') : null) },
      { label: 'Signed in with', cell: (s) => authLabel(s.auth_method) },
      { label: 'Address', cell: (s) => h('code', null, String(s.remote || '—')) },
      { label: 'Started', cell: (s) => timeEl(s.created_at, { relative: true }), sort: (s) => Date.parse(s.created_at) || null, sortFirst: 'desc' },
      { label: 'Last active', cell: (s) => timeEl(s.last_seen_at, { relative: true }), sort: (s) => Date.parse(s.last_seen_at) || null, sortFirst: 'desc' },
      { label: 'Expires', cell: (s) => h('span', { class: 'stack-tight' }, untilEl(s.expires_at), s.idle_expires_at ? h('span', { class: 'muted' }, 'idle ', untilEl(s.idle_expires_at)) : null) },
      { label: 'Action', cell: (s) => (isSessionHandle(s.handle) ? h('button', {
        class: ['btn', 'btn--sm', s.current ? '' : 'btn--danger'], type: 'button',
        'aria-label': s.current ? 'Sign out of this browser' : `Revoke the session from ${s.client || 'an unknown client'} at ${s.remote || 'an unknown address'}`,
        on: { click: (e) => onRevoke(s, e.currentTarget) },
      }, s.current ? 'Sign out' : 'Revoke') : '—') },
    ].filter(Boolean),
    rows: items,
  });
}

export async function revokeSessionFlow(ctx, s, { revoke, after, who = 'your account' }) {
  const ok = await confirmAction({
    title: s.current ? 'Sign out of this browser?' : 'Revoke this session?',
    consequence: s.current
      ? 'This browser is signed out now. Signing in again needs a token, an API key or single sign-on.'
      : `That browser is signed out at its next request, and its live views stop. Other sessions of ${who} are not affected.`,
    targetLabel: 'Session',
    target: `${s.client || 'Unknown client'} · ${s.remote || 'unknown address'} · ${s.handle}`,
    confirmLabel: s.current ? 'Sign out' : 'Revoke session',
    onConfirm: () => revoke(s.handle),
    refusal: { what: 'revoking this session' },
  });
  if (!ok) return;
  if (s.current) {
    ctx.signedOut();
    return;
  }
  toast('ok', `Session revoked: ${s.client || 'unknown client'} at ${s.remote || 'unknown address'}.`);
  await after();
}

async function sessions(v) {
  const { ctx } = v;
  if (v.meMissing) return olderServerState();
  v.hint = 'Revoke a session you do not recognise. Revoking this browser’s session signs you out.';
  const holder = h('div');
  const load = async () => {
    let res;
    try {
      res = await ctx.api.mySessions({ signal: ctx.signal });
    } catch (err) {
      if (err?.name === 'AbortError') return;
      mount(holder, isMissingEndpoint(err) ? olderServerState() : panel({ body: sectionError(err, load) }));
      return;
    }
    const items = Array.isArray(res?.items) ? res.items : [];
    const others = items.filter((s) => !s.current && isSessionHandle(s.handle));
    const revokeOthers = others.length ? h('button', { class: ['btn', 'btn--danger'], type: 'button' }, 'Sign out all other sessions') : null;
    revokeOthers?.addEventListener('click', async () => {
      const ok = await confirmAction({
        title: 'Sign out every other session?',
        consequence: `${others.length} other ${others.length === 1 ? 'session is' : 'sessions are'} signed out at their next request. This browser stays signed in.`,
        confirmLabel: `Sign out ${others.length}`,
        onConfirm: async () => {
          const results = await Promise.allSettled(others.map((s) => ctx.api.revokeMySession(s.handle)));
          const failed = results.filter((r) => r.status === 'rejected').length;
          if (failed === others.length) throw results.find((r) => r.status === 'rejected').reason;
          return { failed };
        },
      });
      if (!ok) return;
      toast(ok.failed ? 'error' : 'ok', ok.failed ? `${others.length - ok.failed} sessions signed out; ${ok.failed} could not be revoked. Reload to check.` : 'Every other session is signed out.');
      await load();
    });
    mount(holder, panel({
      title: 'Your sessions', primary: true, flush: true,
      meta: `${items.length} signed-in ${items.length === 1 ? 'session' : 'sessions'}. A session ends when it expires, when it is idle too long, or when it is revoked.`,
      actions: revokeOthers,
      body: items.length ? sessionsTable(items, {
        onRevoke: (s) => revokeSessionFlow(ctx, s, { revoke: (handle) => ctx.api.revokeMySession(handle), after: load }),
      }) : empty('No sessions listed', 'The server lists none for your account, which can happen right after a restart.'),
    }));
  };
  await load();
  return holder;
}

// ---- API keys ------------------------------------------------------------------------

export function keysTable(items, { onRevoke, caption = 'API keys' }) {
  return table({
    caption,
    columns: [
      { label: 'Label', className: 'col-summary', cell: (k) => h('span', { class: 'stack-tight' }, h('span', { class: 'key-label' }, String(k.label || '—')), h('code', { class: 'muted' }, `${String(k.prefix || 'amk_')}…`)), sort: (k) => String(k.label || '').toLowerCase() },
      { label: 'Status', cell: (k) => { const m = keyStatusMeta(k.status); return badge(m.badge, m.label); } },
      { label: 'Created', cell: (k) => h('span', { class: 'stack-tight' }, timeEl(k.created_at, { relative: true }), k.created_by ? h('span', { class: 'muted' }, `by ${k.created_by}`) : null), sort: (k) => Date.parse(k.created_at) || null, sortFirst: 'desc' },
      { label: 'Expires', cell: (k) => (k.status === 'revoked' ? h('span', { class: 'stack-tight' }, h('span', null, 'revoked'), timeEl(k.revoked_at, { relative: true })) : untilEl(k.expires_at)), sort: (k) => Date.parse(k.expires_at) || null },
      { label: 'Last used', cell: (k) => (k.last_used_at ? timeEl(k.last_used_at, { relative: true }) : h('span', { class: 'muted' }, 'never')), sort: (k) => Date.parse(k.last_used_at) || null, sortFirst: 'desc' },
      { label: 'Action', cell: (k) => (k.status === 'active' && isKeyId(k.id) ? h('button', {
        class: ['btn', 'btn--sm', 'btn--danger'], type: 'button', 'aria-label': `Revoke key ${k.label}`, on: { click: () => onRevoke(k) },
      }, 'Revoke') : h('span', { class: 'muted' }, '—')) },
    ],
    rows: items,
  });
}

export function revokeKeyFlow(k, { revoke, after, owner = 'your account' }) {
  return confirmAction({
    title: 'Revoke this API key?',
    consequence: `Anything that uses it (a script, a SIEM pull) is refused from its next request. This cannot be undone; ${owner} can create a new key.`,
    targetLabel: 'Key',
    target: `${k.label} (${k.prefix}…)`,
    typed: String(k.label || ''),
    confirmLabel: 'Revoke key',
    onConfirm: () => revoke(k.id),
    refusal: { what: 'revoking this key' },
  }).then(async (ok) => {
    if (!ok) return;
    toast('ok', `Key revoked: ${k.label}.`);
    await after();
  });
}

// The create form: a label and a lifetime. `create(body)` returns the
// minted key; the reveal panel shows its token once.
export function createKeyForm({ create, onMinted, owner = '' }) {
  const summary = errorSummary();
  const labelField = formField({
    label: 'Label',
    control: h('input', { class: 'input', type: 'text', name: 'label', maxlength: 64, autocomplete: 'off', spellcheck: 'false', placeholder: 'for example siem-pull on splunk-hf-01' }),
    hint: 'Name the script or host that will use the key, so you know what breaks if you revoke it. Never put a secret here.',
  });
  const expiry = choices({ legend: 'Expires after', name: 'expiry', options: EXPIRY_PRESETS.map((d) => [String(d), expiryLabel(d)]), value: String(EXPIRY_DEFAULT), hint: 'A key stops working at the end of its lifetime. Shorter is safer; create a new one before it ends.' });
  const submit = h('button', { class: ['btn', 'btn--primary'], type: 'submit' }, icon('plus', { size: 'sm' }), 'Create key');
  const form = h('form', { class: 'form', novalidate: true },
    summary.el,
    h('div', { class: 'form__row' }, labelField.el, expiry.el),
    h('div', { class: 'form__actions' }, submit, h('span', { class: 'field__hint' }, owner ? `The key acts as ${owner}, with its role and tenants.` : 'The key acts as you, with your role and tenants.')));
  wireForm(form, {
    submit, busyLabel: 'Creating…', summary,
    checks: [{ field: labelField, label: 'Label', validate: () => validateKeyLabel(labelField.control.value) }],
    onSubmit: async () => {
      let minted = await create({ label: labelField.control.value.trim(), expires_in_days: Number(expiry.value()) || EXPIRY_DEFAULT });
      labelField.control.value = '';
      onMinted(minted);
      minted = null;
    },
  });
  return form;
}

async function keys(v) {
  const { ctx, me } = v;
  if (v.meMissing) return olderServerState();
  v.hint = 'Create a key for a script or integration; it acts as you. Revoke keys you no longer use.';
  if (me && !me.capabilities?.manage_own_keys) {
    return panel({ body: empty('Your account cannot create API keys', me.source === 'oidc'
      ? 'Single sign-on identities are owned by the identity provider, so this server does not let them mint keys. Ask an admin for a managed service account instead.'
      : `The server does not allow ${me.role || 'this'} accounts to manage their own keys. Ask an admin for a managed service account if a script needs access.`, null, { icon: 'key' }) });
  }
  const revealSlot = h('div');
  const listSlot = h('div');
  let reveal = null;
  v.cleanups.push(() => reveal?.destroy());
  const load = async () => {
    let res;
    try {
      res = await ctx.api.myKeys({ signal: ctx.signal });
    } catch (err) {
      if (err?.name === 'AbortError') return;
      if (err instanceof ApiError && err.status === 403) {
        mount(listSlot, panel({ body: empty('Your account cannot create API keys', 'The server refused to list keys for this account. Ask an admin for a managed service account if a script needs access.', null, { icon: 'key' }) }));
        return;
      }
      mount(listSlot, isMissingEndpoint(err) ? olderServerState() : panel({ body: sectionError(err, load) }));
      return;
    }
    const items = Array.isArray(res?.items) ? res.items : [];
    mount(listSlot, panel({
      title: 'Your keys', flush: true, meta: keysLine(items),
      body: items.length ? keysTable(items, { onRevoke: (k) => revokeKeyFlow(k, { revoke: (id) => ctx.api.revokeMyKey(id), after: load }) })
        : empty('No API keys yet', 'Create one above when a script or integration needs to call the console API as you.', null, { icon: 'key' }),
    }));
  };
  const form = createKeyForm({
    create: (body) => ctx.api.createMyKey(body),
    onMinted: (minted) => {
      reveal?.destroy();
      reveal = keyReveal(minted, { onDone: () => { reveal = null; toast('ok', 'The key is no longer shown on this page.'); } });
      mount(revealSlot, reveal.el);
      reveal.focus();
      load();
    },
  });
  await load();
  return h('div', { class: 'stack-lg' },
    revealSlot,
    panel({ title: 'Create an API key', primary: true, actions: helpTip(glossaryEntry('apikey')), body: form }),
    listSlot);
}

const SECTIONS = { profile, preferences, sessions, keys };

export default {
  async render(id, v) {
    const fn = SECTIONS[id] || profile;
    return fn(v);
  },
};
