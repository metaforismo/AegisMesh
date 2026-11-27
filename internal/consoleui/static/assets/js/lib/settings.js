import { SECTION_PERMS } from './perms.js';

// Settings and administration: the section registry, role and source
// explanations, validation and the wording for the server's refusals, and
// (round 6) the editable console settings: formatting, constraints, input
// parsing and the change history. Pure data and functions; the screens in
// screens/settings*.js draw them.
//
// Role gating here is a convenience: the server decides every request, and
// the screens handle its 401 and 403 answers whatever this file says.

export const ACCOUNT_SECTIONS = Object.freeze([
  { id: 'profile', label: 'Profile', icon: 'user', hint: 'Who you are signed in as and what your role allows' },
  { id: 'preferences', label: 'Preferences', icon: 'settings', hint: 'Time zone, default window, density, theme, motion' },
  { id: 'sessions', label: 'Sessions', icon: 'devices', hint: 'Where your account is signed in' },
  { id: 'keys', label: 'API keys', icon: 'key', hint: 'Tokens for scripts and integrations' },
  { id: 'notifications', label: 'Notifications', icon: 'bell', hint: 'What reaches your inbox, and the one notice for critical items' },
]);

// Administration pages. `settings` names the /admin/settings sections a
// page renders (read-only, file-driven).
export const ADMIN_SECTIONS = Object.freeze([
  { id: 'accounts', label: 'Accounts', icon: 'users', hint: 'Configured, single sign-on and managed accounts' },
  { id: 'roles', label: 'Roles', icon: 'role', hint: 'Built-in and custom roles, and what each permits' },
  { id: 'active-sessions', label: 'Active sessions', icon: 'devices', hint: 'Every signed-in session on this server' },
  { id: 'sso', label: 'Single sign-on', icon: 'sign-in', hint: 'OpenID Connect, read-only', settings: ['sso'] },
  { id: 'security', label: 'Security and access', icon: 'lock', hint: 'Sign-in, sessions, key lifetimes, listener, tenants', settings: ['access', 'listener', 'tenants'] },
  { id: 'console', label: 'Console', icon: 'settings', hint: 'Organisation name, sign-in banner, default window', settings: ['console'] },
  { id: 'data', label: 'Data and retention', icon: 'database', hint: 'Evidence storage, encryption, index', settings: ['evidence'] },
  { id: 'detection', label: 'Detection', icon: 'rules', hint: 'Rules, correlation, actions mode', settings: ['detection'] },
  { id: 'fleet', label: 'Fleet', icon: 'fleet', hint: 'Hub and agent roles', settings: ['fleet'] },
  { id: 'exports', label: 'Exports', icon: 'download', hint: 'File formats and limits', settings: ['exports'] },
  { id: 'history', label: 'Change history', icon: 'history', hint: 'Who changed which setting, from what to what, and why' },
  { id: 'audit-export', label: 'Audit export', icon: 'audit', hint: 'Download the audit chain' },
  { id: 'system', label: 'System', icon: 'node', hint: 'Version, uptime, component health' },
]);

export const SECTION_IDS = Object.freeze([...ACCOUNT_SECTIONS, ...ADMIN_SECTIONS].map((s) => s.id));
export const isSectionId = (v) => SECTION_IDS.includes(v);
export const isAdminSection = (v) => ADMIN_SECTIONS.some((s) => s.id === v);
export const sectionMeta = (id) => [...ACCOUNT_SECTIONS, ...ADMIN_SECTIONS].find((s) => s.id === id) || null;

// The /admin/settings sections a known page renders; anything the server
// adds later appears on System under "Other settings".
export const MAPPED_SETTINGS = Object.freeze(ADMIN_SECTIONS.flatMap((s) => s.settings || []));

// Account ids: managed (acc_…), configured (cfg:<name>), OIDC (oidc:<12 hex>).
const ACCOUNT_ID = /^(acc_[a-z0-9]{4,64}|cfg:[A-Za-z0-9_.@-]{1,64}|oidc:[0-9a-f]{12})$/;
export const isAccountId = (v) => typeof v === 'string' && ACCOUNT_ID.test(v);
export const isSessionHandle = (v) => typeof v === 'string' && /^ses_[0-9a-f]{16}$/.test(v);
export const isKeyId = (v) => typeof v === 'string' && /^key_[0-9a-f]{12}$/.test(v);

// What a role can do, in plain words. Matches the server's role checks
// (docs/architecture/console-api.md); the server stays the authority.
export const ROLE_TEXT = Object.freeze({
  viewer: {
    label: 'Viewer',
    summary: 'Reads everything the decoys observed. Changes nothing.',
    can: ['Read events, sources, sessions, campaigns, decoys, honeytokens, rules and the digest', 'Follow live events', 'Set your own preferences and sign out your own sessions'],
    cannot: ['Create or change investigations', 'Download reports, indicators or event exports', 'Read the audit trail or manage accounts'],
  },
  analyst: {
    label: 'Analyst',
    summary: 'Everything a viewer can, plus recording judgement and taking evidence out.',
    can: ['Everything a viewer can', 'Open, update and annotate investigations', 'Download session reports, indicators and SIEM event files', 'Create API keys for your own scripts, where the server allows it'],
    cannot: ['Read the audit trail', 'Manage accounts, other people’s sessions or fleet enrollment'],
  },
  admin: {
    label: 'Admin',
    summary: 'Everything an analyst can, plus access management and the audit trail.',
    can: ['Everything an analyst can', 'Read, verify and export the audit trail', 'Create and change managed accounts, their keys and sessions', 'Enroll and revoke fleet nodes', 'Read the effective server settings'],
    cannot: ['Change configured operators or single sign-on identities (they come from the config file and the identity provider)', 'Change server settings from the console: they are file-driven'],
  },
});
export const roleText = (role) => ROLE_TEXT[role] || { label: 'Unknown role', summary: 'The server returned a role this console does not know.', can: [], cannot: [] };

// Where an account comes from, and whether the console may change it.
export const SOURCES = Object.freeze({
  config: {
    label: 'Configured',
    long: 'Configured operator',
    editable: false,
    why: 'Defined in the config file (console.operators). It is the break-glass path, so the console cannot change or disable it. Edit the file and restart.',
  },
  oidc: {
    label: 'Single sign-on',
    long: 'Single sign-on identity',
    editable: false,
    why: 'Appeared when it first signed in through the identity provider. Its name comes from the provider and its role and tenants from the claim mapping, so change them there.',
  },
  managed: {
    label: 'Managed',
    long: 'Managed account',
    editable: true,
    why: 'Created by an admin in this console. It signs in with API keys only (there are no passwords) and can be changed or disabled here.',
  },
});
export const sourceMeta = (s) => SOURCES[s] || { label: 'Unknown', long: 'Unknown source', editable: false, why: 'The server returned a source this console does not know, so it is shown read-only.' };

export const KIND_LABEL = Object.freeze({ person: 'Person', service: 'Service' });
export const kindLabel = (k) => KIND_LABEL[k] || 'Unknown kind';

export const AUTH_LABEL = Object.freeze({ token: 'Token', oidc: 'Single sign-on' });
export const authLabel = (m) => AUTH_LABEL[m] || 'Unknown';

// API key and account states → badge kind and word.
export const KEY_STATUS = Object.freeze({
  active: { badge: 'ok', label: 'Active' },
  expired: { badge: 'neutral', label: 'Expired' },
  revoked: { badge: 'neutral', label: 'Revoked' },
});
export const keyStatusMeta = (s) => KEY_STATUS[s] || { badge: 'neutral', label: 'Unknown' };
export const ACCOUNT_STATUS = Object.freeze({
  active: { badge: 'ok', label: 'Active' },
  disabled: { badge: 'warn', label: 'Disabled' },
});
export const accountStatusMeta = (s) => ACCOUNT_STATUS[s] || { badge: 'neutral', label: 'Unknown' };

// Setting provenance (where the effective value came from).
export const SETTING_SOURCES = Object.freeze({
  config: { label: 'Config file', hint: 'Set in the config file' },
  default: { label: 'Default', hint: 'Not set: the built-in default applies' },
  env: { label: 'Environment', hint: 'Set by an environment variable' },
  runtime: { label: 'Measured', hint: 'Observed by the running server (usage, occupancy, discovery, certificate expiry), not a setting' },
  console: { label: 'Console', hint: 'Changed in the console. The console stores it; the config file is not written.' },
});
export const settingSourceMeta = (s) => SETTING_SOURCES[s] || { label: 'Unknown source', hint: 'The server did not say where this value comes from' };

// A component's health on System.
export const HEALTH = Object.freeze({
  ok: { badge: 'ok', label: 'Working' },
  degraded: { badge: 'warn', label: 'Degraded' },
  off: { badge: 'neutral', label: 'Off' },
});
export const healthMeta = (s) => HEALTH[s] || { badge: 'neutral', label: 'Unknown' };
export const COMPONENT_LABEL = Object.freeze({ console: 'Console', storage: 'Evidence storage', index: 'Event index', sensors: 'Sensors', fleet: 'Fleet', oidc: 'Single sign-on', settings: 'Console settings' });

// API key lifetimes offered in the create form (the server allows 1..365).
export const EXPIRY_PRESETS = Object.freeze([30, 90, 180, 365]);
export const EXPIRY_DEFAULT = 90;
export const expiryLabel = (d) => (d === 365 ? '1 year' : `${d} days`);
// The presets the server allows (`limits.max_key_days`) and its default
// (`limits.default_key_days`), when it says; otherwise the contract's.
export function expiryOptions(limits) {
  const max = Number.isInteger(limits?.max_key_days) && limits.max_key_days > 0 ? limits.max_key_days : 365;
  const presets = EXPIRY_PRESETS.filter((d) => d <= max);
  const list = presets.length ? presets : [max];
  const def = Number.isInteger(limits?.default_key_days) && list.includes(limits.default_key_days) ? limits.default_key_days : (list.includes(EXPIRY_DEFAULT) ? EXPIRY_DEFAULT : list[list.length - 1]);
  return { presets: list, def };
}
// Whether the console may change an account: the server's `editable` when
// present, else the source rule.
export const accountEditable = (a) => (typeof a?.editable === 'boolean' ? a.editable && a.source === 'managed' : a?.source === 'managed');

// Validation for the forms. Each returns '' when the value is acceptable,
// otherwise one sentence that says what to change.
export function validateKeyLabel(v) {
  const s = String(v ?? '').trim();
  if (!s) return 'Give the key a label, for example the host or script that will use it.';
  if (Array.from(s).length > 64) return 'Keep the label to 64 characters or fewer.';
  if (/[\u0000-\u001f\u007f]/.test(s)) return 'Use printable characters only.';
  return '';
}

export function validateAccountName(v) {
  const s = String(v ?? '').trim();
  if (!s) return 'Enter a name.';
  if (Array.from(s).length > 64) return 'Keep the name to 64 characters or fewer.';
  if (!/^[\p{L}\p{N} ._@()-]+$/u.test(s)) return 'Use letters, digits, spaces and . _ @ ( ) - only.';
  return '';
}

export function validateTenants(list, allowed) {
  const chosen = Array.isArray(list) ? list : [];
  if (!chosen.length) return 'Choose at least one tenant.';
  if (allowed && chosen.some((t) => !allowed.includes(t))) return 'Choose only tenants this server declares.';
  return '';
}

// Typed confirmation: the exact target, ignoring surrounding spaces.
export function typedMatches(input, expected) {
  return typeof input === 'string' && typeof expected === 'string' && expected.length > 0 && input.trim() === expected;
}

// The server's refusals, in words that say what to do. `err` is an ApiError.
export function refusalMessage(err, { what = 'this change' } = {}) {
  const reason = err?.reason || '';
  if (reason === 'builtin') return 'Built-in roles cannot be changed or deleted. Duplicate it as a custom role instead.';
  if (reason === 'in_use') return `This role is still assigned (${err?.message || 'in use'}). Move those accounts to another role first.`;
  if (reason === 'editing_disabled') return 'Console editing is off on this server (console.settings_editing: off), so settings change only in the config file. Nothing was changed.';
  if (reason === 'not_editable') return 'This setting cannot be changed from the console. Change it in the config file and restart.';
  if (reason === 'exceeds_own_permissions') return 'This touches permissions your own role does not include, so the server refused it. Someone whose role includes them can make the change.';
  if (reason === 'last_admin') return 'This would leave no active admin. Make another account an admin first, then try again.';
  if (reason === 'not_managed') return 'This account is not managed in the console: configured operators change in the config file, single sign-on identities at the identity provider.';
  if (reason === 'name_taken') return 'An account with this name already exists. Choose another name.';
  if (reason === 'limit_reached') return `The server's limit is reached. Revoke or remove something first. (${err?.message || 'limit reached'})`;
  if (err?.status === 403) return `The server refused ${what}: your account does not have the permission it needs. Ask an admin.`;
  if (err?.status === 404) return 'It no longer exists on the server. Reload the page.';
  if (err?.status === 400) return `The server rejected the values: ${err.message}`;
  if (err?.status === 0) return 'The console server could not be reached. Nothing was changed.';
  return err?.message ? `${err.message}` : 'The request failed.';
}

// A server sentence ends with a full stop before another sentence follows.
export const sentence = (t) => { const s = String(t ?? '').trim(); return !s || /[.!?]$/.test(s) ? s : `${s}.`; };

// Which settings pages this principal sees: each administration page needs
// its permission (lib/perms.js SECTION_PERMS). `can` is the principal's
// permission predicate; without one (an older caller), `me.capabilities`.
export function visibleSections(me, can = null) {
  if (typeof can !== 'function') {
    const admin = Boolean(me?.capabilities?.administer);
    return { account: ACCOUNT_SECTIONS, admin: admin ? ADMIN_SECTIONS : [] };
  }
  return { account: ACCOUNT_SECTIONS, admin: ADMIN_SECTIONS.filter((s) => can(SECTION_PERMS[s.id])) };
}

// Sections of /admin/settings by id; unknown ids land in "other".
export function groupSettings(body) {
  const byId = new Map();
  const other = [];
  for (const s of Array.isArray(body?.sections) ? body.sections : []) {
    if (!s || typeof s.id !== 'string') continue;
    if (MAPPED_SETTINGS.includes(s.id)) byId.set(s.id, s);
    else other.push(s);
  }
  return { byId, other };
}

// Count of active keys and the per-account limit, as one sentence.
export function keysLine(items, limit) {
  const active = (items || []).filter((k) => k.status === 'active').length;
  return limit ? `${active} of ${limit} active keys` : `${active} active ${active === 1 ? 'key' : 'keys'}`;
}

// ---- Editable console settings (round 6) ----------------------------------------

// The contract's allowlist: console-only values with a low blast radius.
// `posture.accepted` is managed on Posture, never through PUT.
export const EDITABLE_KEYS = Object.freeze([
  'console.session_ttl_seconds', 'console.session_idle_seconds', 'console.key_max_days', 'console.key_default_days',
  'console.sign_in_banner', 'console.organization_name', 'console.default_window', 'posture.accepted',
]);
export const isSettingKey = (v) => typeof v === 'string' && /^[a-z][a-z0-9_.]{1,80}$/.test(v);

export const SETTING_LABELS = Object.freeze({
  'console.session_ttl_seconds': 'Session lifetime',
  'console.session_idle_seconds': 'Idle timeout',
  'console.key_max_days': 'Longest API key lifetime',
  'console.key_default_days': 'Default API key lifetime',
  'console.sign_in_banner': 'Sign-in banner',
  'console.organization_name': 'Organisation name',
  'console.default_window': 'Default time window',
  'posture.accepted': 'Accepted posture risks',
});
export const settingLabel = (key, item) => (typeof item?.label === 'string' && item.label) || SETTING_LABELS[key] || key;

const WINDOW_LABEL = { '1h': '1 hour', '24h': '24 hours', '7d': '7 days' };

// Whole seconds → "8 hours", "1 hour 30 minutes", "45 seconds".
export function durationWords(sec) {
  const n = Math.floor(Number(sec));
  if (!Number.isFinite(n) || n < 0) return '—';
  if (n === 0) return '0 seconds';
  const parts = [];
  const d = Math.floor(n / 86400); const hh = Math.floor((n % 86400) / 3600); const mm = Math.floor((n % 3600) / 60); const ss = n % 60;
  const w = (v, one) => `${v} ${one}${v === 1 ? '' : 's'}`;
  if (d) parts.push(w(d, 'day'));
  if (hh) parts.push(w(hh, 'hour'));
  if (mm) parts.push(w(mm, 'minute'));
  if (ss) parts.push(w(ss, 'second'));
  return parts.slice(0, 2).join(' ');
}

const numeric = (c) => Boolean(c && (Number.isFinite(c.min) || Number.isFinite(c.max) || c.unit === 's' || c.unit === 'days'));
export const isNumericSetting = (item) => numeric(item?.constraints);

// A raw value (the server's canonical string) in words, for "from → to",
// the file value and the history.
export function formatSettingRaw(item, raw) {
  const key = item?.key || '';
  const c = item?.constraints || {};
  const s = raw === null || raw === undefined ? '' : String(raw);
  if (s === '') return 'not set';
  if (c.unit === 's' || /_seconds$/.test(key)) {
    if (!/^\d+$/.test(s)) return s;
    if (s === '0' && (c.allow_zero || key === 'console.session_idle_seconds')) return 'off';
    return durationWords(Number(s));
  }
  if (c.unit === 'days' || /_days$/.test(key)) return /^\d+$/.test(s) ? `${s} ${s === '1' ? 'day' : 'days'}` : s;
  if (key === 'console.default_window') return WINDOW_LABEL[s] || s;
  return s;
}

const fmt = (n) => Number(n).toLocaleString('en-US');

// The constraints as one help sentence.
export function constraintText(item) {
  const c = item?.constraints || {};
  if (Array.isArray(c.enum) && c.enum.length) return `One of ${c.enum.map((v) => formatSettingRaw(item, v)).join(', ')}.`;
  if (numeric(c)) {
    const unit = c.unit === 'days' ? 'days' : c.unit === 's' ? 'seconds' : '';
    const words = (v) => (c.unit === 's' ? ` (${durationWords(v)})` : '');
    const range = Number.isFinite(c.min) && Number.isFinite(c.max)
      ? `${fmt(c.min)} to ${fmt(c.max)} ${unit}`.trim() + (c.unit === 's' ? ` (${durationWords(c.min)} to ${durationWords(c.max)})` : '')
      : Number.isFinite(c.max) ? `At most ${fmt(c.max)} ${unit}${words(c.max)}` : `At least ${fmt(c.min)} ${unit}${words(c.min)}`;
    const zero = c.allow_zero ? '0 turns it off; otherwise ' : '';
    return `${zero}${zero ? range.charAt(0).toLowerCase() + range.slice(1) : range}.`;
  }
  if (Number.isFinite(c.max_len)) return `Plain text${c.multiline ? ', line breaks kept' : ''}, at most ${fmt(c.max_len)} characters. Shown as typed, never as markup.`;
  return '';
}

export const appliesText = (a) => (a === 'live' ? 'Applies at once' : a === 'restart' ? 'Applies after a restart' : a === 'none' ? 'Fixed: a built-in limit or a measured fact' : 'The server did not say when it applies');

// What a change to this key does beyond "applies at once".
export const SETTING_EFFECT = Object.freeze({
  'console.session_ttl_seconds': 'Sessions started after the change get the new lifetime; signed-in sessions keep theirs.',
  'console.session_idle_seconds': 'Every session uses the new idle timeout from its next request.',
  'console.key_max_days': 'Keys created after the change; existing keys keep their expiry.',
  'console.key_default_days': 'Preselected when a key is created. At most the longest lifetime.',
  'console.sign_in_banner': 'Shown on the sign-in page and once per session after sign-in, as plain text.',
  'console.organization_name': 'Shown in the top bar and on printed reports.',
  'console.default_window': 'The window for accounts that have not chosen their own in Preferences.',
});

// Parse an input against the item's constraints. Returns { value } (a
// number for numeric settings, a string otherwise, as the PUT body wants)
// or { error } with one sentence.
export function parseSettingInput(item, raw) {
  const c = item?.constraints || {};
  const label = settingLabel(item?.key, item);
  if (numeric(c)) {
    const t = String(raw ?? '').trim();
    if (!/^\d{1,9}$/.test(t)) return { error: `Enter ${label.toLowerCase()} as a whole number.` };
    const n = Number(t);
    if (n === 0 && c.allow_zero) return { value: 0 };
    const unit = c.unit === 'days' ? ' days' : c.unit === 's' ? ' seconds' : '';
    if ((Number.isFinite(c.min) && n < c.min) || (Number.isFinite(c.max) && n > c.max)) {
      return { error: `${label} must be ${c.allow_zero ? '0 (off) or ' : ''}${Number.isFinite(c.min) ? fmt(c.min) : '0'} to ${Number.isFinite(c.max) ? fmt(c.max) : 'any'}${unit}${c.unit === 's' && Number.isFinite(c.min) && Number.isFinite(c.max) ? ` (${durationWords(c.min)} to ${durationWords(c.max)})` : ''}.` };
    }
    return { value: n };
  }
  const v = String(raw ?? '');
  if (Array.isArray(c.enum) && c.enum.length) return c.enum.includes(v) ? { value: v } : { error: `Choose one of ${c.enum.map((x) => formatSettingRaw(item, x)).join(', ')}.` };
  const t = v.trim();
  if (Number.isFinite(c.max_len) && Array.from(t).length > c.max_len) return { error: `Keep ${label.toLowerCase()} to ${fmt(c.max_len)} characters or fewer (now ${fmt(Array.from(t).length)}).` };
  const multi = item?.constraints?.multiline === true || item?.key === 'console.sign_in_banner';
  if ((multi ? /[\u0000-\u0009\u000b-\u001f\u007f]/ : /[\u0000-\u001f\u007f]/).test(t)) return { error: 'Use printable characters only.' };
  if (/[‪-‮⁦-⁩]/.test(t)) return { error: 'Remove the text-direction control characters.' };
  return { value: t };
}

export function validateChangeReason(v) {
  const s = String(v ?? '').trim();
  if (!s) return 'Say why you are changing it. The reason is kept in the change history and the audit trail.';
  if (Array.from(s).length > 200) return 'Keep the reason to 200 characters or fewer.';
  if (/[\u0000-\u001f\u007f]/.test(s)) return 'Use printable characters only.';
  return '';
}

// Whether a setting can be changed here, and if not, why (one sentence).
// body: the /admin/settings answer; canManage: settings.manage.
export function editState(item, body, canManage) {
  if (!item || typeof item.editable !== 'boolean') return { editable: false, why: '' };
  if (item.key === 'posture.accepted') return { editable: false, why: 'posture' };
  if (body?.editing === 'off' || (body && body.editable === false && !item.editable)) return { editable: false, why: EDITABLE_KEYS.includes(item.key) ? 'off' : '' };
  if (!item.editable) return { editable: false, why: '' };
  if (!canManage) return { editable: false, why: 'permission' };
  return { editable: true, why: '' };
}

// History entries: newest first, a known shape only.
export function normalizeHistory(body) {
  const items = Array.isArray(body?.items) ? body.items : [];
  return items.filter((e) => e && isSettingKey(e.key)).map((e) => ({
    seq: Number.isInteger(e.seq) ? e.seq : null,
    key: e.key,
    from: e.from === null || e.from === undefined ? '' : String(e.from),
    to: e.to === null || e.to === undefined ? '' : String(e.to),
    actor: typeof e.actor_name === 'string' && e.actor_name ? e.actor_name : (typeof e.actor_id === 'string' ? e.actor_id : 'unknown'),
    actorId: typeof e.actor_id === 'string' ? e.actor_id : '',
    reason: typeof e.reason === 'string' ? e.reason : '',
    at: typeof e.at === 'string' ? e.at : '',
    action: e.action === 'revert' ? 'revert' : e.action === 'update' ? 'update' : '',
  })).sort((a, b) => (Date.parse(b.at) || 0) - (Date.parse(a.at) || 0) || (b.seq ?? 0) - (a.seq ?? 0));
}

// ---- Audit details (round 6) ----------------------------------------------------

// The server writes structured details as `key=value` pairs, values either
// bare (`seq=4`, `permissions=a,b`) or Go-quoted (`from="3600"`, with \" \\
// \n \t \uXXXX \xXX escapes). Returns a plain object, or null when the text
// is not in that shape (an older or free-text detail is shown as is). A
// detail cut at 256 bytes may end inside a quote: the open value is kept
// with "…".
export function parseAuditDetail(text) {
  const s = typeof text === 'string' ? text : '';
  if (!s || s.length > 4096) return null;
  const out = {};
  let i = 0;
  const unescape = { n: '\n', t: '\t', r: '\r', '"': '"', '\\': '\\', a: '\u0007', b: '\b', f: '\f', v: '\v' };
  while (i < s.length) {
    while (s[i] === ' ') i++;
    if (i >= s.length) break;
    const m = /^([a-z][a-z0-9_]{0,31})=/.exec(s.slice(i));
    if (!m) return null;
    const key = m[1];
    i += m[0].length;
    if (s[i] === '"') {
      i++;
      let v = '';
      let closed = false;
      while (i < s.length) {
        const ch = s[i];
        if (ch === '"') { closed = true; i++; break; }
        if (ch === '\\' && i + 1 < s.length) {
          const e = s[i + 1];
          if (unescape[e] !== undefined) { v += unescape[e]; i += 2; continue; }
          if (e === 'u' && /^[0-9a-fA-F]{4}$/.test(s.slice(i + 2, i + 6))) { v += String.fromCharCode(parseInt(s.slice(i + 2, i + 6), 16)); i += 6; continue; }
          if (e === 'x' && /^[0-9a-fA-F]{2}$/.test(s.slice(i + 2, i + 4))) { v += String.fromCharCode(parseInt(s.slice(i + 2, i + 4), 16)); i += 4; continue; }
          v += e; i += 2; continue;
        }
        v += ch; i++;
      }
      out[key] = closed ? v : `${v}…`;
      if (closed && i < s.length && s[i] !== ' ') return null;
    } else {
      const end = s.indexOf(' ', i);
      out[key] = s.slice(i, end < 0 ? s.length : end);
      i = end < 0 ? s.length : end;
    }
  }
  return Object.keys(out).length ? out : null;
}
