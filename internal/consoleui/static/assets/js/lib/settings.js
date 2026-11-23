// Settings and administration: the section registry, role and source
// explanations, validation and the wording for the server's refusals. Pure
// data and functions; the screens in screens/settings*.js draw them.
//
// Role gating here is a convenience: the server decides every request, and
// the screens handle its 401 and 403 answers whatever this file says.

export const ACCOUNT_SECTIONS = Object.freeze([
  { id: 'profile', label: 'Profile', icon: 'user', hint: 'Who you are signed in as and what your role allows' },
  { id: 'preferences', label: 'Preferences', icon: 'settings', hint: 'Time zone, default window, density, theme, motion' },
  { id: 'sessions', label: 'Sessions', icon: 'devices', hint: 'Where your account is signed in' },
  { id: 'keys', label: 'API keys', icon: 'key', hint: 'Tokens for scripts and integrations' },
]);

// Administration pages. `settings` names the /admin/settings sections a
// page renders (read-only, file-driven).
export const ADMIN_SECTIONS = Object.freeze([
  { id: 'accounts', label: 'Accounts', icon: 'users', hint: 'Configured, single sign-on and managed accounts' },
  { id: 'active-sessions', label: 'Active sessions', icon: 'devices', hint: 'Every signed-in session on this server' },
  { id: 'sso', label: 'Single sign-on', icon: 'sign-in', hint: 'OpenID Connect, read-only', settings: ['sso'] },
  { id: 'security', label: 'Security and access', icon: 'shield', hint: 'Sign-in, sessions, listener, tenants', settings: ['access', 'listener', 'tenants'] },
  { id: 'data', label: 'Data and retention', icon: 'database', hint: 'Evidence storage, encryption, index', settings: ['evidence'] },
  { id: 'detection', label: 'Detection', icon: 'rules', hint: 'Rules, correlation, actions mode', settings: ['detection'] },
  { id: 'fleet', label: 'Fleet', icon: 'fleet', hint: 'Hub and agent roles', settings: ['fleet'] },
  { id: 'exports', label: 'Exports', icon: 'download', hint: 'File formats and limits', settings: ['exports'] },
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
});
export const settingSourceMeta = (s) => SETTING_SOURCES[s] || { label: 'Unknown source', hint: 'The server did not say where this value comes from' };

// A component's health on System.
export const HEALTH = Object.freeze({
  ok: { badge: 'ok', label: 'Working' },
  degraded: { badge: 'warn', label: 'Degraded' },
  off: { badge: 'neutral', label: 'Off' },
});
export const healthMeta = (s) => HEALTH[s] || { badge: 'neutral', label: 'Unknown' };
export const COMPONENT_LABEL = Object.freeze({ console: 'Console', storage: 'Evidence storage', index: 'Event index', sensors: 'Sensors', fleet: 'Fleet', oidc: 'Single sign-on' });

// API key lifetimes offered in the create form (the server allows 1..365).
export const EXPIRY_PRESETS = Object.freeze([30, 90, 180, 365]);
export const EXPIRY_DEFAULT = 90;
export const expiryLabel = (d) => (d === 365 ? '1 year' : `${d} days`);

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

// Which settings pages this principal sees. `me` may be null (older server).
export function visibleSections(me) {
  const admin = Boolean(me?.capabilities?.administer);
  return { account: ACCOUNT_SECTIONS, admin: admin ? ADMIN_SECTIONS : [] };
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
