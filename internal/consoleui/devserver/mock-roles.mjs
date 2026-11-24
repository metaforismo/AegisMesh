// Mock twin of contract r6: the permission catalogue, custom roles, the
// editable console settings overlay with its change history, and accepted
// risk on posture checks.
//
// A fixture: not embedded, never shipped. Synthetic data only. The config
// file is never written (there is none): the overlay lives in this process.

import { randomBytes } from 'node:crypto';

const iso = (ms) => new Date(ms).toISOString().replace(/\.\d+Z$/, 'Z');

// ---- Permission catalogue (version 1) -------------------------------------------

export const PERMISSIONS = Object.freeze([
  { id: 'evidence.read', group: 'Evidence', label: 'Read events, sources, sessions, campaigns, decoys, honeytokens and rules', risk: 'low' },
  { id: 'analysis.read', group: 'Evidence', label: 'Read the digest, posture, coverage and techniques', risk: 'low' },
  { id: 'evidence.export', group: 'Evidence', label: 'Download event and indicator exports', risk: 'elevated' },
  { id: 'reports.download', group: 'Evidence', label: 'Download session and investigation reports', risk: 'elevated' },
  { id: 'investigations.read', group: 'Investigations', label: 'Read investigations and their notes', risk: 'low' },
  { id: 'investigations.write', group: 'Investigations', label: 'Open, update and annotate investigations, attach evidence', risk: 'elevated' },
  { id: 'audit.read', group: 'Audit', label: 'Read and verify the audit trail', risk: 'elevated' },
  { id: 'audit.export', group: 'Audit', label: 'Export the audit trail as a file', risk: 'elevated' },
  { id: 'fleet.read', group: 'Fleet', label: 'Read fleet nodes and their status', risk: 'low' },
  { id: 'fleet.manage', group: 'Fleet', label: 'Enroll and revoke fleet nodes, manage enrollment tokens', risk: 'high' },
  { id: 'accounts.read', group: 'Access', label: 'Read accounts, roles and every signed-in session', risk: 'elevated' },
  { id: 'accounts.manage', group: 'Access', label: 'Create and change managed accounts and their API keys', risk: 'high' },
  { id: 'roles.manage', group: 'Access', label: 'Create, change and delete custom roles', risk: 'high' },
  { id: 'sessions.manage', group: 'Access', label: 'Sign out any account’s sessions', risk: 'high' },
  { id: 'keys.self', group: 'Access', label: 'Create and revoke your own API keys', risk: 'low' },
  { id: 'settings.read', group: 'Settings and system', label: 'Read the server’s effective settings and their change history', risk: 'elevated' },
  { id: 'settings.manage', group: 'Settings and system', label: 'Change console settings and accept posture risk', risk: 'high' },
  { id: 'system.read', group: 'Settings and system', label: 'Read the version and component health', risk: 'low' },
].map(Object.freeze));
export const PERMISSION_IDS = Object.freeze(PERMISSIONS.map((p) => p.id));

const VIEWER = ['evidence.read', 'analysis.read', 'investigations.read', 'fleet.read', 'keys.self'];
const ANALYST = [...VIEWER, 'evidence.export', 'reports.download', 'investigations.write'];
export const BUILTIN = Object.freeze({
  viewer: Object.freeze([...VIEWER].sort()),
  analyst: Object.freeze([...ANALYST].sort()),
  admin: Object.freeze([...PERMISSION_IDS].sort()),
});
const BUILTIN_META = {
  viewer: { name: 'viewer', description: 'Reads everything the decoys observed. Changes nothing.' },
  analyst: { name: 'analyst', description: 'Everything a viewer can, plus recording judgement and taking evidence out.' },
  admin: { name: 'admin', description: 'Everything, including access management, settings and the audit trail.' },
};
export const MAX_ROLES = 32;
export const PERMISSION_DEPS = Object.freeze({ 'roles.manage': ['accounts.manage'], 'settings.manage': ['accounts.manage', 'settings.read'], 'accounts.manage': ['accounts.read'], 'sessions.manage': ['accounts.read'] });
const ROLE_ID = /^(viewer|analyst|admin|role_[0-9a-f]{12})$/;
export const isRoleId = (v) => typeof v === 'string' && ROLE_ID.test(v);

// The two permissions that together keep the server administrable.
export const holdsAdmin = (perms) => perms.includes('roles.manage') && perms.includes('accounts.manage');

// Would a change leave no active principal holding roles.manage and
// accounts.manage? `principals`: [{ id, active, role }]; `change` may
// replace one principal's role or status, and/or one role's permissions.
export function wouldLeaveNoAdmin(principals, permsOfRole, { principalId, role, active, roleId, permissions } = {}) {
  const permsAfter = (r) => (roleId && r === roleId ? permissions : permsOfRole(r));
  const holders = principals.filter((p) => {
    const merged = p.id === principalId ? { ...p, ...(role !== undefined ? { role } : {}), ...(active !== undefined ? { active } : {}) } : p;
    return merged.active && holdsAdmin(permsAfter(merged.role) || []);
  });
  return holders.length === 0;
}

// Role body validation shared by POST and PATCH. Returns an error object
// { status, code, reason?, message } or null.
export function checkRoleBody(b, { partial = false } = {}) {
  const bad = (message, reason) => ({ status: 400, code: 'invalid_argument', ...(reason ? { reason } : {}), message });
  if (!partial || b.name !== undefined) {
    if (typeof b.name !== 'string') return bad('name is required');
    const n = b.name.trim();
    if (Array.from(n).length < 1 || Array.from(n).length > 40) return bad('name must be 1 to 40 characters');
    if (/[\u0000-\u001f\u007f]/.test(n)) return bad('name must be printable');
  }
  if (b.description !== undefined && (typeof b.description !== 'string' || Array.from(b.description).length > 200 || /[\u0000-\u0008\u000b-\u001f\u007f]/.test(b.description))) {
    return bad('description must be at most 200 printable characters');
  }
  if (!partial || b.permissions !== undefined) {
    if (!Array.isArray(b.permissions) || !b.permissions.length) return bad('permissions must list at least one permission id');
    const unknown = b.permissions.filter((p) => !PERMISSION_IDS.includes(p));
    if (unknown.length) return bad(`unknown permission ${JSON.stringify(String(unknown[0])).slice(0, 60)}`);
    if (new Set(b.permissions).size !== b.permissions.length) return bad('permissions must not repeat');
    // Like the server: a permission that changes access or settings needs
    // the ones that let its holder see what they change.
    for (const [p, needs] of Object.entries(PERMISSION_DEPS)) {
      const miss = needs.filter((n) => !b.permissions.includes(n));
      if (b.permissions.includes(p) && miss.length) return bad(`${p} requires ${miss.join(' and ')}`);
    }
  }
  return null;
}

// ---- Roles ---------------------------------------------------------------------

export const SEED_ROLE_IDS = Object.freeze({ ticket: 'role_7c1e5a90b3d4', auditor: 'role_2b8f04c6e1a7', fleet: 'role_e4d93a1f6c20' });

export function createRoles({ startedAt = Date.now(), round6 = true } = {}) {
  const roles = new Map();
  for (const id of ['viewer', 'analyst', 'admin']) {
    roles.set(id, { id, ...BUILTIN_META[id], builtin: true, permissions: [...BUILTIN[id]], created_at: null, created_by: 'builtin', updated_at: null });
  }
  const day = 86400e3;
  if (round6) {
    const seed = (id, name, description, permissions, ago, by = 'ada') => roles.set(id, {
      id, name, description, builtin: false, permissions: [...permissions].sort(), created_at: iso(startedAt - ago * day), created_by: by, updated_at: iso(startedAt - Math.max(1, ago - 3) * day),
    });
    seed(SEED_ROLE_IDS.ticket, 'Ticket bridge', 'For the ticketing integration: reads evidence and keeps investigations in step with tickets.', ['evidence.read', 'investigations.read', 'investigations.write'], 40);
    seed(SEED_ROLE_IDS.auditor, 'Auditor', 'Quarterly access review: reads the audit trail, accounts and settings, and exports the chain. Changes nothing.', ['evidence.read', 'analysis.read', 'audit.read', 'audit.export', 'accounts.read', 'settings.read', 'system.read'], 18);
    seed(SEED_ROLE_IDS.fleet, 'Fleet operator', 'Enrolls and retires sensor nodes. No access management.', ['evidence.read', 'analysis.read', 'fleet.read', 'fleet.manage'], 6);
  }
  const permsOf = (id) => roles.get(id)?.permissions || [];
  return { roles, permsOf, exists: (id) => roles.has(id), nameOf: (id) => roles.get(id)?.name || '' };
}

// ---- Settings overlay --------------------------------------------------------------

// Seconds → "8h", "12h 30m", "30m", "off" for 0.
export function formatSeconds(n) {
  const s = Number(n);
  if (!Number.isFinite(s)) return String(n);
  if (s === 0) return 'off';
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  const r = s % 60;
  return [h ? `${h}h` : '', m ? `${m}m` : '', r ? `${r}s` : ''].filter(Boolean).join(' ');
}
const plDays = (n) => `${n} ${Number(n) === 1 ? 'day' : 'days'}`;

const BANNER = 'Authorised operators only. Every action in this console is recorded in the audit trail. Report suspected misuse to soc@example.com.';

// The editable allowlist: file value, constraints, display and where the
// item sits in /admin/settings.
export const EDITABLE = Object.freeze({
  'console.session_ttl_seconds': { section: 'access', label: 'Session lifetime', kind: 'duration', file: 28800, numeric: true, constraints: { min: 900, max: 86400, unit: 's' }, show: formatSeconds, note: 'Applies to sessions started after the change.' },
  'console.session_idle_seconds': { section: 'access', label: 'Idle timeout', kind: 'duration', file: 1800, numeric: true, constraints: { min: 300, max: 86400, unit: 's', allow_zero: true }, show: formatSeconds, note: '0 turns the idle timeout off; otherwise 5 minutes to 24 hours.' },
  'console.organization_name': { section: 'console', label: 'Organisation name', kind: 'text', file: 'Example SOC', constraints: { max_len: 80 }, show: (v) => v || 'not set', note: 'Shown in the top bar and on report headers.' },
  'console.sign_in_banner': { section: 'console', label: 'Sign-in banner', kind: 'text', file: BANNER, constraints: { max_len: 500 }, show: (v) => v || 'not set', note: 'Plain text, shown on the sign-in page and once per session after sign-in.' },
  'console.default_window': { section: 'console', label: 'Default time window', kind: 'enum', file: '24h', constraints: { enum: ['1h', '24h', '7d'] }, show: (v) => ({ '1h': '1 hour', '24h': '24 hours', '7d': '7 days' }[v] || v), note: 'The default for accounts that have not chosen their own.' },
  'console.key_max_days': { section: 'access', label: 'Longest API key lifetime', kind: 'count', file: 365, numeric: true, constraints: { min: 1, max: 365, unit: 'days' }, show: plDays, note: 'Applies to keys created after the change; existing keys keep their expiry.' },
  'console.key_default_days': { section: 'access', label: 'Default API key lifetime', kind: 'count', file: 90, numeric: true, constraints: { min: 1, max: 365, unit: 'days' }, show: plDays, note: 'Preselected when a key is created. At most the longest lifetime.' },
});
export const EDITABLE_KEYS = Object.freeze(Object.keys(EDITABLE));

export function createSettingsOverlay({ editing = true, round6 = true, startedAt = Date.now() } = {}) {
  const day = 86400e3;
  const values = new Map(); // key → overridden raw value
  const history = [];
  let seq = 0;
  const on = round6 && editing;
  const push = (e) => { history.unshift({ seq: ++seq, ...e }); if (history.length > 200) history.length = 200; };
  if (round6) {
    const ada = { actor_id: 'cfg:ada', actor_name: 'ada' };
    push({ key: 'console.key_default_days', from: '90', to: '30', reason: 'Shorter default lifetime for the pilot integrations.', at: iso(startedAt - 20 * day), action: 'update', ...ada });
    push({ key: 'console.key_default_days', from: '30', to: '90', reason: 'Pilot over; back to the file value.', at: iso(startedAt - 12 * day), action: 'revert', ...ada });
    push({ key: 'console.default_window', from: '24h', to: '7d', reason: 'Trying a weekly default for the morning review.', at: iso(startedAt - 9 * day), action: 'update', ...ada });
    push({ key: 'console.default_window', from: '7d', to: '24h', reason: 'Analysts preferred the shorter window.', at: iso(startedAt - 8 * day), action: 'revert', ...ada });
    push({ key: 'console.session_ttl_seconds', from: '28800', to: '43200', reason: 'Night shift works 12-hour rotations; avoid sign-outs mid-shift.', at: iso(startedAt - 3 * day), action: 'update', ...ada });
    values.set('console.session_ttl_seconds', 43200);
  }

  const effective = (key) => (values.has(key) ? values.get(key) : EDITABLE[key]?.file);

  // An item as /admin/settings shows it.
  function item(key) {
    const d = EDITABLE[key];
    const eff = effective(key);
    return {
      key, label: d.label, value: d.show(eff), kind: d.kind === 'enum' ? 'text' : d.kind, source: values.has(key) ? 'console' : 'config',
      note: d.note, editable: on, effective: String(eff), file_value: String(d.file), overridden: values.has(key),
      constraints: { ...d.constraints, ...(d.numeric || d.constraints.enum ? {} : { multiline: key === 'console.sign_in_banner' }), reason_max_len: 200 }, applies: 'live',
    };
  }

  // Validate a PUT value; returns { value } or { error }.
  function parse(key, raw) {
    const d = EDITABLE[key];
    const c = d.constraints;
    if (d.numeric) {
      const n = typeof raw === 'number' ? raw : (typeof raw === 'string' && /^\d{1,9}$/.test(raw.trim()) ? Number(raw.trim()) : NaN);
      if (!Number.isInteger(n)) return { error: `${d.label} must be a whole number` };
      const unit = c.unit === 'days' ? ' days' : ' seconds';
      if (key === 'console.session_idle_seconds') {
        if (n !== 0 && (n < c.min || n > c.max)) return { error: `${d.label} must be 0 (off) or ${c.min} to ${c.max} seconds` };
        return { value: n };
      }
      const max = key === 'console.key_default_days' ? Math.min(c.max, Number(effective('console.key_max_days'))) : c.max;
      if (n < c.min || n > max) return { error: `${d.label} must be ${c.min} to ${max}${unit}${key === 'console.key_default_days' ? ' (at most the longest lifetime)' : ''}` };
      if (key === 'console.key_max_days' && n < Number(effective('console.key_default_days'))) {
        return { error: `the longest lifetime cannot be shorter than the default lifetime (${effective('console.key_default_days')} days); lower the default first` };
      }
      return { value: n };
    }
    if (typeof raw !== 'string') return { error: `${d.label} must be text` };
    const v = raw.trim();
    if (c.enum) return c.enum.includes(v) ? { value: v } : { error: `${d.label} must be one of ${c.enum.join(', ')}` };
    if (Array.from(v).length > c.max_len) return { error: `${d.label} must be at most ${c.max_len} characters` };
    const ctrl = key === 'console.sign_in_banner' ? /[\u0000-\u0009\u000b-\u001f\u007f]/ : /[\u0000-\u001f\u007f]/;
    if (ctrl.test(v)) return { error: `${d.label} must be plain printable text` };
    if (/[‪-‮⁦-⁩]/.test(v)) return { error: `${d.label} must not contain direction overrides` };
    return { value: v };
  }

  function set(key, value, { reason, actor }) {
    const from = String(effective(key));
    const fileValue = EDITABLE[key].file;
    if (value === fileValue) values.delete(key); else values.set(key, value);
    push({ key, from, to: String(value), reason, at: iso(Date.now()), action: 'update', actor_id: actor.id, actor_name: actor.name });
    return { from, to: String(value) };
  }

  function revert(key, { reason, actor }) {
    const from = String(effective(key));
    values.delete(key);
    const to = String(EDITABLE[key].file);
    push({ key, from, to, reason, at: iso(Date.now()), action: 'revert', actor_id: actor.id, actor_name: actor.name });
    return { from, to };
  }

  return {
    editing: on,
    round6,
    effective,
    item,
    parse,
    set,
    revert,
    history: (key) => history.filter((e) => !key || e.key === key),
    lastSeq: () => seq,
    // Posture acceptances are recorded in the same history (key posture.accepted).
    record: (e) => push({ ...e, at: iso(Date.now()) }),
    meta: () => ({ organization_name: String(effective('console.organization_name') || ''), sign_in_banner: String(effective('console.sign_in_banner') || '') }),
    keyLimits: () => ({ max_key_days: Number(effective('console.key_max_days')), default_key_days: Number(effective('console.key_default_days')) }),
    defaultWindow: () => String(effective('console.default_window')),
    sessionTtl: () => Number(effective('console.session_ttl_seconds')),
  };
}

// ---- Posture: accepted risk ------------------------------------------------------------

export const MAX_ACCEPT_DAYS = 180;
const RFC3339_UTC = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$/;

export function createAcceptance({ startedAt = Date.now(), round6 = true } = {}) {
  const accepted = new Map(); // check id → { by, reason, until }
  if (round6) {
    accepted.set('POS-004', {
      by: 'cfg:ada', by_name: 'ada',
      reason: 'Credentials for the AI-service decoys ship with the December rollout; until then a replayed key cannot happen there.',
      until: iso(startedAt + 60 * 86400e3),
    });
  }
  const live = (id, now = Date.now()) => {
    const a = accepted.get(id);
    if (a && Date.parse(a.until) <= now) { accepted.delete(id); return null; }
    return a || null;
  };

  // Decorate a posture body: accepted attention items report "accepted".
  function decorate(body) {
    if (!round6) return body;
    const checks = body.checks.map((c) => {
      const a = c.status === 'attention' ? live(c.id) : null;
      if (c.status !== 'attention' && accepted.has(c.id)) accepted.delete(c.id);
      return a ? { ...c, status: 'accepted', accepted: { ...a } } : { ...c, accepted: null };
    });
    const summary = { attention: 0, accepted: 0, ok: 0, info: 0 };
    for (const c of checks) summary[c.status]++;
    return { ...body, summary, checks };
  }

  function validate(b, now = Date.now()) {
    const reason = typeof b.reason === 'string' ? b.reason.trim() : '';
    if (!reason || Array.from(reason).length > 200) return { error: 'reason is required, at most 200 characters' };
    if (/[\u0000-\u001f\u007f]/.test(reason)) return { error: 'reason must be printable' };
    if (typeof b.until !== 'string' || !RFC3339_UTC.test(b.until) || Number.isNaN(Date.parse(b.until))) return { error: 'until must be an RFC 3339 UTC time' };
    const t = Date.parse(b.until);
    if (t <= now) return { error: 'until must be in the future' };
    if (t > now + MAX_ACCEPT_DAYS * 86400e3 + 60e3) return { error: `until must be at most ${MAX_ACCEPT_DAYS} days ahead` };
    return { reason, until: iso(t) };
  }

  return {
    decorate,
    validate,
    accept: (id, by, v, byName = by) => accepted.set(id, { by, by_name: byName, reason: v.reason, until: v.until }),
    revoke: (id) => accepted.delete(id),
    count: () => [...accepted.keys()].filter((id) => live(id)).length,
  };
}

export const newRoleId = () => `role_${randomBytes(6).toString('hex')}`;
