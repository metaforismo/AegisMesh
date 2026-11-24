// Permissions and roles (contract r6): the catalogue the console falls back
// to, the built-in roles' permission sets, what a principal may do, the
// role editor's rules and wording, and which screen or settings page needs
// which permission.
//
// Everything here is a convenience for drawing the interface. The server
// checks every request against the caller's current role; a 403 is always
// handled where it happens, whatever this file says.

const ID = /^[a-z]+(\.[a-z]+)+$/;
export const isPermissionId = (v) => typeof v === 'string' && v.length <= 40 && ID.test(v);
export const isRoleId = (v) => typeof v === 'string' && /^(viewer|analyst|admin|role_[0-9a-f]{12})$/.test(v);
export const BUILTIN_ROLES = Object.freeze(['viewer', 'analyst', 'admin']);

// The contract's catalogue, version 1. The server's GET /permissions wins
// when it answers; this copy labels permissions on older servers and when
// the catalogue could not be read.
export const CATALOGUE = Object.freeze([
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
export const PERMISSION_IDS = Object.freeze(CATALOGUE.map((p) => p.id));

// Built-in roles grant exactly what viewer, analyst and admin granted before
// permissions existed (the server pins every route against them).
const VIEWER = ['evidence.read', 'analysis.read', 'investigations.read', 'fleet.read', 'keys.self'];
const ANALYST = [...VIEWER, 'evidence.export', 'reports.download', 'investigations.write'];
export const BUILTIN_PERMS = Object.freeze({
  viewer: Object.freeze([...VIEWER]),
  analyst: Object.freeze([...ANALYST]),
  admin: Object.freeze([...PERMISSION_IDS]),
});

export const RISK = Object.freeze({
  low: { label: 'Low', text: 'Reads what the decoys observed or manages only your own things.' },
  elevated: { label: 'Elevated', text: 'Takes evidence out of the console, records judgement, or reads who has access.' },
  high: { label: 'High risk', text: 'Can grant access or change how the console behaves for everyone.' },
});
export const riskMeta = (r) => RISK[r] ? { key: r, ...RISK[r] } : { key: 'unknown', label: 'Unknown risk', text: 'The server did not say how risky this permission is.' };

// The catalogue as the server sent it (validated), else the built-in copy.
export function normalizeCatalogue(body) {
  const items = Array.isArray(body?.items) ? body.items : [];
  const out = [];
  for (const it of items) {
    if (!it || !isPermissionId(it.id) || out.some((x) => x.id === it.id)) continue;
    const known = CATALOGUE.find((c) => c.id === it.id);
    out.push({
      id: it.id,
      group: typeof it.group === 'string' && it.group.trim() ? it.group.trim().slice(0, 40) : (known?.group || 'Other'),
      label: typeof it.label === 'string' && it.label.trim() ? it.label.trim().slice(0, 160) : (known?.label || it.id),
      risk: RISK[it.risk] ? it.risk : (known?.risk || 'unknown'),
    });
  }
  return out.length ? out : CATALOGUE.map((c) => ({ ...c }));
}

// Groups in first-seen order, each with its permissions.
export function groupCatalogue(catalogue) {
  const groups = [];
  for (const p of catalogue) {
    let g = groups.find((x) => x.group === p.group);
    if (!g) { g = { group: p.group, items: [] }; groups.push(g); }
    g.items.push(p);
  }
  return groups;
}

// What a principal may do. `/me.permissions` (round 6) wins; an older
// server's built-in role name maps to its fixed set; anything else (a custom
// role id with no list) grants nothing in the interface.
export function permissionsOf(me, session) {
  if (Array.isArray(me?.permissions)) return new Set(me.permissions.filter(isPermissionId));
  const role = me?.role || session?.principal?.role || '';
  return new Set(BUILTIN_PERMS[role] || []);
}

// A predicate over a permission id. Accepts a Set, an array, a built-in
// role name (older call sites and tests) or a predicate.
export function toCan(x) {
  if (typeof x === 'function') return x;
  if (typeof x === 'string') return toCan(BUILTIN_PERMS[x] || []);
  const set = x instanceof Set ? x : new Set(Array.isArray(x) ? x : []);
  return (id) => !id || set.has(id);
}

// ---- Where each permission matters -----------------------------------------

// Screens (route names) and the permission they need. Unlisted screens need
// only a session (Guide, Settings).
export const ROUTE_PERMS = Object.freeze({
  overview: 'evidence.read', events: 'evidence.read', event: 'evidence.read', sources: 'evidence.read', source: 'evidence.read',
  sessions: 'evidence.read', attack_session: 'evidence.read', campaigns: 'evidence.read', campaign: 'evidence.read',
  decoys: 'evidence.read', honeytokens: 'evidence.read', sensors: 'evidence.read', rules: 'evidence.read', node: 'evidence.read',
  digest: 'analysis.read', techniques: 'analysis.read', recommendations: 'analysis.read', posture: 'analysis.read',
  investigations: 'investigations.read', investigation: 'investigations.read',
  fleet: 'fleet.read', fleet_node: 'fleet.read',
  audit: 'audit.read',
});

// Settings pages that need a permission to open.
export const SECTION_PERMS = Object.freeze({
  accounts: 'accounts.read', 'active-sessions': 'accounts.read', roles: 'accounts.read',
  sso: 'settings.read', security: 'settings.read', console: 'settings.read', data: 'settings.read', detection: 'settings.read',
  fleet: 'settings.read', exports: 'settings.read', history: 'settings.read',
  'audit-export': 'audit.export', system: 'system.read',
});

export const permissionLabel = (id, catalogue = CATALOGUE) => catalogue.find((p) => p.id === id)?.label || id;

// "Your account cannot …" — one sentence naming what is missing.
export function missingText(id, catalogue = CATALOGUE) {
  const label = permissionLabel(id, catalogue);
  return `Needs the permission “${label}” (${id}), which your role does not include.`;
}

// ---- The role editor ----------------------------------------------------------

export const ROLE_NAME_MAX = 40;
export const ROLE_DESCRIPTION_MAX = 200;
// The server's rules: a permission that changes access or settings needs
// the ones that let its holder see what they change.
export const PERMISSION_DEPS = Object.freeze({
  'roles.manage': ['accounts.manage'],
  'settings.manage': ['accounts.manage', 'settings.read'],
  'accounts.manage': ['accounts.read'],
  'sessions.manage': ['accounts.read'],
});

// Every permission `list` needs but lacks, following the rules transitively,
// in catalogue order.
export function missingDependencies(list) {
  const have = new Set(list || []);
  const need = new Set();
  const visit = (p) => { for (const d of PERMISSION_DEPS[p] || []) { if (!have.has(d) && !need.has(d)) { need.add(d); visit(d); } } };
  for (const p of [...have]) visit(p);
  return PERMISSION_IDS.filter((p) => need.has(p));
}

export function validateRoleName(v, others = []) {
  const s = String(v ?? '').trim();
  if (!s) return 'Give the role a name, for example “Incident responder”.';
  if (Array.from(s).length > ROLE_NAME_MAX) return `Keep the name to ${ROLE_NAME_MAX} characters or fewer.`;
  if (/[\u0000-\u001f\u007f‪-‮⁦-⁩]/.test(s)) return 'Use printable characters only.';
  if (others.some((n) => String(n).trim().toLowerCase() === s.toLowerCase())) return 'Another role already has this name. Names are compared without case.';
  return '';
}

export function validateRoleDescription(v) {
  const s = String(v ?? '');
  if (Array.from(s.trim()).length > ROLE_DESCRIPTION_MAX) return `Keep the description to ${ROLE_DESCRIPTION_MAX} characters or fewer.`;
  if (/[\u0000-\u0008\u000b-\u001f\u007f]/.test(s)) return 'Use printable characters only.';
  return '';
}

// The server's dependency rules, said as one sentence naming what is
// missing: nobody should change access or settings while unable to see who
// holds access or what the settings are.
export function validateRolePermissions(list) {
  const set = new Set(list || []);
  if (!set.size) return 'Choose at least one permission. A role with none could not even read evidence.';
  const missing = missingDependencies([...set]);
  if (missing.length) {
    const why = [...set].filter((p) => (PERMISSION_DEPS[p] || []).some((d) => !set.has(d)));
    const join = (xs) => (xs.length < 2 ? xs.join('') : `${xs.slice(0, -1).join(', ')} and ${xs[xs.length - 1]}`);
    return `${join(why.map((p) => `“${permissionLabel(p)}”`))} also ${why.length === 1 ? 'needs' : 'need'} ${join(missing.map((p) => `“${permissionLabel(p)}”`))}: a role that changes access or settings must be able to see what it changes.`;
  }
  return '';
}

// Added and removed permission ids, in catalogue order.
export function permissionDiff(before, after, catalogue = CATALOGUE) {
  const b = new Set(before || []);
  const a = new Set(after || []);
  const order = (x, y) => catalogue.findIndex((p) => p.id === x) - catalogue.findIndex((p) => p.id === y);
  return { added: [...a].filter((x) => !b.has(x)).sort(order), removed: [...b].filter((x) => !a.has(x)).sort(order) };
}

export const assignedTotal = (assigned) => ['managed', 'config', 'oidc'].reduce((n, k) => n + (Number.isInteger(assigned?.[k]) && assigned[k] > 0 ? assigned[k] : 0), 0);

const count = (n, one, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;

// "Adds 2, removes 1; affects 3 accounts — takes effect on their next request."
export function diffSentence(diff, affected) {
  const parts = [];
  if (diff.added.length) parts.push(`adds ${diff.added.length}`);
  if (diff.removed.length) parts.push(`removes ${diff.removed.length}`);
  const head = parts.length ? parts.join(', ') : 'changes no permissions';
  const tail = affected > 0 ? `affects ${count(affected, 'account')} — takes effect on their next request.` : 'no account holds this role yet.';
  const s = `${head}; ${tail}`;
  return s.charAt(0).toUpperCase() + s.slice(1);
}

// What a set of permissions allows and does not, in the catalogue's words.
export function roleSummary(perms, catalogue = CATALOGUE) {
  const set = new Set(perms || []);
  const can = catalogue.filter((p) => set.has(p.id));
  const cannot = catalogue.filter((p) => !set.has(p.id));
  return { can, cannot, high: can.filter((p) => p.risk === 'high'), unknown: [...set].filter((id) => !catalogue.some((p) => p.id === id)) };
}

// "7 permissions, 2 high risk" for lists and the role picker.
export function permCountLine(perms, catalogue = CATALOGUE) {
  const s = roleSummary(perms, catalogue);
  const n = s.can.length + s.unknown.length;
  return `${count(n, 'permission')}${s.high.length ? `, ${s.high.length} high risk` : ''}`;
}

// The role list's risk summary.
export function rolesRisk(roles) {
  const list = Array.isArray(roles) ? roles : [];
  const custom = list.filter((r) => !r.builtin);
  const high = custom.filter((r) => (r.permissions || []).some((p) => CATALOGUE.find((c) => c.id === p)?.risk === 'high'));
  const unused = custom.filter((r) => assignedTotal(r.assigned) === 0);
  return { custom: custom.length, high: high.length, unused: unused.length };
}

// Role refusals from the server, in words that say what to do.
export function roleRefusal(err) {
  const reason = err?.reason || '';
  if (reason === 'builtin') return 'Built-in roles cannot be changed or deleted. Duplicate it as a custom role instead.';
  if (reason === 'in_use') return `This role is still assigned (${err?.message || 'in use'}). Move those accounts to another role first.`;
  if (reason === 'last_admin') return 'This would leave nobody able to manage accounts and roles. Give another active account that access first.';
  return '';
}

// Roles by id for labels in lists (account role column, profile).
// Built-in roles are named by their id on the server ("viewer"); the
// console says them as words.
const BUILTIN_LABEL = { viewer: 'Viewer', analyst: 'Analyst', admin: 'Admin' };
export function roleNameOf(id, roles) {
  if (BUILTIN_LABEL[id]) return BUILTIN_LABEL[id];
  const r = (roles || []).find((x) => x.id === id);
  if (r?.name) return String(r.name);
  return typeof id === 'string' && id.startsWith('role_') ? 'Custom role' : 'Unknown role';
}
export const roleDisplayName = (r) => (BUILTIN_LABEL[r?.id] && r?.builtin !== false ? BUILTIN_LABEL[r.id] : String(r?.name || r?.id || 'Unknown role'));
