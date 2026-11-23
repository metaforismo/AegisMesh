// Mock twin of contract r5: accounts, access and settings.
//
// Configured operators (the mock's dev tokens) are read-only `config`
// accounts; OIDC identities appear as `oidc` accounts once they sign in;
// managed accounts live only in this process and sign in with API keys
// (`amk_` + 43 base64url characters, kept here as a SHA-256 digest only).
// Synthetic data only: documentation-range addresses, `.example` names,
// keys that are obviously fake and valid nowhere else.

import { createHash, createHmac, randomBytes } from 'node:crypto';

const ROLES = ['viewer', 'analyst', 'admin'];
const KINDS = ['person', 'service'];
export const PREF_VALUES = Object.freeze({
  timezone: ['utc', 'local'],
  default_window: ['1h', '24h', '7d'],
  density: ['comfortable', 'compact'],
  theme: ['system', 'dark', 'light'],
  reduce_motion: ['system', 'on'],
});
export const PREF_DEFAULTS = Object.freeze({ timezone: 'utc', default_window: '24h', density: 'comfortable', theme: 'system', reduce_motion: 'system' });
const KEY_TOKEN = /^amk_[A-Za-z0-9_-]{43}$/;
const ACCOUNT_ID = /^(acc_[a-z0-9]{4,64}|cfg:[A-Za-z0-9_.@-]{1,64}|oidc:[0-9a-f]{12})$/;
const LIMITS = Object.freeze({ max_accounts: 200, max_keys_per_account: 10, max_key_days: 365, default_key_days: 90 });

const iso = (ms) => new Date(ms).toISOString().replace(/\.\d+Z$/, 'Z');
const digest = (token) => createHash('sha256').update(token).digest('hex');
export const oidcAccountId = (sub) => `oidc:${createHash('sha256').update(String(sub)).digest('hex').slice(0, 12)}`;

// The fixed client vocabulary the contract describes: a family derived from
// the User-Agent, never the raw header.
export function clientFamily(ua) {
  const s = String(ua || '');
  if (/^curl\//i.test(s)) return 'curl';
  if (/node|undici/i.test(s) && !/Mozilla/.test(s)) return 'Script';
  const browser = /Firefox\//.test(s) ? 'Firefox' : /Edg\//.test(s) ? 'Edge' : /Chrome\//.test(s) ? 'Chrome' : /Safari\//.test(s) ? 'Safari' : '';
  const os = /iPhone|iPad/.test(s) ? 'iOS' : /Android/.test(s) ? 'Android' : /Mac OS X|Macintosh/.test(s) ? 'macOS' : /Windows/.test(s) ? 'Windows' : /Linux/.test(s) ? 'Linux' : '';
  if (!browser) return 'Unknown client';
  return os ? `${browser} on ${os}` : browser;
}

export function createAccounts({ tenants, localTenant, configured, tokenLogin = true, startedAt = Date.now() }) {
  const secret = randomBytes(32);
  const handleOf = (sid) => `ses_${createHmac('sha256', secret).update(sid).digest('hex').slice(0, 16)}`;
  const accounts = new Map();
  const keys = new Map();
  const prefs = new Map();
  const T0 = startedAt;
  const day = 86400e3;
  const second = tenants[1] || localTenant;

  const put = (a) => { accounts.set(a.id, { status: 'active', last_seen_at: null, created_by: '', updated_at: a.created_at ?? null, ...a }); return accounts.get(a.id); };
  // Configured operators: the break-glass path, read-only here.
  for (const [, p] of configured) {
    put({ id: `cfg:${p.name}`, name: p.name, kind: 'person', source: 'config', role: p.role, tenants: [...p.tenants], created_at: null, created_by: 'config file' });
  }
  // OIDC users who signed in before (synthetic).
  put({ id: oidcAccountId('00u1grace-synthetic-41aa'), name: 'grace@example.test', kind: 'person', source: 'oidc', role: 'analyst', tenants: [localTenant], created_at: iso(T0 - 21 * day), created_by: 'first sign-in', last_seen_at: iso(T0 - 2 * day) });
  put({ id: oidcAccountId('00u1lin-synthetic-08cd'), name: 'lin@example.test', kind: 'person', source: 'oidc', role: 'viewer', tenants: [localTenant], created_at: iso(T0 - 9 * day), created_by: 'first sign-in', last_seen_at: iso(T0 - 6 * 3600e3) });
  // Managed accounts: created in the console, keys only.
  put({ id: 'acc_7k2m9q4wz1', name: 'morgan@soc.example', kind: 'person', source: 'managed', role: 'analyst', tenants: [localTenant], created_at: iso(T0 - 30 * day), created_by: 'ada', last_seen_at: iso(T0 - 50 * 60e3) });
  put({ id: 'acc_3p8x1d6vt4', name: 'siem-pull', kind: 'service', source: 'managed', role: 'viewer', tenants: [localTenant, second].filter((v, i, a) => a.indexOf(v) === i), created_at: iso(T0 - 64 * day), created_by: 'ada', last_seen_at: iso(T0 - 4 * 60e3) });
  put({ id: 'acc_9c4n2h7rb5', name: 'ticket-bridge', kind: 'service', source: 'managed', role: 'analyst', tenants: [localTenant], created_at: iso(T0 - 120 * day), created_by: 'ada', last_seen_at: iso(T0 - 19 * day) });
  put({ id: 'acc_5w1j8f3ky2', name: 'former-contractor@soc.example', kind: 'person', source: 'managed', role: 'viewer', tenants: [localTenant], status: 'disabled', created_at: iso(T0 - 200 * day), created_by: 'ada', last_seen_at: iso(T0 - 75 * day) });

  // Keys: digests only. The seeded ones have no known token.
  let keySeq = 0;
  const seedKey = (accountId, label, { created, expires, used = null, revoked = null, by = 'ada' }) => {
    const id = `key_${createHash('sha256').update(`${accountId}${label}${keySeq++}`).digest('hex').slice(0, 12)}`;
    keys.set(id, { id, account_id: accountId, label, prefix: `amk_${createHash('sha256').update(id).digest('base64url').slice(0, 4)}`, digest: digest(id), created_at: iso(created), created_by: by, expires_at: iso(expires), last_used_at: used === null ? null : iso(used), revoked_at: revoked === null ? null : iso(revoked) });
  };
  seedKey('acc_3p8x1d6vt4', 'splunk-hf-01.example', { created: T0 - 40 * day, expires: T0 + 50 * day, used: T0 - 4 * 60e3 });
  seedKey('acc_3p8x1d6vt4', 'old collector', { created: T0 - 64 * day, expires: T0 + 26 * day, used: T0 - 41 * day, revoked: T0 - 40 * day });
  seedKey('acc_9c4n2h7rb5', 'ticketing (2026 H1)', { created: T0 - 120 * day, expires: T0 - 30 * day, used: T0 - 31 * day });
  seedKey('acc_9c4n2h7rb5', 'ticketing (2026 H2)', { created: T0 - 20 * day, expires: T0 + 160 * day, used: T0 - 19 * day });
  seedKey('acc_7k2m9q4wz1', 'laptop cli', { created: T0 - 30 * day, expires: T0 + 60 * day, used: T0 - 50 * 60e3, by: 'ada' });
  seedKey('cfg:ada', 'ci smoke test', { created: T0 - 12 * day, expires: T0 + 78 * day, used: T0 - 3 * day, by: 'ada' });
  seedKey('cfg:ana', 'jupyter notebook', { created: T0 - 5 * day, expires: T0 + 25 * day, used: null, by: 'ana' });

  // Sessions of other accounts, so the admin list shows more than you.
  const synthetic = [
    { handle: 'ses_4f1c9a20b7d3e815', account_id: 'acc_7k2m9q4wz1', auth_method: 'token', tenant: localTenant, created_at: iso(T0 - 3 * 3600e3), last_seen_at: iso(T0 - 6 * 60e3), expires_at: iso(T0 + 5 * 3600e3), idle: true, remote: '198.51.100.23', client: 'Firefox on Linux' },
    { handle: 'ses_a07e33c51d9b2f64', account_id: oidcAccountId('00u1lin-synthetic-08cd'), auth_method: 'oidc', tenant: localTenant, created_at: iso(T0 - 7 * 3600e3), last_seen_at: iso(T0 - 6 * 3600e3), expires_at: iso(T0 + 1 * 3600e3), idle_expires_at: null, remote: '2001:db8::4c', client: 'Safari on iOS' },
    { handle: 'ses_0b6d2e9f7a14c358', account_id: 'cfg:ada', auth_method: 'token', tenant: localTenant, created_at: iso(T0 - 26 * 3600e3), last_seen_at: iso(T0 - 22 * 3600e3), expires_at: iso(T0 + 2 * 3600e3), idle_expires_at: null, remote: '192.0.2.10', client: 'Chrome on Windows' },
  ];

  const keyStatus = (k, now = Date.now()) => (k.revoked_at ? 'revoked' : Date.parse(k.expires_at) <= now ? 'expired' : 'active');
  const publicKey = (k) => {
    const { digest: _d, account_id: _a, ...rest } = k;
    return { ...rest, status: keyStatus(k) };
  };
  const keysOf = (id) => [...keys.values()].filter((k) => k.account_id === id).sort((a, b) => Date.parse(b.created_at) - Date.parse(a.created_at));

  function liveSessions(sessionsMap) {
    const out = [];
    for (const [sid, s] of sessionsMap) {
      if (Date.parse(s.expires_at) < Date.now()) continue;
      out.push({ sid, s, view: {
        handle: handleOf(sid), current: false, auth_method: s.auth_method, tenant: s.tenant,
        created_at: s.created_at, last_seen_at: s.last_seen_at || s.created_at, expires_at: s.expires_at,
        idle_expires_at: s.last_seen_at ? iso(Date.parse(s.last_seen_at) + 1800e3) : null,
        remote: s.remote || '127.0.0.1', client: s.client || 'Unknown client',
      }, account_id: s.account_id });
    }
    for (const x of synthetic) {
      const { account_id, idle, ...view } = x;
      // An idle deadline stays ahead of now while the mock runs.
      const idleAt = idle ? iso(Math.max(Date.parse(view.last_seen_at) + 1800e3, Date.now() + 20 * 60e3)) : null;
      out.push({ sid: null, view: { current: false, ...view, idle_expires_at: idleAt }, account_id });
    }
    return out;
  }
  const withAccount = (x, current) => ({ ...x.view, current: x.view.handle === current, account_id: x.account_id, account_name: accounts.get(x.account_id)?.name || 'unknown' });
  const activeSessionsOf = (sessionsMap, id) => liveSessions(sessionsMap).filter((x) => x.account_id === id).length;

  // Like the server: a configured operator reads "disabled" while token
  // sign-in is off; only managed accounts are editable.
  const publicAccount = (a, sessionsMap) => ({
    id: a.id, name: a.name, kind: a.kind, source: a.source, role: a.role, tenants: [...a.tenants],
    status: a.source === 'config' && !tokenLogin ? 'disabled' : a.status,
    created_at: a.created_at, created_by: a.created_by, updated_at: a.updated_at ?? null, last_seen_at: a.last_seen_at,
    editable: a.source === 'managed',
    active_keys: keysOf(a.id).filter((k) => keyStatus(k) === 'active').length,
    active_sessions: activeSessionsOf(sessionsMap, a.id),
  });

  function mintKey(accountId, label, days, by) {
    const token = `amk_${randomBytes(32).toString('base64url').slice(0, 43)}`;
    const id = `key_${randomBytes(6).toString('hex')}`;
    const now = Date.now();
    const k = { id, account_id: accountId, label, prefix: token.slice(0, 8), digest: digest(token), created_at: iso(now), created_by: by, expires_at: iso(now + days * day), last_used_at: null, revoked_at: null };
    keys.set(id, k);
    return { key: publicKey(k), token };
  }

  // Key sign-in (POST /session with an amk_ token). Returns the principal
  // fields for a new cookie session, or null.
  function principalForKey(token) {
    if (!KEY_TOKEN.test(String(token))) return null;
    const d = digest(token);
    const k = [...keys.values()].find((x) => x.digest === d);
    if (!k || keyStatus(k) !== 'active' || !tokenLogin) return null; // token sign-in off disables keys too
    const a = accounts.get(k.account_id);
    if (!a || a.status !== 'active') return null;
    k.last_used_at = iso(Date.now());
    a.last_seen_at = k.last_used_at;
    return { name: a.name, role: a.role, tenants: a.tenants.filter((t) => tenants.includes(t)), account_id: a.id };
  }

  // OIDC sign-in upserts an `oidc` account.
  function touchOidc(sub, name, role, ts) {
    const id = oidcAccountId(sub);
    const now = iso(Date.now());
    const prev = accounts.get(id);
    put({ ...(prev || { created_at: now, created_by: 'first sign-in' }), id, name, kind: 'person', source: 'oidc', role, tenants: [...ts], last_seen_at: now });
    return id;
  }

  const capabilitiesOf = (a) => ({
    // Viewers in this mock cannot manage their own keys, to exercise the
    // 403 path; OIDC identities neither (the provider owns them).
    manage_own_keys: a.source !== 'oidc' && a.role !== 'viewer',
    administer: a.role === 'admin',
  });

  const validName = (v) => typeof v === 'string' && v.trim().length >= 1 && v.length <= 64 && /^[\p{L}\p{N} ._@()-]+$/u.test(v);
  const validLabel = (v) => typeof v === 'string' && v.trim().length >= 1 && v.length <= 64 && !/[\u0000-\u001f\u007f]/.test(v);
  const activeAdmins = (except, patch = {}) => [...accounts.values()].filter((a) => {
    const merged = a.id === except ? { ...a, ...patch } : a;
    return merged.status === 'active' && merged.role === 'admin';
  }).length;

  function settingsBody(ctx) {
    const it = (key, label, value, kind, source, note) => ({ key, label, value, kind, source, editable: false, note });
    const file = 'Change in the config file and restart.';
    return {
      generated_at: iso(Date.now()),
      editable: false,
      note: 'Read-only. Change the config file (or the environment where marked) and restart',
      sections: [
        { id: 'access', title: 'Access and sessions', items: [
          it('console.token_login', 'Operator token sign-in', ctx.tokenAuth ? 'enabled' : 'disabled', 'bool', 'default', file),
          it('console.session_ttl_seconds', 'Session lifetime', '8h', 'duration', 'config', file),
          it('console.session_idle_seconds', 'Idle timeout', '30m', 'duration', 'default', 'Set 0 to turn it off, or 5m to 24h. Change in the config file and restart.'),
          it('console.login_throttle', 'Sign-in throttling', '10 failures per 5m per address', 'text', 'default', 'Fixed in this release.'),
          it('console.operators', 'Configured operators', String(configured.size), 'count', 'config', 'Break-glass accounts. Edit the config file; they cannot be changed in the console.'),
        ] },
        { id: 'sso', title: 'Single sign-on', items: [
          it('console.oidc.enabled', 'OpenID Connect', ctx.oidc ? 'enabled' : 'disabled', 'bool', ctx.oidc ? 'config' : 'default', file),
          ...(ctx.oidc ? [
            it('console.oidc.issuer', 'Issuer host', 'idp.example', 'text', 'config', file),
            it('console.oidc.discovery', 'Provider discovery', 'cached 12m ago', 'text', 'runtime', 'Observed by the server; refreshed on demand.'),
            it('console.oidc.client_id', 'Client id', 'aegismesh-console', 'text', 'config', file),
            it('console.oidc.client_secret_file', 'Client secret', 'set (read from a file, never shown)', 'secret', 'config', 'Rotate the file and restart. The console never displays the secret.'),
            it('console.oidc.role_claim', 'Role claim', 'groups', 'text', 'config', file),
            it('console.oidc.role_mappings', 'Role mappings', '3', 'count', 'config', file),
            it('console.oidc.tenant_claim', 'Tenant claim', 'aegismesh_tenants', 'text', 'env', 'Set by AEGISMESH_OIDC_TENANT_CLAIM in the environment. Change it there and restart.'),
          ] : []),
        ] },
        { id: 'tenants', title: 'Tenants', items: [
          it('console.tenants', 'Declared tenants', tenants.join(', '), 'list', tenants.length > 1 ? 'config' : 'default', file),
          it('console.local_tenant', 'Local tenant', localTenant, 'text', tenants.length > 1 ? 'config' : 'default', 'Owns this node’s sensors, rules and node record. ' + file),
        ] },
        { id: 'listener', title: 'Listener', items: [
          it('console.listen', 'Address', '127.0.0.1:9121', 'address', 'config', file),
          it('console.tls.enabled', 'TLS', 'off (loopback only)', 'bool', 'default', 'A non-loopback address requires TLS. ' + file),
          it('console.tls.cert_expiry', 'Certificate expiry', 'not applicable', 'text', 'runtime', 'Measured from the certificate when TLS is on and it is readable.'),
        ] },
        { id: 'evidence', title: 'Evidence and retention', items: [
          it('storage.data_dir', 'Data directory usage', '412 MiB', 'bytes', 'runtime', 'Measured now. The directory itself is set in the config file.'),
          it('storage.encryption.enabled', 'Encryption at rest', 'on (AES-256-GCM, key from file)', 'bool', 'config', 'The key file path is not shown. ' + file),
          it('index.capacity', 'Index capacity', '100,000 events', 'count', 'default', file),
          it('index.occupancy', 'Index occupancy', '1,284 events (1.3%)', 'text', 'runtime', 'Measured now. Older evidence stays on disk.'),
          it('storage.retention_days', 'Retention', '90 days', 'duration', 'config', file),
        ] },
        { id: 'detection', title: 'Detection', items: [
          it('detection.rules.enabled', 'Detection rules', 'enabled (19 rules)', 'bool', 'default', file),
          it('detection.correlation.enabled', 'Correlation', 'enabled (4 rules)', 'bool', 'default', file),
          it('detection.actions.mode', 'Actions mode', 'observe', 'enum', 'default', 'Observe records what a rule would select and never acts. ' + file),
          it('detection.ai.enabled', 'AI-assisted triage', 'off', 'bool', 'default', file),
        ] },
        { id: 'fleet', title: 'Fleet', items: [
          it('fleet.hub.enabled', 'Hub', ctx.fleetHub ? 'enabled' : 'disabled', 'bool', ctx.fleetHub ? 'config' : 'default', file),
          it('fleet.hub.listen', 'Hub address', ctx.fleetHub ? '127.0.0.1:9130' : 'not listening', 'address', ctx.fleetHub ? 'config' : 'default', file),
          it('fleet.hub.accept_evidence', 'Accept forwarded evidence', ctx.acceptEvidence ? 'on' : 'off', 'bool', 'config', file),
          it('fleet.agent.enabled', 'Agent', 'disabled', 'bool', 'default', file),
        ] },
        { id: 'exports', title: 'Exports', items: [
          it('export.siem.formats', 'SIEM file formats', 'CEF, RFC 5424 syslog, OTLP JSON, ECS', 'list', 'default', 'Fixed in this release.'),
          it('export.indicators.formats', 'Indicator formats', 'STIX 2.1, CSV, text', 'list', 'default', 'Fixed in this release.'),
          it('export.max_events', 'Largest export', '10,000 events', 'count', 'default', file),
        ] },
      ],
    };
  }

  // Returns true when it answered. ctx: { req, res, url, p, m, s, sessions,
  // send, fail, readBody, audit, who, remote, endStreams, T, flags }.
  async function handle(c) {
    const { req, res, url, p, m, s, sessions: sessionsMap, send, fail, readBody, audit, who, remote } = c;
    const me = accounts.get(s.account_id);
    if (me) me.last_seen_at = iso(Date.now());
    if (!p.startsWith('/me') && !p.startsWith('/admin') && p !== '/system') return false;
    if (!me) { fail(res, 'unauthenticated', 'account no longer exists'); return true; }
    const caps = capabilitiesOf(me);
    const current = handleOf(s.id);

    if (p === '/me' && m === 'GET') {
      send(res, 200, { id: me.id, name: me.name, kind: me.kind, source: me.source, role: me.role, tenants: [...me.tenants], tenant: s.tenant, auth_method: s.auth_method, created_at: me.created_at, last_seen_at: me.last_seen_at, capabilities: caps });
      return true;
    }
    if (p === '/me/preferences') {
      if (m === 'GET') { send(res, 200, { ...PREF_DEFAULTS, ...(prefs.get(me.id) || {}) }); return true; }
      if (m === 'PUT') {
        let b;
        try { b = await readBody(req, Object.keys(PREF_VALUES)); } catch (err) { fail(res, 'invalid_argument', err.message); return true; }
        for (const [k, v] of Object.entries(b)) {
          if (!PREF_VALUES[k].includes(v)) { fail(res, 'invalid_argument', `${k} must be one of ${PREF_VALUES[k].join(', ')}`); return true; }
        }
        if (c.flags.failPrefs) { fail(res, 'unavailable', 'preferences store is read-only (mock --fail-prefs)'); return true; }
        // Partial bodies merge, like the server.
        const next = { ...PREF_DEFAULTS, ...(prefs.get(me.id) || {}), ...b };
        prefs.set(me.id, next);
        audit(who.name, who.role, 'preferences.update', me.id, 'ok', remote, Object.keys(b).sort().join(','));
        send(res, 200, next);
        return true;
      }
    }
    if (p === '/me/sessions' && m === 'GET') {
      const items = liveSessions(sessionsMap).filter((x) => x.account_id === me.id).map((x) => withAccount(x, current));
      items.sort((a, b) => (b.current - a.current) || Date.parse(b.last_seen_at) - Date.parse(a.last_seen_at));
      send(res, 200, { items });
      return true;
    }
    const meSession = p.match(/^\/me\/sessions\/(ses_[0-9a-f]{16})$/);
    if (meSession && m === 'DELETE') {
      const hit = liveSessions(sessionsMap).find((x) => x.view.handle === meSession[1] && x.account_id === me.id);
      if (!hit) { fail(res, 'not_found', 'session not found'); return true; }
      revokeSession(c, hit, 'session.revoke');
      return true;
    }
    if (p === '/me/keys') {
      if (!caps.manage_own_keys) {
        audit(who.name, who.role, 'authz.denied', '', 'denied', remote, 'key.list');
        fail(res, 'forbidden', 'this account cannot manage its own API keys');
        return true;
      }
      if (m === 'GET') { send(res, 200, { items: keysOf(me.id).map(publicKey) }); return true; }
      if (m === 'POST') { createKey(c, me, me.name); return true; }
    }
    const meKey = p.match(/^\/me\/keys\/(key_[0-9a-f]{12})$/);
    if (meKey && m === 'DELETE') {
      if (!caps.manage_own_keys) { fail(res, 'forbidden', 'this account cannot manage its own API keys'); return true; }
      revokeKey(c, me, meKey[1]);
      return true;
    }

    // ---- Administration -------------------------------------------------
    if (p.startsWith('/admin') || p === '/system') {
      if (!caps.administer || !me.tenants.includes(localTenant) || s.tenant !== localTenant) {
        audit(who.name, who.role, 'authz.denied', '', 'denied', remote, p);
        fail(res, 'forbidden', 'requires admin in the local tenant');
        return true;
      }
    }
    if (p === '/admin/accounts') {
      if (m === 'GET') {
        const items = [...accounts.values()].map((a) => publicAccount(a, sessionsMap));
        const order = { config: 0, managed: 1, oidc: 2 };
        items.sort((a, b) => (order[a.source] - order[b.source]) || a.name.localeCompare(b.name));
        send(res, 200, { items, limits: LIMITS });
        return true;
      }
      if (m === 'POST') {
        let b;
        try { b = await readBody(req, ['name', 'kind', 'role', 'tenants']); } catch (err) { fail(res, 'invalid_argument', err.message); return true; }
        if (!validName(b.name)) { fail(res, 'invalid_argument', 'name must be 1 to 64 letters, digits, spaces or . _ @ ( ) -'); return true; }
        if (!KINDS.includes(b.kind)) { fail(res, 'invalid_argument', 'kind must be person or service'); return true; }
        if (!ROLES.includes(b.role)) { fail(res, 'invalid_argument', 'role must be viewer, analyst or admin'); return true; }
        if (!Array.isArray(b.tenants) || !b.tenants.length || b.tenants.some((t) => !tenants.includes(t))) { fail(res, 'invalid_argument', 'tenants must name declared tenants'); return true; }
        if ([...accounts.values()].some((a) => a.name.toLowerCase() === b.name.trim().toLowerCase())) { send(res, 409, { error: { code: 'conflict', message: 'an account with this name already exists' } }); return true; }
        if (accounts.size >= LIMITS.max_accounts) { send(res, 409, { error: { code: 'conflict', message: `at most ${LIMITS.max_accounts} accounts` } }); return true; }
        const id = `acc_${randomBytes(5).toString('hex')}`;
        const a = put({ id, name: b.name.trim(), kind: b.kind, source: 'managed', role: b.role, tenants: [...new Set(b.tenants)], created_at: iso(Date.now()), created_by: who.name });
        audit(who.name, who.role, 'account.create', id, 'ok', remote);
        send(res, 201, publicAccount(a, sessionsMap));
        return true;
      }
    }
    const acc = p.match(/^\/admin\/accounts\/([^/]+)(\/keys(?:\/(key_[0-9a-f]{12}))?)?$/);
    if (acc) {
      let id;
      try { id = decodeURIComponent(acc[1]); } catch { id = ''; }
      const a = ACCOUNT_ID.test(id) && accounts.get(id);
      if (!a) { fail(res, 'not_found', 'account not found'); return true; }
      if (!acc[2]) {
        if (m === 'GET') {
          const ks = keysOf(a.id).map(publicKey);
          const ss = liveSessions(sessionsMap).filter((x) => x.account_id === a.id).map((x) => withAccount(x, current));
          send(res, 200, { ...publicAccount(a, sessionsMap), keys: ks, sessions: ss });
          return true;
        }
        if (m === 'PATCH') {
          let b;
          try { b = await readBody(req, ['name', 'role', 'tenants', 'status']); } catch (err) { fail(res, 'invalid_argument', err.message); return true; }
          if (a.source !== 'managed') { send(res, 409, { error: { code: 'not_managed', message: `${a.source === 'config' ? 'configured operators are changed in the config file' : 'single sign-on identities are changed at the identity provider'}` } }); return true; }
          if (b.name !== undefined && !validName(b.name)) { fail(res, 'invalid_argument', 'name must be 1 to 64 letters, digits, spaces or . _ @ ( ) -'); return true; }
          if (b.role !== undefined && !ROLES.includes(b.role)) { fail(res, 'invalid_argument', 'role must be viewer, analyst or admin'); return true; }
          if (b.status !== undefined && !['active', 'disabled'].includes(b.status)) { fail(res, 'invalid_argument', 'status must be active or disabled'); return true; }
          if (b.tenants !== undefined && (!Array.isArray(b.tenants) || !b.tenants.length || b.tenants.some((t) => !tenants.includes(t)))) { fail(res, 'invalid_argument', 'tenants must name declared tenants'); return true; }
          if (a.role === 'admin' && a.status === 'active' && activeAdmins(a.id, b) === 0) { send(res, 409, { error: { code: 'last_admin', message: 'this change would leave no active admin' } }); return true; }
          if (b.name !== undefined) a.name = b.name.trim();
          if (b.role !== undefined) a.role = b.role;
          if (b.tenants !== undefined) a.tenants = [...new Set(b.tenants)];
          a.updated_at = iso(Date.now());
          if (b.status !== undefined && b.status !== a.status) {
            a.status = b.status;
            if (b.status === 'disabled') for (const x of liveSessions(sessionsMap).filter((y) => y.account_id === a.id)) dropSession(c, x);
          }
          audit(who.name, who.role, 'account.update', a.id, 'ok', remote, Object.keys(b).sort().join(','));
          send(res, 200, publicAccount(a, sessionsMap));
          return true;
        }
      } else if (!acc[3] && m === 'POST') {
        if (a.source !== 'managed') { send(res, 409, { error: { code: 'not_managed', message: 'keys for configured and single sign-on accounts are created by the account itself' } }); return true; }
        createKey(c, a, who.name);
        return true;
      } else if (acc[3] && m === 'DELETE') {
        revokeKey(c, a, acc[3]);
        return true;
      }
    }
    if (p === '/admin/sessions' && m === 'GET') {
      const items = liveSessions(sessionsMap).map((x) => withAccount(x, current)).sort((a, b) => Date.parse(b.last_seen_at) - Date.parse(a.last_seen_at));
      send(res, 200, { items });
      return true;
    }
    const adminSession = p.match(/^\/admin\/sessions\/(ses_[0-9a-f]{16})$/);
    if (adminSession && m === 'DELETE') {
      const hit = liveSessions(sessionsMap).find((x) => x.view.handle === adminSession[1]);
      if (!hit) { fail(res, 'not_found', 'session not found'); return true; }
      revokeSession(c, hit, 'session.revoke');
      return true;
    }
    if (p === '/admin/settings' && m === 'GET') { send(res, 200, settingsBody(c.flags)); return true; }
    if (p === '/admin/audit/export' && m === 'GET') {
      for (const k of url.searchParams.keys()) if (!['format', 'since'].includes(k)) { fail(res, 'invalid_argument', `unknown parameter "${k}"`); return true; }
      const format = url.searchParams.get('format') || 'jsonl';
      if (!['jsonl', 'csv'].includes(format)) { fail(res, 'invalid_argument', 'format must be jsonl or csv'); return true; }
      const since = url.searchParams.get('since');
      if (since !== null && (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$/.test(since) || Number.isNaN(Date.parse(since)))) { fail(res, 'invalid_argument', 'since must be RFC 3339 UTC'); return true; }
      audit(who.name, who.role, 'audit.export', '', 'ok', remote, format);
      // The active tenant's chain, oldest first, at most 10,000 records.
      const rows = c.T.audit.filter((r) => !since || Date.parse(r.time) >= Date.parse(since)).slice(0, 10000);
      const cols = ['seq', 'time', 'actor', 'role', 'action', 'target', 'outcome', 'remote', 'detail', 'prev_hash', 'hash'];
      const csvCell = (v) => {
        let t = String(v ?? '');
        if (/^[=+\-@\t\r]/.test(t)) t = `'${t}`; // never a spreadsheet formula
        return /[",\n\r]/.test(t) ? `"${t.replace(/"/g, '""')}"` : t;
      };
      const body = format === 'csv'
        ? `${cols.join(',')}\n${rows.map((r) => cols.map((k) => csvCell(r[k])).join(',')).join('\n')}\n`
        : rows.map((r) => JSON.stringify(r)).join('\n') + (rows.length ? '\n' : '');
      res.writeHead(200, c.headers({
        'Content-Type': format === 'csv' ? 'text/csv; charset=utf-8' : 'application/x-ndjson',
        'Content-Disposition': `attachment; filename="aegismesh-audit.${format}"`,
        'Cache-Control': 'no-store', 'X-AegisMesh-Audit-Records': String(rows.length),
      }));
      res.end(body);
      return true;
    }
    if (p === '/system' && m === 'GET') {
      const up = Math.floor((Date.now() - T0) / 1000) + 3 * 86400 + 4 * 3600;
      send(res, 200, {
        version: '0.3.0-dev (mock)', commit: 'f00dfeed1234', build_date: '2026-11-23T08:00:00Z', go_version: 'go1.27.4',
        started_at: iso(Date.now() - up * 1000), uptime_seconds: up, config_schema: 'v1',
        components: [
          { id: 'console', status: 'ok', detail: 'Listening on 127.0.0.1:9121' },
          { id: 'storage', status: 'ok', detail: 'Writable, 412 MiB used' },
          { id: 'index', status: 'ok', detail: '1,284 of 100,000 events' },
          { id: 'sensors', status: 'degraded', detail: '5 of 6 running; ssh-decoy failed to bind' },
          { id: 'fleet', status: c.flags.fleetHub ? 'ok' : 'off', detail: c.flags.fleetHub ? 'Hub with 4 nodes' : 'Not enabled' },
          { id: 'oidc', status: c.flags.oidc ? 'ok' : 'off', detail: c.flags.oidc ? 'Discovery cached 12 min ago' : 'Not configured' },
        ],
        licenses_url: '',
      });
      return true;
    }
    fail(res, 'not_found', 'no such endpoint');
    return true;
  }

  function createKey(c, owner, by) {
    const { req, res, fail, send, audit, who, remote } = c;
    return c.readBody(req, ['label', 'expires_in_days']).then((b) => {
      if (!validLabel(b.label)) return fail(res, 'invalid_argument', 'label must be 1 to 64 printable characters');
      const days = b.expires_in_days === undefined ? LIMITS.default_key_days : b.expires_in_days;
      if (!Number.isInteger(days) || days < 1 || days > LIMITS.max_key_days) return fail(res, 'invalid_argument', `expires_in_days must be 1..${LIMITS.max_key_days}`);
      if (owner.status !== 'active') return send(res, 409, { error: { code: 'conflict', message: 'the account is disabled' } });
      if (keysOf(owner.id).filter((k) => keyStatus(k) === 'active').length >= LIMITS.max_keys_per_account) {
        return send(res, 409, { error: { code: 'conflict', message: `at most ${LIMITS.max_keys_per_account} active keys per account` } });
      }
      const minted = mintKey(owner.id, b.label.trim(), days, by);
      audit(who.name, who.role, 'key.create', minted.key.id, 'ok', remote);
      return send(res, 201, minted);
    }, (err) => fail(res, 'invalid_argument', err.message));
  }

  function revokeKey(c, owner, keyId) {
    const k = keys.get(keyId);
    if (!k || k.account_id !== owner.id) return c.fail(c.res, 'not_found', 'key not found');
    if (!k.revoked_at) k.revoked_at = iso(Date.now());
    c.audit(c.who.name, c.who.role, 'key.revoke', keyId, 'ok', c.remote);
    return c.send(c.res, 204, null);
  }

  function dropSession(c, hit) {
    if (hit.sid) { c.sessions.delete(hit.sid); c.endStreams(hit.sid); } else {
      const i = synthetic.findIndex((x) => x.handle === hit.view.handle);
      if (i >= 0) synthetic.splice(i, 1);
    }
  }

  function revokeSession(c, hit, action) {
    const self = hit.sid === c.s.id;
    dropSession(c, hit);
    c.audit(c.who.name, c.who.role, action, hit.view.handle, 'ok', c.remote);
    return c.send(c.res, 204, null, self ? { 'Set-Cookie': 'aegismesh_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0' } : {});
  }

  return { handle, principalForKey, touchOidc, configuredId: (name) => `cfg:${name}`, handleOf, accounts, keys };
}
