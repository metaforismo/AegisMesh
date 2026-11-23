// Console API v1 client (docs/architecture/console-api.md).
//
// The CSRF token lives only in this closure: never in storage, never in the
// DOM. The session itself is an HttpOnly cookie the page cannot read.

import { encodeSegment, toQuery } from './route.js';

export class ApiError extends Error {
  constructor(status, code, message) {
    super(message || code || `HTTP ${status}`);
    this.name = 'ApiError';
    this.status = status;
    this.code = code || 'internal';
  }

  get retryAfter() {
    return this._retryAfter ?? 0;
  }
}

const KNOWN_CODES = new Set(['invalid_argument', 'unauthenticated', 'forbidden', 'not_found', 'conflict', 'rate_limited', 'unavailable', 'internal']);
// A server may answer a conflict with a specific reason in place of the
// generic code (409 "last_admin", "not_managed", "name_taken",
// "limit_reached"). The generic code still follows the status; the reason is
// kept separately, and only as a short lowercase token, never as text.
const REASON = /^[a-z][a-z0-9_]{1,39}$/;
const CSRF_HEADER = 'X-AegisMesh-CSRF';
const MAX_ERROR_MESSAGE = 300;

function codeForStatus(status) {
  return {
    400: 'invalid_argument', 401: 'unauthenticated', 403: 'forbidden', 404: 'not_found',
    409: 'conflict', 429: 'rate_limited', 503: 'unavailable',
  }[status] ?? 'internal';
}

async function toApiError(res) {
  let code = codeForStatus(res.status);
  let message = '';
  let reason = '';
  try {
    const body = await res.json();
    if (body && typeof body.error === 'object' && body.error) {
      if (KNOWN_CODES.has(body.error.code)) code = body.error.code;
      else if (typeof body.error.code === 'string' && REASON.test(body.error.code)) reason = body.error.code;
      if (typeof body.error.reason === 'string' && REASON.test(body.error.reason)) reason = body.error.reason;
      if (typeof body.error.message === 'string') message = body.error.message.slice(0, MAX_ERROR_MESSAGE);
    }
  } catch {
    // Non-JSON error bodies (a proxy page, an empty 502) keep the status code.
  }
  const err = new ApiError(res.status, code, message || `Request failed (${res.status})`);
  err.reason = reason;
  const ra = Number(res.headers?.get?.('Retry-After'));
  if (Number.isFinite(ra) && ra > 0) err._retryAfter = ra;
  return err;
}

export function createApi({ fetchImpl = globalThis.fetch?.bind(globalThis), base = '/api/v1', onUnauthenticated = () => {} } = {}) {
  let csrf = null;
  // A tenant switch rotates the session cookie and invalidates the old one.
  // A request that was already on its way with the old cookie can come back
  // 401 even though the operator is still signed in, so a 401 for a request
  // that started before (or during) a switch is an answer, not a sign-out.
  let epoch = 0;
  let switching = false;

  async function request(method, path, { query, body, signal, allow401 = false, raw = false } = {}) {
    const startedAt = epoch;
    const qs = query ? toQuery(query) : '';
    const headers = { Accept: raw ? '*/*' : 'application/json' };
    const init = { method, headers, credentials: 'same-origin', cache: 'no-store', signal };
    if (body !== undefined) {
      headers['Content-Type'] = 'application/json';
      init.body = JSON.stringify(body);
    }
    if (method !== 'GET' && csrf) headers[CSRF_HEADER] = csrf;
    let res;
    try {
      res = await fetchImpl(`${base}${path}${qs ? `?${qs}` : ''}`, init);
    } catch (err) {
      if (err?.name === 'AbortError') throw err;
      throw new ApiError(0, 'unavailable', 'The console server could not be reached.');
    }
    if (res.status === 204) return null;
    if (!res.ok) {
      const err = await toApiError(res);
      if (res.status === 401) {
        const superseded = switching || startedAt !== epoch;
        if (!superseded) csrf = null;
        if (!allow401 && !superseded) onUnauthenticated(err);
      }
      throw err;
    }
    if (raw) return res;
    try {
      return await res.json();
    } catch {
      throw new ApiError(res.status, 'internal', 'The server returned a response that is not JSON.');
    }
  }

  const seg = encodeSegment;
  const get = (path, query, opts) => request('GET', path, { query, ...opts });

  return {
    request,
    hasCsrf: () => csrf !== null,
    forgetSession() {
      csrf = null;
    },

    meta: (opts) => get('/meta', undefined, { ...opts, allow401: true }),

    async login(token, opts) {
      const session = await request('POST', '/session', { body: { token }, allow401: true, ...opts });
      csrf = typeof session?.csrf_token === 'string' ? session.csrf_token : null;
      return session;
    },

    // Probe used at boot and after a stream drop: a 401 here is an answer,
    // not an event that should redirect.
    async session(opts) {
      const session = await get('/session', undefined, { allow401: true, ...opts });
      csrf = typeof session?.csrf_token === 'string' ? session.csrf_token : null;
      return session;
    },

    // Move this session to another member tenant. The server rotates the
    // session cookie and the CSRF token; the old session (and its live
    // streams) stop working. Cookie sessions only.
    async switchTenant(tenant) {
      switching = true;
      epoch++;
      try {
        const session = await request('POST', '/session/tenant', { body: { tenant }, allow401: true });
        csrf = typeof session?.csrf_token === 'string' ? session.csrf_token : null;
        return session;
      } finally {
        epoch++;
        switching = false;
      }
    },

    async logout() {
      try {
        await request('DELETE', '/session', { allow401: true });
      } finally {
        csrf = null;
      }
    },

    overview: (window, opts) => get('/overview', { window }, opts),
    events: (filters, cursor, limit, opts) => get('/events', { ...filters, cursor, limit }, opts),
    // `node` ("local" or a node id) pins the detail to one origin; ids are
    // unique only within an origin. Empty lets the server choose (local first).
    event: (id, node, opts) => get(`/events/${seg(id)}`, node ? { node } : undefined, opts),
    sources: (window, limit, opts) => get('/sources', { window, limit }, opts),
    source: (source, cursor, limit, opts) => get(`/sources/${seg(source)}`, { cursor, limit }, opts),
    sensors: (opts) => get('/sensors', undefined, opts),
    rules: (opts) => get('/rules', undefined, opts),
    recommendations: (limit, opts) => get('/recommendations', { limit }, opts),
    node: (opts) => get('/node', undefined, opts),
    investigations: (status, opts) => get('/investigations', { status }, opts),
    investigation: (id, opts) => get(`/investigations/${seg(id)}`, undefined, opts),
    createInvestigation: (body) => request('POST', '/investigations', { body }),
    updateInvestigation: (id, body) => request('PATCH', `/investigations/${seg(id)}`, { body }),
    addNote: (id, text) => request('POST', `/investigations/${seg(id)}/notes`, { body: { text } }),
    attachEvent: (id, eventId) => request('PUT', `/investigations/${seg(id)}/events/${seg(eventId)}`),
    detachEvent: (id, eventId) => request('DELETE', `/investigations/${seg(id)}/events/${seg(eventId)}`),
    audit: (filters, cursor, limit, opts) => get('/audit', { ...filters, cursor, limit }, opts),
    verifyAudit: (opts) => get('/audit/verify', undefined, opts),

    // Experimental fleet inventory (ADR-0018). Read-only except token
    // management and revocation; there is no route that controls a node.
    // Derived views (ADR-0022). Downloads return the raw Response (an
    // attachment); the caller reads it as a Blob and never trusts its
    // Content-Disposition filename.
    sessions: (window, source, cursor, limit, opts) => get('/sessions', { window, source, cursor, limit }, opts),
    attackSession: (id, opts) => get(`/sessions/${seg(id)}`, undefined, opts),
    coverage: (window, opts) => get('/coverage', { window }, opts),
    exportIndicators: (scope, format, opts) => get('/export/indicators', { ...scope, format }, { ...opts, raw: true }),
    sessionReport: (id, opts) => get(`/sessions/${seg(id)}/report`, undefined, { ...opts, raw: true }),
    investigationReport: (id, opts) => get(`/investigations/${seg(id)}/report`, undefined, { ...opts, raw: true }),
    // Local SIEM event files (CEF, RFC 5424 syslog, OTLP JSON, ECS): an
    // audited analyst download of one scope. File formats only; nothing is sent.
    exportEvents: (scope, format, opts) => get('/export/events', { ...scope, format }, { ...opts, raw: true }),

    // Catalogs and the on-demand digest (round 3). Decoys and honeytokens
    // describe this node's own configuration; honeytoken values never leave
    // the server.
    decoys: (window, opts) => get('/decoys', { window }, opts),
    honeytokens: (window, opts) => get('/honeytokens', { window }, opts),
    digest: (window, opts) => get('/digest', { window }, opts),

    // Round 4: campaigns (several sources, one playbook; similar behaviour,
    // not attribution) and the configuration posture review. Older servers
    // answer 404 on these collection paths; screens say so plainly.
    campaigns: (opts) => get('/campaigns', undefined, opts),
    campaign: (id, opts) => get(`/campaigns/${seg(id)}`, undefined, opts),
    posture: (opts) => get('/posture', undefined, opts),

    // Round 5: your account, its preferences, sessions and API keys. An API
    // key's token is in the create response exactly once; callers show it in
    // the reveal panel and keep it nowhere else. Older servers answer 404.
    me: (opts) => get('/me', undefined, opts),
    preferences: (opts) => get('/me/preferences', undefined, opts),
    putPreferences: (body) => request('PUT', '/me/preferences', { body }),
    mySessions: (opts) => get('/me/sessions', undefined, opts),
    revokeMySession: (handle) => request('DELETE', `/me/sessions/${seg(handle)}`),
    myKeys: (opts) => get('/me/keys', undefined, opts),
    createMyKey: (body) => request('POST', '/me/keys', { body }),
    revokeMyKey: (id) => request('DELETE', `/me/keys/${seg(id)}`),

    // Round 5 administration (admin role in the local tenant).
    accounts: (opts) => get('/admin/accounts', undefined, opts),
    account: (id, opts) => get(`/admin/accounts/${seg(id)}`, undefined, opts),
    createAccount: (body) => request('POST', '/admin/accounts', { body }),
    updateAccount: (id, body) => request('PATCH', `/admin/accounts/${seg(id)}`, { body }),
    createAccountKey: (id, body) => request('POST', `/admin/accounts/${seg(id)}/keys`, { body }),
    revokeAccountKey: (id, keyId) => request('DELETE', `/admin/accounts/${seg(id)}/keys/${seg(keyId)}`),
    allSessions: (opts) => get('/admin/sessions', undefined, opts),
    revokeAnySession: (handle) => request('DELETE', `/admin/sessions/${seg(handle)}`),
    adminSettings: (opts) => get('/admin/settings', undefined, opts),
    system: (opts) => get('/system', undefined, opts),
    // Audited download of the whole audit chain (or since a time).
    exportAudit: (format, since, opts) => get('/admin/audit/export', { format, since }, { ...opts, raw: true }),

    fleet: (opts) => get('/fleet', undefined, opts),
    fleetNodes: (status, opts) => get('/fleet/nodes', { status }, opts),
    fleetNode: (id, opts) => get(`/fleet/nodes/${seg(id)}`, undefined, opts),
    revokeNode: (id) => request('POST', `/fleet/nodes/${seg(id)}/revoke`),
    enrollmentTokens: (opts) => get('/fleet/enrollment-tokens', undefined, opts),
    // The response carries the raw token exactly once. Callers must not keep it.
    createEnrollmentToken: (body) => request('POST', '/fleet/enrollment-tokens', { body }),
    deleteEnrollmentToken: (id) => request('DELETE', `/fleet/enrollment-tokens/${seg(id)}`),
  };
}

// Plain-language explanation for an error, written for the operator.
export function describeError(err) {
  if (!(err instanceof ApiError)) return { title: 'Something went wrong', detail: String(err?.message ?? err) };
  switch (err.code) {
    case 'unauthenticated': return { title: 'Session ended', detail: 'Sign in again to continue.' };
    case 'forbidden': return { title: 'Not permitted', detail: 'Your role does not grant access to this. Ask an admin if you need it.' };
    case 'not_found': return { title: 'Not found', detail: 'It may have aged out of the in-memory index. Older evidence stays on disk; the aegismesh inspect command reads it.' };
    case 'rate_limited': return { title: 'Too many attempts', detail: err.retryAfter ? `Wait ${err.retryAfter}s and try again.` : 'Wait a moment and try again.' };
    case 'unavailable': return { title: 'Console unavailable', detail: err.status === 0 ? 'The console server could not be reached. Check that AegisMesh is running.' : err.message };
    case 'invalid_argument': return { title: 'Request rejected', detail: err.message };
    case 'conflict': return { title: 'Conflict', detail: err.message };
    default: return { title: 'Server error', detail: err.message };
  }
}

// What a screen says when it cannot load, and where the operator can go
// next. `name` is the route name; detail routes name their list so a
// missing object offers the way back. A collection path the server does not
// know (404/405/501 on a list screen) means an older server, not a missing
// object, and retrying will not help.
const LIST_OF = Object.freeze({
  event: ['#/events', 'Go to events'],
  source: ['#/sources', 'Go to sources'],
  attack_session: ['#/sessions', 'Go to sessions'],
  campaign: ['#/campaigns', 'Go to campaigns'],
  investigation: ['#/investigations', 'Go to investigations'],
  fleet_node: ['#/fleet', 'Go to the fleet'],
});
const OVERVIEW = ['#/overview', 'Go to the overview'];

export function screenFailure(err, { name = '', title = 'This page' } = {}) {
  const parent = LIST_OF[name] || null;
  const status = err instanceof ApiError ? err.status : -1;
  if (!parent && (status === 404 || status === 405 || status === 501)) {
    return {
      title: `This server does not provide ${title.toLowerCase()} yet`,
      detail: 'The console is newer than the AegisMesh server answering it. Update the server to use this screen; the other screens keep working.',
      retry: false,
      actions: [OVERVIEW, ['#/guide', 'Open the guide']],
    };
  }
  const d = describeError(err);
  if (err instanceof ApiError && err.code === 'not_found') return { ...d, retry: false, actions: [parent || OVERVIEW] };
  if (err instanceof ApiError && err.code === 'forbidden') return { ...d, retry: false, actions: [OVERVIEW] };
  if (err instanceof ApiError && err.code === 'unauthenticated') return { ...d, retry: false, actions: [] };
  return { ...d, retry: true, actions: parent ? [parent] : [OVERVIEW] };
}
