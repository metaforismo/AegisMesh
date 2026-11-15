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
  try {
    const body = await res.json();
    if (body && typeof body.error === 'object' && body.error) {
      if (KNOWN_CODES.has(body.error.code)) code = body.error.code;
      if (typeof body.error.message === 'string') message = body.error.message.slice(0, MAX_ERROR_MESSAGE);
    }
  } catch {
    // Non-JSON error bodies (a proxy page, an empty 502) keep the status code.
  }
  const err = new ApiError(res.status, code, message || `Request failed (${res.status})`);
  const ra = Number(res.headers?.get?.('Retry-After'));
  if (Number.isFinite(ra) && ra > 0) err._retryAfter = ra;
  return err;
}

export function createApi({ fetchImpl = globalThis.fetch?.bind(globalThis), base = '/api/v1', onUnauthenticated = () => {} } = {}) {
  let csrf = null;

  async function request(method, path, { query, body, signal, allow401 = false } = {}) {
    const qs = query ? toQuery(query) : '';
    const headers = { Accept: 'application/json' };
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
        csrf = null;
        if (!allow401) onUnauthenticated(err);
      }
      throw err;
    }
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

    async logout() {
      try {
        await request('DELETE', '/session', { allow401: true });
      } finally {
        csrf = null;
      }
    },

    overview: (window, opts) => get('/overview', { window }, opts),
    events: (filters, cursor, limit, opts) => get('/events', { ...filters, cursor, limit }, opts),
    event: (id, opts) => get(`/events/${seg(id)}`, undefined, opts),
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
    case 'not_found': return { title: 'Not found', detail: 'It may have aged out of the in-memory index. Older evidence stays on disk and is reachable with `aegismesh inspect`.' };
    case 'rate_limited': return { title: 'Too many attempts', detail: err.retryAfter ? `Wait ${err.retryAfter}s and try again.` : 'Wait a moment and try again.' };
    case 'unavailable': return { title: 'Console unavailable', detail: err.status === 0 ? 'The console server could not be reached. Check that AegisMesh is running.' : err.message };
    case 'invalid_argument': return { title: 'Request rejected', detail: err.message };
    case 'conflict': return { title: 'Conflict', detail: err.message };
    default: return { title: 'Server error', detail: err.message };
  }
}
