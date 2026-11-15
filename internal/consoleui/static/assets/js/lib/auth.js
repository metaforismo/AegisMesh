// Sign-in options and OpenID Connect error codes (console API contract,
// "OIDC and tenant contract").
//
// `GET /meta` says which sign-in methods the server accepts. OIDC (single
// sign-on) is experimental. The browser starts it with a plain same-origin
// navigation to OIDC_LOGIN_PATH; the server redirects to the identity
// provider, and failures come back as `#/login?error=<code>` with one of a
// fixed set of codes. The provider's own text is discarded by the server and
// is never shown here: an unknown code gets the generic message.

export const OIDC_LOGIN_PATH = '/api/v1/auth/oidc/login';

export const LOGIN_ERROR_CODES = Object.freeze([
  'unavailable', 'rate_limited', 'invalid_request', 'invalid_state', 'invalid_identity', 'access_denied',
]);

const DEFAULT_SSO_NAME = 'Single sign-on';
const MAX_DISPLAY_NAME = 64;

// The display name is configuration, shown as plain text in a button label.
// Collapse whitespace, drop control and bidi-override characters and cap the
// length so a long or odd value cannot break the sign-in card.
export function ssoDisplayName(value) {
  if (typeof value !== 'string') return DEFAULT_SSO_NAME;
  const clean = value.replace(/\s+/g, ' ').replace(/[\u0000-\u001f\u007f-\u009f‎‏‪-‮⁦-⁩]/g, '').trim();
  if (!clean) return DEFAULT_SSO_NAME;
  const chars = [...clean];
  return chars.length > MAX_DISPLAY_NAME ? `${chars.slice(0, MAX_DISPLAY_NAME - 1).join('')}…` : clean;
}

// Which controls the sign-in card shows.
//   token, oidc   methods offered
//   primary       'oidc' | 'token' | 'none'
//   collapseToken the token form sits behind "Use an operator token"
//   known         false when /meta could not be read (older server or an
//                 outage): the token form is shown, as before OIDC existed
export function signInOptions(meta) {
  const auth = meta && typeof meta === 'object' ? meta.auth : undefined;
  if (!auth || typeof auth !== 'object') {
    return { token: true, oidc: false, displayName: DEFAULT_SSO_NAME, primary: 'token', collapseToken: false, known: Boolean(meta) };
  }
  const token = auth.token !== false;
  const oidc = Boolean(auth.oidc && typeof auth.oidc === 'object' && auth.oidc.enabled === true);
  const primary = oidc ? 'oidc' : token ? 'token' : 'none';
  return {
    token, oidc,
    displayName: ssoDisplayName(oidc ? auth.oidc.display_name : ''),
    primary,
    collapseToken: oidc && token,
    known: true,
  };
}

// The error code from a login route's query: a known code, 'unknown' for
// anything else that was present, or '' when there is none.
export function loginErrorCode(query) {
  const raw = query && Object.hasOwn(query, 'error') ? query.error : undefined;
  if (raw === undefined) return '';
  return LOGIN_ERROR_CODES.includes(raw) ? raw : 'unknown';
}

// Operator-facing words for each code. Calm and specific; never the
// provider's text. `tokenAvailable` adds the token fallback where it helps.
export function loginErrorMessage(code, { tokenAvailable = false } = {}) {
  const orToken = tokenAvailable ? ' You can also sign in with an operator token.' : '';
  switch (code) {
    case 'unavailable':
      return {
        title: 'Single sign-on is temporarily unavailable',
        detail: `The console could not complete sign-in with the identity provider. Try again in a moment.${orToken}`,
      };
    case 'rate_limited':
      return { title: 'Too many sign-in attempts', detail: 'Sign-in is paused briefly for this address. Wait a minute, then try again.' };
    case 'invalid_request':
      return { title: 'The sign-in response was incomplete', detail: 'The identity provider returned an answer the console could not use. Start again from this page.' };
    case 'invalid_state':
      return {
        title: 'That sign-in attempt expired',
        detail: 'Each sign-in attempt works once, for two minutes, in the browser that started it. Start again from this page.',
      };
    case 'invalid_identity':
      return {
        title: 'Your identity was not accepted',
        detail: 'The identity provider answered, but the console could not verify the identity or has no operator mapped to it. Ask an admin to check the OIDC operator mapping.',
      };
    case 'access_denied':
      return {
        title: 'Sign-in was not granted',
        detail: `The identity provider did not grant access, or sign-in was cancelled there.${orToken}`,
      };
    default:
      return { title: 'Single sign-on did not complete', detail: `Start again from this page.${orToken}` };
  }
}

// How the current session signed in, for the account menu.
export function authMethodLabel(method, meta) {
  if (method === 'oidc') {
    const opts = signInOptions(meta);
    return opts.oidc ? `Single sign-on (${opts.displayName})` : 'Single sign-on (OIDC)';
  }
  if (method === 'token') return 'Operator token';
  return 'Unknown method';
}
