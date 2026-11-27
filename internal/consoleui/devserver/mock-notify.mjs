// Round 8 mock: the in-console notification inbox (contract r8, section 1).
//
// Derived from observations already in the mock index and from console
// state; nothing is sent anywhere. Per tenant: a bounded ring of items
// (newest first), per-principal read state (a "read before" cursor plus
// read ids) and per-principal preferences. Repeats of the same
// kind + rule + source within 10 minutes raise `group_count` instead of
// adding an item. Items addressed to one principal (`account_security`,
// `assignment`) are visible to that principal only; the rest need
// evidence.read.
//
// Synthetic data only. Titles and summaries are composed here from fixed
// words plus ids and source keys the sensors recorded; the console shows
// them as text.

export const NOTIFY_KINDS = Object.freeze(['critical_observation', 'honeytoken_replay', 'agent_canary', 'new_campaign', 'posture_attention', 'account_security', 'assignment']);
export const NOTIFY_SEVERITIES = Object.freeze(['info', 'low', 'medium', 'high', 'critical']);
export const NOTIFY_RING = 2000;
export const GROUP_WINDOW_MS = 10 * 60e3;
// Findings are also rate-limited per rule + source: within six hours of the
// item that opened, repeats count into it rather than adding another.
export const FINDING_RATE_MS = 6 * 3600e3;
// Seeded items older than this are already read when a principal first
// opens the inbox, so the unread count looks like one shift's.
export const SEED_READ_AGE_MS = 8 * 3600e3;
export const DEFAULT_MIN_SEVERITY = 'info';
// The minimum severities a principal may choose, and the kind that can be
// neither turned off nor filtered by severity (the backend's rules).
export const PREF_SEVERITIES = Object.freeze(['info', 'medium', 'high', 'critical']);
export const ALWAYS_ON = 'account_security';
export const READ_IDS_MAX = 200;
export const LINK_ROUTES = Object.freeze(['session', 'campaign', 'event', 'posture', 'settings', 'investigation']);

const rank = (s) => NOTIFY_SEVERITIES.indexOf(s);
const iso = (t) => new Date(t).toISOString().replace(/\.\d+Z$/, 'Z');

export function defaultPrefs() {
  return { kinds: Object.fromEntries(NOTIFY_KINDS.map((k) => [k, true])), min_severity: DEFAULT_MIN_SEVERITY };
}

// Merge a PUT body into preferences. Unknown kinds, non-boolean toggles,
// unknown fields and unknown severities are refused (the caller answers 400).
export function mergePrefs(current, body) {
  if (!body || typeof body !== 'object' || Array.isArray(body)) return { error: 'body must be a JSON object' };
  for (const k of Object.keys(body)) if (k !== 'kinds' && k !== 'min_severity') return { error: `unknown field "${k}"` };
  const next = { kinds: { ...current.kinds }, min_severity: current.min_severity };
  if ('kinds' in body) {
    if (!body.kinds || typeof body.kinds !== 'object' || Array.isArray(body.kinds)) return { error: 'kinds must be an object' };
    for (const [k, v] of Object.entries(body.kinds)) {
      if (!NOTIFY_KINDS.includes(k)) return { error: `unknown notification kind "${k}"` };
      if (typeof v !== 'boolean') return { error: `kinds.${k} must be true or false` };
      if (k === ALWAYS_ON && v === false) return { error: `${ALWAYS_ON} cannot be turned off` };
      next.kinds[k] = v;
    }
  }
  if ('min_severity' in body) {
    if (!PREF_SEVERITIES.includes(body.min_severity)) return { error: `min_severity must be one of ${PREF_SEVERITIES.join(', ')}` };
    next.min_severity = body.min_severity;
  }
  return { prefs: next };
}

export function createNotifications({ rand = Math.random, clock = () => Date.now(), ring = NOTIFY_RING } = {}) {
  const items = []; // newest first by creation
  const reads = new Map(); // principal → { before, ids: Set }
  const prefs = new Map(); // principal → prefs
  const hex = (n) => Array.from({ length: n }, () => Math.floor(rand() * 16).toString(16)).join('');

  const readsOf = (who) => {
    if (!reads.has(who)) reads.set(who, { before: clock() - SEED_READ_AGE_MS, ids: new Set() });
    return reads.get(who);
  };
  const prefsOf = (who) => prefs.get(who) || defaultPrefs();
  const isRead = (it, who) => {
    const r = readsOf(who);
    return r.ids.has(it.id) || it._at <= r.before;
  };
  const visible = (it, who, perms) => (it._for ? it._for === who : perms.includes('evidence.read'));
  const wanted = (it, who) => {
    const p = prefsOf(who);
    if (it.kind === ALWAYS_ON) return true;
    return p.kinds[it.kind] !== false && rank(it.severity) >= rank(p.min_severity);
  };
  const shown = (who, perms) => items.filter((it) => visible(it, who, perms) && wanted(it, who));
  const view = (it, who) => ({
    id: it.id, kind: it.kind, severity: it.severity, title: it.title, summary: it.summary,
    created_at: it.created_at, updated_at: iso(it._last), read: isRead(it, who), link: it.link ? { ...it.link } : null, group_count: it.group_count,
  });

  // Add one notification (or group it into a recent one). Returns
  // { item, grouped } so the caller can push it to live streams.
  function add({ kind, severity, title, summary = '', link = null, at, key = '', for: who = null }) {
    if (!NOTIFY_KINDS.includes(kind) || !NOTIFY_SEVERITIES.includes(severity)) throw new Error(`bad notification ${kind}/${severity}`);
    const t = at ?? clock();
    const groupKey = key ? `${kind}|${key}|${who || ''}` : '';
    if (groupKey) {
      const hit = items.find((x) => x._key === groupKey && t >= x._at && (t - x._last <= GROUP_WINDOW_MS || (kind === 'critical_observation' && t - x._at <= FINDING_RATE_MS)));
      if (hit) {
        hit.group_count++;
        hit._last = t;
        if (rank(severity) > rank(hit.severity)) hit.severity = severity;
        return { item: hit, grouped: true };
      }
    }
    const it = { id: `ntf_${hex(16)}`, kind, severity, title, summary, link, created_at: iso(t), group_count: 1, _at: t, _last: t, _key: groupKey, _for: who };
    // Seeds arrive in time order and live items are newest, so inserting
    // in order keeps the list newest first in both cases.
    let i = 0;
    while (i < items.length && items[i]._at > t) i++;
    items.splice(i, 0, it);
    if (items.length > ring) items.length = ring;
    return { item: it, grouped: false };
  }

  function list(who, perms, { unread = false, cursor = 0, limit = 50, kind = '', severity = '' } = {}) {
    const all = shown(who, perms);
    const pool = all.filter((it) => (!unread || !isRead(it, who)) && (!kind || it.kind === kind) && (!severity || it.severity === severity));
    const page = pool.slice(cursor, cursor + limit);
    return {
      items: page.map((it) => view(it, who)),
      unread: all.filter((it) => !isRead(it, who)).length,
      next_cursor: cursor + limit < pool.length ? String(cursor + limit) : null,
      limits: { max_items: ring, per_minute: 20, per_wall_minute: 60, group_window_seconds: GROUP_WINDOW_MS / 1000 },
    };
  }

  const unreadCount = (who, perms) => shown(who, perms).filter((it) => !isRead(it, who)).length;

  function markRead(who, perms, body) {
    const r = readsOf(who);
    if (body.all === true) {
      const before = body.before ? Date.parse(body.before) : clock();
      r.before = Math.max(r.before, before);
      for (const id of [...r.ids]) if (items.find((x) => x.id === id && x._at <= r.before)) r.ids.delete(id);
    } else {
      for (const id of body.ids) if (items.some((x) => x.id === id && visible(x, who, perms))) r.ids.add(id);
    }
    return unreadCount(who, perms);
  }

  return {
    add, list, unreadCount, markRead,
    prefs: (who) => structuredClone(prefsOf(who)),
    putPrefs(who, body) {
      const out = mergePrefs(prefsOf(who), body);
      if (out.prefs) prefs.set(who, out.prefs);
      return out;
    },
    view, visible, wanted,
    get size() { return items.length; },
  };
}

// ---- Seeds ---------------------------------------------------------------------

const OBS_TITLE = {
  critical: 'Critical finding on a decoy',
  high: 'High-severity finding on a decoy',
};

// What a finding notification says. The rule id and sensor are interface
// ids; the source key is what the sensor recorded (attacker-influenced),
// which the console prints as text, never as markup.
export function observationNotice(e, ruleTitle = '') {
  const r = new Set(e.rule_ids || []);
  if (r.has('HT-001') || r.has('COR-008')) {
    return {
      kind: 'honeytoken_replay', severity: 'critical',
      title: r.has('COR-008') ? 'Planted key replayed on a second sensor' : 'Planted credential presented to a decoy',
      summary: `A decoy credential came back on ${e.sensor?.id || 'a sensor'} from source ${e.source}. Only someone who read a decoy can hold it.`,
      key: `${r.has('COR-008') ? 'COR-008' : 'HT-001'}|${e.source}`,
    };
  }
  if (r.has('AGT-001')) {
    return {
      kind: 'agent_canary', severity: 'high',
      title: 'An agent followed a planted instruction',
      summary: `Rule AGT-001 on ${e.sensor?.id || 'a sensor'}: the agent marker came back from source ${e.source}. Consistent with an automated agent; not a verdict.`,
      key: `AGT-001|${e.source}`,
    };
  }
  if (e.severity === 'critical' || e.severity === 'high') {
    const rule = (e.rule_ids || [])[0] || '';
    return {
      kind: 'critical_observation', severity: e.severity,
      title: OBS_TITLE[e.severity],
      summary: `${rule}${ruleTitle ? ` (${ruleTitle})` : ''} on ${e.sensor?.id || 'a sensor'}, source ${e.source}.`,
      key: `${rule}|${e.source}`,
    };
  }
  return null;
}

// Fill a tenant's store from what the index and console already hold, in
// time order so grouping and the ring behave as they would live.
export function seedNotifications(store, { events = [], campaigns = [], posture = null, investigations = [], ruleTitle = () => '', now = Date.now(), principals = {} }) {
  const seeds = [];
  for (const e of events) {
    if (e.node) continue;
    const n = observationNotice(e, ruleTitle(e.rule_ids?.[0]));
    if (n) seeds.push({ ...n, at: Date.parse(e.time), link: { route: 'event', id: e.id } });
  }
  for (const c of campaigns) {
    seeds.push({
      kind: 'new_campaign', severity: 'medium', at: Date.parse(c.first_seen) + 60e3, key: c.id,
      title: 'New campaign: several sources, one playbook',
      summary: `${c.label || 'A shared sequence'} across ${c.source_count} sources. Similar behaviour, not attribution.`,
      link: { route: 'campaign', id: c.id },
    });
  }
  for (const [i, chk] of (posture?.checks || []).filter((x) => x.status === 'attention').entries()) {
    seeds.push({
      kind: 'posture_attention', severity: 'medium', at: now - (2 + i * 5) * 3600e3, key: chk.id,
      title: 'Posture check needs attention', summary: `${chk.id}: ${chk.title}.`,
      link: { route: 'posture', id: chk.id },
    });
  }
  // Addressed to one principal.
  if (principals.admin) {
    seeds.push({ kind: 'account_security', severity: 'high', at: now - 3 * 3600e3, for: principals.admin, title: 'An API key was created for your account', summary: 'Label "laptop cli", expires in 90 days. If this was not you, revoke it in Settings, API keys.', link: { route: 'settings', id: 'keys' } });
  }
  if (principals.analyst) {
    seeds.push({ kind: 'account_security', severity: 'high', at: now - 26 * 3600e3, for: principals.analyst, title: 'A session of yours was revoked by someone else', summary: 'ada revoked your session from Firefox on Linux. Your other sessions were not affected.', link: { route: 'settings', id: 'sessions' } });
    const inv = investigations[0];
    if (inv) seeds.push({ kind: 'assignment', severity: 'medium', at: now - 50 * 60e3, for: principals.analyst, title: 'You were assigned an investigation', summary: `ada assigned you "${inv.title}".`, link: { route: 'investigation', id: inv.id } });
  }
  if (principals.viewer) {
    seeds.push({ kind: 'account_security', severity: 'medium', at: now - 5 * 86400e3, for: principals.viewer, title: 'Your role changed', summary: 'Your role is now viewer. It can read evidence and investigations; it cannot change them.', link: { route: 'settings', id: 'profile' } });
  }
  seeds.sort((a, b) => a.at - b.at);
  for (const s of seeds) store.add(s);
  return seeds.length;
}
