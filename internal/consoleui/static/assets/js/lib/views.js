// Saved event-filter views and palette recents, kept in this browser's
// localStorage. Pure parsing and editing live here; the screen supplies the
// storage object, so tests use a plain Map-backed stand-in.
//
// What is stored, and what is not:
// - Per tenant, under its own key, so a view saved in one tenant never
//   appears in another (tenant names are validated before they form a key).
// - Only non-evidence filters: node, classification, sensor, kind, rule,
//   severity, since, until. Source keys and search text are attacker-
//   influenced evidence and the console keeps evidence out of browser
//   storage (docs/design-system.md, "Console security rules"); a view saved
//   while they are set keeps the other filters and says it dropped them.
// - Everything read back is untrusted: it is parsed defensively, names are
//   cleaned and capped, and filters go through normalizeEventFilters before
//   they can reach a URL or a request.

import { normalizeEventFilters } from './route.js';

export const VIEW_KEYS = Object.freeze(['node', 'classification', 'sensor', 'kind', 'rule', 'severity', 'since', 'until']);
export const NOT_SAVED = Object.freeze(['source', 'q']);
export const MAX_VIEWS = 20;
export const MAX_NAME = 48;
const TENANT = /^[A-Za-z0-9_.-]{1,64}$/;
const PREFIX = 'aegismesh.views.';

export function viewsKey(tenant) {
  const t = TENANT.test(String(tenant ?? '')) ? String(tenant) : 'default';
  return `${PREFIX}${t}`;
}

// Control and bidi-override characters out, whitespace collapsed, capped.
export function cleanName(value) {
  const s = Array.from(String(value ?? '')
    .replace(/[\u0000-\u001f\u007f-\u009f​-‏‪-‮⁦-⁩﻿]/g, '')
    .replace(/\s+/g, ' ').trim());
  return s.slice(0, MAX_NAME).join('');
}

// The filters a view may keep, and the keys that were dropped.
export function viewFilters(filters) {
  const { filters: clean } = normalizeEventFilters(filters || {});
  const kept = {};
  for (const k of VIEW_KEYS) if (clean[k]) kept[k] = clean[k];
  const dropped = NOT_SAVED.filter((k) => clean[k]);
  return { filters: kept, dropped };
}

export function parseViews(raw) {
  let data;
  try {
    data = JSON.parse(String(raw ?? ''));
  } catch {
    return [];
  }
  if (!Array.isArray(data)) return [];
  const out = [];
  const names = new Set();
  for (const v of data) {
    if (!v || typeof v !== 'object') continue;
    const name = cleanName(v.name);
    if (!name || names.has(name.toLowerCase())) continue;
    const { filters } = viewFilters(v.filters && typeof v.filters === 'object' ? v.filters : {});
    if (!Object.keys(filters).length) continue;
    names.add(name.toLowerCase());
    out.push({ name, filters });
    if (out.length >= MAX_VIEWS) break;
  }
  return out;
}

// Add or replace (same name, case-insensitive) a view; newest first.
export function addView(views, name, filters) {
  const clean = cleanName(name);
  if (!clean) throw new Error('Give the view a name.');
  const { filters: kept, dropped } = viewFilters(filters);
  if (!Object.keys(kept).length) {
    throw new Error(dropped.length ? 'Source and search filters are not saved, and no other filter is set.' : 'Set at least one filter before saving a view.');
  }
  const rest = views.filter((v) => v.name.toLowerCase() !== clean.toLowerCase());
  return { views: [{ name: clean, filters: kept }, ...rest].slice(0, MAX_VIEWS), dropped };
}

export function removeView(views, name) {
  return views.filter((v) => v.name !== name);
}

export function loadViews(storage, tenant) {
  try {
    return parseViews(storage?.getItem(viewsKey(tenant)));
  } catch {
    return [];
  }
}

// Returns false when the browser refused (private mode, quota).
export function storeViews(storage, tenant, views) {
  try {
    storage.setItem(viewsKey(tenant), JSON.stringify(views.map((v) => ({ name: v.name, filters: v.filters }))));
    return true;
  } catch {
    return false;
  }
}

// ---- Palette recents ---------------------------------------------------------
// Recently opened palette items, per tenant. Only kinds whose identifier is
// interface data are kept (screens, actions, rules, sensors, investigations
// by id); sources and events are evidence and are never written.

export const RECENT_KINDS = Object.freeze(['screen', 'action', 'rule', 'sensor', 'investigation', 'guide']);
export const MAX_RECENTS = 6;
const RECENT_ID = /^[A-Za-z0-9_.:\-/ ]{1,96}$/;
const RECENTS_PREFIX = 'aegismesh.recent.';

export function recentsKey(tenant) {
  const t = TENANT.test(String(tenant ?? '')) ? String(tenant) : 'default';
  return `${RECENTS_PREFIX}${t}`;
}

export function parseRecents(raw) {
  let data;
  try {
    data = JSON.parse(String(raw ?? ''));
  } catch {
    return [];
  }
  if (!Array.isArray(data)) return [];
  const out = [];
  const seen = new Set();
  for (const r of data) {
    if (!r || !RECENT_KINDS.includes(r.kind) || typeof r.id !== 'string' || !RECENT_ID.test(r.id)) continue;
    const k = `${r.kind}:${r.id}`;
    if (seen.has(k)) continue;
    seen.add(k);
    out.push({ kind: r.kind, id: r.id });
    if (out.length >= MAX_RECENTS) break;
  }
  return out;
}

export function pushRecent(list, entry) {
  if (!entry || !RECENT_KINDS.includes(entry.kind) || typeof entry.id !== 'string' || !RECENT_ID.test(entry.id)) return list;
  const rest = list.filter((r) => !(r.kind === entry.kind && r.id === entry.id));
  return [{ kind: entry.kind, id: entry.id }, ...rest].slice(0, MAX_RECENTS);
}

export function loadRecents(storage, tenant) {
  try {
    return parseRecents(storage?.getItem(recentsKey(tenant)));
  } catch {
    return [];
  }
}

export function storeRecents(storage, tenant, list) {
  try {
    storage.setItem(recentsKey(tenant), JSON.stringify(list));
    return true;
  } catch {
    return false;
  }
}
