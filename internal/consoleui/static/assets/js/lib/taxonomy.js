// Closed vocabularies from the console API contract. API values are matched
// against these before they influence a class name, label or route.

export const SEVERITIES = Object.freeze(['info', 'low', 'medium', 'high', 'critical']);

const SEVERITY_LABELS = Object.freeze({
  info: 'Info', low: 'Low', medium: 'Medium', high: 'High', critical: 'Critical',
});

export function isSeverity(value) {
  return SEVERITIES.includes(value);
}

// Rank: unknown or "" (no finding) ranks below info.
export function severityRank(value) {
  return SEVERITIES.indexOf(value);
}

export function compareSeverity(a, b) {
  return severityRank(a) - severityRank(b);
}

export function maxSeverity(values) {
  let best = '';
  for (const v of values) if (severityRank(v) > severityRank(best)) best = v;
  return best;
}

export function severityLabel(value) {
  return SEVERITY_LABELS[value] ?? 'No finding';
}

// Classification key → presentation key used in CSS class names.
export const CLASSIFICATIONS = Object.freeze(['interaction', 'canary_invocation', 'correlation_signal']);

const CLASSIFICATION_META = Object.freeze({
  interaction: { label: 'Interaction', glyph: 'interaction' },
  canary_invocation: { label: 'Canary invocation', glyph: 'canary' },
  correlation_signal: { label: 'Correlation signal', glyph: 'signal' },
});

export function isClassification(value) {
  return CLASSIFICATIONS.includes(value);
}

export function classificationMeta(value) {
  return CLASSIFICATION_META[value] ?? { label: 'Unknown classification', glyph: null };
}

export const SENSOR_KINDS = Object.freeze(['http', 'tcp', 'ssh', 'mcp']);
export const SENSOR_STATES = Object.freeze(['running', 'failed', 'stopped']);
export const INVESTIGATION_STATUSES = Object.freeze(['open', 'monitoring', 'closed']);
export const PRIORITIES = Object.freeze(['low', 'medium', 'high']);
export const ROLES = Object.freeze(['viewer', 'analyst', 'admin']);
export const WINDOWS = Object.freeze(['1h', '24h', '7d']);
export const HISTORY_STATES = Object.freeze(['complete', 'truncated', 'unavailable']);
export const AUDIT_ACTIONS = Object.freeze([
  'session.login', 'session.login_failed', 'session.logout',
  'session.oidc_login', 'session.oidc_denied', 'session.tenant_switch',
  'investigation.create', 'investigation.update', 'investigation.note',
  'investigation.attach', 'investigation.detach', 'audit.read', 'audit.verify',
  'authz.denied',
  'fleet.token.create', 'fleet.token.delete', 'fleet.node.enroll', 'fleet.node.revoke',
  'fleet.node.rejected',
  'export.indicators', 'session.report', 'investigation.report',
]);

export function roleAtLeast(role, minimum) {
  const have = ROLES.indexOf(role);
  return have >= 0 && have >= ROLES.indexOf(minimum);
}

export function capitalize(value) {
  const s = String(value ?? '');
  return s ? s[0].toUpperCase() + s.slice(1) : s;
}
