// Save an authenticated API attachment (report or indicators) as a file.
//
// The request goes through the console's API client (session cookie, same
// origin; these are GETs, so no CSRF token is involved). The file name is
// one of the server's fixed names, chosen here by kind: the response's
// Content-Disposition is never read, so no server or attacker string can
// pick a name. The object URL is revoked once the browser has the file.

export const DOWNLOAD_NAMES = Object.freeze({
  stix: 'aegismesh-indicators.json',
  csv: 'aegismesh-indicators.csv',
  txt: 'aegismesh-indicators.txt',
  report: 'aegismesh-observation-report.md',
  // Local SIEM event files (GET /export/events), the server's fixed names.
  cef: 'aegismesh-events-cef.log',
  'syslog-rfc5424': 'aegismesh-events-syslog-rfc5424.log',
  'otlp-json': 'aegismesh-events-otlp-json.json',
  ecs: 'aegismesh-events-ecs.ndjson',
});

const int = (v) => {
  const n = Number(v);
  return Number.isInteger(n) && n >= 0 ? n : null;
};

// The bounds and skip counts the server attaches to every download.
export function downloadFacts(headers) {
  const get = (k) => headers?.get?.(k) ?? null;
  return {
    skippedSources: int(get('X-AegisMesh-Skipped-Non-IP-Sources')),
    skippedEvents: int(get('X-AegisMesh-Skipped-Non-IP-Events')),
    scanned: int(get('X-AegisMesh-Scanned-Events')),
    scanLimit: int(get('X-AegisMesh-Scan-Limit')),
    truncated: get('X-AegisMesh-Scan-Truncated') === 'true',
    history: ['complete', 'truncated', 'unavailable'].includes(get('X-AegisMesh-Index-History')) ? get('X-AegisMesh-Index-History') : '',
  };
}

export async function saveResponse(res, kind) {
  const name = DOWNLOAD_NAMES[kind];
  if (!name) throw new Error('unknown download kind');
  const blob = await res.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = name;
  a.hidden = true;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 30000);
  return { name, bytes: blob.size, ...downloadFacts(res.headers) };
}
