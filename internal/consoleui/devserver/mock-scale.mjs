// `--scale large`: synthetic volume comparable to the backend's seeded demo
// (`aegismesh demo --console --seed large`), so the console can be measured
// and tuned for real scale: ~50,000 events over 7 days, hundreds of sources,
// several dozen sensors, many campaigns (some with dozens of lanes and long
// playbooks) and thousands of audit records.
//
// Everything is deterministic and synthetic: addresses come only from the
// RFC 5737 / RFC 3849 documentation ranges. The generators take the mock's
// own seeded random function, so `--scale normal` (the default) never calls
// them and its data set is unchanged.

export const SCALES = Object.freeze(['normal', 'large']);

export const LARGE = Object.freeze({
  events: 50000,
  sources: 640,
  extraSensors: 40,
  campaigns: 36,
  auditRecords: 6000,
});

const NETS = ['192.0.2', '198.51.100', '203.0.113'];

// Fisher-Yates with the mock's seeded random, so runs stay deterministic.
function shuffled(list, rand) {
  const a = [...list];
  for (let i = a.length - 1; i > 0; i--) {
    const j = Math.floor(rand() * (i + 1));
    [a[i], a[j]] = [a[j], a[i]];
  }
  return a;
}

// A pool of distinct documentation-range sources: IPv4 from the three
// TEST-NETs, then IPv6 from 2001:db8::/32 once those run out.
export function sourcePool(n, rand) {
  const out = new Set();
  let guard = 0;
  while (out.size < n && guard++ < n * 20) {
    if (out.size < 700) out.add(`${NETS[Math.floor(rand() * 3)]}.${1 + Math.floor(rand() * 254)}`);
    else out.add(`2001:db8:${Math.floor(rand() * 0xffff).toString(16)}::${Math.floor(rand() * 0xffff).toString(16)}`);
  }
  return [...out];
}

// Extra decoys of the common kinds, named like a real estate's edge.
export function extraSensors(n) {
  const kinds = [['http', 'web-edge', 8080], ['ssh', 'ssh-edge', 2222], ['tcp', 'tcp-edge', 6390], ['mcp', 'mcp-edge', 8190]];
  return Array.from({ length: n }, (_, i) => {
    const [kind, name, base] = kinds[i % kinds.length];
    return { id: `${name}-${String(Math.floor(i / kinds.length) + 1).padStart(2, '0')}`, kind, listen: `127.0.0.1:${base + i}`, state: i % 13 === 7 ? 'failed' : 'running', process_isolation: kind !== 'http' };
  });
}

// Heavy-tailed source choice: a few sources make most of the noise, like a
// real internet-facing decoy (scanners), with a long tail of one-offs.
export function pickSource(pool, rand) {
  return pool[Math.min(pool.length - 1, Math.floor(rand() ** 2.4 * pool.length))];
}

const PATHS = [
  '/wp-login.php', '/wp-admin/setup-config.php', '/.env', '/.git/config', '/admin', '/admin/login', '/phpmyadmin/', '/server-status',
  '/api/v1/users', '/api/v1/models', '/v1/models', '/api/tags', '/api/version', '/actuator/health', '/actuator/env', '/console',
  '/solr/admin/cores', '/cgi-bin/luci', '/boaform/admin/formLogin', '/HNAP1/', '/owa/auth/logon.aspx', '/remote/login', '/vpn/index.html',
  '/geoserver/web/', '/jenkins/login', '/manager/html', '/.aws/credentials', '/config.json', '/debug/pprof/', '/metrics', '/graphql',
  '/v2/_catalog', '/druid/index.html', '/nacos/', '/xmlrpc.php', '/user/login', '/autodiscover/autodiscover.xml', '/sdk', '/api/jsonws',
];
const SSH_USERS = ['root', 'admin', 'ubuntu', 'oracle', 'test', 'git', 'deploy', 'pi', 'postgres', 'user', 'support', 'ftp'];
const EXEC = ['recon', 'download', 'persistence', 'miner', 'cleanup'];

// Many campaigns: each a playbook (an opening of four distinct steps plus a
// tail) run by several sources inside the analysis window, members skipping
// or adding a step so the score has gaps. A few run from dozens of sources
// and take long playbooks, to stress the score's lanes and columns.
export function campaignRuns({ now, rand, pool, count = LARGE.campaigns }) {
  const runs = [];
  for (let g = 0; g < count; g++) {
    const ssh = g % 4 === 3;
    const big = g % 9 === 0;
    const lanes = big ? 30 + Math.floor(rand() * 40) : 2 + Math.floor(rand() * 7);
    const length = big ? 14 + Math.floor(rand() * 10) : 5 + Math.floor(rand() * 5);
    const steps = [];
    if (ssh) {
      const users = shuffled(SSH_USERS, rand).slice(0, 3 + (g % 4));
      users.forEach((u) => steps.push(['ssh', `auth password user=${u} password=[redacted]`]));
      steps.push(['ssh', 'session open shell (decoy prompt)']);
      EXEC.slice(0, 2 + (g % 3)).forEach((c) => steps.push(['ssh', `exec class=${c} cmd="…" (decoy output)`]));
    } else {
      const order = shuffled(PATHS, rand);
      for (let i = 0; i < length; i++) steps.push(['http', `${i % 5 === 3 ? 'POST' : 'GET'} ${order[i]} → ${[200, 401, 403, 404][(g + i) % 4]}`]);
    }
    const gap = ssh ? 1500 + Math.floor(rand() * 2000) : 400 + Math.floor(rand() * 9000);
    for (let lane = 0; lane < lanes; lane++) {
      const source = pool[Math.floor(rand() * pool.length)];
      // Inside the newest ~2 hours so the 8,192-event analysis snapshot
      // still holds them.
      const start = now - Math.floor(rand() * 2 * 3600e3) - 60e3;
      // Keep the opening (it defines the campaign); drop some later steps.
      const mine = steps.filter((_, i) => i < 4 || rand() > 0.22);
      runs.push({ campaign: g, source, start, gap, steps: mine });
    }
  }
  return runs;
}

// Audit records spread over the last 30 days, oldest first, for the audit
// trail's long list. Actions and actors from the mock's own vocabulary.
export function auditBackfill({ now, rand, count = LARGE.auditRecords }) {
  const who = [['ana', 'analyst'], ['ada', 'admin'], ['vera', 'viewer'], ['svc-export', 'analyst']];
  const actions = [
    ['session.login', 'ok', ''], ['event.read', 'ok', 'local:'], ['audit.read', 'ok', ''], ['investigation.create', 'ok', 'inv_'],
    ['investigation.note', 'ok', 'inv_'], ['export.events', 'ok', ''], ['session.login_failed', 'denied', ''], ['authz.denied', 'denied', ''],
    ['report.session', 'ok', ''], ['session.logout', 'ok', ''],
  ];
  const span = 30 * 86400e3;
  return Array.from({ length: count }, (_, i) => {
    const [actor, role] = who[Math.floor(rand() * who.length)];
    const [action, outcome, target] = actions[Math.floor(rand() ** 1.5 * actions.length)];
    const t = now - span + Math.floor((i / count) * span) + Math.floor(rand() * 60e3);
    const hex = Array.from({ length: target === 'local:' ? 32 : 12 }, () => Math.floor(rand() * 16).toString(16)).join('');
    return {
      time: new Date(t).toISOString().replace(/\.\d+Z$/, 'Z'),
      actor: action === 'session.login_failed' ? '' : actor, role: action === 'session.login_failed' ? '' : role,
      action, target: target ? `${target}${hex}` : '', outcome,
      remote: `${NETS[i % 3]}.${10 + (i % 200)}`,
      detail: action === 'export.events' ? `format=jsonl window=24h events=${100 + Math.floor(rand() * 5000)}` : '',
    };
  });
}
