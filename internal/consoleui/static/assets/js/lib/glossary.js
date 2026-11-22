// The in-product guide: what the console's words mean. Plain data, so the
// Guide screen, the "what is this?" tips and the palette read one source,
// and a test checks every cross-reference resolves.
//
// Copy rules: describe what the product does today, state limits plainly,
// never claim detection of something the runtime does not do. Everything
// here is interface text written by the project, never API data.

export const GLOSSARY = Object.freeze([
  {
    id: 'observation',
    term: 'Event (observation)',
    group: 'Reading events',
    short: 'One thing a decoy sensor recorded. An observation, not an incident.',
    body: [
      'Every row in Events is one stored envelope: a connection, a request, a tool call, or a derived correlation signal, with the time, the sensor that saw it and the source it came from.',
      'An event says what happened against a decoy. It does not say who was behind it or whether it matters. Deciding that is your call, and Investigations is where you record it.',
    ],
    see: ['incident', 'classification', 'evidence'],
  },
  {
    id: 'incident',
    term: 'Observation vs incident',
    group: 'Reading events',
    short: 'The console never declares an incident. Counts are observations.',
    body: [
      'Decoys have no legitimate users, so any touch is worth a look, but a scanner, a misconfigured script and a targeted operator can all produce the same event. Classification is mechanical; incident determination requires a person.',
      'For that reason changes against the previous window are printed in neutral ink: more observations are not "worse" and fewer are not "better".',
    ],
    see: ['observation', 'recommendation'],
  },
  {
    id: 'classification',
    term: 'Classification',
    group: 'Reading events',
    short: 'Interaction, canary invocation or correlation signal. Mechanical, never a verdict.',
    body: [
      'Interaction (circle): ordinary contact with a decoy, such as a request, a login attempt, or listing an MCP server\'s tools.',
      'Canary invocation (diamond): use of a planted surface no honest client should touch, such as calling a canary MCP tool. It is the highest-signal class the runtime emits, because there is no legitimate reason for it.',
      'Correlation signal (triangle): a derived event written by a correlation rule that links several earlier events, for example one source switching between protocols (protocol hopping) or probing tools. Its related events are listed on its detail page.',
    ],
    see: ['canary', 'correlation'],
  },
  {
    id: 'canary',
    term: 'Canary invocation',
    group: 'Reading events',
    short: 'A planted tool or credential was used. Treat each one as a reason to investigate.',
    body: [
      'Canary tools look operationally interesting but are fiction: every answer is a canned, synthetic payload and nothing executes. Listing them is an interaction; calling one is a canary invocation.',
      'Unknown tool names are recorded as canary events too, because probing is itself signal.',
    ],
    cli: 'aegismesh recommend --data-dir DIR --classification canary_invocation',
    see: ['classification', 'recommendation'],
  },
  {
    id: 'severity',
    term: 'Severity',
    group: 'Findings and rules',
    short: 'The highest severity among an event\'s findings, or "No finding". Shown as a five-step meter plus a word.',
    body: [
      'Severity belongs to findings, not to events: an event takes the highest severity of the detection findings it carries. Most events carry no finding at all, which is normal for decoy traffic.',
      'The minimum-severity filter keeps events at that level or above; it cannot select "No finding".',
    ],
    see: ['finding', 'rule'],
  },
  {
    id: 'finding',
    term: 'Finding',
    group: 'Findings and rules',
    short: 'A detection rule matched an event. Rule-authored text; it never quotes the matched input.',
    body: [
      'A finding carries the rule id, a severity, a confidence and a reason written by the rule\'s author. The reason is interface text; the matched input stays in the event\'s evidence.',
    ],
    see: ['rule', 'correlation', 'severity'],
  },
  {
    id: 'correlation',
    term: 'Findings vs correlation signals',
    group: 'Findings and rules',
    short: 'A finding annotates one event; a correlation signal is a new event that links several.',
    body: [
      'Detection rules look at one event and attach findings to it. Correlation rules look across events and, when their condition holds, write a separate correlation signal that cites the events it was built from.',
      'Correlation rules have no severity of their own. Signals are stored like any other event and appear in the same lists.',
    ],
    see: ['finding', 'classification'],
  },
  {
    id: 'rule',
    term: 'Rule',
    group: 'Findings and rules',
    short: 'A detection or correlation rule from the runtime\'s registry. Rules screen lists them.',
    body: [
      'Rule ids such as PI-001 appear on events and in the Top rules panel. Selecting one filters the events that cite it.',
    ],
    cli: 'aegismesh rules list',
    see: ['finding', 'correlation'],
  },
  {
    id: 'evidence',
    term: 'Evidence text',
    group: 'Reading events',
    short: 'Text in tinted monospace came from the attacker, exactly as received.',
    body: [
      'Paths, previews, user agents, tool names, summaries and source keys are attacker-controlled. The console shows them as plain text on a faint violet inset and never interprets them: no links, no markup, no formatting.',
      'Long values are shortened in tables; hover or focus them to read the full value, or open the event.',
    ],
    see: ['source', 'observation'],
  },
  {
    id: 'source',
    term: 'Source',
    group: 'Reading events',
    short: 'The remote host, or a correlation key, an event came from. What the sensor recorded, not a verified identity.',
    body: [
      'Addresses can be spoofed, shared or relayed, so a source is a lead, not an attribution. The Source page shows everything loaded for one source, its activity over time, and the gaps between its events.',
    ],
    see: ['cadence', 'evidence'],
  },
  {
    id: 'cadence',
    term: 'Cadence (gaps between events)',
    group: 'Reading events',
    short: 'How regularly a source\'s events arrive, computed in the browser from the loaded events.',
    body: [
      'Scripts and agent tool loops often arrive at short, regular gaps; people arrive irregularly. The cadence strip shows the distribution of gaps between consecutive loaded events and a few plain statistics.',
      'It is an observation, never a verdict: a person can be regular, a program can be slow, and the strip only sees the events that are loaded on the page.',
    ],
    see: ['source'],
  },
  {
    id: 'recommendation',
    term: 'Recommendations',
    group: 'Acting on what you see',
    short: 'Proposed, not executed. Nothing in the console changes a sensor, a policy or a firewall.',
    body: [
      'Recommendations are deterministic guidance generated from recent evidence (at most the latest 4,096 indexed envelopes). Each one is a proposal for a person to review; the console has no enforcement path.',
    ],
    cli: 'aegismesh recommend --data-dir DIR',
    see: ['incident'],
  },
  {
    id: 'investigation',
    term: 'Investigation',
    group: 'Acting on what you see',
    short: 'Your notes and a set of attached events. Operator-authored, audited, never automatic.',
    body: [
      'Investigations are where an analyst records what a set of events means. Creating one, changing it, adding notes and attaching events each write an audit record.',
    ],
    see: ['audit'],
  },
  {
    id: 'index',
    term: 'Index bounds',
    group: 'Limits',
    short: 'The console reads a bounded, in-memory index of recent events. Older evidence stays on disk.',
    body: [
      'The index keeps the newest events up to its configured size (50,000 by default) and a memory budget. When it has evicted older events its history is "truncated"; with evidence encrypted at rest the runtime cannot read stored history and the index starts at process start ("unavailable").',
      'Counts, charts and lists describe the index, not all evidence ever recorded. Use the CLI to read the full store.',
    ],
    cli: 'aegismesh inspect list --data-dir DIR --verify',
    see: ['observation'],
  },
  {
    id: 'integrity',
    term: 'Integrity',
    group: 'Limits',
    short: 'Each event\'s stored hash is recomputed when you open it. It proves the record is unchanged, not who wrote it.',
    body: [
      'A verified seal means the stored envelope matches its recorded hash. Forwarded copies on a hub are checked for consistency on that hub; the forwarding node\'s own store stays the authoritative record.',
    ],
    see: ['audit'],
  },
  {
    id: 'audit',
    term: 'Audit trail',
    group: 'Limits',
    short: 'A hash-chained log of console actions. It proves internal consistency, not writer identity.',
    body: [
      'Sign-ins, investigation changes and reading the audit trail itself are recorded. Verification checks that every record links to the previous one; someone with write access to the file could still rewrite the whole chain.',
    ],
    see: ['integrity'],
  },
  {
    id: 'session',
    term: 'Session',
    group: 'Sessions and AI decoys',
    short: 'Consecutive events from one source key, until it was quiet for more than 30 minutes.',
    body: [
      'Sessions are built on request from the newest 8,192 indexed events; nothing is stored. Correlation signals and forwarded copies with the same source key are included. The timeline shows the first 200 events.',
      'A source key is not an actor identity: NAT and proxies can combine clients, and one client can change address. A session id is derived from its first retained event, so it can change when that event ages out or the process restarts.',
      'Stages (discovery, credential access, AI service use, decoy credential replay) name which rules fired in a run of events. They can recur in any order and do not infer intent.',
    ],
    see: ['regularity', 'automation', 'source'],
  },
  {
    id: 'regularity',
    term: 'Pace and regularity',
    group: 'Sessions and AI decoys',
    short: 'The gaps between a session’s events: median, 90th percentile, shortest, events per minute, and how many gaps sit near the median.',
    body: [
      'The median is the upper median of the gaps; the 90th percentile is nearest-rank. Events per minute is (events − 1) divided by the elapsed minutes.',
      'Regularity is the share of gaps within 25% of the median gap; with a zero median, only zero gaps count. A short, steady pace is typical of scripts and agent tool loops; uptime monitors and scheduled clients can look the same. Zero gaps can be clock precision.',
    ],
    see: ['automation', 'cadence'],
  },
  {
    id: 'automation',
    term: 'Automation observation',
    group: 'Sessions and AI decoys',
    short: 'Whether a session’s pace or rules are consistent with automation, with each supporting observation listed. Never a verdict.',
    body: [
      'At least eight non-signal events are needed; with fewer the reading is “too few events”. Then any one of these holds the reading “consistent with automation”: a median interaction gap under a second; a median of 1 to 30 seconds with at most one gap more than 25% away; or AGT-001, COR-005, COR-006, HT-001 or COR-008 in the session.',
      '“No automation pattern established” means none of these selected checks held. It is not evidence of a person. Correlation signals are left out of the timing, because their timestamps are generated.',
    ],
    see: ['regularity', 'agentcanary', 'honeytoken'],
  },
  {
    id: 'honeytoken',
    term: 'Honeytoken (decoy credential)',
    group: 'Sessions and AI decoys',
    short: 'A fake credential planted only in decoy material. If it comes back inbound (HT-001), whoever sent it read the decoy.',
    body: [
      'The operator configures fake values and plants them in decoy responses such as a key-information page. Evidence keeps only the token id, never the value. COR-008 links a replay to earlier contact by the same peer on another sensor; it does not prove that sensor disclosed it.',
      'Never use a real credential as a honeytoken.',
    ],
    cli: 'aegismesh honeytoken new --kind credential --format openai --id planted-key',
    see: ['agentcanary', 'llmjacking'],
  },
  {
    id: 'agentcanary',
    term: 'Agent canary',
    group: 'Sessions and AI decoys',
    short: 'An instruction planted in decoy text that asks the reader to fetch a path or echo a marker. Following it is AGT-001.',
    body: [
      'An LLM-driven client that reads decoy content may act on the instruction. A person or a scanner can copy it too, so a hit is consistent with an LLM client, not proof of one.',
    ],
    cli: 'aegismesh honeytoken new --kind agent_canary --format generic --id diagnostic-echo',
    see: ['honeytoken', 'automation'],
  },
  {
    id: 'llmjacking',
    term: 'LLMjacking pattern',
    group: 'Sessions and AI decoys',
    short: 'Looking for exposed AI services to use someone else’s quota: enumerate endpoints, validate a key cheaply, then use or change resources.',
    body: [
      'The AI decoy profile serves static Ollama, OpenAI-compatible, LiteLLM and vLLM shapes; no model runs behind them. LLM-001 notes a known AI API path, LLM-002 a minimal-cost completion probe (a tiny token budget), LLM-003 a model or key change, LLM-004 a provider-shaped key, and COR-006 one source touching several AI families.',
      'A session can show these steps in order; the console describes the observations and never concludes the service was abused successfully.',
    ],
    cli: 'aegismesh init --profile ai-decoy --dir ./ai-lab',
    see: ['honeytoken', 'session'],
  },
  {
    id: 'mapping',
    term: 'Technique mapping (editorial)',
    group: 'Sessions and AI decoys',
    short: 'Rules list the MITRE ATT&CK, MITRE ATLAS and OWASP LLM 2025 entries they relate to. Editorial references, not coverage.',
    body: [
      'The Techniques screen counts indexed events in the window that cited a rule related to each technique. An observed technique means a related rule fired, not that the technique was used or succeeded; an unobserved one means no related rule fired, not that the technique is detectable or was absent.',
      'AGT-001 relates to prompt injection because the defender mirrors that technique in decoy content, not because an attacker used it.',
    ],
    see: ['rule', 'session'],
  },
  {
    id: 'blocklist',
    term: 'Proposed blocklist and indicators',
    group: 'Sessions and AI decoys',
    short: 'IP indicators exported for your own tools. Proposed for review; AegisMesh never applies them.',
    body: [
      'Only literal IPv4 and IPv6 source keys are exported; anything else is skipped and counted. Confidence is 15 out of 100 on purpose: contact with a decoy is an observation. STIX 2.1, CSV and a plain list are available to analysts; each download is recorded in the audit trail.',
    ],
    see: ['recommendation', 'source'],
  },
  {
    id: 'decoy',
    term: 'Decoy',
    group: 'Decoys and planted markers',
    short: 'A synthetic service that exists only to be found. Nothing behind it is real, so any contact is an observation worth reading.',
    body: [
      'Each configured sensor is a decoy: an HTTP, TCP, SSH or MCP listener that answers from static configuration. The Decoys screen lists them with what they imitate, their static rules, tools and fake files, and the honeytoken ids planted in their responses.',
      'The console reads the catalog from the running configuration and cannot add, change or stop a decoy. Response bodies, prompts, file contents and token values are never returned by the API.',
    ],
    cli: 'aegismesh run --config mesh.yaml --dry-run',
    see: ['aidecoy', 'mcpenv', 'honeytoken'],
  },
  {
    id: 'aidecoy',
    term: 'AI-service decoy',
    group: 'Decoys and planted markers',
    short: 'A decoy shaped like an Ollama, OpenAI-compatible, LiteLLM or vLLM endpoint. No model runs behind it.',
    body: [
      'The surface family is derived from the configured request paths, never from prose or a user agent. Responses are static bodies: a model list, a tiny completion, a key-information page carrying a planted credential.',
      'Contact is recorded as LLM-001 to LLM-004 observations. They describe the request shape; they do not establish that a model was used or that a key was valid.',
    ],
    cli: 'aegismesh init --profile ai-decoy --dir ./ai-lab',
    see: ['llmjacking', 'decoy', 'honeytoken'],
  },
  {
    id: 'mcpenv',
    term: 'MCP decoy environment',
    group: 'Decoys and planted markers',
    short: 'A synthetic MCP workspace with five tools (list_files, read_file, get_env, search, run_query) over declared fake entries.',
    body: [
      'Every answer is exact declared content: there is no file system, environment, shell or database behind the tools. Arguments are lookup keys, never paths or commands; anything unknown gets a fixed “not found”.',
      'MCP-001 observes a read of a declared credential-bearing file or env entry; MCP-002 a connection reaching the configured exploration depth; MCP-003 a write- or execution-shaped tool name (nothing is executed). All three are observe-only. A later presentation of the planted value is HT-001, and COR-008 can link it to the earlier contact on another sensor.',
      'The sequence is tracked per connection only; it is not identity tracking across reconnects or proxies.',
    ],
    see: ['decoy', 'honeytokenhit', 'session'],
  },
  {
    id: 'honeytokenhit',
    term: 'Honeytoken hit',
    group: 'Decoys and planted markers',
    short: 'An event whose detection metadata names a planted id: the fake value came back. An observation, not proof of successful use.',
    body: [
      'A decoy-credential hit (HT-001) means the fake value only present in decoy material was presented to a sensor. It cannot have worked anywhere, because it is fake. An agent-canary hit (AGT-001) means a planted instruction marker came back, which is consistent with a client acting on what it read.',
      'The Honeytokens screen counts hits per id in the window and lists the source keys that presented it. A source key is not an actor identity, and a hit does not say which response disclosed the value. Values are never shown by the console.',
    ],
    cli: 'aegismesh honeytoken new --kind credential --format openai --id planted-key',
    see: ['honeytoken', 'agentcanary', 'mcpenv'],
  },
  {
    id: 'digest',
    term: 'Digest',
    group: 'Decoys and planted markers',
    short: 'A briefing for the last 24 hours or 7 days against the window before, computed on demand. Nothing is scheduled or sent.',
    body: [
      'Totals by class, new and returning sources (new means absent from the window before, not first ever), sessions consistent with automation, the most cited rules, related techniques cited for the first time in the comparison, planted-marker hits, open investigations and dry-run recommendations, followed by the server’s limits.',
      'The console can copy it as Markdown (server strings fenced as code) or print it. The CLI produces the same digest from local evidence.',
    ],
    cli: 'aegismesh digest --since 24h --data-dir ./data --format md',
    see: ['incident', 'automation', 'recommendation'],
  },
  {
    id: 'siemformats',
    term: 'SIEM event formats',
    group: 'Decoys and planted markers',
    short: 'CEF, RFC 5424 syslog, OTLP JSON and ECS files of the observations, for import into your own tools. AegisMesh sends nothing.',
    body: [
      'Analysts can download one session, source, investigation or window as a file. The server reads at most the newest 8192 events, caps the output at 2 MiB, records the download in the audit trail and uses a fixed file name.',
      'OTLP JSON is a file format only: AegisMesh ships no exporter or collector client. Severity in each file is the rule catalog’s, not an incident rating. No external SIEM was tested.',
    ],
    cli: 'aegismesh export events --data-dir ./data --format cef',
    see: ['blocklist', 'audit'],
  },
]);

const BY_ID = new Map(GLOSSARY.map((e) => [e.id, e]));

export const glossaryEntry = (id) => BY_ID.get(id) || null;
export const isGlossaryId = (id) => BY_ID.has(id);

export function glossaryGroups() {
  const groups = [];
  for (const e of GLOSSARY) {
    let g = groups.find((x) => x.title === e.group);
    if (!g) groups.push((g = { title: e.group, entries: [] }));
    g.entries.push(e);
  }
  return groups;
}
