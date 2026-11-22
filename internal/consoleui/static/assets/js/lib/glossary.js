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
