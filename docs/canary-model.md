# The canary model: MCP tools no honest agent should call

AegisMesh's MCP sensor exposes a decoy MCP (Model Context Protocol) server
whose tools look operationally interesting — `canary:prod-db-export`,
`read_build_log`, `fetch_artifact` — but are pure fiction. The operator
model has three parts.

## 1. Honest agents never call restricted surface

The design bet: a well-behaved agent, given an agent-visible tool catalog,
calls only what its task requires and what policy allows. Tools with names
like `prod-db-export` are not "required" for any legitimate task that hasn't
been granted production access already. So:

- **listing** the tools (`tools/list`) is an ordinary `interaction` — recon
  happens, and knowing who listed is useful but unalarming;
- **calling** any canary tool is a `canary_invocation` — the highest-signal
  event AegisMesh emits, because there is no honest reason for it.

## 2. Every answer is canned; nothing executes

`result_json` returns a fixed synthetic payload (a plausible "queued export"
receipt). There is no database behind it, no filesystem, no subprocess. The
security invariant holds even if the caller is fully malicious: the worst
outcome is that the attacker learns nothing except that we learned
everything.

Unknown tool names still record a canary event (rule `unknown-tool`) and get
a JSON-RPC invalid-params error — probing is itself signal.

## 3. Operator workflow

1. Deploy one or more MCP sensors where agents might discover them
   (internal networks, CI runners' egress paths, developer workstations).
2. Treat every `canary_invocation` in evidence as an investigation trigger:
   who/what connected (`remote_host`), which tool, argument preview
   (redacted, hashed) in `args_preview`/`args_sha256`.
3. Feed `inspect export --verify` NDJSON into your existing alerting/SIEM
   pipeline if you have one; the schema is documented in
   docs/architecture/data-flow.md.
4. Run `aegismesh recommend --data-dir DIR --classification canary_invocation`
   for deterministic, evidence-linked investigation guidance. The output is a
   proposal, not an incident determination or enforcement instruction.

## What this model is NOT

- Not attribution: an event proves a connection from a host, not intent.
- Not containment: AegisMesh never blocks, rate-limits, or retaliates.
- Not proof of compromise on its own — it is a signal to investigate.
