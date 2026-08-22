# FAQ

**Is AegisMesh a honeypot?**
It shares the deception-technology problem space but is local-first and
evidence-focused: decoys bind loopback by default, never execute input, and
produce bounded redacted evidence. See docs/PRODUCT.md and
docs/THREAT-MODEL.md for the precise positioning.

**Can it execute attacker commands like a high-interaction honeypot?**
No — by design. Responses are static rules or canned/deterministic LLM text.
Nothing attacker-controlled reaches exec, paths, or config. This is an
invariant, not a feature flag.

**What are MCP canaries for?**
Agents (human-directed or autonomous) that can reach your network should
never call tools labeled as restricted internal surface. Any call is a
high-signal `canary_invocation` event. The operator model: deploy canary
tools where agents might scrape them; investigate every hit. See
docs/canary-model.md.

**Where does evidence go, and who reads it?**
JSONL segments under `runtime.data_dir` on the machine running AegisMesh.
Nothing leaves the machine. `inspect list/show/export` read it locally;
export produces plain NDJSON you own.

**Is evidence tamper-proof?**
Tamper-*evident*: each event carries a SHA-256 over its payload, verified at
read/export time. There is no chain-of-custody anchor yet (roadmap); treat
integrity failures as compromise of the host, not just the file.

**Does it send my data to an LLM API?**
Not in this release. Only the deterministic offline provider exists; remote
adapters fail closed until roadmap R2 lands.

**Why strict config parsing?**
A decoy platform's worst failure mode is silently doing something other than
what the operator wrote. Unknown fields, misplaced fields, and ambiguous
values are rejected with line numbers instead.

**How is this different from Beelzebub?**
Independent clean-room implementation; no code/text shared. The importer
translates documented Beelzebub YAML shapes with exact per-field reporting.
Differences are tabulated in docs/research/competitive-landscape.md.

**Is this production-ready?**
It is a tested vertical slice (v0.1.0): real listeners, evidence pipeline,
CLI, extension contract — plus honest limits (no TLS termination on decoys,
local provider only, Compose-only container support). Read docs/ROADMAP.md
before deploying anywhere you care about.
