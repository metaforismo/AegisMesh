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
`inspect list/show/export` read it locally; export produces native or
ECS-compatible NDJSON you own. Nothing leaves by default. An explicitly enabled
webhook sends bounded evidence batches to its fixed operator-configured endpoint,
and an explicitly selected remote provider sends bounded prompt context to its
fixed API endpoint.

**Is evidence tamper-proof?**
Tamper-*evident*: each event carries a SHA-256 over its payload, verified at
read/export time. There is no chain-of-custody anchor yet (roadmap); treat
integrity failures as compromise of the host, not just the file.

**Does it send my data to an LLM API?**
Not by default. The deterministic offline provider is the default. Opt-in
`ollama` and OpenAI-compatible adapters are shipped with fixed destinations,
dial-time egress checks, credential references, cancellation, and response caps.

**Why strict config parsing?**
A decoy platform's worst failure mode is silently doing something other than
what the operator wrote. Unknown fields, misplaced fields, and ambiguous
values are rejected with line numbers instead.

**How is this different from Beelzebub?**
Independent clean-room implementation; no code/text shared. The importer
translates documented Beelzebub YAML shapes with exact per-field reporting.
Differences are tabulated in docs/research/competitive-landscape.md.

**Is this production-ready?**
No production-readiness claim is made. It is a tested early vertical slice with
real listeners and evidence paths, plus honest limits: no TLS termination on
decoys, no at-rest encryption, an authentication-only SSH decoy with no
post-authentication channels, no autonomous response, and no verified
real-cluster Kubernetes support. Read docs/ROADMAP.md first.
