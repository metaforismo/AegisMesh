# AegisMesh threat model

Version: 0.1.0. Method: STRIDE-per-trust-boundary plus agentic-specific threats. Living document.

## Assets

- A1 Evidence store (contains attacker payloads, synthetic credentials, operator environment hints)
- A2 Operator workstation/host running the runtime
- A3 Decoy configurations (persona definitions, response rules)
- A4 Admin endpoints (health/metrics/readiness)
- A5 Extension manifests and extension host
- A6 Reputation/integrity of the evidence chain (if evidence can be tampered with, it is worthless)

## Trust boundaries

- TB1: Attacker network → sensor listeners (HTTP/TCP/MCP). Everything crossing this line is untrusted.
- TB2: Sensor runtime core → storage (evidence writes).
- TB3: Config files on disk → runtime (operator-controlled, but must be validated: configs may come from
  repos, migration imports, or other machines — treat as semi-trusted input).
- TB4: LLM provider (local fake or remote API) → policy layer. Provider output is untrusted data.
- TB5: Extensions → extension host (out-of-process; untrusted code by definition).
- TB6: Admin listener → operators/monitoring. Loopback-only by default.

## STRIDE summary per boundary

| Boundary | Threats | Mitigations in this batch |
|---|---|---|
| TB1 | Spoofing source IPs, DoS via slowloris/huge bodies/regex bombs, injection via logged payloads, decoy escape | No trust of client-supplied identity fields (recorded as data, never used for authz); server timeouts + MaxBytesReader + bounded read loops; Go regexp (RE2, no catastrophic backtracking) + pattern length caps at validation time; all payload bytes percent-encoded/redacted before write; sensors have no filesystem/exec capability — responses come from config rules or provider text only |
| TB2 | Log/evidence forging after compromise, unbounded disk growth | Envelope carries SHA-256 integrity hash over the canonical payload; per-event sequence numbers from the writing process; retention enforces max count and max age; redaction applied at event construction (single choke point) |
| TB3 | Malicious config (SSRF-ish binds, privileged ports, regex abuse, huge allocations), path traversal via body_file | Strict schema validation with unknown-field rejection; bind address policy check (public/privileged requires explicit opt-in flags); regex compile with length caps; body_file resolved relative to config dir with symlink+containment checks |
| TB4 | Prompt-injected provider output instructing follow-on actions, jailbreak content stored/replayed, provider SSRF | Provider output treated exactly like attacker input: size-capped, redacted, stored as quoted text; it can only ever become a decoy *response string* — there is no code path from provider output to exec, paths, config mutation, or enforcement; outbound provider URL is fixed by config, allowlisted scheme http(s), timeout-bounded |
| TB5 | Malicious extension code, manifest spoofing, output flooding, zombie processes | Out-of-process execution only; manifest schema validation; required sha256 digest + optional ed25519 signature verification; handshake version negotiation; hard deadlines; stdout size caps; revocation = process kill; host refuses to auto-start extensions (operator runs `aegismesh ext` explicitly) |
| TB6 | Recon via metrics/health, header injection into admin responses | Separate loopback-only listener, no attacker-reachable data in responses, explicit opt-out documented but default on |

## Agentic-specific threats

1. **Prompt injection against agent tool surfaces** — the MCP canary exists to detect exactly this: any
   `tools/call` against a canary is a guardrail-bypass signal. The canary's own tool descriptions are static,
   config-provided strings; the sensor never generates descriptions from observed traffic (prevents
   description-poisoning feedback loops).
2. **Tool poisoning** — a decoy's returned "results" are synthetic and clearly derived from config; we do not
   fabricate live-looking secrets beyond the declared synthetic persona, and every value is generated from
   the config file, reviewable in VCS.
3. **Event spoofing / evidence poisoning** — an attacker who can reach sensors can inflate event volume or
   plant payloads. Accepted residual risk (inherent to deception tech); mitigated by rate limits per sensor
   and integrity hashing that proves what the sensor saw (not what the attacker wanted recorded). Cross-host
   attestation is roadmap.
4. **Decoy escape** — decoys expose no interpreter, no exec, no file APIs; MCP canary "actions" return canned
   JSON. Escape surface reduces to the Go HTTP/TCP parsers themselves (hardened, stdlib-maintained).

## Residual risks accepted in this batch

- Single-process runtime: a parser 0-day in Go's net stack could crash the runtime (availability loss, not
  escape). Per-sensor OS isolation is a roadmap option (ADR-0002 alternative).
- Local JSONL evidence is plaintext at rest; disk encryption is the operator's responsibility. At-rest
  encryption is roadmap.
- The deterministic local provider produces obviously-synthetic text; realism against human attackers is a
  roadmap concern for real providers (with the same untrusted-output pipeline).

## Explicitly out of scope (never build)

Autonomous exploitation, credential theft, persistence mechanisms, botnet participation, destructive
containment (e.g., firewall-dropping production IPs without approval), phishing delivery infrastructure,
execution of captured malware samples.
