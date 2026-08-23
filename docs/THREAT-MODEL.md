# AegisMesh threat model

Version: 0.1.0. Method: STRIDE-per-trust-boundary plus agentic-specific threats. Living document.

## Assets

- A1 Evidence store (contains attacker payloads, synthetic credentials, operator environment hints)
- A2 Operator workstation/host running the runtime
- A3 Decoy configurations (persona definitions, response rules)
- A4 Admin endpoints (health/metrics/readiness)
- A5 Extension manifests and extension host
- A6 Reputation/integrity of the evidence chain (if evidence can be tampered with, it is worthless)
- A7 Provider/webhook credential references and operator-configured outbound destinations

## Trust boundaries

- TB1: Attacker network → sensor listeners (HTTP/TCP/MCP). Everything crossing this line is untrusted.
- TB2: Sensor runtime core → storage (evidence writes).
- TB3: Config files on disk → runtime (operator-controlled, but must be validated: configs may come from
  repos, migration imports, or other machines — treat as semi-trusted input).
- TB4: LLM provider (local deterministic or remote API) → policy layer. Provider output is untrusted data.
- TB5: Observer extensions ↔ extension supervisor (out-of-process; untrusted code by definition).
- TB6: Admin listener → operators/monitoring. Loopback-only by default.
- TB7: Runtime → operator-configured remote provider or webhook collector. Disabled by default; fixed destinations only.

## STRIDE summary per boundary

| Boundary | Threats | Mitigations in this batch |
|---|---|---|
| TB1 | Spoofing source IPs, DoS via slowloris/huge bodies/regex bombs, injection via logged payloads, decoy escape | No trust of client-supplied identity fields (recorded as data, never used for authz); server timeouts + MaxBytesReader + bounded read loops; Go regexp (RE2, no catastrophic backtracking) + pattern length caps at validation time; all payload bytes percent-encoded/redacted before write; sensors have no filesystem/exec capability — responses come from config rules or provider text only |
| TB2 | Log/evidence forging after compromise, unbounded disk growth | Envelope carries SHA-256 integrity hash over the canonical payload; per-event sequence numbers from the writing process; retention enforces max count and max age; redaction applied at event construction (single choke point) |
| TB3 | Malicious config (SSRF-ish binds, privileged ports, regex abuse, huge allocations), path traversal via body_file | Strict schema validation with unknown-field rejection; bind address policy check (public/privileged requires explicit opt-in flags); regex compile with length caps; body_file resolved relative to config dir with symlink+containment checks |
| TB4 | Prompt-injected provider output instructing follow-on actions, jailbreak content stored/replayed, provider SSRF | Provider output treated exactly like attacker input: size-capped, redacted, stored as quoted text; it can only ever become a decoy *response string* — there is no code path from provider output to exec, paths, config mutation, or enforcement; outbound provider URL is fixed by config, allowlisted scheme http(s), timeout-bounded |
| TB5 | Malicious extension code, manifest spoofing, output flooding, zombie processes, compromised extension artifact | Out-of-process execution only; manifest schema validation; required sha256 digest + optional ed25519 signature verification; handshake negotiation; deadlines/output caps; minimal environment; revocation = process kill. Configured `observe` extensions may auto-start, but replies are acks/errors and have no path to policy, evidence mutation, filesystem selection or enforcement |
| TB6 | Recon via metrics/health, header injection into admin responses | Separate loopback-only listener, no attacker-reachable data in responses, explicit opt-out documented but default on |
| TB7 | SSRF, DNS rebinding, secret disclosure, redirect abuse, data exfiltration, unbounded provider/collector cost | Outbound edges are opt-in and fixed by validated config; destination classification occurs before startup and at dial time; redirects/proxies are refused; credentials resolve before listeners bind and are never logged; requests, responses, queues, retries and time are bounded. Enabling either edge intentionally sends data outside the host |

## Agentic-specific threats

1. **Prompt injection through descriptions, schemas and returned content** — all three are untrusted prompt
   surfaces. AegisMesh serves static, config-reviewed tool definitions and canned synthetic results; observed
   traffic never rewrites them and returned content cannot invoke another tool or reach execution.
2. **Mutable-definition rug pulls and tool shadowing** — a compromised server can change a previously approved
   tool or influence selection of a more privileged tool. The shipped decoy is a server, not a general MCP
   client, and has no cross-server tool router. Future client/gateway work must pin complete definitions and
   isolate each server as its own security domain.
3. **Confused deputy, excessive permissions and token passthrough** — the shipped decoy has no downstream
   authority and implements no protected-resource authorization flow. Future authenticated MCP work must bind
   tokens to the server audience/resource (and issuer where applicable), reject over-scoped credentials, and
   obtain a separate token for any upstream API; inbound tokens must never be forwarded.
4. **Context over-sharing and indirect exfiltration** — MCP arguments and remote-provider prompts may contain
   sensitive context. Inputs are capped and redacted before storage; remote providers remain explicit egress.
   No component may encode captured context into a new destination or tool call.
5. **Extension/model supply-chain compromise** — digest/signature checks establish artifact identity, not
   benign behavior, and remote model behavior can change outside this repository. Extensions stay
   out-of-process and data-only; provider output stays size-capped, redacted and non-behavioral.
6. **Event spoofing / evidence poisoning** — an attacker who can reach sensors can inflate event volume or
   plant payloads. This inherent residual risk is mitigated by resource caps and integrity hashing, which
   proves what the sensor recorded rather than the attacker's identity or intent. Cross-host attestation is future work.
7. **Canary over-interpretation** — a `canary_invocation` is an observation that a tool was called. It can
   result from prompt injection, direct exploration, operator testing or misconfiguration; it is not proof of
   compromise and never triggers enforcement.
8. **Decoy escape** — decoys expose no interpreter, shell, exec, or file API; MCP "actions" return canned JSON.
   Escape surface is limited to the protocol parsers and Go runtime.

## Residual risks accepted in this batch

- Single-process runtime: a parser 0-day in Go's net stack could crash the runtime (availability loss, not
  escape). Per-sensor OS isolation is a roadmap option (ADR-0002 alternative).
- Local JSONL evidence is plaintext at rest; disk encryption is the operator's responsibility. At-rest
  encryption is roadmap.
- Remote providers can improve realism but intentionally disclose bounded prompt context to the configured
  endpoint and can incur cost; the deterministic local provider remains the zero-egress default.

## Primary agentic-security references

- [OWASP MCP Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/MCP_Security_Cheat_Sheet.html)
  for tool/schema/output poisoning, rug pulls, cross-server isolation and least privilege.
- [OWASP MCP Tool Poisoning](https://owasp.org/www-community/attacks/MCP_Tool_Poisoning)
  for indirect prompt injection through tool results.
- [MCP authorization specification](https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization)
  for resource indicators, audience validation, token-passthrough prohibition and confused-deputy controls.

These are design references. Their presence does not imply that optional MCP
authorization or multi-server client behavior is implemented here.

## Explicitly out of scope (never build)

Autonomous exploitation, credential theft, persistence mechanisms, botnet participation, destructive
containment (e.g., firewall-dropping production IPs without approval), phishing delivery infrastructure,
execution of captured malware samples.
