# Competitive landscape research

Status: initial research note for the first batch. All vendor claims are recorded as claims, not facts.
Access dates: 2026-08-22 unless noted. Links checked at authoring time.

## 1. Beelzebub (primary reference)

Sources inspected:

- Repository README: <https://github.com/beelzebub-labs/beelzebub> (accessed 2026-08-22)
- Marketing site copy (local capture of beelzebub.ai homepage): `~/.codex/attachments/d621576f-b8ce-4ef3-a672-adc657bf59a4/pasted-text.txt`
- Help Net Security coverage: <https://www.helpnetsecurity.com/2025/02/10/beelzebub-open-source-honeypot-framework/>
- United Ventures investment note: <https://unitedventures.com/2026/07/27/why-we-backed-beelzebub/>

### 1.1 Verified open-source capabilities (from the public repo)

| Capability | Evidence (public README, 2026-08-22) |
|---|---|
| Go deception runtime, GPL-3.0 | Repo license badge and LICENSE; module `github.com/beelzebub-labs/beelzebub/v3` |
| Protocols: SSH, HTTP, TCP, TELNET, MCP | "Multi-protocol coverage" section; per-protocol service docs |
| Two-tier YAML config (core + per-service files), regex command matching | Configuration Reference section |
| LLM-driven adaptive responses via plugins (`LLMHoneypot`, OpenAI or Ollama endpoints) | Key Features / Deception Services sections |
| MCP decoy tools that "should never be invoked under normal operation"; invocation signals guardrail bypass | MCP Deception Service section |
| Plugins compiled into the same process (`init()` registration; `plugin install` fetches from GitHub and rebuilds) | Plugin System section |
| Prometheus metrics on `:2112/metrics`; RabbitMQ event streaming to SIEM | Observability section |
| CLI: `run`, `validate`, `plugin`, `version` | CLI Reference |
| Deployment: Docker, Helm chart, graceful shutdown, per-service memory limit flag | Quick Start / production-ready claims |

### 1.2 Commercial platform claims — recorded as CLAIMS requiring evidence

From the marketing site copy and investor note. None verified by us:

- "Zero False Positives. Every Alert Is a Real Threat." — a strong universal claim; in our experience any
  detection surface has false-positive modes (misconfigured decoys reachable by benign scanners, uptime
  probes, vulnerability scanners on shared networks). We do not repeat this claim about AegisMesh.
- "Cut MTTR from hours to seconds", "reduce SOC operational costs by up to 60%" — unverified percentages;
  no methodology published in the sources we inspected.
- Compliance alignment (NIS2, DORA, EU AI Act, SOC 2) with "undeniable audit trails" — compliance is an
  organizational process; software can produce evidence but cannot make an org compliant.
- "Instant threat containment", autonomous isolation — automated enforcement against real assets is a
  high-blast-radius action; AegisMesh deliberately starts in recommendation/dry-run mode instead.

### 1.3 Design observations relevant to AegisMesh

1. **In-process compiled plugins** are a supply-chain and blast-radius concern: `plugin install` fetches
   third-party Go code and rebuilds the honeypot binary around it; the README itself warns "Install plugins
   only from repositories you trust." AegisMesh keeps first-party sensors compiled in (trusted core) and
   requires any third-party extension to run out-of-process under a capability manifest (ADR-0006).
2. **LLM output is treated as response content** in Beelzebub's LLM honeypots. AegisMesh formalizes this:
   provider output is untrusted data, size-capped and redacted, never executed, never used to pick paths,
   commands, or policy (ADR-0005).
3. **Default addresses include privileged ports** in several published example configs (`:80`, `:22`,
   `:23`). AegisMesh defaults every listener to loopback on unprivileged ports and requires explicit,
   validated opt-in to change either property.
4. **GPL-3.0 core**: fine for Beelzebub, but it constrains embedding for some users. AegisMesh chooses
   Apache-2.0 with zero GPL dependencies so the full product stays permissively licensed (ADR-0007).
5. **Event semantics**: interactions are marketed as confirmed breaches. AegisMesh separates *observation*
   (something touched a decoy) from *incident* (human-verified compromise) in the data model itself.

## 2. Adjacent OSS projects consulted conceptually (not copied)

- **OpenCanary / Thinkst Canary** — low-interaction honeypots with high-fidelity alerts; validates that
  simple, credible decoys with quiet-by-default alerting are operationally valuable. Not a code reference.
- **T-Pot / honeypot aggregators** — demonstrate both the value and the operational weight of running many
  honeypot images; motivates our single-binary, single-config golden path.
- **OWASP Honeypot project** — modular Python honeypots; independent confirmation that YAML-defined decoys
  lower the barrier for small teams.
- No source code, tests, config samples, docs wording, or internal architecture was copied from any of
  these projects. AegisMesh is an independent implementation (clean-room).

## 3. Name collision check (2026-08-22)

Searched for existing uses of "AegisMesh" / "aegis-mesh":

- `github.com/aegismesh` GitHub org exists (content unrelated to deception tech).
- `aegismesh.dev` — an AI-agent security control plane startup (different domain, pre-incorporation).
- `aegismesh.ch` — enterprise gateway/service-mesh company (unrelated domain).
- A hackathon project named AegisMesh (lablab.ai, June 2026) and an unrelated Devpost entry.
- `github.com/aegis-mesh/aegisbox` Go module exists (different path).

Conclusion / uncertainty: the *product name* is not unique across the industry. The *Go module path*
`github.com/metaforismo/aegismesh` is org-namespaced and therefore unambiguous for Go tooling. Before
publishing to package registries beyond GitHub (Homebrew tap names, container image coordinates under the
`metaforismo` org), re-verify those specific coordinates; recorded here as an open item rather than a
resolved fact.

## 4. What AegisMesh does differently (summary; details in docs/PRODUCT.md)

1. Full defensive lifecycle intended as transparent OSS — no open-core split, no "commercial only" tier for
   response or intelligence.
2. Local-first and offline-capable: deterministic local provider means a working demo needs no API key and
   no internet.
3. Secure defaults as product: loopback binds, unprivileged ports, bounded queues/bodies/timeouts,
   redaction-on-write, retention bounds — enforced in code and validated by `aegismesh doctor`.
4. Safer extension model: out-of-process, manifest+digest(+optional signature) verified, permission-scoped,
   deadline- and output-limited, revocable. No plugin compilation into the core binary.
5. Honest evidence language: events are observations; classification and incident status require operator
   verification. The event envelope encodes this distinction.
6. Explainable CLI with dry-run everywhere, actionable errors, JSON output for automation, and a
   five-minute empty-directory-to-running-demo golden path.
7. Migration over lock-in: `aegismesh migrate beelzebub` imports documented public YAML shapes clean-room,
   dry-run first, never touching source files, reporting unsupported fields exactly.
