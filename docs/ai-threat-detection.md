# AI service decoys and behavioural observations

`aegismesh init --profile ai-decoy --dir ./ai-lab` scaffolds static synthetic
HTTP APIs on `127.0.0.1:11434` and `127.0.0.1:8001`. It configures the local
provider, no fallback, one fake credential and one agent marker. There is no
model behind these surfaces: requests never cause inference, model downloads,
key creation, code execution or changes to configuration or assets.
`examples/ai-decoy.yaml` is a checked-in template with rejected `REPLACE_WITH_`
placeholders. Replace both markers everywhere using `honeytoken new`, or generate a fresh
profile for each deployment instead of reusing its marker values.

The first listener serves Ollama root/version/tags/ps/generate/chat/show/pull,
OpenAI-compatible models/chat/completions/embeddings, LiteLLM health/model/key
information and key-generation shapes, and vLLM version/metrics shapes. The
second serves a vLLM-style `/v1/models` variant. JSON and text bodies are small
static responses; inference-shaped replies are 200, embeddings is a static
401 with an OpenAI-style missing-key error (even when a key is supplied).
Method mismatches use the existing 405 behaviour. Model names and version
personas come from a small built-in pool; response IDs and both markers use
crypto/rand at scaffold time. This reduces byte-identical deployment
fingerprints; it does not make a decoy indistinguishable from a real service.

## Honeytokens and agent markers

```yaml
honeytokens:
  - id: planted-key
    kind: credential
    value: synthetic-example-key-marker
  - id: diagnostic-echo
    kind: agent_canary
    value: synthetic-example-agent-marker
```

These values must be fake. **Never use a real credential as a honeytoken.**
Plant credential markers only in decoy material; ordinary production use of the
same string would invalidate the observation's premise. Plant an agent marker
in decoy text that instructs a client to request a diagnostic path or echo a
string. The generated `/key/info` and `/key/generate` replies contain the fake
key; `/model/info` contains the diagnostic instruction. A human or scanner can
copy these too: neither hit proves a client is an LLM or identifies an attacker.

The optional top-level list accepts at most 64 entries. IDs are unique slugs
`[a-z0-9][a-z0-9-]{0,63}`; values are unique, 16..256 printable ASCII bytes
without spaces; kinds are exactly `credential` or `agent_canary`. Unknown
fields fail strict decoding. Values are never interpolated into regexes.
Matching is case-sensitive plain substring matching in separately acquired,
bounded fields, not a timing-side-channel-resistant secret comparison. There
is no cross-field concatenation, decoding of obfuscated markers, or scan of
bytes a sensor did not acquire. It covers HTTP URI/query and all received
header names/values and body, TCP lines, MCP message/arguments and SSH
username/password. Existing protocol read caps still apply (at most 4 MiB per
field); tokens beyond a read cap are not observed. Token matching is separate
from the shorter legacy detection text preview.

Redaction records include `honeytoken_scrub`. Native findings retain `token_id`; preview content is replaced with
`[honeytoken:<id>]` before generic credential scrubbing and truncation. Dropped
queries, non-allowlisted header values and SSH credentials remain dropped;
their safe finding supplies the token id. Matching/redaction stays active when
findings are disabled. Disabling detection suppresses findings, not redaction.
Values are not logged. Config files and planted response bodies deliberately
contain these fake values and must never contain real keys.

Generate another synthetic marker with:

```sh
aegismesh honeytoken new --kind credential --format openai --id planted-key
aegismesh honeytoken new --kind agent_canary --format generic --id diagnostic-echo
```

Formats use crypto/rand with unbiased rejection sampling: `openai` is `sk-proj-`
plus 48 base62 characters; `anthropic` is `sk-ant-api03-` plus 86 base64url
characters and `AA`; `aws` is `AKIA` plus 16 characters from A-Z/2-7; `github`
is `ghp_` plus 36 base62 characters; `generic` is 40 hexadecimal characters.
No generated value contains an intentional synthetic marker. Values are locally
random and never registered or validated with a provider. An offline generator
cannot prove that a random string can never collide with a provider credential;
no such guarantee is claimed. Never use real keys. Merge the printed snippet
and replace any planted response-body copies; the command does not modify files
or contact a provider. Repository fixtures contain short obvious fakes or
runtime-generated markers, not committed full provider-shaped values.

## Detection rules

Existing registration order and meanings remain unchanged. These are appended
in this order, and **all six are observe-only**, irrespective of configured
severity actions or the throttle limit. An older rule matching the same input
still has its usual action.

| Rule | Severity | Observable predicate |
|---|---|---|
| LLM-001 | low | A known AI API request path, or a valid message to the MCP HTTP sensor; records `ai_family`. Prose mentions do not match. |
| LLM-002 | medium | POST to a completion/chat/generate path, valid JSON within `detection.max_input_bytes` (default 8 KiB, max 64 KiB), explicit `max_tokens`, `num_predict` or `options.num_predict` in 0..5, and a nonempty prompt of at most 32 bytes total. At most two user/system messages; no other roles. Every supplied budget must be tiny. Consistent with a minimal-cost validation probe; legitimate clients can match. |
| LLM-003 | medium | POST/PUT/DELETE to known model pull/push/create/delete/copy or LiteLLM model/key mutation paths, or DELETE to `/v1/models/<id>`; consistent with resource hijacking. |
| LLM-004 | low | A provider-shaped or placeholder key in a credential context; stores only `credential_class`. |
| HT-001 | critical | A configured credential marker was presented inbound; records the token id. |
| AGT-001 | high | An inbound agent marker followed a diagnostic instruction embedded in decoy content; consistent with an LLM-driven client. |

Families are `ollama`, `openai_compatible`, `litellm`, `vllm`, `mcp_http`.
Shared `/v1/*` paths are classified `openai_compatible`, including the second
listener: request shape alone cannot identify vLLM. Distinctive `/tokenize`,
`/detokenize`, `/v1/score`, `/rerank` and `/invocations` select the vLLM-like
family. `/mcp` identifies the MCP HTTP path. Generic `/version`, `/metrics`,
`/sse` and root `/` do not identify AI families or contribute families to
COR-006, although the decoy still serves version/metrics responses. No user-agent, rotating IP, provider access validation,
client attribution or model call is used to infer these findings.

LLM-004 recognizes Bearer in Authorization/Proxy-Authorization, X-API-Key /
API-Key values, top-level JSON or query `api_key`/`key`/`token`, TCP bare-key or
AUTH lines, and SSH passwords. Prose mentions do not establish a presentation. Classes are `openai_like`, `anthropic_like`, `aws_like`,
`github_like`, `placeholder` (EMPTY, ollama, sk-xxxx). Selection is bounded and
deterministic; values are minimized using the credential redaction path.

## Correlation rules

Correlation remains opt-in (`correlation.enabled: true`), single-node,
event-time based, and non-enforcing. Defaults remain a 600-second window,
64 events/source and 4096 sources, with existing caps, FIFO eviction and
one-window cooldown per source/rule. Disable IDs with
`correlation.disabled_rules`. New thresholds use 0/omitted for 8:

```yaml
correlation:
  enabled: true
  automation_threshold: 8  # 4..per_source_events
  credential_threshold: 8  # 3..per_source_events
```

| Rule | Exact predicate and limitations |
|---|---|
| COR-005 | Last N events for one peer host, sorted by event time in the window ending at the trigger. There are N-1 adjacent gaps for the last N events. Fire if their upper median is <1 second, OR if it is <=30 seconds and at most one gap differs from that median by more than 25%. Exactly 1/30 seconds are inclusive in the regular branch; exactly 25% difference is allowed. Zero gaps count in the fast branch; ties may reflect timestamp precision or scheduling, not client reactions. Summary: consistent with scripted or agent-driven activity. Ordinary scanners, scheduled clients and uptime monitors may match. |
| COR-006 | One source touched at least two distinct AI families within the window, using LLM-001 finding metadata. A disabled LLM-001 supplies no family evidence. |
| COR-007 | At least N distinct bounded credential attempts from one source within the window, across HTTP auth headers and SSH password authentication. HTTP Basic and SSH compare the username/password tuple; bearer/API-key values compare as keys. Duplicate attempts count once. Synthetic SSH accepts bounded passwords, so these are attempts, not failed logins. |
| COR-008 | HT-001 on the triggering sensor, after an earlier-in-event-time interaction by the **same peer host** with a different sensor ID, inside the window. It does not prove that the earlier sensor disclosed the token. |

New rules exclude events later than the trigger on out-of-order arrivals.
All signals link to contributing envelope IDs. Sources are direct peer hosts,
not forwarded headers; NAT can group clients and IP rotation can split them.
No cross-source, cross-node, historical stuffing replay or restart continuity
is claimed.

Distinctness for COR-007 uses length-framed SHA-256 digests **only in memory**:
sensor -> bounded private worker IPC when enabled -> bus -> correlation ring.
The digests are excluded from native JSON, storage, console indexes, exports,
extensions, webhooks and fleet forwarding. Only event IDs reach the derived
signal. This rule therefore cannot be recomputed from saved evidence alone;
review that deliberate privacy/reproducibility tradeoff. No secret or digest
is persisted for offline guessing.

## Framework references

`rules list`, `rules explain` (text and JSON) and `GET /api/v1/rules` expose
`frameworks: [{framework, id, name}]`. The exact editorial table is pinned in
`internal/rulecatalog/testdata/frameworks.tsv`, including explicit empty cells.
Frameworks are only `mitre-attack`, `mitre-atlas`, `owasp-llm-2025`.
These are **editorial "relates to" references**, not claims of framework
coverage, completeness, attribution or compliance. AGT-001's mapping reflects
the prompt-injection technique the defender mirrors in decoy content, not
proof of attacker use of that technique. References are fixed in this change;
no runtime fetch or framework content can influence behaviour.

## Synthetic measurement and demo

`go test -v ./internal/ruletest -run TestSyntheticCorpus` reports each rule's
hits on the checked-in 26-sample synthetic benign corpus, and checks nine
attack-shaped interactions covering every new detection rule. The test fails
if any medium-or-higher detection rule fires on the benign set. Measurement
results are recorded in `docs/verification.md` after execution. These counts
are properties of this corpus, **not a false-positive rate or a field claim**.
The companion checked-in corpus has four benign event sequences and four
attack-shaped sequences covering COR-005..008. On this four-sequence synthetic
benign corpus, COR-006 hits once (ordinary clients of two AI families); other
correlation rules hit zero times. Unit cases additionally cover a cadence
outlier, repeated auth values, source controls, cooldown and bounds.

On this 26-sample synthetic benign interaction corpus, LLM-001 hits 6 times
and LLM-004 hits once; every other detection rule hits zero times. No
medium-or-higher rule fires on these samples. These are corpus counts, not a
false-positive rate, attribution accuracy or field measurement.

`aegismesh demo` also sends a fixed synthetic enumeration -> one-token request
-> fake-key replay -> agent-marker sequence to its own OS-assigned loopback
HTTP decoy. It verifies redacted evidence and prints the observed rule IDs;
`demo --console` exposes those same observations in the local console. There
is no LLM client, external service, offensive framework or real key involved.


## Console stories and operator downloads

The console now derives bounded source sessions with a 30-minute idle threshold,
rule-linked phases, cadence and explicit automation observations; eight non-signal
events are the minimum for a non-inconclusive assessment. Signals are excluded
from automation timing to avoid generated timestamp artefacts. Framework views
count unique observed entries per catalog technique; these are editorial
relations, never completeness or technique-success claims. Analyst downloads
provide conservative STIX/CSV/TXT IP indicators and inert Markdown observation
reports with proposed, unexecuted recommendations. No model, enforcement or
console egress is added. The newest-8192 scan, 200-event detail cap, 2 MiB response
limit, formulas, roles and final field shapes are in
[console-api.md](architecture/console-api.md), ADR-0022 and [cli.md](cli.md).

## Multi-step MCP environment (round 3, local)

The AI-decoy scaffold additionally declares a bounded synthetic workspace on
`127.0.0.1:8002`. Five fixed tools select static in-memory file/env/query content,
record connection steps and scrubbed sequences, and append observe-only
MCP-001..003 findings. Configuration, limits, exact lookup semantics and the
existing HT-001/COR-008 replay boundary are in
[mcp-environments.md](mcp-environments.md). The demo now contains a short
multi-step MCP exploration (eleven total observations, eight dry-run proposals).
Local SIEM files and on-demand periodic summaries add no delivery/egress edge;
see [siem-export.md](siem-export.md) and [console-api.md](architecture/console-api.md).

## Actor profile

Every session (`GET /api/v1/sessions`, `/sessions/{id}`, campaign detail)
carries `actor: {assessment, summary, signals}`. It is a hedged observation
derived from retained, redacted summaries; it never names a person, tool,
model or organisation, and it does not replace the existing `automation`
field, which keeps its earlier semantics. Signals are small pure functions in
`internal/evidenceview/actor.go`; **all ten are always listed**, with
`present:false` when evaluated and not observed. Timing uses interactions
only (correlation signals excluded), as for `automation`.

| Code | Strength | Present when (constants in `actor.go`) |
|---|---|---|
| `regular_cadence` | moderate | >= 8 interactions, upper-median gap <= 30 s and at most 1 gap outside median ±25%; or COR-005 fired |
| `sub_second_bursts` | moderate | >= 8 interactions and upper-median gap < 1 s |
| `agent_canary_followed` | strong | AGT-001 fired (an `agent_canary` marker came back) |
| `honeytoken_replayed` | moderate | HT-001 or COR-008 fired |
| `tool_call_chaining` | strong | MCP `tools/list` before the first `tools/call`, >= 3 calls, >= 2 distinct tools, and at least one tool reused (a one-call-per-tool sweep does not qualify) |
| `sdk_client_family` | moderate | an HTTP User-Agent self-identifies as an LLM SDK or agent framework (OpenAI, Anthropic, LangChain, LlamaIndex, LiteLLM, Ollama client, MCP client) |
| `adaptive_after_error` | strong | a decoy 400/405/415/422 followed, within the next 3 interactions and <= 3 s, by a 2xx on the same sensor and path |
| `human_think_time` | moderate | >= 8 interactions, upper-median gap 2 s..2 min, <= 50% of gaps within ±25% of it, <= 25% of gaps under 1 s |
| `typo_corrections` | moderate | a 404 followed 1..60 s later, same sensor, by a path >= 4 characters within edit distance 2 |
| `multi_surface_sweep` | weak | COR-002 or COR-006 fired |

Assessment rule, first match wins:

1. `possibly_ai_agent`: >= 3 interactions and any of `agent_canary_followed`,
   `tool_call_chaining`, `adaptive_after_error`. Fast or regular traffic alone
   never reaches this level.
2. `inconclusive`: fewer than 8 interactions.
3. `inconclusive`: automation signals (`regular_cadence`, `sub_second_bursts`,
   `sdk_client_family`) and human signals both present.
4. `likely_automated`: any automation signal.
5. `likely_human`: `human_think_time` or `typo_corrections`. Absence of
   automation is never enough.
6. `inconclusive` otherwise.

Caveats. A source key is a peer address: NAT, proxies and shared egress can
merge clients (making timing look irregular or fast) and one client can
rotate addresses. A person can copy a canary, retry quickly with shell
history, or drive an agent; an agent can add jitter. The User-Agent is
client-controlled and only mapped to a closed family vocabulary (the raw value
is not retained by the index). Small samples are inconclusive by design. These
are observations to prioritise review, not attribution or verdicts.

## Campaigns

`GET /api/v1/campaigns` groups sessions from **different source keys** that
followed the same behaviour. Each session's interactions become *shapes*:

- HTTP: method (uppercase A–Z, else `OTHER`) plus path template. Per segment:
  digits-only `{n}`, UUID `{uuid}`, hex >= 8 chars `{hex}`, > 32 runes
  `{token}`, >= 10 bytes with >= 3 digits `{id}`, `[honeytoken:…]`
  `{honeytoken}`, `[redacted…]` `{redacted}`; at most 12 segments then `/…`.
  The decoy status suffix is removed using the stored status, never parsed
  from text. Query strings are never stored.
- MCP: method plus tool name (same segment rule). SSH: `login <method> ·
  <outcome>`; commands are not captured by the authentication-only sensor.
  TCP: `exchange · rule <name>` or `exchange · no rule`; banners and line
  content are not part of the index projection, so no banner class exists.
- Correlation signals are not steps.

Shapes come from already scrubbed stored fields, are scrubbed again with
`redact.Scrub`, control characters are replaced and they are capped at 120
runes. They remain attacker-influenced text. Consecutive repeats are collapsed
and a session keeps at most 32 steps.

**Rule.** A session with >= 3 collapsed steps has fingerprint = its first
`min(len, 8)` kind/shape pairs. Sessions with equal fingerprints form a
campaign when they span >= 2 distinct source keys. Shorter sequences must
therefore match exactly; longer ones share the first eight steps. `basis` is
`same_step_sequence` (every member has the identical full sequence) or
`same_step_prefix`, plus `same_client_family` when every member reported one
identical, non-`other` client family. The ID is `cmp_` + the first 12 hex of
SHA-256 over the JSON array `[tenant, fingerprint]`: stable while the
fingerprint exists, different per tenant. Each session belongs to at most one
campaign (`campaign_id`, otherwise `null`). Bounds: newest 4096 sessions of
the newest-8192-event sample, 100 campaigns per list, 20 sources and 50
session references per campaign, 32 steps.

Limits. A five-step session does not join a campaign whose members share
eight steps; similarity scoring was rejected for explainability (ADR-0024).
Public scanners and common tools produce identical sequences, so a campaign is
shared behaviour, never a shared operator.

## Posture review

`GET /api/v1/posture` and `aegismesh posture --config FILE [--json]` run fixed
checks over a secret-free snapshot of the validated configuration and the
retained sample. Statuses are `attention`, `ok` or `info`; `ok` carries no
recommendation. It is advisory, never a security guarantee. Details never
include token values, digests, URLs or secret references. For a console tenant
other than `local_tenant`, only POS-017 is evaluated (`scope: evidence_only`).

| ID | Area | Attention / info when |
|---|---|---|
| POS-001 | exposure | info: a sensor binds beyond loopback (intended for decoys; anything on that network can reach it) |
| POS-002 | exposure | info: `allow_public_bind`, `allow_privileged_ports` or `allow_private_llm_egress` is set |
| POS-003 | exposure | info: console beyond loopback with TLS; attention without TLS (validation normally prevents it) |
| POS-004 | exposure | attention: a sensor's LLM fallback sends attacker prompts to a non-loopback provider; info for loopback |
| POS-005 | exposure | info: webhook or fleet evidence forwarding enabled (notes a hub without `hub_ca_file`) |
| POS-006 | access | attention: every token operator is admin, or a single token without OIDC; info if console disabled |
| POS-007 | deception | attention: no honeytokens |
| POS-008 | deception | attention: honeytokens but no `agent_canary` |
| POS-009 | deception | attention: a token found in no inline decoy content (body files are not read) |
| POS-010 | deception | info: no configured token observed in the retained sample (normal when quiet) |
| POS-011 | deception | attention: no AI-family HTTP surface and no MCP sensor |
| POS-012 | deception | info: an MCP sensor without a synthetic environment, or no MCP sensor |
| POS-013 | detection | attention: detection disabled; info: rules disabled |
| POS-014 | detection | attention: correlation disabled; info: rules disabled |
| POS-015 | detection | info: a severity maps to throttle/isolate/refuse (decoy-only, but observable) |
| POS-016 | evidence | info: a configured sensor has no local observations in the sample |
| POS-017 | evidence | attention: the newest-8192 analysis sample is saturated, older evidence is not analysed |
| POS-018 | evidence | info: evidence encryption at rest is off |
| POS-019 | access | info: no config-file admin token can sign in, so recovery depends on managed accounts or OIDC (the CLI review cannot see managed accounts) |

The CLI reads the newest 8192 verified envelopes from `--data-dir` (default
`runtime.data_dir`); when evidence is missing, encrypted without `--identity`
or contains unverifiable lines, POS-010/016/017 report "Not evaluated". There
are no configurable redaction or evidence-verification settings, so no check
claims to review them.
