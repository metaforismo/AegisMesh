# AI service decoys and behavioural observations

`aegismesh init --profile ai-decoy --dir ./ai-lab` scaffolds static synthetic
HTTP APIs on `127.0.0.1:11434` and `127.0.0.1:8001`. It configures the local
provider, no fallback, one fake credential and one agent marker. There is no
model behind these surfaces: requests never cause inference, model downloads,
key creation, code execution or changes to configuration or assets.
`examples/ai-decoy.yaml` is a checked-in synthetic example; generate a fresh
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

Formats `openai`, `anthropic`, `aws`, `github`, and `generic` add recognizable
prefixes and an explicit synthetic marker plus 128 random bits. They are
look-alikes, not valid provider-issued credentials. Merge the printed snippet
into your configuration; the command does not modify files or contact a provider.

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
listener: request shape alone cannot identify vLLM. `/version` and `/metrics`
are vLLM-like enumeration surfaces here, and ordinary version/metrics clients
can match this low rule. Generic root `/` is deliberately not enough to
identify an AI family. No user-agent, rotating IP, provider access validation,
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
| COR-005 | Last N events for one peer host, sorted by event time in the window ending at the trigger. Upper median inter-arrival gap is 1..30 seconds, and at most one gap differs from that median by more than 25%. Equal timestamps do not establish a cadence. Summary: consistent with scripted or agent-driven activity. Ordinary scanners, scheduled clients and uptime monitors may match. |
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
hits on the checked-in 24-sample synthetic benign corpus, and checks eight
attack-shaped interactions covering every new detection rule. The test fails
if any medium-or-higher detection rule fires on the benign set. Measurement
results are recorded in `docs/verification.md` after execution. These counts
are properties of this corpus, **not a false-positive rate or a field claim**.
The companion checked-in corpus has four benign event sequences and four
attack-shaped sequences covering COR-005..008. On this four-sequence synthetic
benign corpus, COR-006 hits once (ordinary clients of two AI families); other
correlation rules hit zero times. Unit cases additionally cover a cadence
outlier, repeated auth values, source controls, cooldown and bounds.

On this 24-sample synthetic benign interaction corpus, LLM-001 hits 7 times
and LLM-004 hits once; every other detection rule hits zero times. No
medium-or-higher rule fires on these samples. These are corpus counts, not a
false-positive rate, attribution accuracy or field measurement.

`aegismesh demo` also sends a fixed synthetic enumeration -> one-token request
-> fake-key replay -> agent-marker sequence to its own OS-assigned loopback
HTTP decoy. It verifies redacted evidence and prints the observed rule IDs;
`demo --console` exposes those same observations in the local console. There
is no LLM client, external service, offensive framework or real key involved.
