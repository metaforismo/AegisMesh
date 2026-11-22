# AI observation pack implementation design

Ground: sensor -> policy.Enforcer -> detect.Engine; sensor-owned redaction ->
event.Bus -> authoritative append -> correlation. Process workers reconstruct
sensors from a bounded WorkerSpec. Catalog metadata drives CLI and console.

Candidate A: central bus-only scanner. Rejected: raw SSH credentials are already
dropped, HTTP headers are minimized, and preview truncation destroys matches.
Candidate B (selected): immutable honeytoken.Matcher injected through Enforcer;
each sensor scans acquired bounded fields and scrubs before preview. Detection
receives typed HTTP context plus safe token matches. No new response engine.

Usage sketch: NewEnforcer(detection, meter, tokens...); Evaluate(sensor, Input{
Text, Method, Path, Headers, Body, RawParts}); Scrub(string) before Preview.
Finding retains only fixed rule metadata, family, credential class and token id.
All added findings are observe-only at the enforcement seam.

Credential distinctness uses ephemeral SHA-256 digests in Envelope.AuthAttempts
(json excluded), including private worker IPC. Only correlation rings consume
these digests; persistence, API serialization and forwarding omit them. COR-007
cannot be reconstructed from stored evidence alone. Signals retain source IDs.

Correlation appends COR-005..008, reuses per-source caps/window/cooldown and event
time. AI family metadata is typed; token ids remain in findings. Scaffold uses
existing static HTTP rules and crypto/rand deployment variation, local provider,
no fallback. Design stages: grounded, compared and implemented; exact verification results
are recorded in docs/verification.md. No separate approval or commit is requested.
