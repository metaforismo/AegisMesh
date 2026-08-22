# Security Policy

## Reporting a vulnerability

Do **not** open a public issue for security problems.

Email: **security@metaforismo.dev** (private disclosure; PGP key published at
`docs/security/pgp-key.txt` when the first release ships — until then, state "no PGP" in your subject and
we will arrange an encrypted channel).

Include: affected version/commit, environment, reproduction steps or PoC, impact assessment. You will get an
acknowledgment within 72 hours and a status update at least every 7 days until resolution.

## Scope

In scope:

- Any code path where untrusted input (network bytes, config files, LLM output, extension artifacts)
  escapes its trust boundary (exec, path traversal, SSRF, config mutation, evidence tampering).
- Decoy escape: any way a decoy gains execution or filesystem access.
- Supply-chain: dependency compromise, build reproducibility breaks.
- The extension host: sandbox escape, manifest verification bypass.

Out of scope:

- Attacks requiring local operator privileges on the host already running AegisMesh.
- Volumetric DoS against decoy listeners (bounded by design; report bypasses of the *bounds* though).
- Reports that assume non-default configurations (public binds, disabled caps) without demonstrating a
  default-config exploit.

## Design invariants we treat as security bugs if broken

1. Inbound bytes / provider output never influence exec, paths, policy, or enforcement.
2. Default configuration always binds loopback on unprivileged ports.
3. Events are redacted before storage; storage cannot be bypassed by sensors.
4. Extensions never load into the main process; manifests verify digests before execution.

## Supported versions

Pre-1.0: only the latest `master` receives fixes. Releases are tagged; see docs/RELEASE.md.
