# AGENTS.md — durable engineering and safety rules

Instructions for AI agents (and humans) working in this repository. These rules outlive any single task.

## Safety rules (never override)

1. **Defensive only.** Never implement: autonomous exploitation, credential theft, persistence, botnet
   behavior, destructive containment, phishing delivery, or execution of captured malware.
2. **Untrusted data never becomes behavior.** Network bytes, config files, LLM output, and extension
   artifacts must never reach: `os/exec`, filesystem path selection, configuration mutation, or enforcement
   actions. There is no exception and no "just this once".
3. **Secure defaults are invariant.** Loopback bind + unprivileged ports by default; caps on bytes, time,
   queue depth, regex length; redaction before storage; dry-run for anything that could affect real assets.
4. **Honesty over marketing.** Do not claim capabilities that are not implemented and verified. Events are
   observations, not incidents. Never write "zero false positives" or similar unprovable claims.

## Engineering rules

5. Small cohesive packages; explicit dependencies injected at seams (`Sensor`, `llm.Provider`,
   `event.Sink`, `observe.Meter`); typed errors with actionable context.
6. Strict config decoding; every new config field gets validation, docs, and a test.
7. Tests are evidence: table-driven units, integration tests that start real listeners on loopback,
   golden files for CLI output, fuzz seeds for parsers. No vacuous tests, no fake mocks of things you own.
8. Formatting/lint/tests/race must pass before commit: `make lint test`.
9. Dependencies require justification + license check (Apache/MIT/BSD only) recorded in the PR; see
   docs/license-policy.md. Currently allowed set is tiny on purpose.
10. Never commit secrets; never log secrets or full credentials-bearing strings; synthetic data only in
    examples and tests.
11. Keep docs truthful: if you change behavior described in README/docs/*, update them in the same change.
12. Commit messages: `area(scope): imperative summary` with body explaining why.

## Verification vocabulary (used across docs)

- **PASS** — command ran locally, exit 0, output captured in docs/verification.md.
- **FAIL** — ran, non-zero; must be fixed or explicitly documented as a known issue with a task.
- **BLOCKED** — tool/environment unavailable; record exact blocker and fallback used.
- **NOT RUN** — deliberately skipped; say why.

## When unsure

Prefer the safer behavior, document the decision in an ADR, and leave a breadcrumb in docs/ROADMAP.md.
