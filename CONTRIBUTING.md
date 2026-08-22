# Contributing to AegisMesh

Thank you for helping build defensive infrastructure. This project has hard safety rules; read them before
writing code.

## Ground rules

1. **Defensive only.** No code that exploits, steals credentials, persists on targets, participates in
   botnets, delivers phishing, or executes captured malware. Decoys must stay isolated and synthetic.
2. **Untrusted data stays data.** Inbound bytes and LLM output must never reach exec, filesystem paths,
   config mutation, or enforcement logic. If your change needs that, it is the wrong change.
3. **Secure defaults are load-bearing.** Loopback binds, unprivileged ports, size/time caps, redaction, and
   dry-run modes may only be relaxed behind explicit, validated operator opt-in.
4. **No open-core.** Everything in this repository is Apache-2.0. No proprietary placeholders.

## Development workflow

```bash
make build      # ./bin/aegismesh
make test       # unit + integration (race detector on)
make lint       # gofmt + go vet (+ golangci-lint if installed)
make fuzz-seed  # run fuzz targets over their seed corpus
```

- One logical change per PR; include tests for behavior changes.
- New dependencies require an ADR note in the PR: what it does, why stdlib is insufficient, license check.
- Update docs when you change behavior the docs describe.

## Commit style

Conventional, imperative subject lines: `sensor(http): bound header read time`. Reference issues in the body.

## Reporting

Security issues: see [SECURITY.md](SECURITY.md) — do not open public issues for them.
Bugs/features: GitHub issues with the templates.

## Code of conduct

See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md). Be rigorous and kind.
