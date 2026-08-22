## What & why

<!-- One paragraph. Link the issue. -->

## Safety check (required)

- [ ] No untrusted input reaches exec / paths / config mutation / enforcement
- [ ] Secure defaults preserved (loopback bind, unprivileged ports, caps, redaction, dry-run)
- [ ] Defensive-only capability; no open-core placeholders

## Verification

- [ ] `make lint` PASS
- [ ] `make test` PASS (race detector on)
- [ ] New config fields: validation + docs + test
- [ ] Docs updated for behavior changes

Dependency changes: justification + license recorded in docs/license-policy.md and the PR body.
