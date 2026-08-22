# Troubleshooting

Symptom-first, exact-cause-first. Run `aegismesh doctor --config mesh.yaml`
before anything else; most answers below appear in its output.

## Config and startup

**`field X not found in type config.Y — unknown field`**
Strict schema: a field exists in an older example or your file has it under
the wrong section. Check spelling against docs/configuration.md; `aegismesh
init --force` regenerates a known-good example.

**`listen "0.0.0.0:8081" binds beyond loopback ... allow_public_bind`**
Default policy. Either bind `127.0.0.1:` or set
`security.allow_public_bind: true` deliberately (the Compose demo does this
for container-local binds only).

**`uses privileged port 808; allow_privileged_ports`**
Ports < 1024 need the explicit opt-in or a port ≥ 1024. Port `0` (OS-assigned)
needs no opt-in.

**Bind fails with "address already in use"**
Another process holds the port. On macOS, AirPlay holds :5000/:7000 — pick
different ports. `doctor` checks availability before you run.

## Sensors

**HTTP decoy answers 404/405 where I expected my rule**
Precedence: first rule matching path **and** method wins; a methods-less
catch-all shadows everything for its paths; method-mismatch → 405 + Allow;
fallback fires only when no rule matches the path. See
docs/configuration.md ("Response precedence").

**HEAD returns 405 although GET works**
GET does not imply HEAD. Add `"HEAD"` to that rule's methods.

**TCP session drops immediately**
An over-long line (> `max_line_bytes`) ends the session by design — no
truncation, so rules can't be split-smuggled.

## Evidence

**`inspect list` shows fewer events than interactions I made**
Events flush to disk every 5s and on graceful shutdown (SIGTERM/SIGINT).
`kill -9` skips the final flush on purpose — evidence integrity beats
completeness.

**`warning: N corrupt line(s) skipped`**
A segment line failed JSON parsing (partial write from a crash, disk issue).
The count is printed wherever you read with `inspect`; corrupt lines are
never silently dropped. Export with `--verify` for an audit trail.

**Integrity check fails (`integrity_ok=false`)**
The payload hash doesn't match — someone/something edited stored evidence.
Treat the affected segment as compromised; investigate out-of-band.

## Extensions

**`ext verify` says digest mismatch**
The manifest's sha256 doesn't match the binary on disk. Rebuild and update
the manifest, or refuse the artifact. This message is the system working.

**Extension killed at call time**
Deadline exceeded → automatic revocation (process kill). Raise
`call_timeout_ms` if the workload justifies it; otherwise treat as hostile
or buggy extension behavior.

## Admin

**Admin listener refuses to bind non-loopback**
Invariant, not a preference. Health/metrics stay internal.
