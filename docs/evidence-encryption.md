# Evidence-at-rest encryption

AegisMesh can encrypt newly written evidence segments with native age/X25519.
The feature is opt-in. Omitting `storage.encryption` preserves the existing
plaintext `.jsonl` format for data directories that have never required
encryption.

Encryption protects event contents on the storage medium at rest. A compromised
runtime host can read events in memory or steal a read identity; a stolen
identity can decrypt its retained history. It does not hide segment names,
sizes, timestamps, retention activity, exports, logs, or other filesystem
metadata, and it does not authenticate the host that wrote an event. Event
integrity hashes remain observation-payload consistency checks rather than
writer signatures or chain-of-custody proofs.

## Write configuration

Only a public age X25519 recipient belongs in runtime configuration:

```yaml
storage:
  max_file_bytes: 16777216
  max_event_bytes: 262144
  encryption:
    enabled: true
    recipient: age1example...
  retention:
    max_events: 100000
    max_age_days: 30
```

AegisMesh accepts exactly the native `age1...` X25519 recipient form. It does
not accept passphrases, SSH recipients, age plugins, KMS identifiers, commands,
or remote key services. An invalid recipient fails runtime construction before
listeners become ready.

When encryption is enabled, segments use `.jsonl.age` and a bounded AegisMesh
frame format. Each frame contains one complete standard age ciphertext for one
native event envelope. Frames are independently authenticated so a crash while
writing the last record does not make earlier complete records cryptographically
undecipherable; the reader still reports the damaged segment and never silently
accepts a truncated frame.

The `aegismesh.ageframes/v2` container is not a single age CLI input. It holds
four-byte big-endian lengths and independent native age ciphertexts, followed
by a zero-length marker and a final length-prefixed age ciphertext. That footer
contains an eight-byte event count and SHA-256 of the ordered length/ciphertext
records. It authenticates segment completion and detects frame removal/reordering
relative to the footer, including truncation exactly at a record boundary.
This is consistency, not writer provenance: anyone with the public recipient
can construct new ciphertext, and whole-file deletion/replacement is not detected.
Unreleased draft v1 framing is rejected; no v1 compatibility or migration is
claimed.

Periodic `Flush` pushes buffered ciphertext frames to the OS without sealing or
rotating. As before, flushing does not call `fsync` or promise persistence across
power loss. Encrypted segments seal only on size rotation, `Close`, or a flush
at or beyond the fixed **five-minute** maximum age measured from the first event
(`maxEncryptedSegmentAge` in `internal/storage/encryption.go`). Empty segments
never age out. An age seal does not eagerly create a successor; only the next
append opens one, and later flushes cannot append another footer.

Five minutes balances read delay against directory/retention overhead: age alone
causes at most 288 seals per day of steady traffic, rather than 17,280 at the
runtime's five-second flush cadence. Size rotation adds files proportional to
stored bytes; restarts also create new files. This is not an absolute bound on
files per day under unlimited traffic or restarts. The append/flush path does no
directory scan; count/age retention scans whole segments on the runtime's separate
ten-minute maintenance cadence and never opens all segment descriptors at once.
Retention holds the store mutex while scanning, so a large pass can delay
appends/flushes.
Retention is a periodic, whole-segment cap, not a hard instantaneous disk quota.
A damaged closed segment can block count retention as described below. Frames
that cannot fit a fresh segment (including header/footer space) are rejected
before rotating, so rejected events cannot force tiny segments or empty successors.

An active segment fails closed with "not sealed" even after a successful flush.
Its events become eligible for verified reads within five minutes of its first
event plus the next runtime flush (normally up to five more seconds), or sooner
on size rotation/close. A delayed maintenance loop can extend that delay.
Full-directory `inspect`/`recommend` still fails if any segment is active/unsealed,
including a newly opened successor under continuous traffic. Stop the runtime for
a complete read, or inspect a separate snapshot containing only sealed segments;
there is no live-read or automatic active-file skipping mode.
Readers consume each ciphertext fully before invoking callbacks, and validate
the footer before CLI output is emitted. Storage callbacks may observe earlier
valid records before a later error; callers must treat their results as provisional
until the whole read returns success.

A crash can leave an unsealed segment even when all its event frames are complete.
Restart preserves that file and opens a new encrypted segment. It does not repair,
append to, skip or silently accept the incomplete file. For recovery, stop the
runtime and preserve a copy of the evidence and guard; work on a separate copy
with the required identities. Deliberately excluding a damaged segment loses its
completeness guarantee and must be recorded by the operator. No automated salvage
or reconstruction command is implemented.

## Identity files and reads

Private identities are supplied only at local read time:

```bash
./bin/aegismesh inspect list \
  --data-dir ./data \
  --identity /secure/current.agekey

./bin/aegismesh inspect export \
  --data-dir ./data \
  --identity /secure/current.agekey \
  --identity /secure/previous.agekey \
  --out evidence.ndjson
```

`inspect list`, `inspect show`, `inspect export`, and `recommend` accept up to
eight repeated `--identity FILE` values for key rotation. Each file must be a
small owner-only regular file and contain exactly one native X25519 identity.
Stable symlinks to an owner-only regular secret file are allowed; FIFOs, device
files, duplicate hard-link aliases, non-X25519 identities, and oversized files
are rejected. Private key material is never accepted inline or included in
errors or logs.

An encrypted segment fails closed when no identity matches, when framing or
ciphertext is corrupt or truncated, or when the segment changes while it is
being opened. Output-producing commands keep their existing staging behavior:
failed decryption cannot produce a partial verified export or overwrite an
existing output target. Exported NDJSON is plaintext and must be protected
separately.

## Rotation and mixed history

Key rotation is explicit:

1. Generate and back up a new X25519 identity using an age-compatible tool.
2. Replace the configured public recipient and restart AegisMesh. Restart always
   creates a new segment; it never appends to an old encrypted stream.
3. Keep both the old and new private identity files available to read mixed
   history during the retention window.
4. Remove an old identity only after every segment encrypted to it has expired
   or has been deliberately handled under the operator's retention/archive
   process.

AegisMesh does not rewrite old plaintext or old-key segments during rotation.
Count and age retention operate across plaintext and encrypted segments and
never delete the active segment. Counting closed ciphertext segments validates
bounded framing and the presence of a footer, without decrypting or asserting
authenticity; the write runtime holds no private key. Counts use live in-memory
records for the active segment. A damaged closed segment blocks count retention
rather than being silently omitted; age retention remains whole-file expiry.
Discovery is oldest modification-time first, with filename tie-breaking across
both suffixes. Retention deletes whole closed segments, so an active segment
alone can exceed the configured event count.

## No silent downgrade

The first successful encrypted-store initialization creates an owner-only mode
guard in the data directory. Later attempts to open that directory for
plaintext writes fail. A directory containing encrypted segment history also
refuses plaintext writes if the guard is missing. This protects against an
accidental configuration rollback; it is not a migration mechanism and does not
make pre-existing plaintext confidential.

Back up the private identity before enabling encryption. Losing every identity
that can decrypt retained segments permanently makes those events unreadable.
AegisMesh deliberately has no recovery key, escrow service, or network key
lookup.

## Limits and trust boundary

- `storage.max_event_bytes` defaults to 256 KiB and cannot exceed the shared
  1 MiB stored-envelope read limit.
- Ciphertext frames have an additional 128 KiB bounded overhead allowance;
  malformed length prefixes are rejected before allocation. A 1 KiB footer
  reserve counts against `max_file_bytes` in encrypted mode.
- Evidence and identity segment paths are checked against symlink/special-file
  substitution and hard-link aliasing at the local read boundary.
- The data directory remains a single-runtime operational resource; encryption
  does not provide filesystem or host isolation against a privileged local
  attacker.
- Enabling encryption adds no runtime network destination, model call, webhook,
  extension authority, subprocess, or enforcement path.

See ADR-0016 in [architecture/adr.md](architecture/adr.md) and the remaining
residual risks in [THREAT-MODEL.md](THREAT-MODEL.md).
