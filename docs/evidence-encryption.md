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

## Container v3 and checkpoints

New writes always use `aegismesh.ageframes/v3\n` (23 ASCII bytes). The container
is not a single age CLI input. All integers below are unsigned big-endian:

| Record | On-disk layout |
| --- | --- |
| Event | `u32 ciphertext_length` followed by that many bytes of native age ciphertext for one event; unchanged from v2 |
| Checkpoint | `u32 0x00000000`, `u32 ciphertext_length`, age ciphertext |
| Seal | `u32 0xffffffff`, `u32 ciphertext_length`, age ciphertext; nothing may follow |

The checkpoint/seal ciphertext decrypts to exactly **42 bytes**: `u8 version=3`,
`u8 kind` (`1=checkpoint`, `2=seal`), `u64 event_count`, then the 32-byte SHA-256
of the ordered event records (`length || ciphertext`) since the segment header.
Headers and control records are excluded from that digest. The plaintext kind
must match the visible marker. Event lengths are bounded before allocation;
control ciphertexts must be 1..1016 bytes, with marker and length fitting the
1 KiB completion reserve. Unknown container versions, wrong layouts/kinds,
count/digest mismatches, record reordering and bytes after a seal fail closed.

With the pinned native age/X25519 implementation, a control ciphertext is 242
bytes: 42 plaintext plus 200 age envelope bytes. Including marker and length,
each checkpoint or seal is **250 bytes**, verified by `TestCheckpointOverhead`.
One checkpoint per five-second runtime flush under continuous traffic adds
50 bytes/second, about 4.12 MiB/day, without adding segment files. Checkpoints
count toward `max_file_bytes`; a flush seals instead when another checkpoint
would consume the reserved seal space. No checkpoint is written unless at least
one event arrived since the previous checkpoint.

`Flush` publishes buffered frames and a checkpoint to the OS. It does **not**
call `fsync` or promise power-loss durability. Size rotation, `Close`, a flush
at the fixed **five-minute** maximum age from the first event, or checkpoint
space exhaustion writes a seal. Empty segments never age out. Sealing does not
eagerly create a successor; only the next append opens one. Age alone causes
at most 288 seals/day under steady traffic; size, checkpoint overhead and
restarts add files. This is not an absolute daily file bound.

## Verified prefix reads and interrupted segments

`inspect list|show|export` and `recommend` accept an open v3 segment once it has
an authenticated checkpoint. Only events through the last valid checkpoint are
returned. A trailing run of complete events, a torn event or an unfinished
control record is excluded with an explicit typed notice: segment name,
verified event count, ignored byte count and whether a successor exists.
Complete corrupt ciphertexts and complete invalid control records fail closed,
even in the uncheckpointed tail; they are never silently treated as crash tails.
A header or events without any complete checkpoint/seal still fail closed.

Each accepted open segment emits one stderr line saying it is not sealed and
later events may exist. List/show JSON and recommend JSON also include
`open_segments` with `segment`, `verified_events`, `trailing_bytes` and
`interrupted`. Exports remain plaintext NDJSON with notices on stderr; no
metadata is inserted into the event stream. The verified count describes the
whole segment prefix, before filters or limits. Exit 0 means the requested read
succeeded, possibly with incomplete history; exit 1 means a read/output failure;
exit 2 means invalid arguments. `--require-sealed` makes every open segment an
exit-1 failure and preserves staged output/destinations.

Discovery remains oldest modification-time first, with filename tie-breaking.
Only the newest segment is treated as normally open. An older unsealed segment
produces a loud **interrupted segment** notice; `doctor` reports a warning using
a keyless structural scan, explicitly without checking authenticity. A newest
unsealed file alone cannot distinguish a live runtime from a crash; after a
successor exists the predecessor is classified as interrupted. Structural
corruption/no usable checkpoint is a doctor failure (human exit 1; existing JSON
mode returns exit 0 with `overall: "fail"`). Earlier interruption warnings remain
visible alongside a later scan failure. Warnings do not change
successful inspect/recommend/doctor exit codes; use strict reads for scripts
that require completeness.

Readers capture each opened file's size, authenticate its records, then replay
only the verified prefix through the same descriptor, rechecking it. Memory is
bounded by one frame rather than a whole segment; reads do not chase growing
files indefinitely. Concurrent appends beyond the snapshot may appear on the
next read. This is not an atomic directory snapshot. Callbacks remain provisional
until the read returns its result; CLI output is buffered/staged through that
result. The legacy `Reader.ForEach` remains strict; `ForEachVerified` returns
prefixes and explicit `OpenSegmentError` notices, honoring `RequireSealed`.

Restart never appends to or repairs an existing segment. Complete checkpointed
prefixes survive a crash and remain readable without surgery; events after the
last checkpoint are not recovered. Preserve evidence before investigating a
crash. No automatic rewrite, salvage of uncheckpointed data, or migration runs.

Historical v2 (`aegismesh.ageframes/v2\n`) segments keep their original layout:
event records, zero marker, then length-prefixed age ciphertext containing
`u64 count || SHA-256(event records)`. Sealed v2 is readable; unsealed v2 fails
closed with guidance that v3 checkpoints enable live reads for new writes only.
The unreleased v1 draft and unknown versions are rejected. No in-place migration
is provided. Mixed plaintext/v2/v3 directories remain supported.

## Completion and rollback limits

A checkpoint authenticates a prefix, not the existence of later bytes. A writer
on the storage medium can truncate an open segment back to an earlier checkpoint
without detection, just as they can already delete whole files. A further limit
is unavoidable: removing a seal and truncating a previously sealed v3 file to
an earlier checkpoint makes it indistinguishable from an open file. Permissive
reads report it as incomplete; they cannot prove that it used to be sealed.
**Full truncation detection requires `--require-sealed`** (or trusted external
completion state, which is not implemented). When a seal is required/present,
count/order/truncation validation remains strict, including bytes after the seal.
Sealed v2 has no checkpoint fallback and keeps strict truncation detection.

This is consistency, not provenance: anyone with the public recipient can forge
whole segments. There are no writer signatures, external monotonic log, or
whole-file deletion/replacement detection. These limits are not a cryptographic
break of age.

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
ciphertext is corrupt (outside the explicitly reported unfinished v3 tail), or when the segment changes while it is
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
never delete the active segment. Counting ciphertext segments scans bounded frames and markers without
private keys or authenticity claims. Sealed files count all frames; interrupted
v3 files count through their last structurally complete checkpoint and ignore
the unfinished tail. Such closed files remain eligible for whole-file retention.
Counts use live in-memory records for the current store's active segment, which
is never deleted. A damaged segment without a usable checkpoint, invalid framing
or an unsealed v2 blocks count retention; age retention remains whole-file expiry.
Retention scans on the separate ten-minute maintenance cadence and opens one
segment at a time, holding the store mutex; large passes can delay appends/flushes.
It is a periodic whole-segment cap, not a hard instantaneous disk quota.
Discovery uses the common ordering across both suffixes. Retention deletes whole closed segments, so an active segment
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
  malformed length prefixes are rejected before allocation. A 1 KiB seal
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
