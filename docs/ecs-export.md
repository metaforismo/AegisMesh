# ECS-compatible evidence export

Status: implemented mapping `aegismesh.ecs/v1`, targeting Elastic Common Schema
9.4.0. This is a documented compatibility profile, not a claim that every ECS
field or every Elastic integration is supported.

Run it locally against already-persisted evidence:

```text
aegismesh inspect export --data-dir ./data --out evidence.ecs.ndjson --profile ecs --verify
```

The command performs no network activity. It preserves the full native
`aegismesh.event/v1` envelope in every output record, so the ECS projection does
not become the only copy of AegisMesh-specific evidence.

## Stable v1 mapping

| ECS-compatible field | Native source or fixed value |
|---|---|
| `@timestamp` | `envelope.time` |
| `ecs.version` | `9.4.0` |
| `event.action` | `envelope.classification` |
| `event.dataset` | `aegismesh.evidence` |
| `event.hash` | `envelope.integrity.payload_sha256` |
| `event.id` | `envelope.id` |
| `event.kind` | `event` — an observation, never an incident assertion |
| `event.module` | `aegismesh` |
| `event.sequence` | `envelope.seq` |
| `observer.name` | `envelope.instance` |
| `observer.product` | `AegisMesh` |
| `observer.type` | `sensor` |
| `service.address` | `envelope.sensor.listen` |
| `service.name` | `envelope.sensor.id` |
| `service.type` | `envelope.sensor.kind` |
| `network.protocol` | known sensor kind (`http`, `mcp`, or `tcp`) |
| `network.transport` | `tcp` for those known sensor kinds |
| `aegismesh.mapping_version` | `aegismesh.ecs/v1` |
| `aegismesh.envelope` | complete native envelope, including redaction and observation |

The mapper deliberately does not decode sensor-private observation JSON into
HTTP, source, user, or threat field sets. Those payloads do not yet form one
versioned cross-sensor contract, and guessing would produce unstable or
misleading fields. A later mapping version may add fields after the native
domain contract is explicit.

## Compatibility and failure behavior

- Omitting `--profile` retains the native export bytes and ordering.
- The output is deterministic for a given envelope sequence.
- `--verify` is on by default. Any corrupt line, structurally invalid envelope,
  or integrity mismatch fails the whole export without replacing the target.
- `--verify=false` skips invalid records with a warning. This is a recovery aid,
  not verified evidence.
- The profile writes NDJSON only; it does not configure Elasticsearch, transmit
  events, create indices, or promise dashboard compatibility.

Primary schema references: [ECS field reference](https://www.elastic.co/docs/reference/ecs/ecs-field-reference),
[ECS guidelines](https://www.elastic.co/guide/en/ecs/current/ecs-guidelines.html),
[event fields](https://www.elastic.co/docs/reference/ecs/ecs-event), and
[observer fields](https://www.elastic.co/docs/reference/ecs/ecs-observer).
