# Architecture and data flow

Version: 0.1.0. Single Go module `github.com/metaforismo/aegismesh`, single binary `aegismesh`.

## Component map

```text
cmd/aegismesh          entrypoint; wires config -> runtime -> admin -> cli
internal/cli           command dispatch, output rendering (human/JSON), errors
internal/config        schema-versioned load/validate/env-override/migrate hooks
internal/runtime       supervisor: sensor lifecycle, bounded event bus, graceful shutdown
internal/sensor        Sensor interface + registry
  /httpsensor          HTTP deception sensor (net/http, hardened server)
  /tcpsensor           TCP deception sensor (banner + line protocol)
  /mcpsensor           MCP decoy endpoint (JSON-RPC 2.0 over streamable HTTP POST)
internal/policy        response policy gate: static rules, provider fallback, redaction choke point
internal/llm           Provider interface + deterministic local provider (+ adapter seam for real ones)
internal/event         versioned envelope, redaction, integrity hashing, bounded bus
internal/storage       JSONL append-only store, rotation, retention, export
internal/admin         loopback listener: /healthz /readyz /metrics /version
internal/ext           extension manifest schema, digest/signature verifier, subprocess host
internal/migrate       clean-room importers (beelzebub YAML shapes)
```

## Runtime data flow

```mermaid
flowchart LR
    subgraph Untrusted side
        A[Attacker scanner] -->|HTTP/TCP/MCP bytes| B(Sensor listeners\nloopback or explicit opt-in)
    end
    B --> C[Sensor handler:\ncap bytes, apply timeouts]
    C --> D{Policy gate}
    D -->|static rule hit| E[Configured response]
    D -->|rule miss + llm fallback enabled| F[LLM provider interface]
    F -->|deterministic local provider| G[Canned persona text\ntreated as untrusted data]
    F -.->|optional remote provider\nopt-in only| H[(Remote API)]
    G --> I[Redact + size cap]
    C --> J[Event construction:\nredact payloads,\nhash, sequence, timestamp]
    E --> K[Response to attacker]
    I --> K
    J --> L[Bounded event bus\nfixed queue, drop-oldest policy]
    L --> M[(JSONL evidence store\nrotation + retention)]
    L --> N[Admin metrics counters]
    O[Operator] --> P[aegismesh inspect / export]
    M --> P
    O --> Q[Admin listener\n127.0.0.1 healthz readyz metrics]
```

## Trust boundary diagram

```mermaid
flowchart TB
    subgraph TB1["TB1: untrusted network"]
        X[Attacker input]
    end
    subgraph CORE["Trusted core process"]
        S[Sensors] 
        POL[Policy gate]
        EV[Event pipeline]
        ST[Storage]
    end
    subgraph TB3["TB3: semi-trusted files"]
        CF[aegismesh.yaml config]
    end
    subgraph TB4["TB4: provider output = untrusted data"]
        LP[Deterministic local provider]
        RP[Optional remote provider]
    end
    subgraph TB5["TB5: extensions = untrusted code"]
        EH[Extension host process]
    end
    X --> S
    CF --> POL
    S --> POL
    LP --> POL
    RP -.-> POL
    S --> EV
    POL --> S
    EV --> ST
    EH -.->|"only via explicit operator command,\nmanifest+digest verified"| EXT[ext host]
```

## Lifecycle

```mermaid
sequenceDiagram
    participant U as Operator
    participant CLI as aegismesh run
    participant R as Supervisor
    participant S as Sensors
    participant Ad as Admin listener
    U->>CLI: run --config mesh.yaml
    CLI->>R: Build(config)
    R->>S: Start each sensor (bounded concurrency)
    R->>Ad: Start loopback admin
    Note over S: interactions produce events -> store
    U->>CLI: SIGINT/SIGTERM
    CLI->>R: Shutdown(ctx with timeout)
    R->>S: Stop listeners, drain in-flight
    R->>Ad: Stop admin
    R->>CLI: exit code reflects failures
```

## Invariants (enforced in code)

1. Every sensor response originates from validated config or from a provider whose output passes the same
   redaction/size pipeline as attacker input.
2. No code path exists from inbound bytes or provider text to `os/exec`, file writes outside the configured
   data dir, or configuration mutation at runtime.
3. The event bus never blocks sensors indefinitely: fixed capacity, explicit overflow counter.
4. Default bind is `127.0.0.1` and port >1024; overrides require validation that fails closed with an
   actionable error.
5. Redaction happens once, at event construction, inside the policy/sensor layer — storage trusts nothing.
