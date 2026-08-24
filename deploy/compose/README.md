# Docker Compose demo

One command runs AegisMesh in a hardened container with three decoy sensors:

```sh
docker compose -f deploy/compose/docker-compose.yaml up --build
```

What you get:

| Surface | Address (host) | What it is |
|---|---|---|
| HTTP admin decoy | `http://127.0.0.1:8081` | fake "Internal Admin" panel |
| TCP build-cache decoy | `127.0.0.1:6399` | line-oriented fake FTP-ish service (`PING`, `STAT`) |
| MCP canary | container-internal only | decoy MCP tools for agent traffic |

Ports are published to host **loopback only**. The admin listener is not
published at all; use `exec` for inspection.

The demo configuration keeps the sensors in-process. For a reviewed
deployment, any sensor kind can opt into `process_isolation: true` in
`mesh.yaml`. That setting starts one same-binary worker inside this same
container using a fixed hidden argument, minimal environment, private
temporary working directory, and bounded canonical stdio protocol. The parent
materializes `body_file` content and sends no paths, credentials, or provider
destinations, models, or credential references. A local fallback's bounded
static prompt remains part of the sensor specification. An isolated HTTP
sensor with an enabled remote LLM fallback fails
closed during validation.

Process isolation is fault containment, not a network, filesystem, CPU,
memory, syscall, or malware sandbox. Workers share this container's UID,
filesystem view, network namespace, and aggregate resource limits; no new
egress or network identity is created. A worker crash degrades readiness for
that sensor while siblings continue, and v0.2 does not automatically restart
it. The container boundary remains the operator's control for stronger
isolation.

## Poke the decoys

```sh
# HTTP interaction
curl --max-time 3 http://127.0.0.1:8081/admin/login

# TCP interaction
printf 'PING\n' | nc -w 2 127.0.0.1 6399

# Evidence review
docker compose -f deploy/compose/docker-compose.yaml exec aegismesh \
  /aegismesh inspect list --data-dir /workspace/data --verify
```

Every hit becomes an integrity-hashed event under `/workspace/data`
(a named volume). Events are observations of decoy interactions, not proof of
compromise; treat them as signals to investigate.

## Hardening applied

- distroless runtime image, unprivileged uid 10001, no shell
- `read_only: true` root filesystem; writable space only via tmpfs + volume
- `cap_drop: ALL` and `no-new-privileges:true`
- process workers, when enabled, remain inside the same container and inherit
  these aggregate container controls

## Stop

```sh
docker compose -f deploy/compose/docker-compose.yaml down   # add -v to wipe evidence
```
