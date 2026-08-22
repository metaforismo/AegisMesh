# aegismesh Helm chart — operator runbook

This chart packages the AegisMesh runtime as one non-root Pod: ConfigMap
(`mesh.yaml`), Deployment, Service exposing decoy ports only, default-on
ingress-isolating NetworkPolicy, opt-in PDB, dedicated token-free
ServiceAccount. Values are machine-checked by `values.schema.json`; the rendered
config is strict-decoded at startup (`aegismesh.io/v1alpha1`) — typos fail the
rollout, not production.

Evidence labels used below —
- **VERIFIED LOCALLY** — ran against this checkout with Helm 4.2.2; no cluster involved.
- **REQUIRES A CLUSTER** — touches a Kubernetes API; **NOT RUN locally** for this release. Do not treat as tested.

## Prerequisites

- Helm 4.x (the CI contract job pins v4.2.2) and a `kubectl` matching your cluster.
- Docker (or an OCI-compatible builder) for the image below; a built `aegismesh` binary (`make build`) for offline verification.

## The image boundary — there is no official image

The release pipeline ships binaries and SBOM only
(`.github/workflows/release.yml`). No AegisMesh OCI image and no packaged
chart artifact are published anywhere. The default
`image.repository=ghcr.io/metaforismo/aegismesh` is a naming convention, not
a pullable artifact: installing without overriding it yields `ImagePullBackOff`.
Build and push your own image from this repository's distroless Dockerfile
(static binary, uid/gid 10001, no shell):

```sh
docker build -f deploy/Dockerfile -t registry.example.com/acme/aegismesh:v0.1.0 .
docker push registry.example.com/acme/aegismesh:v0.1.0
```

(`registry.example.com/acme/aegismesh` is a placeholder for *your* registry;
prefer immutable tags over `latest`, digest pins strongest.)

## Verify offline before touching a cluster

All VERIFIED LOCALLY:
```console
$ helm lint deploy/helm/aegismesh
1 chart(s) linted, 0 chart(s) failed
$ helm template edge1 deploy/helm/aegismesh -f my-values.yaml > rendered.yaml
```
`helm template` is the whole story this chart can tell without a cluster, and
CI keeps it honest continuously (`make helm-contract` shells out to it).
You can also validate the rendered config with the real parser: extract
`data.mesh.yaml` from `rendered.yaml` into `rendered-mesh.yaml`, then
```console
$ ./bin/aegismesh validate --config rendered-mesh.yaml
ok: rendered-mesh.yaml (schema aegismesh.io/v1alpha1, 1 sensor(s))
```

`doctor` checks ports/storage on the machine you run it on — its storage check
rightly rejects `/workspace/data` on a workstation — so offline, `validate` is the gate.

## Install and upgrade — REQUIRES A CLUSTER (NOT RUN locally)

**Namespaces:** the chart renders no Namespace object; create the target
yourself or pass `--create-namespace`. Both are explicit operator choices.

Minimal user values file — override the image you pushed, bring sensors you have actually read:

```yaml
# my-values.yaml
image:
  repository: registry.example.com/acme/aegismesh
  tag: v0.1.0
meshConfig:
  api_version: aegismesh.io/v1alpha1
  runtime:
    data_dir: /workspace/data        # absolute: relative resolves under read-only /etc/aegismesh
  security:
    allow_public_bind: true          # required by 0.0.0.0 decoy binds; see below
  sensors:                           # at least one; see docs/configuration.md
    - id: http-admin-decoy
      kind: http
      listen: "0.0.0.0:8081"
      rules:
        - name: admin-login
          path_regex: "^/admin/login$"
          methods: ["GET"]
          status: 200
          body: "<html><body>sign-in decoy</body></html>"
```

```sh
helm install edge1 deploy/helm/aegismesh -n aegismesh --create-namespace -f my-values.yaml
helm upgrade edge1 deploy/helm/aegismesh -n aegismesh -f my-values.yaml
```

A changed `meshConfig` changes the Pod's `checksum/config` annotation, so upgrades
roll the Pod instead of leaving stale config mounted. Neither command has been run
against a cluster by this repository.

## What gets created

Five objects, all named `<release>-aegismesh`: NetworkPolicy, ServiceAccount,
ConfigMap, Service, Deployment. Nothing is cluster-scoped; no RBAC objects exist
because the runtime never calls the Kubernetes API. `replicas` stays 1 by design:
evidence segments are append-only files on an `emptyDir`; multi-writer storage
would corrupt them.

## ServiceAccount: created vs external

Default (`serviceAccount.create=true`) renders a dedicated account named after
the release with `automountServiceAccountToken: false` on both account and Pod —
it carries no token and grants nothing. To use an account you manage:
`serviceAccount.create=false` plus `serviceAccount.name=<yours>`; the schema
rejects a missing name (`minLength: got 0, want 1`), and no SA is then rendered.

## NetworkPolicy: ingress isolated, egress deliberately unpolicied

Default-on (`networkPolicy.enabled=true`) with `policyTypes: [Ingress]`:
inbound traffic is admitted only to the decoy targetPorts under
`service.ports`. The admin listener stays loopback-bound by validated
runtime invariant and appears nowhere. Egress is intentionally unconstrained
so local inference, remote LLM providers, webhook delivery, and event sinks
keep working unchanged. Two caveats: a CNI that enforces NetworkPolicy is required
(otherwise the object is inert decoration), and `enabled=false` restores flat
networking — every relaxation widens attack surface.

## PDB: off by default, opt-in with exactly one threshold

`pdb.enabled=false` is deliberate, not laziness. The supported shape is one
replica on ephemeral storage, where any enforcing budget blocks *every*
voluntary eviction (routine node drains stall until removed) while the
evidence it would "protect" dies on any restart anyway.

To opt in, set exactly one threshold. Keeping `maxUnavailable` semantics:

```sh
helm template edge1 deploy/helm/aegismesh \
  --set pdb.enabled=true --set pdb.maxUnavailable=0
```

Switching to `minAvailable` requires nulling the other key first — with both
set the schema rejects the release (`'oneOf' failed, subschemas 0, 1 matched`):

```sh
--set pdb.enabled=true --set pdb.maxUnavailable=null --set pdb.minAvailable=1
```

Read it as a disruption gate, never as availability or durability.

## Configuration overrides, migration input, and secrets

Unset `meshConfig` sections fall back to the runtime's safe defaults (admin
on `127.0.0.1:9110`, JSON logging, retention caps). Three rules bite people:

- Non-loopback decoy binds require `security.allow_public_bind: true`.
  Without it the strict loader refuses: `binds beyond loopback; decoys must
  never face production networks by accident`. Binds stay inside the Pod;
  reachability comes only through the Service.
- `runtime.data_dir` must be absolute (the config mount is read-only).
- Values are data, never templates: nothing under `meshConfig` is templated.

**From Beelzebub configs:** the importer produces candidates, not installs.
Shortest honest path ([full field mapping](../../../docs/migration-beelzebub.md)):

```console
$ ./bin/aegismesh migrate beelzebub svc.yaml --out ./imported   # dry-run report first
dry-run only; re-run with --write to create files under ./imported
$ # read every reported approximation/unsupported field, then write files:
$ ./bin/aegismesh migrate beelzebub svc.yaml --out ./imported --write
generated config validation: ok: generated config passes strict validation
$ ./bin/aegismesh validate --config ./imported/svc.aegismesh.yaml
```

Then copy the *reviewed* sensor entries into `my-values.yaml` (`meshConfig.sensors`),
flip each `listen` from `127.0.0.1:X` to `0.0.0.0:X`, add `security.allow_public_bind: true`,
and re-run the lint/template/validate chain. Never feed an unreviewed import straight into a
release: emitted regexes and bodies become live decoy behavior under your name.

**Secrets:** no values field accepts credentials; keep it that way. LLM keys belong in
`llm.api_key_env` / `llm.api_key_file` references resolved from a Secret-backed env source
or file at runtime — never inline in config, never in Git.

## Post-install inspection — REQUIRES A CLUSTER (NOT RUN locally)

```sh
kubectl -n aegismesh get pods,svc,netpol,pdb
kubectl -n aegismesh exec deploy/edge1-aegismesh -- \
  /aegismesh inspect list --data-dir /workspace/data --verify --limit 5
```

Events are observations of decoy interactions, not proof of compromise.

## Rollback and uninstall — REQUIRES A CLUSTER (NOT RUN locally)

`helm rollback` / `helm uninstall` behave as Helm normally does, plus one hard
fact: evidence lives on an `emptyDir`, lost on every Pod restart *and* destroyed
by uninstall. No persistence option exists in this core chart; if retention matters,
solve that first ([boundary map](../../../docs/deploy/kubernetes.md)), not with a volume hack after the fact.

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `helm template/install` fails `'oneOf' failed` at `/pdb` | both PDB thresholds set | null one (`pdb.maxUnavailable=null`) |
| Fails at `/serviceAccount/name`: `minLength: got 0, want 1` | `create=false` without external `name` | set `serviceAccount.name` |
| Pod stuck `ImagePullBackOff` | default image ref names nothing public | build/push your own; override `image.*` |
| `CrashLoopBackOff`, log says binds beyond loopback | `allow_public_bind` missing/false with non-loopback listens | set it deliberately, or bind loopback (then no Service routes — pick one honestly) |
| Node drain hangs indefinitely | enforcing PDB with `replicas=1` blocks voluntary evictions | disable the PDB; it cannot help a single-replica release |
| Decoys reachable on non-exposed ports | CNI does not enforce NetworkPolicy | verify CNI capabilities; the object alone enforces nothing |
