# Kubernetes deployment

Status: **Helm is the current packaging path; cluster operation is not yet
supported.** The chart at [deploy/helm/aegismesh](../../deploy/helm/aegismesh/README.md)
is real, schema-checked, and continuously contract-tested — but everything in
this page that needs an API server remains unexecuted by this repository. The
Compose demo (deploy/compose/) stays the supported container workflow. Track
what would make Kubernetes "supported" in docs/ROADMAP.md.

## Boundary map

- **VERIFIED LOCALLY** — `helm lint`, `helm template` (all values scenarios),
  `values.schema.json` rejections, and strict validation of the rendered
  `mesh.yaml` via `./bin/aegismesh validate`. Continuously enforced by CI's
  `make helm-contract` job.
- **REQUIRES A CLUSTER** — every `helm install` / `upgrade` / `rollback` /
  `uninstall`, all `kubectl` inspection, NetworkPolicy and PDB behavior under
  a real CNI and node drains. **NOT RUN locally** for this release.
- **NOT YET AVAILABLE** — published OCI image or packaged chart artifact
  (release ships binaries + SBOM only), persistence beyond emptyDir,
  multi-replica, liveness/readiness probes.

## Design intent

AegisMesh is a single static binary with local-first evidence storage. On
Kubernetes that translates to:

- **One container per Pod** running `aegismesh run --config /etc/aegismesh/mesh.yaml`.
  No sidecars, no operators, no CRDs for the MVP.
- **ConfigMap** holds `mesh.yaml` (non-secret configuration).
- **Secrets**, when a remote LLM provider is used, come from a Secret mounted
  as an env source (`llm.api_key_env`) or file (`llm.api_key_file`) — never
  baked into images, values, or ConfigMaps.
- **Evidence** (`runtime.data_dir`) goes to an emptyDir today. JSONL segments
  are append-only; no shared-multi-writer storage, which is why `replicas`
  stays 1 until a shared-storage design exists.
- **Loopback defaults stay meaningful**: decoy listeners bind inside the Pod
  network namespace. Exposure to the cluster is an explicit Service decision —
  the same deliberate-exposure model as Compose's loopback publishing.

## Current shape (rendered by the chart)

Do not hand-write manifests; render them and read the result:

```sh
helm template edge1 deploy/helm/aegismesh -f my-values.yaml > rendered.yaml
```

That produces exactly five namespaced objects — ConfigMap, Deployment,
Service, ingress-only NetworkPolicy, ServiceAccount — with hardened
pod/container security contexts (non-root uid 10001, dropped capabilities,
read-only rootfs) mirroring deploy/Dockerfile. An earlier draft of this page
showed a hand-written Pod referencing `ghcr.io/metaforismo/aegismesh:latest`;
that image does not exist, which is exactly why the example is gone: build and
push your own image first (chart runbook, "The image boundary").

Install, upgrade, PDB opt-in, ServiceAccount choices, migration input, and
troubleshooting live in the
[chart operator runbook](../../deploy/helm/aegismesh/README.md); this page
does not duplicate them.

## What must exist before this becomes "supported"

1. A published image with SBOM + provenance attestation (see docs/RELEASE.md
   process) and digests pinned in rendered output.
2. A smoke test that runs the chart against kind with the demo config and
   asserts one HTTP decoy interaction lands in evidence.
3. Documented *and exercised* upgrade/rollback: config schema version gates
   (v1alpha1) mean rollbacks require compatible configs; the runbook describes
   the mechanics but no rollback has been run against a cluster.
4. Resource limits guidance derived from measured RSS under demo load
   (current chart limits are conservative placeholders).

None of these exist yet; do not run AegisMesh on Kubernetes expecting support.
