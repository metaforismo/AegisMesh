# Kubernetes deployment (direction)

Status: **direction document, not a supported path yet.** The Compose demo
(deploy/compose/) is the supported container workflow for this release. This
page describes how Kubernetes support is intended to land, so operators can
plan and reviewers can hold the implementation to it. Track progress in
docs/ROADMAP.md.

## Design intent

AegisMesh is a single static binary with local-first evidence storage. On
Kubernetes that translates to:

- **One container per Pod** running `aegismesh run --config /etc/aegismesh/mesh.yaml`.
  No sidecars, no operators, no CRDs for the MVP.
- **ConfigMap** holds `mesh.yaml` (non-secret configuration).
- **Secrets**, when a remote LLM provider lands (roadmap R2), come from a
  Secret mounted as an env source (`AEGISMESH_LLM_API_KEY`) — never baked into
  images or ConfigMaps.
- **Evidence** (`runtime.data_dir`) goes to an emptyDir or a ReadWriteOnce
  PVC. JSONL segments are append-only; no shared-multi-writer storage.
- **Loopback defaults stay meaningful**: decoy listeners bind inside the Pod
  network namespace. Exposure to the cluster is an explicit Service decision —
  the same deliberate-exposure model as Compose's loopback publishing.

## Example shape (illustrative, not yet tested)

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: aegismesh-decoys
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 10001
    seccompProfile: { type: RuntimeDefault }
  containers:
    - name: aegismesh
      image: ghcr.io/metaforismo/aegismesh:latest   # pin by digest in real use
      args: ["run", "--config", "/etc/aegismesh/mesh.yaml"]
      securityContext:
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        capabilities: { drop: ["ALL"] }
      volumeMounts:
        - { name: config, mountPath: /etc/aegismesh, readOnly: true }
        - { name: data, mountPath: /workspace/data }
  volumes:
    - name: config
      configMap: { name: aegismesh-mesh-yaml }
    - name: data
      emptyDir: {}
```

## What must exist before this becomes "supported"

1. A published image with SBOM + provenance attestation (see docs/RELEASE.md
   process) and digests pinned in manifests.
2. A smoke test that runs the chart/manifest against kind with the demo
   config and asserts one HTTP decoy interaction lands in evidence.
3. Documented upgrade/rollback: config schema version gates (v1alpha1) mean
   rollbacks require compatible configs; state the rule explicitly.
4. Resource limits guidance derived from measured RSS under the demo load.

None of these exist yet; do not run AegisMesh on Kubernetes expecting support.
