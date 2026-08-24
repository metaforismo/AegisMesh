# echo-responder — reference observer acknowledgement fixture

The historical directory name is retained for compatibility with repository
tests. This program does not generate decoy responses or runtime policy: it
only returns the exact acknowledgement required by the observer protocol.

Demonstrates the AegisMesh out-of-process extension contract
(`ext.aegismesh.io/v1alpha1`, transport `subprocess-ndjson`).

Build and verify:

```bash
cd examples/extensions/echo-responder
go build -o echo-responder .
NEW=$(shasum -a 256 echo-responder | cut -d' ' -f1)
# put NEW into manifest.json digest.value, then:
aegismesh ext verify --manifest manifest.json
aegismesh ext run --manifest manifest.json --input '{"synthetic":true}'
```

The extension is deliberately boring: stdio JSON only, no network, no
filesystem access, and one canonical acknowledgement tied to the synthetic
probe event. Its output cannot become a decoy response, policy, evidence, or
enforcement action. Anything beyond that requires a new manifest schema, ADR,
and security review.
