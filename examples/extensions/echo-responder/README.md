# echo-responder — reference extension

Demonstrates the AegisMesh out-of-process extension contract
(`ext.aegismesh.io/v1alpha1`, transport `subprocess-ndjson`).

Build and verify:

```bash
cd examples/extensions/echo-responder
go build -o echo-responder .
NEW=$(shasum -a 256 echo-responder | cut -d' ' -f1)
# put NEW into manifest.json digest.value, then:
aegismesh ext verify --manifest manifest.json
aegismesh ext run --manifest manifest.json --input '{"prompt":"hi"}'
```

The extension is deliberately boring: stdio JSON only, no network, no
filesystem access, canned output. Anything beyond that requires new manifest
schema versions, new permissions, and a security review.
