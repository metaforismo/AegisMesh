package settings

import (
	"encoding/json"
	"testing"
)

func FuzzDecode(f *testing.F) {
	f.Add([]byte(`{"schema":"aegismesh.console.settings/v1","next_seq":1,"values":{},"accepted":{},"history":[]}`))
	f.Add([]byte(`{"schema":"aegismesh.console.settings/v1","next_seq":3,"values":{"console.session_ttl_seconds":"7200",` +
		`"console.sign_in_banner":"Authorized use only.\nActivity is logged."},"accepted":{"POS-007":{"by":"cfg:admin",` +
		`"by_name":"admin","reason":"lab node","until":"2027-01-01T00:00:00Z","accepted_at":"2026-11-01T00:00:00Z"}},` +
		`"history":[{"seq":1,"key":"console.session_ttl_seconds","from":"3600","to":"7200","actor_id":"cfg:admin",` +
		`"actor_name":"admin","reason":"shifts","at":"2026-11-01T00:00:00Z"},{"seq":2,"key":"posture.accepted",` +
		`"from":"POS-007: not accepted","to":"POS-007: accepted until 2027-01-01T00:00:00Z","actor_id":"cfg:admin",` +
		`"actor_name":"admin","reason":"lab node","at":"2026-11-01T00:00:00Z"}]}`))
	f.Add([]byte(`{"schema":"aegismesh.console.settings/v1","next_seq":1,"values":{"console.listen":"0.0.0.0:80"},"accepted":{},"history":[]}`))
	f.Add([]byte(`{"schema":"aegismesh.console.settings/v1","next_seq":1,"values":{},"accepted":{"../x":{}},"history":[]}`))
	f.Add([]byte(`{"schema":"aegismesh.console.settings/v2"}`))
	f.Add([]byte(`{"schema":"x","schema":"y"}`))
	f.Fuzz(func(t *testing.T, body []byte) {
		decoded, err := decode(body)
		if err != nil {
			return
		}
		if validate(decoded) != nil {
			t.Fatal("decode accepted an invalid snapshot")
		}
		for key := range decoded.Values {
			// Nothing outside the compiled-in allowlist can ever be stored.
			if _, ok := Lookup(key); !ok {
				t.Fatalf("non-allowlisted key %q decoded", key)
			}
		}
		encoded, err := json.Marshal(decoded)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := decode(encoded); err != nil {
			t.Fatalf("re-encoded snapshot rejected: %v", err)
		}
	})
}
