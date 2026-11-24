package accounts

import (
	"encoding/json"
	"testing"
)

func FuzzDecode(f *testing.F) {
	f.Add([]byte(`{"schema":"aegismesh.console.accounts/v1","identity_key":"` +
		"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff" +
		`","accounts":[],"oidc_identities":[],"preferences":{}}`))
	f.Add([]byte(`{"schema":"aegismesh.console.accounts/v1","identity_key":"` +
		"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff" +
		`","accounts":[{"id":"acc_0123456789abcdef","name":"Svc","kind":"service","role":"viewer",` +
		`"tenants":["default"],"status":"active","created_at":"2026-11-01T00:00:00Z","created_by":"cfg:alice",` +
		`"updated_at":"2026-11-01T00:00:00Z","last_seen_at":null,"keys":[{"id":"key_0123456789ab","label":"k",` +
		`"prefix":"amk_abcd","sha256":"` + "aa00000000000000000000000000000000000000000000000000000000000000" +
		`","created_at":"2026-11-01T00:00:00Z","created_by":"cfg:alice","expires_at":"2026-12-01T00:00:00Z",` +
		`"last_used_at":null,"revoked_at":null}]}],"oidc_identities":[],"preferences":{"cfg:alice":` +
		`{"timezone":"utc","default_window":"24h","density":"compact","theme":"dark","reduce_motion":"on"}}}`))
	f.Add([]byte(`{"schema":"aegismesh.console.accounts/v2","identity_key":"` +
		"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff" +
		`","accounts":[{"id":"acc_0123456789abcdef","name":"Svc","kind":"service","role":"role_0123456789ab",` +
		`"tenants":["default"],"status":"active","created_at":"2026-11-01T00:00:00Z","created_by":"cfg:alice",` +
		`"updated_at":"2026-11-01T00:00:00Z","last_seen_at":null,"keys":[]}],"oidc_identities":[],"preferences":{},` +
		`"roles":[{"id":"role_0123456789ab","name":"Responder","description":"","permissions":["evidence.read"],` +
		`"created_at":"2026-11-01T00:00:00Z","created_by":"cfg:alice","updated_at":"2026-11-01T00:00:00Z"}]}`))
	f.Add([]byte(`{"schema":"aegismesh.console.accounts/v2","identity_key":"` +
		"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff" +
		`","accounts":[],"oidc_identities":[],"preferences":{},"roles":[{"id":"role_0123456789ab","name":"Shadow",` +
		`"description":"","permissions":["roles.manage"],"created_at":"2026-11-01T00:00:00Z","created_by":"cfg:alice",` +
		`"updated_at":"2026-11-01T00:00:00Z"}]}`))
	f.Add([]byte(`{"schema":"aegismesh.console.accounts/v9","roles":[]}`))
	f.Add([]byte(`{"schema":"x","schema":"y"}`))
	f.Add([]byte(`[]`))
	f.Add([]byte(`{"accounts":[{"role":"root"}]}`))
	f.Fuzz(func(t *testing.T, body []byte) {
		decoded, err := decode(body)
		if err != nil {
			return
		}
		if validate(decoded) != nil {
			t.Fatal("decode accepted an invalid snapshot")
		}
		encoded, err := json.Marshal(decoded)
		if err != nil {
			t.Fatal(err)
		}
		again, err := decode(encoded)
		if err != nil {
			t.Fatalf("re-encoded snapshot rejected: %v", err)
		}
		for _, account := range again.Accounts {
			if again.roleName(account.Role) == "" {
				t.Fatalf("account holds unknown role %q", account.Role)
			}
		}
		for _, role := range again.Roles {
			// Custom roles only combine catalogue ids under the combination rules.
			if !ValidPermissions(role.Permissions) {
				t.Fatalf("role %q holds invalid permissions %v", role.ID, role.Permissions)
			}
		}
	})
}
