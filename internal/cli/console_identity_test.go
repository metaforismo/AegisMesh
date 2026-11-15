package cli

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/metaforismo/aegismesh/internal/config"
)

func TestIdentityReportDoesNotResolveSecrets(t *testing.T) {
	cfg := &config.Config{Console: (config.Console{
		Tenants: []string{"default", "bravo"}, LocalTenant: "bravo",
		Operators: []config.Operator{{Name: "operator", Role: "viewer", TokenSHA256: "synthetic-digest", Tenants: []string{"bravo"}}},
		OIDC:      config.OIDC{Enabled: true, Issuer: "https://idp.example.invalid", ClientSecretEnv: "TEST_IDENTITY_SECRET"},
	}).WithDefaults()}
	t.Setenv("TEST_IDENTITY_SECRET", "must-never-appear")
	body, err := json.Marshal(identityReport(cfg))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(body, []byte("must-never-appear")) || bytes.Contains(body, []byte("synthetic-digest")) ||
		!bytes.Contains(body, []byte("TEST_IDENTITY_SECRET")) || !bytes.Contains(body, []byte("bravo")) {
		t.Fatal("unsafe identity report")
	}
	var text bytes.Buffer
	printIdentity(&text, cfg)
	if strings.Contains(text.String(), "must-never-appear") {
		t.Fatal("unsafe human report")
	}
}
