package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/metaforismo/aegismesh/internal/console/audit"
)

const accountsFixture = `{"schema":"aegismesh.console.accounts/v1",` +
	`"identity_key":"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff","accounts":[` +
	`{"id":"acc_00000000000000a1","name":"SIEM pull","kind":"service","role":"viewer","tenants":["default"],` +
	`"status":"active","created_at":"2026-10-01T09:00:00Z","created_by":"cfg:alice","updated_at":"2026-10-01T09:00:00Z",` +
	`"last_seen_at":"2026-11-01T11:59:00Z","keys":[{"id":"key_0000000000b1","label":"splunk","prefix":"amk_AbCd",` +
	`"sha256":"1111111111111111111111111111111111111111111111111111111111111111","created_at":"2026-10-01T09:00:00Z",` +
	`"created_by":"cfg:alice","expires_at":"2026-12-30T09:00:00Z","last_used_at":"2026-11-01T11:59:00Z","revoked_at":null},` +
	`{"id":"key_0000000000b2","label":"old","prefix":"amk_EfGh",` +
	`"sha256":"2222222222222222222222222222222222222222222222222222222222222222","created_at":"2026-08-01T09:00:00Z",` +
	`"created_by":"cfg:alice","expires_at":"2026-10-30T09:00:00Z","last_used_at":null,"revoked_at":null}]},` +
	`{"id":"acc_00000000000000a2","name":"Dana Admin","kind":"person","role":"admin","tenants":["default"],` +
	`"status":"active","created_at":"2026-10-02T09:00:00Z","created_by":"cfg:alice","updated_at":"2026-10-02T09:00:00Z",` +
	`"last_seen_at":null,"keys":[]}],"oidc_identities":[],"preferences":{}}`

func accountsState(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "console")
	for _, path := range []string{filepath.Join(dir, "accounts"), filepath.Join(dir, "tenants", "default")} {
		if err := os.MkdirAll(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "accounts", "accounts.json"), []byte(accountsFixture), 0600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestAccountsCLIGolden(t *testing.T) {
	fixedClock(t)
	dir := accountsState(t)
	code, text, stderr := run(t, "accounts", "list", "--state-dir", dir)
	if code != 0 {
		t.Fatalf("list: %d %s", code, stderr)
	}
	checkGolden(t, "accounts-list.golden.txt", text)
	code, body, stderr := run(t, "accounts", "list", "--state-dir", dir, "--json")
	if code != 0 {
		t.Fatalf("list json: %d %s", code, stderr)
	}
	checkGolden(t, "accounts-list.golden.json", body)
	if strings.Contains(text+body, "1111111111") || strings.Contains(text+body, "sha256") {
		t.Fatal("listing exposes key digests")
	}
}

func TestAccountsCLIBreakGlass(t *testing.T) {
	fixedClock(t)
	dir := accountsState(t)
	for _, args := range [][]string{
		{"accounts", "disable", "--state-dir", dir, "acc_00000000000000a1"},
		{"accounts", "key", "revoke", "--state-dir", dir, "acc_00000000000000a1", "key_0000000000b1"},
		{"accounts", "enable", "--state-dir", dir, "acc_00000000000000a1"},
	} {
		if code, _, stderr := run(t, args...); code != 0 {
			t.Fatalf("%v: %d %s", args, code, stderr)
		}
	}
	_, body, _ := run(t, "accounts", "list", "--state-dir", dir, "--json")
	if !strings.Contains(body, `"status": "active"`) || !strings.Contains(body, `"status": "revoked"`) {
		t.Fatalf("state after break-glass: %s", body)
	}
	chain, err := audit.New(filepath.Join(dir, "tenants", "default"))
	if err != nil {
		t.Fatal(err)
	}
	defer chain.Close()
	records, _, err := chain.Collect(goldenEpoch.Add(-24*365*60*60*1e9), 10)
	if err != nil || len(records) != 3 || records[0].ActorID != "cli:local" || records[1].Action != "key.revoke" ||
		records[1].Target != "key_0000000000b1" {
		t.Fatalf("audit = %+v %v", records, err)
	}
	if verification := chain.Verify(); !verification.Verified {
		t.Fatalf("audit chain: %+v", verification)
	}

	for _, testCase := range []struct {
		name string
		args []string
		code int
	}{
		{"no subcommand", []string{"accounts"}, 2},
		{"no state dir", []string{"accounts", "list"}, 2},
		{"unknown", []string{"accounts", "delete", "--state-dir", dir, "acc_00000000000000a1"}, 2},
		{"bad id", []string{"accounts", "disable", "--state-dir", dir, "../etc"}, 2},
		{"bad key", []string{"accounts", "key", "revoke", "--state-dir", dir, "acc_00000000000000a1", "x"}, 2},
		{"json on mutation", []string{"accounts", "disable", "--json", "--state-dir", dir, "acc_00000000000000a1"}, 2},
		{"bad tenant", []string{"accounts", "disable", "--local-tenant", "../x", "--state-dir", dir, "acc_00000000000000a1"}, 2},
		{"unknown account", []string{"accounts", "disable", "--state-dir", dir, "acc_ffffffffffffffff"}, 1},
		{"missing store", []string{"accounts", "list", "--state-dir", filepath.Join(dir, "nope")}, 1},
		{"missing chain", []string{"accounts", "disable", "--local-tenant", "bravo", "--state-dir", dir, "acc_00000000000000a1"}, 1},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			if code, _, _ := run(t, testCase.args...); code != testCase.code {
				t.Fatalf("exit = %d; want %d", code, testCase.code)
			}
		})
	}
	if _, err := os.Stat(filepath.Join(dir, "tenants", "bravo")); err == nil {
		t.Fatal("the CLI created tenant state")
	}
}
