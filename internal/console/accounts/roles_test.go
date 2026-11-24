package accounts

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/metaforismo/aegismesh/internal/console/permission"
)

func TestMigrateV1FixtureKeepsBackupAndRefusesNewer(t *testing.T) {
	fixture, err := os.ReadFile(filepath.Join("testdata", "accounts-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "accounts")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, FileName), fixture, 0o600); err != nil {
		t.Fatal(err)
	}
	opts := Options{Tenants: []string{"default"}, LocalTenant: "default"}
	store, err := Open(dir, opts)
	if err != nil {
		t.Fatal(err)
	}
	accounts := store.List()
	if len(accounts) != 2 || len(store.Roles()) != 0 || store.UsableAdmins() != 1 ||
		store.Preferences("cfg:alice").Theme != "dark" {
		t.Fatalf("migrated accounts = %+v roles = %v admins = %d", accounts, store.Roles(), store.UsableAdmins())
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	backup, err := os.ReadFile(filepath.Join(dir, BackupV1))
	if err != nil || !bytes.Equal(backup, fixture) {
		t.Fatalf("v1 backup missing or changed: %v", err)
	}
	current, _ := os.ReadFile(filepath.Join(dir, FileName))
	if !strings.Contains(string(current), `"schema":"`+Schema+`"`) || !strings.Contains(string(current), `"roles":[]`) {
		t.Fatalf("store not rewritten as v2: %s", current)
	}
	// Reopening v2 is not a migration and leaves the backup untouched.
	reopened, err := Open(dir, opts)
	if err != nil {
		t.Fatal(err)
	}
	_ = reopened.Close()

	// A snapshot from a newer version is refused with a clear error, never rewritten.
	newer := bytes.Replace(current, []byte(Schema), []byte("aegismesh.console.accounts/v3"), 1)
	if err := os.WriteFile(filepath.Join(dir, FileName), newer, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(dir, opts); !errors.Is(err, ErrNewer) || !strings.Contains(err.Error(), BackupV1) {
		t.Fatalf("newer schema: %v", err)
	}
	after, _ := os.ReadFile(filepath.Join(dir, FileName))
	if !bytes.Equal(after, newer) {
		t.Fatal("a newer snapshot was modified")
	}
	// v1 documents must not carry roles.
	withRoles := bytes.Replace(fixture, []byte(`"preferences":`), []byte(`"roles":[],"preferences":`), 1)
	if _, _, err := decodeVersioned(withRoles); !errors.Is(err, ErrInvalid) {
		t.Fatalf("v1 with roles: %v", err)
	}
}

func TestRoleValidation(t *testing.T) {
	store, _, _ := newStore(t)
	if _, err := store.CreateRole(RoleInput{Name: "Responder", Permissions: []string{"evidence.read"}}, "cfg:alice"); err != nil {
		t.Fatal(err)
	}
	for _, testCase := range []struct {
		name  string
		input RoleInput
		want  error
	}{
		{"valid", RoleInput{Name: "Triage", Description: "First line", Permissions: []string{"investigations.write", "evidence.read", "evidence.read"}}, nil},
		{"no permissions", RoleInput{Name: "Signed in only"}, nil},
		{"40 runes", RoleInput{Name: strings.Repeat("é", 40), Permissions: []string{}}, nil},
		{"41 runes", RoleInput{Name: strings.Repeat("é", 41), Permissions: []string{}}, ErrInvalid},
		{"empty name", RoleInput{Name: "", Permissions: []string{}}, ErrInvalid},
		{"padded", RoleInput{Name: " Ops", Permissions: []string{}}, ErrInvalid},
		{"long description", RoleInput{Name: "Desc", Description: strings.Repeat("d", 201)}, ErrInvalid},
		{"unknown permission", RoleInput{Name: "Root", Permissions: []string{"root"}}, ErrInvalid},
		{"roles without accounts", RoleInput{Name: "Shadow", Permissions: []string{"roles.manage"}}, ErrInvalid},
		{"settings without accounts", RoleInput{Name: "Tuner", Permissions: []string{"settings.manage", "settings.read"}}, ErrInvalid},
		{"accounts manage without read", RoleInput{Name: "Blind", Permissions: []string{"accounts.manage"}}, ErrInvalid},
		{"settings manage without read", RoleInput{Name: "Blind settings", Permissions: []string{"accounts.manage", "accounts.read", "settings.manage"}}, ErrInvalid},
		{"coherent settings", RoleInput{Name: "Settings admin", Permissions: []string{"accounts.manage", "accounts.read", "settings.manage", "settings.read"}}, nil},
		{"builtin name", RoleInput{Name: "Admin", Permissions: []string{}}, ErrNameTaken},
		{"duplicate name", RoleInput{Name: "responder", Permissions: []string{}}, ErrNameTaken},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			role, err := store.CreateRole(testCase.input, "cfg:alice")
			if !errors.Is(err, testCase.want) {
				t.Fatalf("err = %v; want %v", err, testCase.want)
			}
			if err == nil && (!ValidRoleID(role.ID) || !slices.IsSorted(role.Permissions) || role.Permissions == nil) {
				t.Fatalf("role = %+v", role)
			}
		})
	}
	if role, _ := store.CreateRole(RoleInput{Name: "Dedup", Permissions: []string{"fleet.read", "evidence.read", "fleet.read"}}, "cfg:alice"); !slices.Equal(role.Permissions, []string{"evidence.read", "fleet.read"}) {
		t.Fatalf("permissions not normalized: %v", role.Permissions)
	}
	for len(store.Roles()) < MaxRoles {
		if _, err := store.CreateRole(RoleInput{Name: "Filler " + time.Now().Format("150405.000000000"), Permissions: []string{}}, "cfg:alice"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store.CreateRole(RoleInput{Name: "One too many", Permissions: []string{}}, "cfg:alice"); !errors.Is(err, ErrLimit) {
		t.Fatalf("role quota: %v", err)
	}
}

func TestRoleUpdateDeleteAndAssignment(t *testing.T) {
	store, _, dir := newStore(t)
	role, err := store.CreateRole(RoleInput{Name: "Responder", Permissions: []string{"evidence.read", "investigations.read"}}, "cfg:alice")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.UpdateRole("admin", RolePatch{Name: ptr("x")}, "cfg:alice", 1); !errors.Is(err, ErrBuiltin) {
		t.Fatalf("built-in update: %v", err)
	}
	if _, err := store.DeleteRole("viewer", "cfg:alice"); !errors.Is(err, ErrBuiltin) {
		t.Fatalf("built-in delete: %v", err)
	}
	if _, _, err := store.UpdateRole(role.ID, RolePatch{}, "cfg:alice", 1); !errors.Is(err, ErrInvalid) {
		t.Fatalf("empty patch: %v", err)
	}
	if _, _, err := store.UpdateRole("role_000000000000", RolePatch{Name: ptr("x")}, "cfg:alice", 1); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown role: %v", err)
	}
	account := mustCreate(t, store, "Custom Holder", role.ID)
	if account.Role != role.ID || store.Assigned(role.ID) != 1 {
		t.Fatalf("assignment: %+v", account)
	}
	if _, err := store.Create(Create{Name: "Ghost", Kind: "person", Role: "role_ffffffffffff", Tenants: []string{"default"}}, "cfg:alice"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unknown role on create: %v", err)
	}
	updated, change, err := store.UpdateRole(role.ID, RolePatch{Permissions: &[]string{"evidence.read"}}, "cfg:alice", 1)
	if err != nil || !slices.Equal(updated.Permissions, []string{"evidence.read"}) ||
		!slices.Equal(change.Removed, []string{"investigations.read"}) || !slices.Equal(change.Fields, []string{"permissions"}) {
		t.Fatalf("update = %+v %+v %v", updated, change, err)
	}
	if _, err := store.DeleteRole(role.ID, "cfg:alice"); !errors.Is(err, ErrInUse) {
		t.Fatalf("delete in use: %v", err)
	}
	viewer := "viewer"
	if _, _, err := store.Update(account.ID, Patch{Role: &viewer}, "cfg:alice", 1); err != nil {
		t.Fatal(err)
	}
	if _, err := store.DeleteRole(role.ID, "cfg:alice"); err != nil {
		t.Fatal(err)
	}
	// Roles survive a restart.
	kept, err := store.CreateRole(RoleInput{Name: "Kept", Permissions: []string{"audit.read"}}, "cfg:alice")
	if err != nil {
		t.Fatal(err)
	}
	_ = store.Close()
	reopened, err := Open(dir, Options{Tenants: []string{"default", "bravo"}, LocalTenant: "default"})
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if got, ok := reopened.Role(kept.ID); !ok || got.Name != "Kept" || len(reopened.Roles()) != 1 {
		t.Fatalf("reopened roles = %v", reopened.Roles())
	}
}

func TestLastAdminAcrossCustomRoles(t *testing.T) {
	store, _, _ := newStore(t)
	full := permission.Builtin(permission.Admin)
	custom, err := store.CreateRole(RoleInput{Name: "Instance owner", Permissions: full}, "cfg:alice")
	if err != nil {
		t.Fatal(err)
	}
	owner := mustCreate(t, store, "Owner", custom.ID)
	if _, _, err := store.CreateKey(owner.ID, "k", 30, "cfg:alice"); err != nil {
		t.Fatal(err)
	}
	if store.UsableAdmins() != 1 {
		t.Fatalf("custom administrators not counted: %d", store.UsableAdmins())
	}
	// Removing roles.manage from the only administering role would leave nobody.
	reduced := []string{"accounts.manage", "accounts.read", "evidence.read"}
	if _, _, err := store.UpdateRole(custom.ID, RolePatch{Permissions: &reduced}, "acc_x", 0); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("last admin via role edit: %v", err)
	}
	viewer := "viewer"
	if _, _, err := store.Update(owner.ID, Patch{Role: &viewer}, "acc_x", 0); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("last admin via reassignment: %v", err)
	}
	// A second administrator under the built-in admin role makes the edit safe.
	second := mustCreate(t, store, "Second", "admin")
	if _, _, err := store.CreateKey(second.ID, "k", 30, "cfg:alice"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.UpdateRole(custom.ID, RolePatch{Permissions: &reduced}, "acc_x", 0); err != nil {
		t.Fatal(err)
	}
	if store.UsableAdmins() != 1 {
		t.Fatalf("usable admins = %d", store.UsableAdmins())
	}
}

func ptr[T any](value T) *T { return &value }
