package accounts

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type clock struct{ nanos atomic.Int64 }

func (c *clock) now() time.Time          { return time.Unix(0, c.nanos.Load()).UTC() }
func (c *clock) advance(d time.Duration) { c.nanos.Add(int64(d)) }

func newStore(t *testing.T) (*Store, *clock, string) {
	t.Helper()
	c := &clock{}
	c.nanos.Store(time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC).UnixNano())
	dir := filepath.Join(t.TempDir(), "accounts")
	store, err := Open(dir, Options{Tenants: []string{"default", "bravo"}, LocalTenant: "default",
		Reserved: []string{"alice"}, Now: c.now})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store, c, dir
}

func mustCreate(t *testing.T, store *Store, name, role string) Account {
	t.Helper()
	account, err := store.Create(Create{Name: name, Kind: "person", Role: role, Tenants: []string{"default"}}, "cfg:alice")
	if err != nil {
		t.Fatal(err)
	}
	return account
}

func digest(token string) [32]byte { return sha256.Sum256([]byte(token)) }

func TestCreateValidation(t *testing.T) {
	store, _, _ := newStore(t)
	mustCreate(t, store, "Existing Person", "viewer")
	for _, testCase := range []struct {
		name  string
		input Create
		want  error
	}{
		{"valid unicode name", Create{Name: "Zoë Analyst", Kind: "person", Role: "analyst", Tenants: []string{"default"}}, nil},
		{"service", Create{Name: "siem-pull", Kind: "service", Role: "viewer", Tenants: []string{"bravo"}}, nil},
		{"80 runes", Create{Name: strings.Repeat("é", 80), Kind: "person", Role: "viewer", Tenants: []string{"default"}}, nil},
		{"81 runes", Create{Name: strings.Repeat("é", 81), Kind: "person", Role: "viewer", Tenants: []string{"default"}}, ErrInvalid},
		{"empty name", Create{Name: "", Kind: "person", Role: "viewer", Tenants: []string{"default"}}, ErrInvalid},
		{"padded name", Create{Name: " bob", Kind: "person", Role: "viewer", Tenants: []string{"default"}}, ErrInvalid},
		{"control name", Create{Name: "bob\x1b[2J", Kind: "person", Role: "viewer", Tenants: []string{"default"}}, ErrInvalid},
		{"role above admin", Create{Name: "root", Kind: "person", Role: "superadmin", Tenants: []string{"default"}}, ErrInvalid},
		{"empty role", Create{Name: "nobody", Kind: "person", Tenants: []string{"default"}}, ErrInvalid},
		{"bad kind", Create{Name: "robot", Kind: "bot", Role: "viewer", Tenants: []string{"default"}}, ErrInvalid},
		{"no tenants", Create{Name: "lonely", Kind: "person", Role: "viewer"}, ErrInvalid},
		{"undeclared tenant", Create{Name: "foreign", Kind: "person", Role: "viewer", Tenants: []string{"charlie"}}, ErrInvalid},
		{"duplicate tenant", Create{Name: "dup", Kind: "person", Role: "viewer", Tenants: []string{"default", "default"}}, ErrInvalid},
		{"path tenant", Create{Name: "path", Kind: "person", Role: "viewer", Tenants: []string{"../x"}}, ErrInvalid},
		{"reserved config name", Create{Name: "ALICE", Kind: "person", Role: "viewer", Tenants: []string{"default"}}, ErrNameTaken},
		{"duplicate name", Create{Name: "existing person", Kind: "person", Role: "viewer", Tenants: []string{"default"}}, ErrNameTaken},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			account, err := store.Create(testCase.input, "cfg:alice")
			if !errors.Is(err, testCase.want) {
				t.Fatalf("err = %v; want %v", err, testCase.want)
			}
			if err == nil && (!ValidAccountID(account.ID) || account.Status != StatusActive || len(account.Keys) != 0) {
				t.Fatalf("account = %+v", account)
			}
		})
	}
}

func TestAccountQuota(t *testing.T) {
	store, _, _ := newStore(t)
	for i := range MaxAccounts {
		mustCreate(t, store, "person "+strings.Repeat("x", i%5)+string(rune('a'+i%26))+string(rune('A'+i/26)), "viewer")
	}
	if _, err := store.Create(Create{Name: "one too many", Kind: "person", Role: "viewer", Tenants: []string{"default"}}, "cfg:alice"); !errors.Is(err, ErrLimit) {
		t.Fatalf("err = %v; want limit", err)
	}
}

func TestKeyLifecycleAndMatch(t *testing.T) {
	store, c, _ := newStore(t)
	account := mustCreate(t, store, "Service One", "analyst")
	for _, testCase := range []struct {
		label string
		days  int
		want  error
	}{
		{"", 30, ErrInvalid},
		{strings.Repeat("k", 65), 30, ErrInvalid},
		{"tab\tlabel", 30, ErrInvalid},
		{"ok", -1, ErrInvalid},
		{"ok", 366, ErrInvalid},
	} {
		if _, _, err := store.CreateKey(account.ID, testCase.label, testCase.days, "cfg:alice"); !errors.Is(err, testCase.want) {
			t.Fatalf("label %q days %d: err = %v", testCase.label, testCase.days, err)
		}
	}
	view, token, err := store.CreateKey(account.ID, "SIEM pull", 0, "cfg:alice")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(token, TokenPrefix) || len(token) != 47 || view.Prefix != token[:8] ||
		view.Status != KeyActive || !ValidKeyID(view.ID) ||
		!view.ExpiresAt.Equal(view.CreatedAt.Add(DefaultKeyDays*24*time.Hour)) {
		t.Fatalf("view = %+v token length %d", view, len(token))
	}
	encoded, _ := json.Marshal(view)
	if strings.Contains(string(encoded), "sha256") || strings.Contains(string(encoded), token[8:]) {
		t.Fatalf("key view leaks secret material: %s", encoded)
	}
	principal, expiry, ok := store.Match(digest(token))
	if !ok || principal.ID != account.ID || principal.Source != "managed" || principal.KeyID != view.ID ||
		principal.Role != "analyst" || principal.Tenant != "default" || !expiry.Equal(view.ExpiresAt) {
		t.Fatalf("principal = %+v %v %v", principal, expiry, ok)
	}
	if _, _, ok := store.Match(digest(token + "x")); ok {
		t.Fatal("wrong token matched")
	}
	// Disabled accounts fail closed immediately.
	disabled := StatusDisabled
	if _, change, err := store.Update(account.ID, Patch{Status: &disabled}, "cfg:alice", 1); err != nil || !change.Revoke {
		t.Fatalf("disable: %v %+v", err, change)
	}
	if _, _, ok := store.Match(digest(token)); ok {
		t.Fatal("disabled account authenticated")
	}
	if _, _, err := store.CreateKey(account.ID, "more", 1, "cfg:alice"); !errors.Is(err, ErrDisabled) {
		t.Fatalf("key for disabled account: %v", err)
	}
	active := StatusActive
	if _, _, err := store.Update(account.ID, Patch{Status: &active}, "cfg:alice", 1); err != nil {
		t.Fatal(err)
	}
	if _, _, ok := store.Match(digest(token)); !ok {
		t.Fatal("re-enabled account failed")
	}
	// Expiry fails closed.
	c.advance(DefaultKeyDays * 24 * time.Hour)
	if _, _, ok := store.Match(digest(token)); ok {
		t.Fatal("expired key authenticated")
	}
	// Revocation fails closed and is idempotent.
	_, second, err := store.CreateKey(account.ID, "second", 1, "cfg:alice")
	if err != nil {
		t.Fatal(err)
	}
	keys, _ := store.Get(account.ID)
	secondID := keys.Keys[len(keys.Keys)-1].ID
	if _, changed, err := store.RevokeKey(account.ID, secondID, "cfg:alice", 1); err != nil || !changed {
		t.Fatalf("revoke: %v %v", err, changed)
	}
	if _, changed, err := store.RevokeKey(account.ID, secondID, "cfg:alice", 1); err != nil || changed {
		t.Fatalf("second revoke: %v %v", err, changed)
	}
	if _, _, ok := store.Match(digest(second)); ok {
		t.Fatal("revoked key authenticated")
	}
	if _, _, err := store.RevokeKey(account.ID, "key_000000000000", "cfg:alice", 1); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown key: %v", err)
	}
}

func TestKeyQuotaPrunesInactiveKeys(t *testing.T) {
	store, _, _ := newStore(t)
	account := mustCreate(t, store, "Quota", "viewer")
	ids := []string{}
	for range MaxKeysPerAccount {
		view, _, err := store.CreateKey(account.ID, "k", 1, "cfg:alice")
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, view.ID)
	}
	if _, _, err := store.CreateKey(account.ID, "k", 1, "cfg:alice"); !errors.Is(err, ErrLimit) {
		t.Fatalf("eleventh active key: %v", err)
	}
	if _, _, err := store.RevokeKey(account.ID, ids[3], "cfg:alice", NoGuard); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.CreateKey(account.ID, "k", 1, "cfg:alice"); err != nil {
		t.Fatalf("key after revocation: %v", err)
	}
	stored, _ := store.Get(account.ID)
	if len(stored.Keys) != MaxKeysPerAccount {
		t.Fatalf("keys = %d", len(stored.Keys))
	}
	for _, key := range stored.Keys {
		if key.ID == ids[3] {
			t.Fatal("revoked key was not pruned")
		}
	}
}

func TestLastAdminGuard(t *testing.T) {
	store, _, _ := newStore(t)
	admin := mustCreate(t, store, "Only Admin", "admin")
	view, _, err := store.CreateKey(admin.ID, "admin key", 30, "cfg:alice")
	if err != nil {
		t.Fatal(err)
	}
	viewer, analyst, disabled := "viewer", "analyst", StatusDisabled
	bravo := []string{"bravo"}
	for _, patch := range []Patch{{Role: &viewer}, {Role: &analyst}, {Status: &disabled}, {Tenants: &bravo}} {
		if _, _, err := store.Update(admin.ID, patch, "acc_x", 0); !errors.Is(err, ErrLastAdmin) {
			t.Fatalf("patch %+v: err = %v; want last admin", patch, err)
		}
	}
	if _, _, err := store.RevokeKey(admin.ID, view.ID, "acc_x", 0); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("revoking the last admin key: %v", err)
	}
	// A config-file admin keeps break-glass access, so the change is allowed.
	if _, _, err := store.Update(admin.ID, Patch{Role: &viewer}, "cfg:alice", 1); err != nil {
		t.Fatal(err)
	}
	// The guard never blocks when there was no usable admin before the change.
	if _, _, err := store.Update(admin.ID, Patch{Status: &disabled}, "cfg:alice", 0); err != nil {
		t.Fatal(err)
	}
	// The offline CLI deliberately bypasses it.
	stored, _ := store.Get(admin.ID)
	if stored.Status != StatusDisabled || stored.Role != "viewer" {
		t.Fatalf("stored = %+v", stored)
	}
}

func TestLastUsedThrottleAndFlush(t *testing.T) {
	store, c, dir := newStore(t)
	account := mustCreate(t, store, "Usage", "viewer")
	_, token, err := store.CreateKey(account.ID, "k", 1, "cfg:alice")
	if err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(filepath.Join(dir, FileName))
	store.Match(digest(token))
	first, _ := store.Get(account.ID)
	c.advance(30 * time.Second)
	store.Match(digest(token))
	second, _ := store.Get(account.ID)
	if first.Keys[0].LastUsedAt == nil || !first.Keys[0].LastUsedAt.Equal(*second.Keys[0].LastUsedAt) {
		t.Fatalf("last_used_at moved within the resolution: %v %v", first.Keys[0].LastUsedAt, second.Keys[0].LastUsedAt)
	}
	after, _ := os.ReadFile(filepath.Join(dir, FileName))
	if string(before) != string(after) {
		t.Fatal("authentication wrote to disk synchronously")
	}
	c.advance(31 * time.Second)
	store.Match(digest(token))
	third, _ := store.Get(account.ID)
	if !third.Keys[0].LastUsedAt.After(*first.Keys[0].LastUsedAt) {
		t.Fatal("last_used_at did not advance after the resolution")
	}
	if err := store.Flush(); err != nil {
		t.Fatal(err)
	}
	persisted, _ := os.ReadFile(filepath.Join(dir, FileName))
	if err := Check(persisted); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(persisted), third.Keys[0].LastUsedAt.Format(time.RFC3339Nano)) {
		t.Fatal("flush did not persist last_used_at")
	}
}

func TestPersistenceStrictnessAndForeignWriters(t *testing.T) {
	store, c, dir := newStore(t)
	account := mustCreate(t, store, "Persisted", "admin")
	if _, _, err := store.CreateKey(account.ID, "k", 10, "cfg:alice"); err != nil {
		t.Fatal(err)
	}
	if err := store.SetPreferences(account.ID, Preferences{Timezone: "local", DefaultWindow: "7d", Density: "compact", Theme: "dark", ReduceMotion: "on"}); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(dir, FileName))
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("state file mode: %v %v", info, err)
	}
	body, _ := os.ReadFile(filepath.Join(dir, FileName))
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(dir, Options{Tenants: []string{"default", "bravo"}, Now: c.now})
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := reopened.Get(account.ID); got.Name != "Persisted" || len(got.Keys) != 1 {
		t.Fatalf("reopened = %+v", got)
	}
	if reopened.Preferences(account.ID).Theme != "dark" || reopened.Preferences("cfg:nobody") != DefaultPreferences {
		t.Fatal("preferences did not persist")
	}
	// Another writer changing the file makes this process fail closed.
	if err := os.WriteFile(filepath.Join(dir, FileName), append(body, ' '), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := reopened.Create(Create{Name: "late", Kind: "person", Role: "viewer", Tenants: []string{"default"}}, "cfg:alice"); !errors.Is(err, ErrModified) {
		t.Fatalf("foreign write: %v", err)
	}
	reopened.Close()

	for name, mutate := range map[string]func([]byte) []byte{
		"corrupt": func([]byte) []byte { return []byte("{") },
		"duplicate": func(b []byte) []byte {
			return []byte(strings.Replace(string(b), `{"schema"`, `{"schema":"x","schema"`, 1))
		},
		"unknown": func(b []byte) []byte {
			return []byte(strings.Replace(string(b), `{"schema"`, `{"extra":1,"schema"`, 1))
		},
		"role":      func(b []byte) []byte { return []byte(strings.Replace(string(b), `"role":"admin"`, `"role":"root"`, 1)) },
		"oversized": func(b []byte) []byte { return append(b, []byte(strings.Repeat(" ", MaxStoreBytes))...) },
	} {
		t.Run(name, func(t *testing.T) {
			bad := filepath.Join(t.TempDir(), "accounts")
			if err := os.MkdirAll(bad, 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(bad, FileName), mutate(body), 0600); err != nil {
				t.Fatal(err)
			}
			if store, err := Open(bad, Options{}); err == nil {
				store.Close()
				t.Fatal("invalid snapshot loaded")
			}
		})
	}
	stale := filepath.Join(t.TempDir(), "accounts")
	_ = os.MkdirAll(stale, 0700)
	_ = os.WriteFile(filepath.Join(stale, FileName+".tmp"), []byte("{}"), 0600)
	if store, err := Open(stale, Options{}); err == nil {
		store.Close()
		t.Fatal("stale temporary state ignored")
	}
}

func TestPreferencesValidation(t *testing.T) {
	store, _, _ := newStore(t)
	valid := DefaultPreferences
	for _, testCase := range []struct {
		id     string
		mutate func(*Preferences)
		ok     bool
	}{
		{"cfg:alice", func(*Preferences) {}, true},
		{"oidc:0123456789ab", func(p *Preferences) { p.Theme = "light" }, true},
		{"cfg:alice", func(p *Preferences) { p.Theme = "neon" }, false},
		{"cfg:alice", func(p *Preferences) { p.DefaultWindow = "30d" }, false},
		{"cfg:alice", func(p *Preferences) { p.Timezone = "Europe/Rome" }, false},
		{"cfg:alice", func(p *Preferences) { p.ReduceMotion = "off" }, false},
		{"../etc", func(*Preferences) {}, false},
		{"cfg:Alice", func(*Preferences) {}, false},
	} {
		preferences := valid
		testCase.mutate(&preferences)
		if err := store.SetPreferences(testCase.id, preferences); (err == nil) != testCase.ok {
			t.Fatalf("%s %+v: err = %v", testCase.id, preferences, err)
		}
	}
}

func TestIdentityDirectory(t *testing.T) {
	store, c, _ := newStore(t)
	id, err := store.SeenIdentity("https://issuer.example", "subject-1", "dana@example.test", "analyst", []string{"default"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(id, "oidc:") || len(id) != 17 || store.IdentityID("https://issuer.example", "subject-1") != id ||
		store.IdentityID("https://issuer.example", "subject-2") == id ||
		store.IdentityID("https://issuer.example\x00subject", "-1") == id {
		t.Fatalf("identity id %q is not a stable keyed hash", id)
	}
	c.advance(time.Minute)
	again, err := store.SeenIdentity("https://issuer.example", "subject-1", "Dana", "admin", []string{"default", "bravo"})
	if err != nil || again != id {
		t.Fatal(err)
	}
	identities := store.Identities()
	if len(identities) != 1 || identities[0].Name != "Dana" || identities[0].Role != "admin" ||
		!identities[0].LastSeenAt.After(identities[0].FirstSeenAt) {
		t.Fatalf("identities = %+v", identities)
	}
	encoded, _ := json.Marshal(identities)
	if strings.Contains(string(encoded), "issuer.example") || strings.Contains(string(encoded), "subject-1") {
		t.Fatalf("directory leaks issuer or subject: %s", encoded)
	}
}

func TestIdentityDirectoryEvictsLeastRecentlySeen(t *testing.T) {
	identityLimit = 8
	t.Cleanup(func() { identityLimit = MaxIdentities })
	store, c, _ := newStore(t)
	first, err := store.SeenIdentity("iss", "first", "first", "viewer", []string{"default"})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetPreferences(first, DefaultPreferences); err != nil {
		t.Fatal(err)
	}
	for i := 1; i < identityLimit; i++ {
		c.advance(time.Second)
		if _, err := store.SeenIdentity("iss", "subject-"+strings.Repeat("x", i%7)+string(rune('a'+i%26))+string(rune(0x100+i)), "n", "viewer", []string{"default"}); err != nil {
			t.Fatal(err)
		}
	}
	if len(store.Identities()) != identityLimit {
		t.Fatalf("identities = %d", len(store.Identities()))
	}
	c.advance(time.Second)
	if _, err := store.SeenIdentity("iss", "newest", "n", "viewer", []string{"default"}); err != nil {
		t.Fatal(err)
	}
	for _, identity := range store.Identities() {
		if identity.ID == first {
			t.Fatal("least recently seen identity was not evicted")
		}
	}
	if store.Preferences(first) != DefaultPreferences {
		t.Fatal("evicted identity kept preferences")
	}
}
