package settings

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metaforismo/aegismesh/internal/config"
)

type clock struct{ nanos atomic.Int64 }

func (c *clock) now() time.Time          { return time.Unix(0, c.nanos.Load()).UTC() }
func (c *clock) advance(d time.Duration) { c.nanos.Add(int64(d)) }

func newStore(t *testing.T) (*Store, *clock, string) {
	t.Helper()
	c := &clock{}
	c.nanos.Store(time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC).UnixNano())
	dir := filepath.Join(t.TempDir(), "settings")
	store, err := Open(dir, c.now)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store, c, dir
}

var admin = Actor{ID: "cfg:admin", Name: "admin"}

func TestDefinitionBounds(t *testing.T) {
	for _, testCase := range []struct {
		key, value string
		maxDays    int
		ok         bool
	}{
		{SessionTTL, "900", 0, true}, {SessionTTL, "899", 0, false}, {SessionTTL, "86400", 0, true},
		{SessionTTL, "86401", 0, false}, {SessionTTL, "0900", 0, false}, {SessionTTL, "1e3", 0, false},
		{SessionIdle, "0", 0, true}, {SessionIdle, "299", 0, false}, {SessionIdle, "300", 0, true},
		{KeyMaxDays, "1", 0, true}, {KeyMaxDays, "365", 0, true}, {KeyMaxDays, "366", 0, false},
		{KeyDefaultDays, "30", 30, true}, {KeyDefaultDays, "31", 30, false}, {KeyDefaultDays, "0", 30, false},
		{SignInBanner, "Authorized use only.\nActivity is logged.", 0, true},
		{SignInBanner, strings.Repeat("b", 500), 0, true}, {SignInBanner, strings.Repeat("b", 501), 0, false},
		{SignInBanner, "", 0, true}, {SignInBanner, "esc\x1b[2J", 0, false},
		{OrganizationName, "Example SOC", 0, true}, {OrganizationName, "a\nb", 0, false},
		{OrganizationName, strings.Repeat("é", 81), 0, false},
		{DefaultWindow, "7d", 0, true}, {DefaultWindow, "30d", 0, false},
	} {
		definition, _ := Lookup(testCase.key)
		if err := definition.Check(testCase.value, testCase.maxDays); (err == nil) != testCase.ok {
			t.Errorf("%s=%q: err=%v", testCase.key, testCase.value, err)
		}
	}
	ttl, _ := Lookup(SessionTTL)
	for raw, want := range map[string]string{`3600`: "3600", `"3600"`: "", `3600.5`: "", `true`: "", `null`: ""} {
		got, err := ttl.Parse(json.RawMessage(raw))
		if got != want || (want == "") != (err != nil) {
			t.Errorf("parse %s = %q %v", raw, got, err)
		}
	}
	banner, _ := Lookup(SignInBanner)
	if got, err := banner.Parse(json.RawMessage(`"hi"`)); got != "hi" || err != nil {
		t.Fatalf("text parse = %q %v", got, err)
	}
	if _, err := banner.Parse(json.RawMessage(`42`)); err == nil {
		t.Fatal("number accepted for text")
	}
	if Editable("console.listen") || Editable("storage.encryption") || !Editable(PostureAccepted) {
		t.Fatal("allowlist")
	}
}

func TestResolve(t *testing.T) {
	file := FileValues(config.Console{})
	effective, overridden, ignored := Resolve(file, map[string]string{
		SessionTTL: "7200", KeyMaxDays: "30", KeyDefaultDays: "60", DefaultWindow: "30d",
	})
	if effective[SessionTTL] != "7200" || effective[KeyDefaultDays] != "90" || effective[DefaultWindow] != "24h" {
		t.Fatalf("effective = %v", effective)
	}
	// The default (60) exceeds the lowered maximum and the file default (90) too, so both
	// overrides are dropped rather than minting keys beyond the maximum.
	if strings.Join(overridden, ",") != SessionTTL || strings.Join(ignored, ",") != KeyDefaultDays+","+DefaultWindow+","+KeyMaxDays {
		t.Fatalf("overridden=%v ignored=%v", overridden, ignored)
	}
	effective, overridden, _ = Resolve(file, map[string]string{KeyMaxDays: "30", KeyDefaultDays: "14"})
	if effective[KeyMaxDays] != "30" || effective[KeyDefaultDays] != "14" || len(overridden) != 2 {
		t.Fatalf("coherent key overrides: %v %v", effective, overridden)
	}
}

func TestSetRevertHistoryAndRestart(t *testing.T) {
	store, c, dir := newStore(t)
	if _, err := store.Set(SessionTTL, "7200", "3600", "", admin); !errors.Is(err, ErrInvalid) {
		t.Fatalf("reason required: %v", err)
	}
	if _, err := store.Set("console.listen", "0.0.0.0:1", "", "why", admin); !errors.Is(err, ErrInvalid) {
		t.Fatalf("non-allowlisted key stored: %v", err)
	}
	change, err := store.Set(SessionTTL, "7200", "3600", "Longer shifts", admin)
	if err != nil || change.Seq != 1 || change.From != "3600" || change.To != "7200" {
		t.Fatalf("set = %+v %v", change, err)
	}
	c.advance(time.Second)
	if _, ok, err := store.Revert(SessionIdle, "1800", "1800", admin); ok || err != nil {
		t.Fatalf("revert without override: %v %v", ok, err)
	}
	revert, ok, err := store.Revert(SessionTTL, "7200", "3600", admin)
	if !ok || err != nil || revert.Seq != 2 {
		t.Fatalf("revert = %+v %v %v", revert, ok, err)
	}
	if _, err := store.Set(OrganizationName, "Example SOC", "", "Branding", admin); err != nil {
		t.Fatal(err)
	}
	history := store.History()
	if len(history) != 3 || history[0].Seq != 3 || history[2].Seq != 1 {
		t.Fatalf("history newest first: %+v", history)
	}
	_ = store.Close()
	reopened, err := Open(dir, c.now)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if reopened.Problem() != "" || reopened.Values()[OrganizationName] != "Example SOC" || len(reopened.History()) != 3 {
		t.Fatalf("restart lost state: %q %v", reopened.Problem(), reopened.Values())
	}
	info, _ := os.Stat(filepath.Join(dir, FileName))
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %v", info.Mode())
	}
}

func TestHistoryCap(t *testing.T) {
	store, _, _ := newStore(t)
	for i := 0; i < MaxHistory+5; i++ {
		value := "Org " + time.Duration(i).String()
		if _, err := store.Set(OrganizationName, value, "", "rename", admin); err != nil {
			t.Fatal(err)
		}
	}
	history := store.History()
	if len(history) != MaxHistory || history[0].Seq != MaxHistory+5 || history[len(history)-1].Seq != 6 {
		t.Fatalf("history len %d first %d last %d", len(history), history[0].Seq, history[len(history)-1].Seq)
	}
}

func TestAcceptanceBoundsAndExpiry(t *testing.T) {
	store, c, dir := newStore(t)
	now := c.now()
	for _, testCase := range []struct {
		name   string
		id     string
		reason string
		until  time.Time
	}{
		{"no reason", "POS-007", "", now.Add(time.Hour)},
		{"past", "POS-007", "why", now.Add(-time.Hour)},
		{"over 180 days", "POS-007", "why", now.Add(181 * 24 * time.Hour)},
		{"bad id", "../x", "why", now.Add(time.Hour)},
		{"long reason", "POS-007", strings.Repeat("r", 201), now.Add(time.Hour)},
	} {
		if _, _, err := store.Accept(testCase.id, testCase.reason, testCase.until, admin); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", testCase.name, err)
		}
	}
	acceptance, change, err := store.Accept("POS-007", "No honeytokens on this lab node", now.Add(48*time.Hour), admin)
	if err != nil || acceptance.By != "cfg:admin" || change.Key != PostureAccepted ||
		change.To != "POS-007: accepted until 2026-11-03T12:00:00Z" || change.From != "POS-007: not accepted" {
		t.Fatalf("accept = %+v %+v %v", acceptance, change, err)
	}
	if got, err := ReadAccepted(dir, now); err != nil || got["POS-007"].Reason == "" {
		t.Fatalf("offline read = %v %v", got, err)
	}
	c.advance(49 * time.Hour)
	if len(store.Accepted()) != 0 {
		t.Fatal("expired acceptance still reported")
	}
	if _, err := store.Unaccept("POS-007", admin); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired acceptance withdrawn: %v", err)
	}
	// The next write prunes it from disk.
	if _, _, err := store.Accept("POS-014", "Correlation off on purpose", c.now().Add(time.Hour), admin); err != nil {
		t.Fatal(err)
	}
	body, _ := os.ReadFile(filepath.Join(dir, FileName))
	if strings.Contains(string(body), `"POS-007":{`) {
		t.Fatalf("expired acceptance not pruned: %s", body)
	}
	if _, err := store.Unaccept("POS-014", admin); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadAccepted(filepath.Join(dir, "missing"), now); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing overlay: %v", err)
	}
}

func TestUnavailableOverlayIsNeverWritten(t *testing.T) {
	for name, body := range map[string]string{
		"corrupt": `{"schema":`,
		"unknown": `{"schema":"aegismesh.console.settings/v1","next_seq":1,"values":{},"accepted":{},"history":[],"x":1}`,
		"newer":   `{"schema":"aegismesh.console.settings/v2"}`,
		"foreign key": `{"schema":"aegismesh.console.settings/v1","next_seq":1,"values":{"console.listen":"0.0.0.0:80"},` +
			`"accepted":{},"history":[]}`,
	} {
		t.Run(name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "settings")
			if err := os.MkdirAll(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, FileName)
			if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			store, err := Open(dir, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			if store.Problem() == "" || len(store.Values()) != 0 {
				t.Fatalf("problem=%q values=%v", store.Problem(), store.Values())
			}
			if _, err := store.Set(OrganizationName, "x", "", "why", admin); !errors.Is(err, ErrUnavailable) {
				t.Fatalf("write to unavailable overlay: %v", err)
			}
			after, _ := os.ReadFile(path)
			if string(after) != body {
				t.Fatal("unavailable overlay modified")
			}
		})
	}
}

func TestOutOfBoundsStoredValueLoads(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "settings")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	body := `{"schema":"aegismesh.console.settings/v1","next_seq":1,"values":{"console.session_ttl_seconds":"5"},` +
		`"accepted":{},"history":[]}`
	if err := os.WriteFile(filepath.Join(dir, FileName), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := Open(dir, nil)
	if err != nil || store.Problem() != "" {
		t.Fatalf("shape-valid overlay rejected: %v %q", err, store.Problem())
	}
	defer store.Close()
	_, overridden, ignored := Resolve(FileValues(config.Console{}), store.Values())
	if len(overridden) != 0 || len(ignored) != 1 || ignored[0] != SessionTTL {
		t.Fatalf("overridden=%v ignored=%v", overridden, ignored)
	}
}
