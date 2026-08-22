package egress

import (
	"strings"
	"testing"
)

// FuzzValidateURL pins the policy invariants under arbitrary input:
//   - ValidateURL never panics;
//   - acceptance implies IsDenied==false and a usable URL;
//   - rejection always carries the typed sentinel.
func FuzzValidateURL(f *testing.F) {
	seeds := []string{
		"http://127.0.0.1:11434/v1", "https://api.openai.com/v1",
		"http://169.254.169.254/", "file:///etc/passwd", "",
		"http://[::ffff:10.0.0.1]/", "http://u:p@h/x?q=1#f",
		strings.Repeat("a", 300), "http://exämple.com", "gopher://x",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		u, err := ValidateURL(Policy{AllowLoopback: true}, raw)
		if err == nil {
			if u == nil || u.Hostname() == "" {
				t.Fatalf("accepted %q without usable host", raw)
			}
			switch u.Scheme {
			case "http", "https":
			default:
				t.Fatalf("accepted non-http(s) scheme %q", raw)
			}
			return
		}
		if !IsDenied(err) {
			t.Fatalf("rejection of %q is not a typed denial: %v", raw, err)
		}
	})
}
