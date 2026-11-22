package evidenceview

import (
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"

	"github.com/metaforismo/aegismesh/internal/evidenceindex"
)

func TestShapeNormalisation(t *testing.T) {
	for _, tc := range []struct {
		name, kind, class, summary string
		status                     int
		want                       string
	}{
		{"http status stripped", "http", "interaction", "GET /api/tags → 200", 200, "GET /api/tags"},
		{"numeric id", "http", "interaction", "GET /v1/users/12345/keys → 404", 404, "GET /v1/users/{n}/keys"},
		{"uuid", "http", "interaction", "DELETE /v1/files/123e4567-e89b-12d3-a456-426614174000", 0, "DELETE /v1/files/{uuid}"},
		{"hex", "http", "interaction", "GET /blob/deadbeefcafe", 0, "GET /blob/{hex}"},
		{"mixed id", "http", "interaction", "GET /runs/run_2024a11b", 0, "GET /runs/{id}"},
		{"long token", "http", "interaction", "GET /s/" + strings.Repeat("abcdefgh", 5), 0, "GET /s/{token}"},
		{"honeytoken marker", "http", "interaction", "GET /k/[honeytoken:decoy-key]", 0, "GET /k/{honeytoken}"},
		{"redaction marker", "http", "interaction", "GET /k/[redacted-provider-key]", 0, "GET /k/{redacted}"},
		{"provider key scrubbed again", "http", "interaction", "GET /k/sk-abcdefghijklmnop", 0, "GET /k/[redacted-provider-key]"},
		{"bearer scrubbed in tool", "mcp", "canary_invocation", "tools/call bearer_abcdefghijkl", 0, "tools/call bearer_abcdefghijkl"},
		{"segment cap", "http", "interaction", "GET /a/b/c/d/e/f/g/h/i/j/k/l/m/n", 0, "GET /a/b/c/d/e/f/g/h/i/j/k/l/…"},
		{"lowercase method", "http", "interaction", "get /x", 0, "OTHER /x"},
		{"forged status without verified status", "http", "interaction", "GET /x → 200", 0, "GET /x → 200"},
		{"http fallback", "http", "interaction", "http observation", 0, "http (unparsed)"},
		{"mcp tool", "mcp", "canary_invocation", "tools/call read_file", 0, "tools/call read_file"},
		{"mcp list", "mcp", "interaction", "tools/list", 0, "tools/list"},
		{"mcp id tool", "mcp", "canary_invocation", "tools/call 1234567890", 0, "tools/call {n}"},
		{"ssh", "ssh", "interaction", "auth password · 3 attempts · rejected", 0, "login password · rejected"},
		{"ssh fallback", "ssh", "interaction", "ssh observation", 0, "ssh session"},
		{"tcp rule", "tcp", "interaction", "3 lines · 120 B · rule redis-info", 0, "exchange · rule redis-info"},
		{"tcp no rule", "tcp", "interaction", "3 lines · 120 B", 0, "exchange · no rule"},
		{"signal", "http", "correlation_signal", "COR-005 · cadence", 0, "http signal"},
		{"unknown kind", "smtp", "interaction", "whatever", 0, "smtp observation"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, _, _, _ := shapeParts(tc.kind, tc.class, tc.summary, tc.status)
			if got != tc.want {
				t.Fatalf("shape = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestShapePartsKeepComparisonInputs(t *testing.T) {
	_, method, path, tool := shapeParts("http", "interaction", "POST /v1/chat/completions → 400", 400)
	if method != "POST" || path != "/v1/chat/completions" || tool != "" {
		t.Fatal(method, path, tool)
	}
	_, method, _, tool = shapeParts("mcp", "canary_invocation", "tools/call read_file", 0)
	if method != "tools/call" || tool != "read_file" {
		t.Fatal(method, tool)
	}
}

func TestCollapseRepeatsAndCap(t *testing.T) {
	items := []interaction{}
	for i := 0; i < 3; i++ {
		items = append(items, interaction{kind: "http", shape: "GET /a"})
	}
	items = append(items, interaction{kind: "mcp", shape: "GET /a"}, interaction{kind: "http", shape: "GET /a"})
	steps, truncated := collapse(items)
	if len(steps) != 3 || truncated {
		t.Fatalf("collapse: %+v", steps)
	}
	long := []interaction{}
	for i := 0; i < MaxShapeSteps+5; i++ {
		long = append(long, interaction{kind: "http", shape: strings.Repeat("x", i+1)})
	}
	steps, truncated = collapse(long)
	if len(steps) != MaxShapeSteps || !truncated {
		t.Fatal("cap not applied")
	}
}

func FuzzShape(f *testing.F) {
	for _, seed := range []struct {
		kind, summary string
		status        int
	}{
		{"http", "GET /api/tags → 200", 200},
		{"http", "POST /v1/chat/completions/" + strings.Repeat("9", 40), 0},
		{"http", "GET /\x00\x1b[31m/../../etc/passwd", 0},
		{"http", "PUT /a/sk-ABCDEFGHIJKLMNOP/b → 201", 201},
		{"mcp", "tools/call " + strings.Repeat("é", 100), 0},
		{"ssh", "auth password · 9 attempts · rejected", 0},
		{"tcp", "1 lines · 9 B · rule x", 0},
		{"http", "\xff\xfe GET", 0},
		{"", "", 0},
	} {
		f.Add(seed.kind, seed.summary, seed.status)
	}
	f.Fuzz(func(t *testing.T, kind, summary string, status int) {
		shape, _, path, tool := shapeParts(evidenceindex.Bound(kind, 32), "interaction", summary, status)
		again, _, _, _ := shapeParts(evidenceindex.Bound(kind, 32), "interaction", summary, status)
		if shape != again {
			t.Fatal("nondeterministic shape")
		}
		if shape == "" || !utf8.ValidString(shape) || utf8.RuneCountInString(shape) > MaxShapeRunes {
			t.Fatalf("unbounded or invalid shape %q", shape)
		}
		for _, r := range shape {
			if unicode.IsControl(r) {
				t.Fatalf("control character in shape %q", shape)
			}
		}
		if utf8.RuneCountInString(path) > 128 || utf8.RuneCountInString(tool) > 64 {
			t.Fatal("comparison inputs exceed bounds")
		}
		if strings.Contains(summary, "sk-ABCDEFGHIJKLMNOP") && strings.Contains(shape, "sk-ABCDEFGHIJKLMNOP") {
			t.Fatalf("provider-key shape survived scrubbing: %q", shape)
		}
	})
}
