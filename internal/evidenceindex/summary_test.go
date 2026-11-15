package evidenceindex

import (
	"encoding/json"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"

	"github.com/metaforismo/aegismesh/internal/event"
)

func TestObservationSummaries(t *testing.T) {
	cases := []struct {
		name           string
		kind           string
		classification string
		observation    string
		want           string
	}{
		{
			name:        "http",
			kind:        "http",
			observation: `{"method":"GET","path":"/path","response":{"status":200}}`,
			want:        "GET /path → 200",
		},
		{
			name:        "mcp call",
			kind:        "mcp",
			observation: `{"method":"tools/call","tool_name":"canary_demo"}`,
			want:        "tools/call canary_demo",
		},
		{
			name:        "mcp list",
			kind:        "mcp",
			observation: `{"method":"tools/list"}`,
			want:        "tools/list",
		},
		{
			name:        "ssh",
			kind:        "ssh",
			observation: `{"outcome":"rejected","auth_method":"password","auth_attempts":3}`,
			want:        "auth password · 3 attempts · rejected",
		},
		{
			name:        "ssh last method",
			kind:        "ssh",
			observation: `{"outcome":"authentication_failed","last_auth_method":"password","auth_attempts":3}`,
			want:        "auth password · 3 attempts · authentication_failed",
		},
		{
			name:        "tcp",
			kind:        "tcp",
			observation: `{"lines_exchanged":2,"bytes_total":64,"response":{"rule_id":"banner"}}`,
			want:        "2 lines · 64 B · rule banner",
		},
		{
			name:        "tcp no match",
			kind:        "tcp",
			observation: `{"lines_exchanged":0,"bytes_total":0}`,
			want:        "0 lines · 0 B",
		},
		{
			name:           "correlation",
			kind:           "correlation",
			classification: "correlation_signal",
			observation:    `{"rule_id":"COR-001","summary":"Stored signal summary"}`,
			want:           "COR-001 · Stored signal summary",
		},
		{
			name:        "stored controls",
			kind:        "mcp",
			observation: `{"method":"tools/call","tool_name":"canary\n\u001b_demo"}`,
			want:        "tools/call canary  _demo",
		},
		{
			name:        "unknown",
			kind:        "other",
			observation: `{"method":"GET","path":"/"}`,
			want:        "other observation",
		},
		{
			name:        "malformed object",
			kind:        "tcp",
			observation: `[]`,
			want:        "tcp observation",
		},
		{
			name:        "malformed http",
			kind:        "http",
			observation: `{"method":"GET","response":{"status":"200"}}`,
			want:        "http observation",
		},
		{
			name:        "malformed ssh",
			kind:        "ssh",
			observation: `{"outcome":"rejected","auth_method":{},"auth_attempts":3}`,
			want:        "ssh observation",
		},
		{
			name:        "negative tcp",
			kind:        "tcp",
			observation: `{"lines_exchanged":-1,"bytes_total":64}`,
			want:        "tcp observation",
		},
		{
			name:        "null tcp",
			kind:        "tcp",
			observation: `{"lines_exchanged":null,"bytes_total":64}`,
			want:        "tcp observation",
		},
		{
			name:        "oversized integer",
			kind:        "tcp",
			observation: `{"lines_exchanged":1e100,"bytes_total":64}`,
			want:        "tcp observation",
		},
		{
			name:           "missing signal summary",
			kind:           "correlation",
			classification: "correlation_signal",
			observation:    `{"rule_id":"COR-001"}`,
			want:           "correlation observation",
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			envelope := event.Envelope{
				Sensor:         event.SensorRef{Kind: testCase.kind},
				Classification: testCase.classification,
				Observation:    json.RawMessage(testCase.observation),
			}
			summary, _, _ := Project(envelope)
			if summary.Summary != testCase.want {
				t.Fatalf("summary = %q; want %q", summary.Summary, testCase.want)
			}
		})
	}
}

func TestSummaryBoundAndSanitization(t *testing.T) {
	for _, kind := range []string{
		"http",
		"mcp",
		"ssh",
		"tcp",
		"correlation",
	} {
		t.Run(kind, func(t *testing.T) {
			text := strings.Repeat("é\n\x00", 200)
			observation, err := json.Marshal(map[string]any{
				"method":          text,
				"path":            text,
				"tool_name":       text,
				"auth_method":     text,
				"auth_attempts":   3,
				"outcome":         text,
				"lines_exchanged": 2,
				"bytes_total":     64,
				"response": map[string]any{
					"status":  200,
					"rule_id": text,
				},
				"rule_id": "COR-001",
				"summary": text,
			})
			if err != nil {
				t.Fatal(err)
			}
			classification := "interaction"
			if kind == "correlation" {
				classification = "correlation_signal"
			}
			envelope := event.Envelope{
				Sensor:         event.SensorRef{Kind: kind},
				Classification: classification,
				Observation:    observation,
			}
			summary, _, _ := Project(envelope)
			repeated, _, _ := Project(envelope)
			if summary.Summary != repeated.Summary || utf8.RuneCountInString(summary.Summary) > 160 {
				t.Fatalf("unbounded or nondeterministic summary: %q", summary.Summary)
			}
			for _, character := range summary.Summary {
				if unicode.IsControl(character) {
					t.Fatalf("control in summary: %q", summary.Summary)
				}
			}
		})
	}
}
