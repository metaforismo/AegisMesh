package eventexport

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/metaforismo/aegismesh/internal/event"
)

func fixture() Record {
	body := json.RawMessage(`{"remote_host":"192.0.2.4","method":"GET","path":"/a|b=c\\d\n\"]","detection":{"findings":[{"rule_id":"PI-001"}]}}`)
	return Record{
		NodeID: "local",
		Envelope: event.Envelope{
			Schema:   event.SchemaV1,
			ID:       strings.Repeat("a", 32),
			Seq:      1,
			Time:     time.Date(2026, 11, 22, 12, 0, 0, 123456789, time.UTC),
			Instance: "synthetic",
			Sensor: event.SensorRef{
				ID:   "synthetic",
				Kind: "http",
			},
			Classification: event.ClassificationInteraction,
			Observation:    body,
			Integrity: event.Integrity{
				Algorithm:     "sha256",
				PayloadSHA256: event.SHA256Hex(body),
			},
		},
	}
}

func TestFormatGoldensAndDeterminism(t *testing.T) {
	for _, format := range []string{"cef", "syslog-rfc5424", "otlp-json", "ecs"} {
		t.Run(format, func(t *testing.T) {
			body, err := Render([]Record{fixture()}, format)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join("testdata", format+".golden")
			if os.Getenv("AEGISMESH_UPDATE_EVENT_GOLDENS") == "1" {
				if err := os.MkdirAll("testdata", 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, body, 0600); err != nil {
					t.Fatal(err)
				}
			}
			want, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(body, want) {
				t.Fatalf("golden drift: %v\n%s", err, body)
			}
			again, err := Render([]Record{fixture()}, format)
			if err != nil || !bytes.Equal(body, again) {
				t.Fatal("nondeterministic")
			}
			if (format == "ecs" || format == "otlp-json") && !json.Valid(body) {
				t.Fatal("invalid JSON")
			}
			if format == "cef" && bytes.Count(body, []byte("\n")) != 1 {
				t.Fatal("CEF record injection")
			}
			if format == "syslog-rfc5424" && (!bytes.HasPrefix(body, []byte("<131>1 ")) || bytes.Count(body, []byte("\n")) != 1) {
				t.Fatal("RFC5424 framing")
			}
		})
	}
}
func TestEscapersAndSeverity(t *testing.T) {
	if got := cefHeader(`a|b\c`); got != `a\|b\\c` {
		t.Fatal(got)
	}
	if got := cefValue("a=b\\c\r\n"); got != `a\=b\\c  ` {
		t.Fatal(got)
	}
	if got := structured(`a\"]`); got != `a\\\"\]` {
		t.Fatal(got)
	}
	for _, tc := range []struct {
		in                string
		cef, syslog, otlp int
	}{{"", 0, 6, 9}, {"info", 0, 6, 9}, {"low", 1, 5, 9}, {"medium", 4, 4, 13}, {"high", 7, 3, 17}, {"critical", 10, 2, 21}} {
		_, a, b, c := severity(tc.in)
		if a != tc.cef || b != tc.syslog || c != tc.otlp {
			t.Fatal(tc)
		}
	}
}
func TestFailClosedAndOrdering(t *testing.T) {
	a, b := fixture(), fixture()
	b.Envelope.ID = strings.Repeat("b", 32)
	first, err := Render([]Record{b, a}, "cef")
	if err != nil {
		t.Fatal(err)
	}
	second, _ := Render([]Record{a, b}, "cef")
	if !bytes.Equal(first, second) {
		t.Fatal("order drift")
	}
	for _, tc := range []struct {
		records []Record
		format  string
	}{{[]Record{a}, "invalid"}, {make([]Record, MaxEvents+1), "cef"}} {
		if body, err := Render(tc.records, tc.format); err == nil || len(body) != 0 {
			t.Fatal("partial or invalid export")
		}
	}
	a.Envelope.Integrity.PayloadSHA256 = strings.Repeat("0", 64)
	if body, err := Render([]Record{fixture(), a}, "ecs"); err == nil || len(body) != 0 {
		t.Fatal("integrity failure did not suppress complete output")
	}
}
func FuzzEscapers(f *testing.F) {
	for _, seed := range []string{"plain", "a=b|c\\d", "\"]\\\r\nCEF:0|forged", "\x00\u202e"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		if len(input) > 8192 {
			return
		}
		for _, out := range []string{cefHeader(input), cefValue(input), structured(input)} {
			if strings.ContainsAny(out, "\r\n\x00") {
				t.Fatal("record injection")
			}
		}
	})
}

func TestOTLPTimestampAndStagedByteBounds(t *testing.T) {
	e := fixture()
	e.Envelope.Time = time.Date(1900, 1, 1, 0, 0, 0, 0, time.UTC)
	if body, err := Render([]Record{e}, "otlp-json"); err == nil || len(body) != 0 {
		t.Fatal("negative uint64 timestamp emitted")
	}
	e = fixture()
	e.Envelope.Observation = json.RawMessage(`{"static":"` + strings.Repeat("x", 4096) + `"}`)
	e.Envelope.Integrity.PayloadSHA256 = event.SHA256Hex(e.Envelope.Observation)
	many := make([]Record, 600)
	for i := range many {
		many[i] = e
	}
	if body, err := Render(many, "ecs"); err == nil || len(body) != 0 {
		t.Fatal("byte limit did not suppress complete output")
	}
}
