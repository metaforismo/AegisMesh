package indicatorexport

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/metaforismo/aegismesh/internal/evidenceindex"
)

func exportEvent(i int, source string, rules ...string) evidenceindex.Summary {
	return evidenceindex.Summary{ID: fmt.Sprintf("%032x", i), Time: time.Unix(1000+int64(i), 0).UTC().Format(time.RFC3339Nano), Source: source, RuleIDs: rules}
}

func TestCollectCanonicalIPsAndSkippedKeys(t *testing.T) {
	events := []evidenceindex.Summary{exportEvent(1, "192.0.2.1"), exportEvent(2, "::ffff:192.0.2.1"), exportEvent(3, "2001:db8::1"), exportEvent(4, "bad.test"), exportEvent(5, "bad.test"), exportEvent(6, "fe80::1%en0"), exportEvent(7, "192.0.2.1:44")}
	result, err := Collect(events)
	if err != nil || len(result.Indicators) != 2 || len(result.Indicators[0].EventRefs) != 2 || result.SkippedSource != 3 || result.SkippedEvents != 4 {
		t.Fatal(result, err)
	}
	for _, format := range []string{"stix", "csv", "txt"} {
		t.Run(format, func(t *testing.T) {
			body, _, err := Render(events, format, "test")
			if err != nil || bytes.Contains(body, []byte("bad.test")) || bytes.Contains(body, []byte("%en0")) {
				t.Fatal("untrusted non-IP leaked or render failed", err)
			}
			if format == "csv" {
				rows, err := csv.NewReader(bytes.NewReader(body)).ReadAll()
				if err != nil || len(rows) != 3 || rows[1][7] != "3" {
					t.Fatal(rows, err)
				}
			}
			if format == "txt" && (!bytes.HasPrefix(body, []byte("# PROPOSED")) || !bytes.Contains(body, []byte("never applied"))) {
				t.Fatal("missing proposal boundary")
			}
		})
	}
}

func TestSTIXRequiredPropertiesAndReferences(t *testing.T) {
	events := []evidenceindex.Summary{exportEvent(1, "192.0.2.1", "HT-001", "AGT-001"), exportEvent(2, "2001:db8::1", "COR-006")}
	body, _, err := Render(events, "stix", "synthetic-instance")
	if err != nil {
		t.Fatal(err)
	}
	events[0], events[1] = events[1], events[0]
	again, _, err := Render(events, "stix", "synthetic-instance")
	if err != nil || !bytes.Equal(body, again) {
		t.Fatal("non-deterministic export")
	}
	var bundle struct {
		Type    string           `json:"type"`
		ID      string           `json:"id"`
		Objects []map[string]any `json:"objects"`
	}
	if json.Unmarshal(body, &bundle) != nil || bundle.Type != "bundle" || len(bundle.Objects) < 8 {
		t.Fatal("invalid bundle")
	}
	uuid5 := regexp.MustCompile(`^[a-z-]+--[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	if !uuid5.MatchString(bundle.ID) {
		t.Fatal(bundle.ID)
	}
	required := map[string][]string{
		"identity":       {"name", "identity_class"},
		"indicator":      {"pattern", "pattern_type", "valid_from"},
		"note":           {"content", "object_refs"},
		"attack-pattern": {"name", "external_references"},
		"relationship":   {"relationship_type", "source_ref", "target_ref"},
	}
	ids, types := map[string]bool{}, map[string]int{}
	for _, object := range bundle.Objects {
		kind, ok := object["type"].(string)
		if !ok || required[kind] == nil {
			t.Fatal("unknown type", object)
		}
		types[kind]++
		for _, property := range append([]string{"type", "id", "spec_version", "created", "modified"}, required[kind]...) {
			if object[property] == nil || object[property] == "" {
				t.Fatalf("missing %s: %+v", property, object)
			}
		}
		id := object["id"].(string)
		if !uuid5.MatchString(id) || ids[id] || !strings.HasPrefix(id, kind+"--") || object["spec_version"] != "2.1" {
			t.Fatal("invalid ID/version", object)
		}
		ids[id] = true
		created, ce := time.Parse(time.RFC3339Nano, object["created"].(string))
		modified, me := time.Parse(time.RFC3339Nano, object["modified"].(string))
		if ce != nil || me != nil || modified.Before(created) {
			t.Fatal("invalid timestamps", object)
		}
		if kind == "indicator" {
			if object["pattern_type"] != "stix" || object["pattern_version"] != "2.1" || object["confidence"] != float64(Confidence) {
				t.Fatal(object)
			}
			pattern := object["pattern"].(string)
			parts := strings.Split(pattern, "'")
			if len(parts) != 3 {
				t.Fatal(pattern)
			}
			ip, err := netip.ParseAddr(parts[1])
			kind := "ipv6-addr"
			if ip.Is4() {
				kind = "ipv4-addr"
			}
			if err != nil || pattern != "["+kind+":value = '"+ip.String()+"']" {
				t.Fatal(pattern)
			}
			if _, err := time.Parse(time.RFC3339Nano, object["valid_from"].(string)); err != nil {
				t.Fatal(err)
			}
		}
		if kind == "attack-pattern" {
			ref := object["external_references"].([]any)[0].(map[string]any)
			if (ref["source_name"] != "mitre-attack" && ref["source_name"] != "mitre-atlas") || ref["external_id"] == "" {
				t.Fatal(ref)
			}
		}
	}
	for kind := range required {
		if types[kind] == 0 {
			t.Fatalf("missing type %s", kind)
		}
	}
	for _, object := range bundle.Objects {
		for _, key := range []string{"created_by_ref", "source_ref", "target_ref"} {
			if ref, ok := object[key].(string); ok && !ids[ref] {
				t.Fatalf("dangling %s: %s", key, ref)
			}
		}
		if refs, ok := object["object_refs"].([]any); ok {
			if len(refs) == 0 {
				t.Fatal("empty refs")
			}
			for _, ref := range refs {
				if !ids[ref.(string)] {
					t.Fatal("dangling note ref")
				}
			}
		}
	}
	if !bytes.Contains(body, []byte("local:00000000000000000000000000000001")) {
		t.Fatal("missing event link")
	}
}

func TestExportBounds(t *testing.T) {
	if _, err := Collect(make([]evidenceindex.Summary, MaxEvents+1)); !errors.Is(err, ErrLimit) {
		t.Fatal(err)
	}
	events := []evidenceindex.Summary{}
	for i := 0; i < MaxEvents; i++ {
		events = append(events, exportEvent(i, fmt.Sprintf("2001:db8::%x", i+1), "HT-001", "AGT-001", "COR-006"))
	}
	body, _, err := Render(events, "stix", "test")
	if !errors.Is(err, ErrLimit) || body != nil {
		t.Fatal("partial/oversized output", err)
	}
	if _, _, err := Render(nil, "invalid", "test"); err == nil {
		t.Fatal("invalid format")
	}
}
