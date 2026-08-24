package recommend

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/metaforismo/aegismesh/internal/event"
	"github.com/metaforismo/aegismesh/internal/rulecatalog"
)

func testEnvelope(t *testing.T, n int, classification string, observation string) event.Envelope {
	t.Helper()
	e := event.Envelope{
		Schema:         event.SchemaV1,
		ID:             fmt.Sprintf("%032x", n),
		Time:           time.Unix(int64(n), 0).UTC(),
		Seq:            uint64(n),
		Instance:       "test",
		Sensor:         event.SensorRef{ID: "sensor-1", Kind: "mcp", Listen: "127.0.0.1:1"},
		Classification: classification,
		Integrity: event.Integrity{
			PayloadSHA256: event.SHA256Hex([]byte(observation)),
			Algorithm:     "sha256",
		},
		Observation: []byte(observation),
	}
	return e
}

func findingObservation(ruleIDs ...string) string {
	findings := make([]string, 0, len(ruleIDs))
	for _, id := range ruleIDs {
		severity := "high"
		if entry, ok := rulecatalog.Lookup(id); ok {
			severity = entry.Severity
		}
		findings = append(findings, fmt.Sprintf(`{"rule_id":%q,"severity":%q,"confidence":"medium","reason":"static"}`, id, severity))
	}
	return `{"method":"tools/call","detection":{"action":"refuse","findings":[` + strings.Join(findings, ",") + `]}}`
}

func correlationObservationJSON(ruleID string, sourceIDs ...string) string {
	ids, _ := json.Marshal(sourceIDs)
	return fmt.Sprintf(`{"rule_id":%q,"summary":"attacker summary must not escape","source_key":"attacker-source","source_event_ids":%s,"truncated":false}`, ruleID, ids)
}

func TestGenerateLabelsAndStaticEvidence(t *testing.T) {
	marker := "ATTACKER_MARKER"
	e := testEnvelope(t, 1, event.ClassificationInteraction,
		`{"tool":"`+marker+`","detection":{"action":"refuse","findings":[{"rule_id":"PI-001","severity":"high","confidence":"medium","reason":"`+marker+`"}]}}`)
	report, err := Generate([]event.Envelope{e}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if report.Schema != SchemaV1 || report.Mode != ModeDryRun || report.Interpretation != InterpretationSignal ||
		report.Kind != KindRecommendation || report.Status != StatusProposed || len(report.Recommendations) != 1 {
		t.Fatalf("unexpected report labels: %+v", report)
	}
	rec := report.Recommendations[0]
	if rec.Kind != KindRecommendation || rec.Status != StatusProposed || rec.RuleIDs[0] != "PI-001" ||
		rec.SensorID != e.Sensor.ID || rec.SensorKind != e.Sensor.Kind {
		t.Fatalf("unexpected recommendation: %+v", rec)
	}
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), marker) {
		t.Fatalf("attacker text escaped into recommendation: %s", encoded)
	}
	if len(rec.Evidence) != 1 || rec.Evidence[0].EventID != e.ID || rec.Evidence[0].PayloadSHA256 != e.Integrity.PayloadSHA256 {
		t.Fatalf("evidence link mismatch: %+v", rec.Evidence)
	}
	if rec.Evidence[0].IntegrityScope != integrityScopeObservation || rec.Evidence[0].Verification != verificationPayloadHash {
		t.Fatalf("evidence verification boundary missing: %+v", rec.Evidence[0])
	}
	wantID := RecommendationID(e.ID, e.Integrity.PayloadSHA256, []string{"PI-001"})
	if rec.ID != wantID || len(rec.ID) != 64 {
		t.Fatalf("recommendation id = %q, want %q", rec.ID, wantID)
	}
}

func TestGenerateNoSignalAndUnknownRule(t *testing.T) {
	tests := []struct {
		name    string
		obs     string
		wantErr bool
	}{
		{name: "plain", obs: `{"path":"/health","body":"ordinary"}`},
		{name: "no findings", obs: `{"detection":{"action":"observe","findings":[]}}`},
		{name: "unknown rule", obs: findingObservation("ATTACKER-999"), wantErr: true},
	}
	for i, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			report, err := Generate([]event.Envelope{testEnvelope(t, i+2, event.ClassificationInteraction, tc.obs)}, Options{})
			if tc.wantErr {
				if err == nil {
					t.Fatal("unknown rule accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if len(report.Recommendations) != 0 {
				t.Fatalf("recommendation for no known signal: %+v", report.Recommendations)
			}
		})
	}
}

func TestGenerateCanaryWithoutDetectionStillRecommendsReview(t *testing.T) {
	e := testEnvelope(t, 8, event.ClassificationCanaryHit, `{"tool_name":"canary_read"}`)
	report, err := Generate([]event.Envelope{e}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Recommendations) != 1 {
		t.Fatalf("canary invocation without detection should be reviewable: %+v", report)
	}
	rec := report.Recommendations[0]
	if rec.Classification != event.ClassificationCanaryHit || len(rec.RuleIDs) != 0 || !strings.Contains(rec.Summary, "canary invocation") {
		t.Fatalf("unexpected canary recommendation: %+v", rec)
	}
}

func TestGenerateConflictMetadataIsStatic(t *testing.T) {
	e := testEnvelope(t, 10, event.ClassificationCanaryHit, findingObservation("PI-001", "RES-001"))
	report, err := Generate([]event.Envelope{e}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Recommendations) != 1 || len(report.Recommendations[0].Conflicts) != 1 {
		t.Fatalf("expected explicit conflict metadata: %+v", report.Recommendations)
	}
	conflict := report.Recommendations[0].Conflicts[0]
	if conflict.Resolution != "operator_review" || conflict.Code != "bounded_input_vs_content_signal" ||
		strings.Contains(conflict.Note, "PI-001") {
		t.Fatalf("unexpected conflict: %+v", conflict)
	}
	if !sort.StringsAreSorted(conflict.RuleIDs) {
		t.Fatalf("conflict rule IDs not sorted: %v", conflict.RuleIDs)
	}
}

func TestGenerateCorrelationResolvesOnlyVerifiedRawSources(t *testing.T) {
	source := testEnvelope(t, 20, event.ClassificationInteraction, findingObservation("PI-001"))
	unknownID := fmt.Sprintf("%032x", 999)
	signal := testEnvelope(t, 21, event.ClassificationCorrelationSignal,
		correlationObservationJSON("COR-001", source.ID, unknownID, source.ID))
	report, err := Generate([]event.Envelope{signal, source}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Recommendations) != 2 {
		t.Fatalf("expected direct and correlation recommendations: %+v", report.Recommendations)
	}
	var corr *Recommendation
	for i := range report.Recommendations {
		if len(report.Recommendations[i].RuleIDs) == 1 && report.Recommendations[i].RuleIDs[0] == "COR-001" {
			corr = &report.Recommendations[i]
		}
	}
	if corr == nil || corr.SourceResolution == nil || corr.SourceResolution.Resolved != 1 || corr.SourceResolution.Unresolved != 1 {
		t.Fatalf("unexpected source resolution: %+v", corr)
	}
	if len(corr.Evidence) != 2 {
		t.Fatalf("only current signal and verified raw source should link: %+v", corr.Evidence)
	}
	for _, link := range corr.Evidence {
		if link.EventID == unknownID {
			t.Fatal("unverified source ID became evidence")
		}
	}
	encoded, _ := json.Marshal(corr)
	if strings.Contains(string(encoded), "attacker-source") || strings.Contains(string(encoded), "attacker summary") {
		t.Fatalf("attacker correlation text escaped: %s", encoded)
	}
}

func TestGenerateRejectsCorrelationFamilyMismatch(t *testing.T) {
	e := testEnvelope(t, 25, event.ClassificationCorrelationSignal, correlationObservationJSON("PI-001"))
	if _, err := Generate([]event.Envelope{e}, Options{}); err == nil {
		t.Fatal("detection rule accepted as correlation signal")
	}
}

func TestGenerateRejectsDuplicateIdentityAndInvalidMetadata(t *testing.T) {
	e := testEnvelope(t, 26, event.ClassificationInteraction, findingObservation("PI-001"))
	if _, err := Generate([]event.Envelope{e, e}, Options{}); err == nil {
		t.Fatal("duplicate event ID accepted")
	}
	for _, mutate := range []func(*event.Envelope){
		func(e *event.Envelope) { e.Integrity.Algorithm = "sha1" },
		func(e *event.Envelope) { e.Integrity.PayloadSHA256 = "G" + strings.Repeat("0", 63) },
		func(e *event.Envelope) { e.ID = "G" + strings.Repeat("0", 31) },
		func(e *event.Envelope) { e.Sensor.ID = "sensor\nspoof" },
		func(e *event.Envelope) { e.Sensor.Kind = "http\x1b[2J" },
		func(e *event.Envelope) { e.Instance = strings.Repeat("i", MaxInstanceBytes+1) },
		func(e *event.Envelope) { e.Sensor.Listen = strings.Repeat("l", MaxListenBytes+1) },
		func(e *event.Envelope) { e.Redaction.Rules = []string{strings.Repeat("r", MaxRedactionRuleBytes+1)} },
		func(e *event.Envelope) { e.Redaction.Rules = make([]string, MaxRedactionRules+1) },
	} {
		bad := e
		mutate(&bad)
		if _, err := Generate([]event.Envelope{bad}, Options{}); err == nil {
			t.Fatal("invalid envelope metadata accepted")
		}
	}
}

func TestGenerateDeterministicOrderingAndLimit(t *testing.T) {
	first := testEnvelope(t, 30, event.ClassificationInteraction, findingObservation("PI-001"))
	second := testEnvelope(t, 31, event.ClassificationInteraction, findingObservation("EXF-001"))
	a, err := Generate([]event.Envelope{first, second}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	b, err := Generate([]event.Envelope{second, first}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	aj, _ := json.Marshal(a)
	bj, _ := json.Marshal(b)
	if string(aj) != string(bj) {
		t.Fatalf("input ordering changed report:\n%s\n%s", aj, bj)
	}
	limited, err := Generate([]event.Envelope{first, second}, Options{Limit: 1})
	if err != nil {
		t.Fatal(err)
	}
	if len(limited.Recommendations) != 1 {
		t.Fatalf("limit not applied: %+v", limited.Recommendations)
	}
	if _, err := Generate([]event.Envelope{first}, Options{Limit: MaxLimit + 1}); err == nil {
		t.Fatal("invalid limit accepted")
	}
}

func TestGenerateFiltersBeforeLimit(t *testing.T) {
	first := testEnvelope(t, 50, event.ClassificationInteraction, findingObservation("PI-001"))
	second := testEnvelope(t, 51, event.ClassificationInteraction, findingObservation("EXF-001"))
	report, err := Generate([]event.Envelope{first, second}, Options{RuleID: "EXF-001", Limit: 1})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Recommendations) != 1 || len(report.Recommendations[0].RuleIDs) != 1 || report.Recommendations[0].RuleIDs[0] != "EXF-001" {
		t.Fatalf("rule filter must precede limit: %+v", report.Recommendations)
	}
	filtered, err := Generate([]event.Envelope{first, second}, Options{SensorID: "sensor-1", Classification: event.ClassificationInteraction})
	if err != nil || len(filtered.Recommendations) != 2 {
		t.Fatalf("conjunctive sensor/classification filters failed: %+v, %v", filtered.Recommendations, err)
	}
	for _, opts := range []Options{
		{RuleID: "UNKNOWN-1"},
		{Classification: "incident"},
		{SensorID: "Bad Sensor"},
	} {
		if _, err := Generate(nil, opts); err == nil {
			t.Fatalf("invalid filter accepted: %+v", opts)
		}
	}
}

func TestCorrelationResolutionSurvivesFilters(t *testing.T) {
	source := testEnvelope(t, 52, event.ClassificationInteraction, findingObservation("PI-001"))
	signal := testEnvelope(t, 53, event.ClassificationCorrelationSignal, correlationObservationJSON("COR-001", source.ID))
	report, err := Generate([]event.Envelope{source, signal}, Options{Classification: event.ClassificationCorrelationSignal})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Recommendations) != 1 || report.Recommendations[0].SourceResolution == nil || report.Recommendations[0].SourceResolution.Resolved != 1 {
		t.Fatalf("filtered correlation lost verified source resolution: %+v", report.Recommendations)
	}
}

func TestGenerateRejectsMalformedOversizedAndInvalidIntegrity(t *testing.T) {
	cases := []struct {
		name string
		mut  func(event.Envelope) event.Envelope
	}{
		{name: "duplicate field", mut: func(e event.Envelope) event.Envelope {
			e.Observation = []byte(`{"detection":{"findings":[],"findings":[]}}`)
			e.Integrity.PayloadSHA256 = event.SHA256Hex(e.Observation)
			return e
		}},
		{name: "unknown detection field", mut: func(e event.Envelope) event.Envelope {
			e.Observation = []byte(`{"detection":{"findings":[],"attacker":"secret"}}`)
			e.Integrity.PayloadSHA256 = event.SHA256Hex(e.Observation)
			return e
		}},
		{name: "unknown detection action", mut: func(e event.Envelope) event.Envelope {
			e.Observation = []byte(`{"detection":{"action":"delete","findings":[]}}`)
			e.Integrity.PayloadSHA256 = event.SHA256Hex(e.Observation)
			return e
		}},
		{name: "missing detection action", mut: func(e event.Envelope) event.Envelope {
			e.Observation = []byte(`{"detection":{"findings":[]}}`)
			e.Integrity.PayloadSHA256 = event.SHA256Hex(e.Observation)
			return e
		}},
		{name: "incomplete finding", mut: func(e event.Envelope) event.Envelope {
			e.Observation = []byte(`{"detection":{"action":"refuse","findings":[{"rule_id":"PI-001"}]}}`)
			e.Integrity.PayloadSHA256 = event.SHA256Hex(e.Observation)
			return e
		}},
		{name: "severity mismatch", mut: func(e event.Envelope) event.Envelope {
			e.Observation = []byte(`{"detection":{"action":"refuse","findings":[{"rule_id":"PI-001","severity":"low","confidence":"medium","reason":"static"}]}}`)
			e.Integrity.PayloadSHA256 = event.SHA256Hex(e.Observation)
			return e
		}},
		{name: "unknown correlation field", mut: func(e event.Envelope) event.Envelope {
			e.Classification = event.ClassificationCorrelationSignal
			e.Observation = []byte(`{"rule_id":"COR-001","summary":"static","source_key":"source","source_event_ids":[],"truncated":false,"extra":true}`)
			e.Integrity.PayloadSHA256 = event.SHA256Hex(e.Observation)
			return e
		}},
		{name: "oversized", mut: func(e event.Envelope) event.Envelope {
			e.Observation = []byte(`{"noise":"` + strings.Repeat("x", MaxObservationBytes) + `"}`)
			e.Integrity.PayloadSHA256 = event.SHA256Hex(e.Observation)
			return e
		}},
		{name: "bad integrity", mut: func(e event.Envelope) event.Envelope {
			e.Integrity.PayloadSHA256 = strings.Repeat("0", 64)
			return e
		}},
	}
	base := testEnvelope(t, 40, event.ClassificationInteraction, findingObservation("PI-001"))
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Generate([]event.Envelope{tc.mut(base)}, Options{}); err == nil {
				t.Fatal("malformed input accepted")
			}
		})
	}
}

func TestGenerateRejectsSupportedBlockCaps(t *testing.T) {
	findings := make([]string, 0, MaxDetectionFindings+1)
	for i := 0; i < MaxDetectionFindings+1; i++ {
		findings = append(findings, `{"rule_id":"PI-001","severity":"high","confidence":"medium","reason":"static"}`)
	}
	detection := `{"detection":{"action":"refuse","findings":[` + strings.Join(findings, ",") + `]}}`
	e := testEnvelope(t, 41, event.ClassificationInteraction, detection)
	if _, err := Generate([]event.Envelope{e}, Options{}); err == nil {
		t.Fatal("finding count cap not enforced")
	}

	sources := make([]string, MaxSourceEventIDs+1)
	for i := range sources {
		sources[i] = fmt.Sprintf("%032x", i+100)
	}
	signal := testEnvelope(t, 42, event.ClassificationCorrelationSignal, correlationObservationJSON("COR-001", sources...))
	if _, err := Generate([]event.Envelope{signal}, Options{}); err == nil {
		t.Fatal("source ID count cap not enforced")
	}
	if _, err := Generate(make([]event.Envelope, MaxEvidence+1), Options{}); err == nil {
		t.Fatal("evidence count cap not enforced")
	}
	badSource := testEnvelope(t, 43, event.ClassificationCorrelationSignal, correlationObservationJSON("COR-001", "not-an-event-id"))
	if _, err := Generate([]event.Envelope{badSource}, Options{}); err == nil {
		t.Fatal("invalid source ID accepted")
	}
	upperSource := testEnvelope(t, 44, event.ClassificationCorrelationSignal, correlationObservationJSON("COR-001", strings.Repeat("A", 32)))
	if _, err := Generate([]event.Envelope{upperSource}, Options{}); err == nil {
		t.Fatal("uppercase source ID accepted")
	}
}

func TestRecommendationIDSortsAndDeduplicatesRules(t *testing.T) {
	got := RecommendationID("00000000000000000000000000000001", strings.Repeat("a", 64), []string{"PI-002", "PI-001", "PI-002"})
	want := RecommendationID("00000000000000000000000000000001", strings.Repeat("a", 64), []string{"PI-001", "PI-002"})
	if got != want {
		t.Fatalf("rule order/duplicates changed ID: %s != %s", got, want)
	}
}
