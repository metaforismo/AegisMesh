package ruletest

import (
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/metaforismo/aegismesh/internal/correlate"
	"github.com/metaforismo/aegismesh/internal/detect"
	"github.com/metaforismo/aegismesh/internal/redact"
)

func TestSyntheticCorrelationCorpus(t *testing.T) {
	type fixtureEvent struct {
		Offset     float64         `json:"offset_seconds"`
		Source     string          `json:"source"`
		SensorID   string          `json:"sensor_id"`
		SensorKind string          `json:"sensor_kind"`
		AIFamily   detect.AIFamily `json:"ai_family"`
		AuthLabel  string          `json:"auth_label"`
		FindingIDs []string        `json:"finding_ids"`
	}
	type sample struct {
		Name   string
		Want   []string
		Events []fixtureEvent
	}
	var corpus struct {
		Benign []sample `json:"benign"`
		Attack []sample `json:"attack_shaped"`
	}
	raw, err := os.ReadFile("testdata/ai-correlation-corpus.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &corpus); err != nil {
		t.Fatal(err)
	}
	if len(corpus.Benign) != 4 || len(corpus.Attack) != 4 {
		t.Fatal("update documented sequence counts")
	}
	evaluate := func(s sample) map[string]bool {
		engine := correlate.New(correlate.Options{})
		hits := map[string]bool{}
		for i, v := range s.Events {
			var attempts []string
			if v.AuthLabel != "" {
				attempts = []string{redact.AuthDigest("password", "synthetic-user", v.AuthLabel)}
			}
			event := correlate.Event{ID: fmt.Sprint(i), Time: time.Unix(0, 0).Add(time.Duration(v.Offset * float64(time.Second))), SourceKey: v.Source, SensorID: v.SensorID, SensorKind: v.SensorKind, Classification: "interaction", AIFamily: v.AIFamily, AuthAttempts: attempts, FindingIDs: v.FindingIDs}
			for _, signal := range engine.Ingest(event) {
				hits[string(signal.RuleID)] = true
			}
		}
		return hits
	}
	counts := map[string]int{}
	for _, s := range corpus.Benign {
		for id := range evaluate(s) {
			counts[id]++
		}
	}
	for _, id := range correlate.KnownRuleIDs() {
		t.Logf("%s: %d hits on this %d-sequence synthetic benign corpus", id, counts[id], len(corpus.Benign))
	}
	covered := map[string]bool{}
	for _, s := range corpus.Attack {
		t.Run(s.Name, func(t *testing.T) {
			hits := evaluate(s)
			for _, id := range s.Want {
				if !hits[id] {
					t.Errorf("missing %s", id)
				} else {
					covered[id] = true
				}
			}
		})
	}
	for _, id := range []string{"COR-005", "COR-006", "COR-007", "COR-008"} {
		if !covered[id] {
			t.Errorf("no attack-shaped sequence for %s", id)
		}
	}
}
