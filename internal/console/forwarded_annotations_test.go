package console_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/metaforismo/aegismesh/internal/console"
	"github.com/metaforismo/aegismesh/internal/evidenceindex"
)

func TestForwardedCollisionCannotInheritLocalInvestigation(t *testing.T) {
	var index *evidenceindex.Index
	harness := newConsoleHarness(t, func(opts *console.Options) { index = opts.Index })
	_, envelope, _, _, ok := index.Get(harness.eventID)
	if !ok {
		t.Fatal("missing fixture")
	}
	node := strings.Repeat("a", 32)
	index.AddForwarded(envelope, node)
	created := harness.request(t, apiRequest{method: "POST", path: "/api/v1/investigations", token: "synthetic-analyst",
		body: `{"title":"Local event"}`})
	requireStatus(t, created, 201)
	var investigation struct {
		ID string `json:"id"`
	}
	if json.Unmarshal(created.body, &investigation) != nil {
		t.Fatal("invalid investigation response")
	}
	path := "/api/v1/investigations/" + investigation.ID
	attached := harness.request(t, apiRequest{method: "PUT", path: path + "/events/" + harness.eventID, token: "synthetic-analyst"})
	requireStatus(t, attached, 200)
	var detail struct {
		Events []evidenceindex.Summary `json:"events"`
	}
	if json.Unmarshal(attached.body, &detail) != nil || len(detail.Events) != 1 || detail.Events[0].Node != nil {
		t.Fatalf("remote collision contaminated local annotation: %s", attached.body)
	}
	remote := harness.request(t, apiRequest{method: "GET", path: "/api/v1/events/" + harness.eventID + "?node=" + node,
		token: "synthetic-viewer"})
	requireStatus(t, remote, 200)
	var eventDetail struct {
		Investigations []json.RawMessage `json:"investigations"`
	}
	if json.Unmarshal(remote.body, &eventDetail) != nil || len(eventDetail.Investigations) != 0 {
		t.Fatalf("remote collision inherited local investigation: %s", remote.body)
	}
}
