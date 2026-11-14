package console_test

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/metaforismo/aegismesh/internal/console"
	"github.com/metaforismo/aegismesh/internal/console/investigations"
)

func TestInvestigationValidationOverHTTP(t *testing.T) {
	harness := newConsoleHarness(t, nil)
	created := harness.request(t, apiRequest{
		method: "POST",
		path:   "/api/v1/investigations",
		token:  "synthetic-admin",
		body:   `{"title":"Validation fixture"}`,
	})
	requireStatus(t, created, 201)
	var investigation investigations.Investigation
	if err := json.Unmarshal(created.body, &investigation); err != nil {
		t.Fatal(err)
	}
	for _, testCase := range []struct {
		name   string
		method string
		suffix string
		body   any
		status int
	}{
		{
			name:   "empty title",
			method: "PATCH",
			body:   map[string]any{"title": ""},
			status: 400,
		},
		{
			name:   "200-character title",
			method: "PATCH",
			body:   map[string]any{"title": strings.Repeat("é", 200)},
			status: 200,
		},
		{
			name:   "201-character title",
			method: "PATCH",
			body:   map[string]any{"title": strings.Repeat("é", 201)},
			status: 400,
		},
		{
			name:   "empty patch",
			method: "PATCH",
			body:   map[string]any{},
			status: 400,
		},
		{
			name:   "invalid status",
			method: "PATCH",
			body:   map[string]any{"status": "deleted"},
			status: 400,
		},
		{
			name:   "invalid priority",
			method: "PATCH",
			body:   map[string]any{"priority": "urgent"},
			status: 400,
		},
		{
			name:   "empty note",
			method: "POST",
			suffix: "/notes",
			body:   map[string]any{"text": ""},
			status: 400,
		},
		{
			name:   "4000-character note",
			method: "POST",
			suffix: "/notes",
			body:   map[string]any{"text": strings.Repeat("é", 4000)},
			status: 201,
		},
		{
			name:   "4001-character note",
			method: "POST",
			suffix: "/notes",
			body:   map[string]any{"text": strings.Repeat("é", 4001)},
			status: 400,
		},
		{
			name:   "malformed attachment",
			method: "PUT",
			suffix: "/events/not-an-event",
			status: 400,
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			var body []byte
			if testCase.body != nil {
				var err error
				body, err = json.Marshal(testCase.body)
				if err != nil {
					t.Fatal(err)
				}
			}
			requireStatus(t, harness.request(t, apiRequest{
				method: testCase.method,
				path:   "/api/v1/investigations/" + investigation.ID + testCase.suffix,
				token:  "synthetic-admin",
				body:   string(body),
			}), testCase.status)
		})
	}
	for _, count := range []int{
		200,
		201,
	} {
		ids := make([]string, count)
		for index := range ids {
			ids[index] = fmt.Sprintf("%032x", index)
		}
		body, err := json.Marshal(investigations.Create{
			Title:    "Event quota",
			EventIDs: ids,
		})
		if err != nil {
			t.Fatal(err)
		}
		want := 201
		if count == 201 {
			want = 400
		}
		requireStatus(t, harness.request(t, apiRequest{
			method: "POST",
			path:   "/api/v1/investigations",
			token:  "synthetic-admin",
			body:   string(body),
		}), want)
	}
	requireStatus(t, harness.request(t, apiRequest{
		method: "POST",
		path:   "/api/v1/investigations",
		token:  "synthetic-admin",
		body:   `{"title":"Duplicate references","event_ids":["` + harness.eventID + `","` + harness.eventID + `"]}`,
	}), 400)
}

func TestInvestigationQuotasOverHTTP(t *testing.T) {
	const targetID = "inv_quota"
	for _, testCase := range []struct {
		name   string
		quota  string
		method string
		suffix string
		body   string
	}{
		{
			name:   "investigations",
			quota:  "investigations",
			method: "POST",
			body:   `{"title":"One too many"}`,
		},
		{
			name:   "notes",
			quota:  "notes",
			method: "POST",
			suffix: "/" + targetID + "/notes",
			body:   `{"text":"One too many"}`,
		},
		{
			name:   "events",
			quota:  "events",
			method: "PUT",
			suffix: "/" + targetID + "/events/" + fmt.Sprintf("%032x", 200),
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			harness := newConsoleHarness(t, func(opts *console.Options) {
				item := investigations.Investigation{
					ID:       targetID,
					Title:    "Synthetic quota fixture",
					Status:   "open",
					Priority: "medium",
				}
				items := map[string]investigations.Investigation{}
				switch testCase.quota {
				case "investigations":
					for index := range investigations.MaxInvestigations {
						item.ID = fmt.Sprintf("inv_%d", index)
						items[item.ID] = item
					}
				case "notes":
					for range investigations.MaxNotes {
						item.Notes = append(item.Notes, investigations.Note{Text: "note"})
					}
					items[targetID] = item
				case "events":
					for index := range 200 {
						item.EventIDs = append(item.EventIDs, fmt.Sprintf("%032x", index))
					}
					items[targetID] = item
				}
				body, err := json.Marshal(items)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.MkdirAll(opts.StateDir, 0700); err != nil {
					t.Fatal(err)
				}
				filename := filepath.Join(opts.StateDir, "investigations.json")
				if err := os.WriteFile(filename, body, 0600); err != nil {
					t.Fatal(err)
				}
			})
			requireStatus(t, harness.request(t, apiRequest{
				method: testCase.method,
				path:   "/api/v1/investigations" + testCase.suffix,
				token:  "synthetic-admin",
				body:   testCase.body,
			}), 409)
		})
	}
}
