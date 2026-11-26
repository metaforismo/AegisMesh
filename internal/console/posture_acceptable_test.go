package console_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/metaforismo/aegismesh/internal/console"
)

func acceptability(t *testing.T, h *consoleHarness, token string) map[string]console.PostureCheck {
	t.Helper()
	response := h.request(t, apiRequest{method: "GET", path: "/api/v1/posture", token: token})
	requireStatus(t, response, 200)
	report := decode[console.PostureResponse](t, response)
	out := map[string]console.PostureCheck{}
	for _, check := range report.Checks {
		if check.Acceptable != (check.AcceptableReason == "") {
			t.Fatalf("%s: acceptable=%t with reason %q", check.ID, check.Acceptable, check.AcceptableReason)
		}
		out[check.ID] = check
	}
	if len(out) == 0 {
		t.Fatal("no checks")
	}
	return out
}

// TestPostureAcceptableMatchesAcceptGate checks every reason code against what
// POST /api/v1/posture/{id}/accept actually does for the same caller.
func TestPostureAcceptableMatchesAcceptGate(t *testing.T) {
	h := newConsoleHarness(t, editingOn)
	until := h.clock.now().Add(time.Hour).UTC().Format(time.RFC3339)
	accept := func(token, id string) apiResponse {
		return h.request(t, apiRequest{method: "POST", path: "/api/v1/posture/" + id + "/accept", token: token, body: `{"reason":"Synthetic test","until":"` + until + `"}`})
	}

	viewer := acceptability(t, h, "synthetic-viewer")
	for id, check := range viewer {
		if check.Acceptable || check.AcceptableReason != "permission_denied" {
			t.Fatalf("viewer %s = %+v", id, check)
		}
	}
	requireCode(t, accept("synthetic-analyst", "POS-007"), 403, "forbidden")

	admin := acceptability(t, h, "synthetic-admin")
	if check := admin["POS-007"]; check.Status != "attention" || !check.Acceptable {
		t.Fatalf("POS-007 = %+v", check)
	}
	if check := admin["POS-001"]; check.Acceptable || check.AcceptableReason != "not_attention" {
		t.Fatalf("POS-001 = %+v", check)
	}
	requireCode(t, accept("synthetic-admin", "POS-001"), 409, "conflict")
	for id, check := range admin {
		if check.Status != "attention" && check.Acceptable {
			t.Fatalf("%s offered while %s", id, check.Status)
		}
	}
	requireStatus(t, accept("synthetic-admin", "POS-007"), 200)
	if check := acceptability(t, h, "synthetic-admin")["POS-007"]; check.Status != "accepted" || check.Acceptable || check.AcceptableReason != "already_accepted" {
		t.Fatalf("accepted POS-007 = %+v", check)
	}
	requireStatus(t, h.request(t, apiRequest{method: "DELETE", path: "/api/v1/posture/POS-007/accept", token: "synthetic-admin"}), 204)
	if check := acceptability(t, h, "synthetic-admin")["POS-007"]; !check.Acceptable {
		t.Fatalf("unaccepted POS-007 = %+v", check)
	}
}

func TestPostureAcceptableEditingOffAndOverlayProblem(t *testing.T) {
	off := newConsoleHarness(t, nil)
	for id, check := range acceptability(t, off, "synthetic-admin") {
		if check.Acceptable || check.AcceptableReason != "editing_disabled" {
			t.Fatalf("editing off %s = %+v", id, check)
		}
	}
	off.close(t)

	stateDir := filepath.Join(t.TempDir(), "console")
	on := newConsoleHarness(t, func(opts *console.Options) { editingOn(opts); opts.StateDir = stateDir })
	requireStatus(t, on.request(t, apiRequest{method: "PUT", path: "/api/v1/admin/settings/console.organization_name",
		token: "synthetic-admin", body: `{"value":"Example SOC","reason":"Create the overlay"}`}), 200)
	on.close(t)
	if err := os.WriteFile(filepath.Join(stateDir, "settings", "settings.json"), []byte(`{"schema":`), 0o600); err != nil {
		t.Fatal(err)
	}
	broken := newConsoleHarness(t, func(opts *console.Options) { editingOn(opts); opts.StateDir = stateDir })
	for id, check := range acceptability(t, broken, "synthetic-admin") {
		if check.Acceptable || check.AcceptableReason != "overlay_unavailable" {
			t.Fatalf("broken overlay %s = %+v", id, check)
		}
	}
	requireStatus(t, broken.request(t, apiRequest{method: "POST", path: "/api/v1/posture/POS-007/accept", token: "synthetic-admin",
		body: `{"reason":"x","until":"` + broken.clock.now().Add(time.Hour).UTC().Format(time.RFC3339) + `"}`}), 503)
}

func TestOrganizationNameInReportsAndDigest(t *testing.T) {
	h := newConsoleHarness(t, editingOn)
	id := sessionID(t, h)
	report := func() string {
		response := h.request(t, apiRequest{method: "GET", path: "/api/v1/sessions/" + id + "/report", token: "synthetic-admin"})
		requireStatus(t, response, 200)
		return string(response.body)
	}
	digest := func() string {
		response := h.request(t, apiRequest{method: "GET", path: "/api/v1/digest?window=24h", token: "synthetic-admin"})
		requireStatus(t, response, 200)
		return string(response.body)
	}
	if strings.Contains(report(), "Organization:") || strings.Contains(digest(), "organization_name") {
		t.Fatal("unset organization rendered")
	}
	requireStatus(t, h.request(t, apiRequest{method: "PUT", path: "/api/v1/admin/settings/console.organization_name",
		token: "synthetic-admin", body: `{"value":"Example <SOC>","reason":"Branding"}`}), 200)
	if body := report(); !strings.Contains(body, "\n```text\n\"Organization: Example \\u003cSOC\\u003e\"\n```\n") || strings.Contains(body, "<SOC>") {
		t.Fatalf("report:\n%s", body)
	}
	if body := digest(); !strings.Contains(body, `"organization_name":"Example \u003cSOC\u003e"`) {
		t.Fatalf("digest: %s", body)
	}
}
