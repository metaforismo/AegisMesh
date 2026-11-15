package console_test

import (
	"bufio"
	"net/http"
	"strings"
	"testing"

	"github.com/metaforismo/aegismesh/internal/console"
	"github.com/metaforismo/aegismesh/internal/evidenceindex"
)

func TestTenantSSEOnlyEmitsItsOwnPartition(t *testing.T) {
	var a, b *evidenceindex.Index
	// Producers use the exact runtime index seam.
	h := newConsoleHarness(t, func(opts *console.Options) {
		opts.Config.Tenants = []string{"default", "bravo"}
		opts.Config.Operators[0].Tenants = []string{"bravo"}
		a = opts.Index
		var err error
		b, err = evidenceindex.New(1000, opts.Meter)
		if err != nil {
			t.Fatal(err)
		}
		opts.TenantIndexes = map[string]*evidenceindex.Index{"bravo": b}
	})
	request, _ := http.NewRequest("GET", h.base+"/api/v1/events/stream", nil)
	request.Header.Set("Authorization", "Bearer synthetic-viewer")
	response, err := h.client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		t.Fatal(response.StatusCode)
	}
	_, envelope, _, _, ok := a.Get(h.eventID)
	if !ok {
		t.Fatal("missing event")
	}
	envelope.ID = strings.Repeat("a", 32)
	a.Add(envelope)
	envelope.ID = strings.Repeat("b", 32)
	b.Add(envelope)
	scanner := bufio.NewScanner(response.Body)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "data:") {
			if !strings.Contains(line, envelope.ID) || strings.Contains(line, strings.Repeat("a", 32)) {
				t.Fatalf("foreign SSE data: %s", line)
			}
			return
		}
	}
	t.Fatalf("no tenant observation: %v", scanner.Err())
}
