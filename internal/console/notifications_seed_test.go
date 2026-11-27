package console

import (
	"testing"

	"github.com/metaforismo/aegismesh/internal/console/notifications"
)

// TestSeededDemoProducesRealisticInbox derives the inbox of the seeded small
// demo history: the evidence kinds and campaigns appear, within the bounds.
func TestSeededDemoProducesRealisticInbox(t *testing.T) {
	s, _, _ := seededMemoServer(t)
	view := s.views["local"]
	view.derivePass(true)
	viewer := notifications.Viewer{ID: "cfg:memo", Can: func(string) bool { return true }}
	page := view.inbox.List(viewer, notifications.Filter{Limit: notifications.MaxItems})
	counts := map[string]int{}
	overflow := 0
	for _, item := range page.Items {
		counts[item.Kind]++
		if item.Title == "More notifications than the inbox limit" {
			overflow++
		}
	}
	t.Logf("seeded inbox: %d items %v, %d overflow, %d folded, unread %d", len(page.Items), counts, overflow,
		view.inbox.Dropped(), page.Unread)
	for _, kind := range []string{notifications.KindHoneytoken, notifications.KindCampaign} {
		if counts[kind] == 0 {
			t.Fatalf("seeded inbox lacks %s: %v", kind, counts)
		}
	}
	if counts[notifications.KindCritical]+counts[notifications.KindCanary] == 0 || len(page.Items) > 400 {
		t.Fatalf("seeded inbox shape: %v", counts)
	}
	// A second pass and a restart-free re-derivation add nothing.
	view.derivePass(true)
	if again := view.inbox.List(viewer, notifications.Filter{Limit: notifications.MaxItems}); len(again.Items) != len(page.Items) {
		t.Fatalf("re-derivation added items: %d → %d", len(page.Items), len(again.Items))
	}
}
