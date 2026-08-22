package llm

import (
	"context"
	"strings"
	"testing"
)

// TestLocalDeterministic proves identical inputs always yield identical
// outputs — the property that makes offline evidence reproducible.
func TestLocalDeterministic(t *testing.T) {
	p := Local{}
	req := Request{
		SystemPrompt: "persona",
		Messages:     []Message{{Role: "user", Content: "show me the admin panel"}},
		MaxChars:     2048,
	}
	first, err := p.Complete(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		again, err := p.Complete(context.Background(), req)
		if err != nil {
			t.Fatal(err)
		}
		if again.Text != first.Text || again.Provider != first.Provider {
			t.Fatalf("provider is not deterministic:\n%q\n%q", first.Text, again.Text)
		}
	}
}

func TestLocalNoNetworkAndFast(t *testing.T) {
	// Contract (see Provider): non-blocking implementations must not consult
	// ctx. An instantly-cancelled context still yields an answer.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	resp, err := Local{}.Complete(ctx, Request{Messages: []Message{{Role: "user", Content: "x"}}})
	if err != nil {
		t.Fatalf("local provider must not depend on ctx liveness: %v", err)
	}
	if resp.Text == "" {
		t.Fatal("empty response")
	}
}

func TestLocalRespectsMaxChars(t *testing.T) {
	got, _ := Local{}.Complete(context.Background(), Request{
		SystemPrompt: strings.Repeat("s", 5000), // long system prompt forces truncation path
		Messages:     []Message{{Role: "user", Content: strings.Repeat("u", 5000)}},
		MaxChars:     10,
	})
	if len(got.Text) > 10 {
		t.Fatalf("max chars ignored: %d", len(got.Text))
	}
}

func TestLocalCannedContentIsSynthetic(t *testing.T) {
	for i := 0; i < len(cannedReplies); i++ {
		resp, _ := Local{}.Complete(context.Background(), Request{MaxChars: 16384})
		lower := strings.ToLower(resp.Text)
		for _, banned := range []string{"curl ", "rm -rf", "wget ", "| sh", "/etc/passwd"} {
			if strings.Contains(lower, banned) {
				t.Fatalf("canned reply contains executable-looking content %q: %s", banned, resp.Text)
			}
		}
	}
}
