package hub

import (
	"net/http/httptest"
	"testing"
)

func TestCapacityRejectionAlwaysHasSecurityHeaders(t *testing.T) {
	f := newAbuseFixture(t, 0)
	// Listener capacity rejection calls reject before ServeHTTP's header setup.
	w := httptest.NewRecorder()
	f.h.reject(w, failure("capacity"))
	if w.Code != 503 || w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("X-Content-Type-Options") != "nosniff" || w.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("capacity response: %d %v", w.Code, w.Header())
	}
}
