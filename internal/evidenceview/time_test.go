package evidenceview

import (
	"math/rand/v2"
	"testing"
	"time"

	"github.com/metaforismo/aegismesh/internal/evidenceindex"
)

// referenceTime is the pre-optimisation implementation of Time.
func referenceTime(e evidenceindex.Summary) time.Time {
	t, _ := time.Parse(time.RFC3339Nano, e.Time)
	return t
}

func TestTimeMatchesTimeParse(t *testing.T) {
	cases := []string{
		"", "garbage", "2026-11-26T12:00:00.000000000Z", "2026-11-26T12:00:00Z", "2026-11-26T12:00:00.5Z",
		"2024-02-29T23:59:59.999999999Z", "2025-02-29T00:00:00.000000000Z", "2026-04-31T00:00:00.000000000Z",
		"2026-13-01T00:00:00.000000000Z", "2026-00-01T00:00:00.000000000Z", "2026-01-00T00:00:00.000000000Z",
		"2026-01-01T24:00:00.000000000Z", "2026-01-01T23:60:00.000000000Z", "2026-01-01T23:59:60.000000000Z",
		"0000-01-01T00:00:00.000000000Z", "9999-12-31T23:59:59.999999999Z", "2026-01-01T00:00:00.000000000+00:00",
		"2026-01-01T00:00:00,000000000Z", "2026-01-01 00:00:00.000000000Z", "2026-01-01T00:00:00.00000000aZ",
		"+026-01-01T00:00:00.000000000Z", "2026-1-01T00:00:00.0000000000Z", "2026-01-01T00:00:00.000000000z",
	}
	rng := rand.New(rand.NewPCG(1, 2))
	base := time.Date(2026, 11, 26, 0, 0, 0, 0, time.UTC)
	for range 20000 {
		at := base.Add(time.Duration(rng.Int64N(int64(400*24*time.Hour))) - 200*24*time.Hour)
		cases = append(cases, at.Format("2006-01-02T15:04:05.000000000Z07:00"))
	}
	for _, value := range cases {
		e := evidenceindex.Summary{Time: value}
		got, want := Time(e), referenceTime(e)
		if got != want || got.Location() != want.Location() {
			t.Fatalf("%q: got %#v, want %#v", value, got, want)
		}
	}
}

func FuzzTimeMatchesTimeParse(f *testing.F) {
	f.Add("2026-11-26T12:00:00.000000000Z")
	f.Add("2024-02-29T23:59:59.999999999Z")
	f.Fuzz(func(t *testing.T, value string) {
		e := evidenceindex.Summary{Time: value}
		if got, want := Time(e), referenceTime(e); got != want {
			t.Fatalf("%q: got %#v, want %#v", value, got, want)
		}
	})
}
