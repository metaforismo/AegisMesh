// Package demoseed generates deterministic, clearly synthetic historical
// evidence for the opt-in `aegismesh demo --console --seed <profile>` mode.
//
// Every generated observation carries "synthetic": true, uses only
// documentation address ranges (RFC 5737 TEST-NET-1/2/3 and RFC 3849
// 2001:db8::/32) as peers, and passes through the same policy gates,
// honeytoken scrubbing and redaction helpers the live sensors use before it is
// serialized. Correlation signals are derived by the real correlation engine
// from the generated sequence. Nothing here opens a socket, reads a file or
// executes anything; output is a pure function of the profile, the anchor
// time and the supplied demo configuration.
package demoseed

import (
	"fmt"
	"sort"
	"time"
)

// Profile names accepted by Lookup.
const (
	// Small is about two thousand sensor observations over seven days.
	Small = "small"
	// Large is fifty thousand sensor observations over seven days.
	Large = "large"
)

// Profile fixes the size and shape of one seeded history.
type Profile struct {
	// Name is the CLI value.
	Name string
	// Events is the exact number of sensor observations (interaction and canary
	// invocation). Derived correlation signals are added on top.
	Events int
	// Span is how far back the oldest observation may start.
	Span time.Duration
	// Templates is how many distinct shared step sequences campaign actors follow.
	Templates int
	// Seed makes the generator reproducible for one profile.
	Seed uint64
}

var profiles = map[string]Profile{
	Small: {Name: Small, Events: 2000, Span: 7 * 24 * time.Hour, Templates: 4, Seed: 0x5eed_0001},
	Large: {Name: Large, Events: 50000, Span: 7 * 24 * time.Hour, Templates: 12, Seed: 0x5eed_0002},
}

// Names returns the accepted profile names in stable order.
func Names() []string {
	out := make([]string, 0, len(profiles))
	for name := range profiles {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// Lookup returns the named profile or an actionable error.
func Lookup(name string) (Profile, error) {
	profile, ok := profiles[name]
	if !ok {
		return Profile{}, fmt.Errorf("unknown seed profile %q (known: %v)", name, Names())
	}
	return profile, nil
}
