package runtime

import "fmt"

// Endpoint is the bound address for one running sensor. It is a
// value returned by Endpoints; modifying a returned value cannot mutate the
// System's runtime state.
type Endpoint struct {
	ID   string
	Kind string
	Addr string
}

type addrProvider interface {
	Addr() string
}

type healthProvider interface {
	Healthy() bool
}

type failureContained interface {
	FailureContained() bool
}

// Endpoints returns sensors in their configured order after a successful
// Start. Discovery rejects calls before all sensors start and after Stop has
// completed; callers must still serialize discovery with a concurrent Stop.
func (s *System) Endpoints() ([]Endpoint, error) {
	if s.stopped.Load() {
		return nil, fmt.Errorf("%w: sensor endpoints are unavailable after stop", errRuntime)
	}
	if got, want := s.started.Load(), uint64(len(s.sensors)); got != want {
		return nil, fmt.Errorf("%w: sensor endpoints unavailable: %d/%d sensors started", errRuntime, got, want)
	}

	endpoints := make([]Endpoint, len(s.sensors))
	for i, sen := range s.sensors {
		if h, ok := sen.(healthProvider); ok && !h.Healthy() {
			return nil, fmt.Errorf("%w: sensor %q (%s) is not healthy", errRuntime, sen.ID(), sen.Kind())
		}
		addrer, ok := sen.(addrProvider)
		if !ok {
			return nil, fmt.Errorf("%w: sensor %q (%s) does not expose a bound address", errRuntime, sen.ID(), sen.Kind())
		}
		addr := addrer.Addr()
		if addr == "" {
			return nil, fmt.Errorf("%w: sensor %q (%s) is not bound", errRuntime, sen.ID(), sen.Kind())
		}
		endpoints[i] = Endpoint{ID: sen.ID(), Kind: sen.Kind(), Addr: addr}
	}
	return endpoints, nil
}

// AdminAddr returns the bound admin listener address. The admin listener is
// created during Build, so this may be used before Start; it becomes
// unavailable after Stop to avoid returning a stale address.
func (s *System) AdminAddr() (string, error) {
	if s.adminSrv == nil {
		return "", fmt.Errorf("%w: admin listener is disabled", errRuntime)
	}
	if s.stopped.Load() {
		return "", fmt.Errorf("%w: admin listener is stopped", errRuntime)
	}
	addr := s.adminSrv.Addr()
	if addr == "" {
		return "", fmt.Errorf("%w: admin listener is not bound", errRuntime)
	}
	return addr, nil
}
