package hub

import (
	"net"
	"strconv"
	"sync"
	"time"
)

const (
	// Enough for 1000 nodes behind one NAT at the minimum ten-second interval.
	remoteRequestsPerMinute   = 8192
	maxRemotes                = 4096
	rejectionSamplesPerMinute = 5
)

type remoteWindow struct {
	start time.Time
	count int
}

// abuseLimits never holds the registry mutex or performs IO in the request path.
// A full remote table refuses new addresses until the next periodic prune.
type abuseLimits struct {
	mu         sync.Mutex
	remotes    map[string]remoteWindow
	auditStart time.Time
	samples    int
	pending    int
	suppressed uint64
}

func (l *abuseLimits) init(now time.Time) {
	l.remotes = make(map[string]remoteWindow)
	l.auditStart = now
}

func (h *Hub) allowRemote(address string) bool {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		host = address
	}
	ip := net.ParseIP(host)
	// Never retain arbitrary request strings, ports, forwarding headers or hostnames.
	host = "unknown"
	if ip != nil {
		host = ip.String()
	}
	now := h.now()
	l := &h.limits
	l.mu.Lock()
	defer l.mu.Unlock()
	window, exists := l.remotes[host]
	if !exists && len(l.remotes) >= maxRemotes {
		return false
	}
	if !exists || now.Sub(window.start) >= time.Minute {
		window = remoteWindow{start: now}
	}
	if window.count >= remoteRequestsPerMinute {
		return false
	}
	window.count++
	l.remotes[host] = window
	return true
}

func (h *Hub) queueRejection() {
	l := &h.limits
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.samples < rejectionSamplesPerMinute {
		l.samples++
		l.pending++
	} else if l.suppressed < ^uint64(0) {
		l.suppressed++
	}
}

// flushRejections writes at most five samples and one suppression summary per
// minute. Only maintenance/shutdown calls it; packet arrivals cannot trigger IO.
func (h *Hub) flushRejections(shutdown bool) {
	l := &h.limits
	l.mu.Lock()
	pending := l.pending
	l.pending = 0
	var suppressed uint64
	now := h.now()
	if shutdown || now.Sub(l.auditStart) >= time.Minute {
		suppressed = l.suppressed
		l.suppressed, l.samples = 0, 0
		l.auditStart = now
	}
	for remote, window := range l.remotes {
		if now.Sub(window.start) >= time.Minute {
			delete(l.remotes, remote)
		}
	}
	l.mu.Unlock()
	if h.failed.Load() {
		return
	}
	for range pending {
		if h.record("fleet.node.rejected", "", "denied") != nil {
			return
		}
	}
	if suppressed > 0 {
		_ = h.record("fleet.node.rejected.summary", strconv.FormatUint(suppressed, 10), "suppressed")
	}
}

func (h *Hub) runMaintenance() {
	defer close(h.done)
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-h.stop:
			return
		case <-ticker.C:
			h.maintain()
		}
	}
}

// The real ticker only wakes the worker. All interval decisions use Now, so
// deterministic tests and liveness share the same injected time source.
func (h *Hub) maintain() {
	h.flushRejections(false)
	h.mu.Lock()
	defer h.mu.Unlock()
	elapsed := h.now().Sub(h.lastFlush)
	if elapsed >= FlushInterval {
		// Keep the original cadence; IO duration or synchronous durable changes must
		// not push the next soft-state flush back by another interval.
		h.lastFlush = h.lastFlush.Add((elapsed / FlushInterval) * FlushInterval)
		if h.dirty {
			_ = h.save()
		}
	}
}
