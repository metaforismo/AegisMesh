// Package admin serves health/readiness/metrics on a dedicated loopback
// listener (GO-DEPLOY-002): diagnostics never share a mux with decoys.
package admin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/metaforismo/aegismesh/internal/observe"
	"github.com/metaforismo/aegismesh/internal/version"
)

// Status feeds /healthz and /readyz.
type Status struct {
	SensorsStarted int    `json:"sensors_started"`
	SensorsWanted  int    `json:"sensors_wanted"`
	StoreHealthy   bool   `json:"store_healthy"`
	DroppedEvents  uint64 `json:"dropped_events"`
}

type Server struct {
	status   func() Status
	meter    observe.Meter
	srv      *http.Server
	ln       net.Listener
	log      *slog.Logger
	wg       sync.WaitGroup
	startErr error
	once     sync.Once
}

func New(listen string, status func() Status, meter observe.Meter, log *slog.Logger) (*Server, error) {
	mux := http.NewServeMux()
	s := &Server{status: status, meter: meter, log: log}

	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		st := s.status()
		w.Header().Set("Content-Type", "application/json")
		if st.StoreHealthy && st.SensorsStarted == st.SensorsWanted {
			writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "detail": st})
			return
		}
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"status": "degraded", "detail": st})
	})
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) {
		st := s.status()
		if st.SensorsStarted == st.SensorsWanted {
			writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
			return
		}
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "starting"})
	})
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		_, _ = w.Write([]byte(s.meter.WritePrometheus()))
	})
	mux.HandleFunc("/version", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, version.Get())
	})

	s.srv = &http.Server{ //nolint:gosec // loopback-only diagnostics listener with explicit timeouts
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
	}
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return nil, fmt.Errorf("admin: bind %s: %v", listen, err)
	}
	s.ln = ln
	return s, nil
}

// Addr reports the bound address (useful when port 0 was requested in tests).
func (s *Server) Addr() string {
	if s.ln == nil {
		return ""
	}
	return s.ln.Addr().String()
}

func (s *Server) Start() {
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		if err := s.srv.Serve(s.ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.log.Error("admin listener failed", "err", err)
		}
	}()
	s.log.Info("admin listener up", "addr", s.Addr(), "endpoints", "/healthz /readyz /metrics /version")
}

func (s *Server) Close(ctx context.Context) error {
	var err error
	s.once.Do(func() {
		err = s.srv.Shutdown(ctx)
		s.wg.Wait()
	})
	return err
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
