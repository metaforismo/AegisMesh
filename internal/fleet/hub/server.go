package hub

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"
)

// Server owns a dedicated inventory-only listener with bounded concurrent request work.
type Server struct {
	server   *http.Server
	listener net.Listener
	once     sync.Once
	wg       sync.WaitGroup
}

// Listen loads TLS before binding; config validation must already have enforced exposure policy.
func Listen(address, certFile, keyFile string, h *Hub) (*Server, error) {
	host, _, err := net.SplitHostPort(address)
	ip := net.ParseIP(host)
	if err != nil || host != "localhost" && (ip == nil || !ip.IsLoopback()) && certFile == "" {
		return nil, errors.New("fleet hub: non-loopback listener requires TLS")
	}
	if (certFile == "") != (keyFile == "") {
		return nil, errors.New("fleet hub: TLS certificate and key must be supplied together")
	}
	var tlsConfig *tls.Config
	if certFile != "" {
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, errors.New("fleet hub: invalid TLS certificate/key")
		}
		tlsConfig = &tls.Config{
			MinVersion:   tls.VersionTLS12,
			Certificates: []tls.Certificate{cert},
		}
	}
	slots := make(chan struct{}, 8)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case slots <- struct{}{}:
			defer func() { <-slots }()
			h.ServeHTTP(w, r)
		default:
			h.reject(w, failure("capacity"))
		}
	})
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return nil, err
	}
	if tlsConfig != nil {
		listener = tls.NewListener(listener, tlsConfig)
	}
	return &Server{
		listener: listener,
		server: &http.Server{
			Handler:           handler,
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       10 * time.Second,
			WriteTimeout:      10 * time.Second,
			IdleTimeout:       30 * time.Second,
			MaxHeaderBytes:    8 << 10,
			ErrorLog:          slog.NewLogLogger(slog.New(slog.DiscardHandler).Handler(), slog.LevelError),
		},
	}, nil
}

// Addr returns the actual listener authority.
func (s *Server) Addr() string {
	return s.listener.Addr().String()
}

// Start begins serving the already-bound listener.
func (s *Server) Start() {
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		_ = s.server.Serve(s.listener)
	}()
}

// Close drains handlers before registry resources are released.
func (s *Server) Close(ctx context.Context) error {
	var err error
	s.once.Do(func() {
		err = s.server.Shutdown(ctx)
		_ = s.server.Close()
		_ = s.listener.Close()
		s.wg.Wait()
	})
	return err
}
