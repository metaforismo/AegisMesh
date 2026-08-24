package sensorproc

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"testing"
	"time"

	"github.com/metaforismo/aegismesh/internal/config"
	"github.com/metaforismo/aegismesh/internal/event"
	"github.com/metaforismo/aegismesh/internal/observe"
	"github.com/metaforismo/aegismesh/internal/sensor"
)

func TestDefaultWorkersContainCrashAndKeepSiblingServing(t *testing.T) {
	workerSpec := func(id string) WorkerSpec {
		return WorkerSpec{Sensor: config.Sensor{
			ID: id, Kind: config.SensorKindHTTP, Listen: "127.0.0.1:0",
			Persona: &config.HTTPPersona{},
			Rules:   []config.HTTPRule{{Name: "root", PathRegex: "^/$", Methods: []string{"GET"}, Status: http.StatusOK, Body: "ok"}},
		}, Instance: "process-test"}
	}
	bus := event.NewBus(8, sinkFunc(func(context.Context, event.Envelope) error { return nil }), slog.Default())
	defer bus.Close()
	meter := observe.NewRegistry()
	seq := &event.Sequencer{}
	deps := func(c config.Sensor) sensor.Deps {
		return sensor.Deps{Config: c, Bus: bus, Meter: meter, Log: slog.Default(), Seq: seq, Instance: "process-test"}
	}

	first, err := NewProxy(ProxyOptions{Spec: workerSpec("first")})
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewProxy(ProxyOptions{Spec: workerSpec("second")})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := first.Start(ctx, deps(first.spec.Sensor)); err != nil {
		t.Fatal(err)
	}
	if err := second.Start(ctx, deps(second.spec.Sensor)); err != nil {
		_ = first.Close(ctx)
		t.Fatal(err)
	}
	defer func() {
		if err := second.Close(ctx); err != nil {
			t.Errorf("close sibling worker: %v", err)
		}
	}()

	first.mu.RLock()
	firstCommand := first.cmd
	first.mu.RUnlock()
	if err := firstCommand.Kill(); err != nil {
		t.Fatalf("kill first worker: %v", err)
	}
	select {
	case err := <-first.Done():
		if err == nil {
			t.Fatal("crashed worker reported a clean stop")
		}
	case <-ctx.Done():
		t.Fatal("crashed worker was not observed and reaped")
	}
	if first.Healthy() {
		t.Fatal("crashed worker remained healthy")
	}

	resp, err := http.Get("http://" + second.Addr() + "/")
	if err != nil {
		t.Fatalf("sibling request after crash: %v", err)
	}
	body, readErr := io.ReadAll(io.LimitReader(resp.Body, 16))
	closeErr := resp.Body.Close()
	if readErr != nil || closeErr != nil || resp.StatusCode != http.StatusOK || string(body) != "ok" {
		t.Fatalf("sibling response status=%d body=%q read=%v close=%v", resp.StatusCode, body, readErr, closeErr)
	}
	if err := first.Close(ctx); err != nil {
		t.Fatalf("close crashed worker: %v", err)
	}
}
