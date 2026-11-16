package runtime

import (
	"context"
	goruntime "runtime"
	"testing"
	"time"

	"github.com/metaforismo/aegismesh/internal/config"
	"github.com/metaforismo/aegismesh/internal/console/auth"
)

func assertGoroutinesSettle(t *testing.T, before, allowance int) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		count := goruntime.NumGoroutine()
		if count <= before+allowance {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("goroutines did not settle: before=%d after=%d allowance=%d", before, count, allowance)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestRepeatedSubsystemShutdownJoinsWorkers(t *testing.T) {
	before := goruntime.NumGoroutine()
	for range 5 {
		cfg := testConfig(t)
		cfg.Console = config.Console{Enabled: true, Listen: "127.0.0.1:0", Operators: []config.Operator{{Name: "synthetic", Role: "viewer", TokenSHA256: auth.Digest("synthetic-lifecycle")}}}
		cfg.Console = cfg.Console.WithDefaults()
		cfg.Fleet.Hub.Enabled = true
		cfg.Fleet.Hub.Listen = "127.0.0.1:0"
		system, err := Build(cfg, quietLogger())
		if err != nil {
			t.Fatal(err)
		}
		if err := system.Start(context.Background()); err != nil {
			system.Stop(context.Background())
			t.Fatal(err)
		}
		system.Stop(context.Background())
	}
	// Leave room for transient runtime/netpoll work; five leaked workers cannot
	// hide within this allowance. No tests in this package use t.Parallel.
	assertGoroutinesSettle(t, before, 2)
}
