package runtime

import (
	"context"
	"os"
	"testing"

	"github.com/metaforismo/aegismesh/internal/sensorproc"
)

func TestMain(m *testing.M) {
	if sensorproc.IsBuiltinWorkerInvocation(os.Args) {
		if err := sensorproc.RunBuiltinWorker(context.Background(), os.Stdin, os.Stdout); err != nil {
			os.Exit(1)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}
