package sensorproc

import (
	"context"
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	if IsBuiltinWorkerInvocation(os.Args) {
		if err := RunBuiltinWorker(context.Background(), os.Stdin, os.Stdout); err != nil {
			os.Exit(1)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}
