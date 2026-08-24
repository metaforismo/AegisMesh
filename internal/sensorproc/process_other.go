//go:build !darwin && !linux

package sensorproc

import (
	"os"
	"syscall"
)

func processAttributes() *syscall.SysProcAttr { return nil }
func terminateProcess(p *os.Process) error {
	if p == nil {
		return nil
	}
	return p.Signal(os.Interrupt)
}
func killProcess(p *os.Process) error {
	if p == nil {
		return nil
	}
	return p.Kill()
}
func PrepareWorkerProcess() error { return nil }
