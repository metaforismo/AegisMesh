//go:build darwin || linux

package sensorproc

import (
	"os"
	"syscall"
)

func processAttributes() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setpgid: true}
}

func terminateProcess(p *os.Process) error {
	if p == nil {
		return nil
	}
	return syscall.Kill(-p.Pid, syscall.SIGTERM)
}

func killProcess(p *os.Process) error {
	if p == nil {
		return nil
	}
	return syscall.Kill(-p.Pid, syscall.SIGKILL)
}

// PrepareWorkerProcess applies a small portable descriptor cap. This is a
// resource bound only; it is not presented as a memory, CPU, or syscall
// sandbox.
func PrepareWorkerProcess() error {
	var current syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &current); err != nil {
		return err
	}
	max := current.Max
	if max > 1024 {
		max = 1024
	}
	cur := current.Cur
	if cur > max {
		cur = max
	}
	lim := &syscall.Rlimit{Cur: cur, Max: max}
	return syscall.Setrlimit(syscall.RLIMIT_NOFILE, lim)
}
