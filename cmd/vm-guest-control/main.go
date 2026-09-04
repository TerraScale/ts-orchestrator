// Command vm-guest-control is the forced SSH command installed only in I-12
// Firecracker qualification guests. It is never a production host backdoor.
package main

import (
	"context"
	"os"
	"os/signal"
	"runtime/debug"
	"syscall"

	"terrascale.tech/orchestrator/src/orchestrator/vmguest"
	"golang.org/x/sys/unix"
)

func main() {
	if os.Geteuid() != 0 {
		os.Exit(1)
	}
	debug.SetMemoryLimit(160 << 20)
	lock, err := acquireSessionLock()
	if err != nil {
		os.Exit(1)
	}
	defer unix.Close(lock)
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	original := os.Getenv("SSH_ORIGINAL_COMMAND")
	if len(os.Args) != 1 && original == "" {
		original = "local arguments"
	}
	if err := vmguest.ServeForced(ctx, os.Stdin, os.Stdout, original, vmguest.DefaultConfig()); err != nil {
		os.Exit(1)
	}
}

func acquireSessionLock() (int, error) {
	fd, err := unix.Open("/run/lock/terrascale-vmqual-control.lock", unix.O_RDWR|unix.O_CREAT|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return -1, err
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || int(stat.Uid) != os.Geteuid() || stat.Mode&0o077 != 0 {
		_ = unix.Close(fd)
		return -1, syscall.EPERM
	}
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = unix.Close(fd)
		return -1, err
	}
	return fd, nil
}
