// Command vm-guest-control is the forced SSH command installed only in I-12
// Firecracker qualification guests. It is never a production host backdoor.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"terrascale.tech/orchestrator/src/orchestrator/vmguest"
)

func main() {
	if os.Geteuid() != 0 {
		os.Exit(1)
	}
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
