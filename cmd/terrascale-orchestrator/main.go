package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/cli"
)

func main() {
	ctx, cancel := commandContext(os.Args[1:])
	defer cancel()
	err := cli.Run(ctx, os.Args[1:], os.Stdout)
	if errors.Is(err, context.Canceled) && ctx.Err() != nil {
		// A signal stopped the command; that is the normal way a service ends.
		return
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func commandContext(args []string) (context.Context, context.CancelFunc) {
	parent := context.Background()
	if len(args) > 0 && (args[0] == "bootstrap" || args[0] == "release") {
		// Operator commands initialize OCI credentials synchronously. Retain
		// default signal termination because that work cannot observe cancellation.
		return parent, func() {}
	}

	signalContext, stopSignals := signal.NotifyContext(parent, os.Interrupt, syscall.SIGTERM)
	ctx, cancel := context.WithCancel(parent)
	stopForwarding := context.AfterFunc(signalContext, func() {
		// Restore default termination before the runtime starts graceful shutdown,
		// so a second signal can stop a runtime whose cleanup is stuck.
		stopSignals()
		cancel()
	})
	return ctx, func() {
		stopForwarding()
		stopSignals()
		cancel()
	}
}
