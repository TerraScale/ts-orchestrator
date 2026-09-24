package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/app"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := app.Run(ctx, os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
