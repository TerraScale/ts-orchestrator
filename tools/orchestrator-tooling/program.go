// Port of tools/TerraScale.Orchestrator.Tooling/Program.cs: the tooling
// entry point delegates to the manual command dispatcher.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	os.Exit(ToolDispatcher.RunAsync(ctx, os.Args[1:]))
}
