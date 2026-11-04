package app

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
)

// TestMain dispatches the runtime children used by the integration fixtures.
func TestMain(m *testing.M) {
	if len(os.Args) == 3 && os.Args[1] == "--runtime-logger" {
		swarmruntime.RunRuntimeLogger(os.Args[2])
		return
	}
	if len(os.Args) == 2 && os.Args[1] == runtimeControllerHostSourceCommand {
		if err := Run(context.Background(), os.Args[1:], os.Stdout); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}
