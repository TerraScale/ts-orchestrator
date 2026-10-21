package app

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/sdnotify"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
)

// RunSingleHost runs a one-node SwarmKit manager+worker with the containerd
// executor. It needs no OCI, Vault, NetBird, NATS or admission.
func RunSingleHost(ctx context.Context, args []string, output io.Writer) error {
	flags := flag.NewFlagSet("single-host", flag.ContinueOnError)
	flags.SetOutput(output)
	state := flags.String("state", "/var/lib/ts-orch", "absolute state directory")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("single-host accepts only --state")
	}
	if os.Geteuid() != 0 {
		return errors.New("single-host requires root")
	}
	executor, err := swarmruntime.NewExecutor("/run/containerd/containerd.sock", *state)
	if err != nil {
		return err
	}
	defer executor.Close()
	node, err := swarmruntime.StartSingleHost(ctx, *state, executor)
	if err != nil {
		return err
	}
	defer func() {
		stop, done := context.WithTimeout(context.Background(), 30*time.Second)
		defer done()
		_ = node.Stop(stop)
	}()
	notifier := sdnotify.FromEnvironment()
	if err := notifier.Ready("single-host node ready"); err != nil {
		return err
	}
	defer func() { _ = notifier.Stopping() }()
	if _, err := fmt.Fprintf(output, "single-host node %s ready; control socket %s\n", node.ID(), swarmruntime.SingleHostSocket(*state)); err != nil {
		return err
	}
	if err := node.Wait(ctx); err != nil && ctx.Err() == nil {
		return err
	}
	return nil
}
