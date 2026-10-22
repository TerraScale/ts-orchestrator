package app

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/natscell/mesh"
	"github.com/TerraScale/ts-orchestrator/internal/releasepush"
	"github.com/TerraScale/ts-orchestrator/internal/sdnotify"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
	"github.com/TerraScale/ts-orchestrator/internal/vaultsecret"
)

// RunSingleHost runs a one-node SwarmKit manager+worker with the containerd
// executor and the release NATS listener (:4222) CI pushes releases to. It
// needs no OCI, Vault, NetBird or admission.
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
	if err := executor.BindVaultSecrets(vaultsecret.ReadInstanceSecrets); err != nil {
		return err
	}
	defer executor.Close()
	if err := executor.SetRegistryResolver(swarmruntime.GHCRResolver(vaultsecret.ReadPullToken)); err != nil {
		return err
	}
	node, err := swarmruntime.StartSingleHost(ctx, *state, executor)
	if err != nil {
		return err
	}
	defer func() {
		stop, done := context.WithTimeout(context.Background(), 30*time.Second)
		defer done()
		_ = node.Stop(stop)
	}()
	if err := releasepush.EnsureFirewall(ctx); err != nil {
		// Workloads keep serving; only release pushes are blocked until the next start.
		fmt.Fprintf(output, "release listener firewall: %v\n", err)
	}
	// The edge's :80/:443 sit behind the same Ubuntu OCI image INPUT REJECT.
	for _, port := range []int{80, 443} {
		if err := releasepush.OpenTCP(ctx, port); err != nil {
			fmt.Fprintf(output, "edge firewall: %v\n", err)
		}
	}
	releases, err := releasepush.NewHandler(*state)
	if err != nil {
		return err
	}
	releases.Mesh = mesh.Bridge(*state)
	natsServer, natsConn, err := releasepush.Start(*state)
	if err != nil {
		return err
	}
	defer natsServer.Shutdown()
	defer natsConn.Close()
	if err := releases.Serve(natsConn); err != nil {
		return err
	}
	notifier := sdnotify.FromEnvironment()
	if err := notifier.Ready("single-host node ready"); err != nil {
		return err
	}
	defer func() { _ = notifier.Stopping() }()
	if _, err := fmt.Fprintf(output, "single-host node %s ready; control socket %s\n", node.ID(), swarmruntime.SingleHostSocket(*state)); err != nil {
		return err
	}
	waited := make(chan error, 1)
	go func() { waited <- node.Wait(ctx) }()
	select {
	case err := <-waited:
		if err != nil && ctx.Err() == nil {
			return err
		}
		return nil
	case <-releases.Installed:
		// Non-zero so Restart=always starts the new binary; containerd keeps workloads running.
		return errors.New("installed a pushed release; exiting so systemd starts it")
	}
}
