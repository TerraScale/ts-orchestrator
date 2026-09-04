// Command vm-qualify is the explicit I-12 Firecracker qualification entrypoint.
// It is test infrastructure and must never be used as a production fallback.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/vmnet"
	"terrascale.tech/orchestrator/src/orchestrator/vmqual"
)

func main() {
	if err := run(context.Background(), os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "vm-qualify:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, out, errOut io.Writer) error {
	if len(args) != 1 {
		return errors.New("usage: vm-qualify {doctor|image|smoke|stack|test|clean}")
	}
	config := vmqual.DefaultConfig()
	config.Root, _ = filepath.Abs(config.Root)
	config.StateRoot, _ = filepath.Abs(config.StateRoot)
	config.JournalPath, _ = filepath.Abs(config.JournalPath)
	config.ImageCacheRoot, _ = filepath.Abs(config.ImageCacheRoot)
	config.ReadinessRoot, _ = filepath.Abs(config.ReadinessRoot)
	switch args[0] {
	case "doctor":
		report := vmqual.RunDoctor(ctx, config)
		report.Write(out)
		return report.Error()
	case "image":
		artifacts, err := vmqual.MaterializeArtifacts(ctx, config)
		if err != nil {
			return err
		}
		return vmqual.WriteImageResult(out, artifacts.Image)
	case "smoke":
		factory, network, err := realComponents(ctx, config, false)
		if err != nil {
			return err
		}
		report, err := vmqual.RunSmoke(ctx, factory, network, 5*time.Minute)
		if err != nil {
			return err
		}
		_, _ = fmt.Fprintf(out, "smoke boot=%s ready=%s cleanup=%s\n", report.Boot, report.Ready, report.Cleanup)
		return nil
	case "stack":
		factory, network, err := realComponents(ctx, config, true)
		if err != nil {
			return err
		}
		stack, err := vmqual.NewStack(vmqual.StackConfig{Guests: vmqual.LaunchGuests(config.MemoryMiB), VMFactory: factory, Network: network, JournalPath: config.JournalPath, StateRoot: config.StateRoot})
		if err != nil {
			return err
		}
		if err := stack.Start(ctx); err != nil {
			return err
		}
		_, _ = fmt.Fprintln(out, "Firecracker qualification stack is ready; press Ctrl-C to stop")
		waitCtx, cancel := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
		defer cancel()
		<-waitCtx.Done()
		return stack.Cleanup(context.Background())
	case "test":
		factory, network, err := realComponents(ctx, config, true)
		if err != nil {
			return err
		}
		stack, err := vmqual.NewStack(vmqual.StackConfig{Guests: vmqual.LaunchGuests(config.MemoryMiB), VMFactory: factory, Network: network, JournalPath: config.JournalPath, StateRoot: config.StateRoot})
		if err != nil {
			return err
		}
		providers, driver, err := vmqual.NewLocalScenarioDriverFromConfig(vmqual.LocalProviderConfig{StateRoot: config.StateRoot})
		if err != nil {
			_ = stack.Cleanup(context.Background())
			return err
		}
		report, err := vmqual.RunSuite(ctx, stack, driver)
		_ = providers.Close()
		_ = vmqual.WriteSuiteReport(out, report)
		return err
	case "clean":
		runner, err := vmnet.DiscoverHostRunner()
		if err != nil {
			return err
		}
		return vmqual.CleanJournal(ctx, config.JournalPath, runner)
	default:
		return errors.New("unknown command")
	}
}

func realComponents(ctx context.Context, config vmqual.Config, full bool) (vmqual.VMFactory, vmqual.NetworkController, error) {
	networkConfig := vmnet.Config{Prefix: "ts", Regions: []vmnet.RegionSpec{{Code: vmnet.GRU, Guests: []vmnet.GuestSpec{{ID: "gru-member-1"}}}}}
	if full {
		networkConfig = vmnet.DefaultConfig()
	}
	runner, err := vmnet.DiscoverHostRunner()
	if err != nil {
		return nil, nil, err
	}
	plan, err := vmnet.Plan(networkConfig)
	if err != nil {
		return nil, nil, err
	}
	config.NetworkPlan = plan
	artifacts, err := vmqual.MaterializeArtifacts(ctx, config)
	if err != nil {
		return nil, nil, err
	}
	config = artifacts.Config
	factory, err := vmqual.NewFirecrackerFactory(config, artifacts.Image)
	if err != nil {
		return nil, nil, err
	}
	network, err := vmqual.NewNetworkController(networkConfig, runner, "")
	if err != nil {
		return nil, nil, err
	}
	return factory, network, nil
}
