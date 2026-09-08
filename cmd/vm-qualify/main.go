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
	"terrascale.tech/orchestrator/src/orchestrator/vmqualruntime"
	"terrascale.tech/orchestrator/src/orchestrator/vmqualsuite"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:], os.Stdout, os.Stderr); err != nil {
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
	if err := validateDeclarationInputs(config); err != nil {
		return err
	}
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
		factory, network, err := realComponents(ctx, config, false, false)
		if err != nil {
			return err
		}
		report, err := vmqual.RunSmoke(ctx, factory, network, 5*time.Minute)
		if err != nil {
			return errors.Join(err, vmqual.WriteSmokeFailureDiagnostics(out, report))
		}
		_, _ = fmt.Fprintf(out, "smoke boot=%s ready=%s cleanup=%s\n", report.Boot, report.Ready, report.Cleanup)
		return nil
	case "stack":
		factory, network, err := realComponents(ctx, config, true, false)
		if err != nil {
			return err
		}
		stack, err := vmqual.NewStack(vmqual.StackConfig{RequireResourceEvidence: true, Guests: vmqual.LaunchGuests(config.MemoryMiB), VMFactory: factory, Network: network, JournalPath: config.JournalPath, StateRoot: config.StateRoot})
		if err != nil {
			return err
		}
		if err := stack.Start(ctx); err != nil {
			return err
		}
		_, _ = fmt.Fprintln(out, "Firecracker qualification stack is ready; press Ctrl-C to stop")
		<-ctx.Done()
		return stack.Cleanup(context.Background())
	case "test":
		factory, network, err := realComponents(ctx, config, true, true)
		if err != nil {
			return err
		}
		stack, err := vmqual.NewStack(vmqual.StackConfig{RequireResourceEvidence: true, Guests: vmqual.LaunchGuests(config.MemoryMiB), VMFactory: factory, Network: network, JournalPath: config.JournalPath, StateRoot: config.StateRoot})
		if err != nil {
			return err
		}
		providers, driver, err := vmqualsuite.NewLocalScenarioDriverFromConfig(vmqualsuite.LocalProviderConfig{StateRoot: config.StateRoot})
		if err != nil {
			_ = stack.Cleanup(context.Background())
			return err
		}
		report, err := vmqualsuite.RunSuite(ctx, stack, driver)
		_ = providers.Close()
		_ = vmqualsuite.WriteSuiteReport(out, report)
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

// validateDeclarationInputs checks the command-owned input boundary before a
// profile performs host work.  The declaration loaders retain responsibility
// for parsing, ownership, and schema validation; this check only prevents a
// selected path from silently becoming an absent input.
func validateDeclarationInputs(config vmqual.Config) error {
	for _, input := range []struct {
		name string
		path string
	}{
		{name: "TerraBase", path: config.TerraBaseDeclarationFile},
		{name: "run", path: config.QualificationRunDeclarationFile},
		{name: "control", path: config.QualificationControlDeclarationFile},
	} {
		if input.path == "" {
			continue
		}
		info, err := os.Lstat(input.path)
		if err != nil {
			return fmt.Errorf("vm-qualify: %s declaration: %w", input.name, err)
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("vm-qualify: %s declaration must be a regular file", input.name)
		}
	}
	return nil
}

func realComponents(ctx context.Context, config vmqual.Config, full, fourthRegion bool) (vmqual.VMFactory, vmqual.NetworkController, error) {
	config, err := vmqual.ResolveRuntimeIdentity(config)
	if err != nil {
		return nil, nil, err
	}
	networkConfig := qualificationNetworkConfig(full, fourthRegion)
	runner, err := vmnet.DiscoverHostRunner()
	if err != nil {
		return nil, nil, err
	}
	networkConfig.TAPUID = uint32(config.JailerUID)
	networkConfig.TAPGID = uint32(config.JailerGID)
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
	networkJournalPath := filepath.Join(config.Root, "network-cleanup-journal.json")
	factory, network, err := vmqualruntime.NewProductionComponents(config, artifacts.Image, networkConfig, runner, networkJournalPath)
	if err != nil {
		return nil, nil, err
	}
	return factory, network, nil
}

func qualificationNetworkConfig(full, fourthRegion bool) vmnet.Config {
	networkConfig := vmnet.Config{Prefix: "ts", Regions: []vmnet.RegionSpec{{Code: vmnet.GRU, Guests: []vmnet.GuestSpec{{ID: "gru-member-1"}}}}}
	if full {
		networkConfig = vmnet.DefaultConfig()
	}
	if fourthRegion {
		networkConfig.Regions = append(networkConfig.Regions, vmnet.RegionSpec{Code: vmqual.FourthRegion, Guests: []vmnet.GuestSpec{{ID: "iad-member-1"}, {ID: "iad-member-2"}}})
	}
	return networkConfig
}
