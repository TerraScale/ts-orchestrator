package vmqual

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/sandboxvm"
	"terrascale.tech/orchestrator/src/orchestrator/vmnet"
)

type guestExecutor interface {
	Execute(context.Context, sandboxvm.Command) error
}
type SmokeReport struct {
	Boot    time.Duration
	Ready   time.Duration
	Cleanup time.Duration
}

// RunSmoke proves the minimum real guest path. The factory supplied by the
// command is always NewFirecrackerFactory; a unit test may inject a narrow VM
// fake, but it cannot be used by vm-smoke itself.
func RunSmoke(ctx context.Context, factory VMFactory, network NetworkController, timeout time.Duration) (SmokeReport, error) {
	if ctx == nil {
		return SmokeReport{}, errors.New("vmqual: smoke context is nil")
	}
	if factory == nil || network == nil {
		return SmokeReport{}, errors.New("vmqual: smoke factory and network are required")
	}
	if timeout <= 0 {
		timeout = 2 * time.Minute
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	started := time.Now()
	if err := network.Apply(ctx); err != nil {
		return SmokeReport{}, err
	}
	networkApplied := true
	defer func() {
		if networkApplied {
			_ = network.Cleanup(context.Background())
		}
	}()
	guest := LaunchGuests(DefaultMemoryMiB)[0]
	vm, err := factory.Create(ctx, guest)
	if err != nil {
		_ = network.Cleanup(context.Background())
		return SmokeReport{}, err
	}
	if vm == nil {
		_ = network.Cleanup(context.Background())
		return SmokeReport{}, errors.New("vm-smoke: factory returned a nil guest")
	}
	boot := time.Since(started)
	if err := vm.StartReady(ctx); err != nil {
		_ = vm.Delete(context.Background())
		_ = network.Cleanup(context.Background())
		return SmokeReport{}, fmt.Errorf("vm-smoke: guest did not become ready: %w", err)
	}
	ready := time.Since(started)
	observation, err := vm.Inspect(ctx)
	if err != nil {
		_ = vm.Stop(context.Background())
		_ = vm.Delete(context.Background())
		_ = network.Cleanup(context.Background())
		return SmokeReport{}, fmt.Errorf("vm-smoke: readiness inspection failed: %w", err)
	}
	if !observation.Running || !observation.Ready {
		_ = vm.Stop(context.Background())
		_ = vm.Delete(context.Background())
		_ = network.Cleanup(context.Background())
		return SmokeReport{}, errors.New("vm-smoke: guest reported not ready after StartReady")
	}
	if observation.ID != "" && observation.ID != guest.ID {
		_ = vm.Stop(context.Background())
		_ = vm.Delete(context.Background())
		_ = network.Cleanup(context.Background())
		return SmokeReport{}, fmt.Errorf("vm-smoke: readiness identity mismatch: %s", observation.ID)
	}
	if observation.Region != "" && observation.Region != guest.Region {
		_ = vm.Stop(context.Background())
		_ = vm.Delete(context.Background())
		_ = network.Cleanup(context.Background())
		return SmokeReport{}, fmt.Errorf("vm-smoke: readiness Region mismatch: %s", observation.Region)
	}
	if observation.MemoryMiB != 0 && observation.MemoryMiB != guest.MemoryMiB {
		_ = vm.Stop(context.Background())
		_ = vm.Delete(context.Background())
		_ = network.Cleanup(context.Background())
		return SmokeReport{}, fmt.Errorf("vm-smoke: readiness memory mismatch: %d MiB", observation.MemoryMiB)
	}
	if executor, ok := vm.(guestExecutor); !ok {
		_ = vm.Stop(context.Background())
		_ = vm.Delete(context.Background())
		_ = network.Cleanup(context.Background())
		return SmokeReport{}, errors.New("vm-smoke: guest execution channel is not configured")
	} else if err := executor.Execute(ctx, sandboxvm.Command{Path: "/usr/bin/systemctl", Args: []string{"is-system-running"}}); err != nil {
		_ = vm.Stop(context.Background())
		_ = vm.Delete(context.Background())
		_ = network.Cleanup(context.Background())
		return SmokeReport{}, fmt.Errorf("vm-smoke: systemd check failed: %w", err)
	}
	if err := vm.Stop(context.Background()); err != nil {
		_ = vm.Delete(context.Background())
		_ = network.Cleanup(context.Background())
		return SmokeReport{}, err
	}
	if err := vm.Delete(context.Background()); err != nil {
		_ = network.Cleanup(context.Background())
		return SmokeReport{}, err
	}
	cleanStarted := time.Now()
	if err := network.Cleanup(context.Background()); err != nil {
		return SmokeReport{}, err
	}
	networkApplied = false
	return SmokeReport{Boot: boot, Ready: ready, Cleanup: time.Since(cleanStarted)}, nil
}

func SingleGuestNetwork() (NetworkController, error) {
	return NewNetworkController(vmnet.Config{Prefix: "ts", Regions: []vmnet.RegionSpec{{Code: vmnet.GRU, CIDR: vmnet.StableCIDR(vmnet.GRU), Guests: []vmnet.GuestSpec{{ID: "member-1"}}}}}, commandRunnerNetwork{}, "")
}

type commandRunnerNetwork struct{}

func (commandRunnerNetwork) Run(ctx context.Context, executable string, args []string) error {
	if !filepath.IsAbs(executable) {
		return errors.New("vmqual: network executable must be absolute")
	}
	return exec.CommandContext(ctx, executable, args...).Run()
}
