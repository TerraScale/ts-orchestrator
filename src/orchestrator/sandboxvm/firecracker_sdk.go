//go:build sandboxvm

package sandboxvm

import (
	"context"
	"errors"
	"fmt"
	"os/exec"

	firecracker "github.com/firecracker-microvm/firecracker-go-sdk"
	models "github.com/firecracker-microvm/firecracker-go-sdk/client/models"
)

// NewSDKMachineFactory binds the lifecycle boundary to the pinned official
// Firecracker Go SDK. It is available only to the explicit qualification build
// and therefore cannot be pulled into a production binary.
func NewSDKMachineFactory() MachineFactory {
	return func(ctx context.Context, cfg Config) (Machine, error) {
		root := true
		readOnly := false
		sdkCfg := firecracker.Config{
			SocketPath:      cfg.SocketPath,
			KernelImagePath: cfg.KernelImage,
			KernelArgs:      "console=ttyS0 reboot=k panic=1 pci=off",
			VMID:            cfg.ID,
			MachineCfg:      models.MachineConfiguration{VcpuCount: &cfg.VCPU, MemSizeMib: &cfg.MemoryMiB},
			Drives: []models.Drive{
				{DriveID: firecracker.String("rootfs"), PathOnHost: &cfg.RootDrive, IsRootDevice: &root, IsReadOnly: &readOnly},
				{DriveID: firecracker.String("data"), PathOnHost: &cfg.DataDrive, IsRootDevice: &readOnly, IsReadOnly: &readOnly},
			},
		}
		m, err := firecracker.NewMachine(ctx, sdkCfg, firecracker.WithProcessRunner(exec.Command(cfg.FirecrackerBinary, "--api-sock", cfg.SocketPath)))
		if err != nil {
			return nil, fmt.Errorf("new Firecracker machine: %w", err)
		}
		return &sdkMachine{machine: m}, nil
	}
}

type sdkMachine struct{ machine *firecracker.Machine }

func (m *sdkMachine) Start(ctx context.Context) error    { return m.machine.Start(ctx) }
func (m *sdkMachine) Shutdown(ctx context.Context) error { return m.machine.Shutdown(ctx) }
func (m *sdkMachine) StopVMM() error                     { return m.machine.StopVMM() }
func (m *sdkMachine) Wait(ctx context.Context) error     { return m.machine.Wait(ctx) }

func (m *sdkMachine) Version(ctx context.Context) (string, error) {
	version, err := m.machine.GetFirecrackerVersion(ctx)
	if err != nil {
		return "", err
	}
	if version == "" {
		return "", errors.New("Firecracker returned an empty version")
	}
	return version, nil
}

func (m *sdkMachine) Inspect(ctx context.Context) (Inspection, error) {
	info, err := m.machine.DescribeInstanceInfo(ctx)
	if err != nil {
		return Inspection{}, err
	}
	state := State("")
	if info.State != nil {
		state = State(*info.State)
	}
	version := ""
	if info.VmmVersion != nil {
		version = *info.VmmVersion
	}
	pid, err := m.machine.PID()
	if err != nil {
		return Inspection{}, err
	}
	return Inspection{State: state, PID: pid, SocketReady: SocketReady(m.machine.Cfg.SocketPath), Version: version}, nil
}
