//go:build sandboxvm

package sandboxvm

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	firecracker "github.com/firecracker-microvm/firecracker-go-sdk"
	models "github.com/firecracker-microvm/firecracker-go-sdk/client/models"
)

// NewSDKMachineFactory binds the lifecycle boundary to the pinned official
// Firecracker Go SDK. It is available only to the explicit qualification build
// and therefore cannot be pulled into a production binary.
func NewSDKMachineFactory() MachineFactory {
	return func(ctx context.Context, cfg Config) (Machine, error) {
		sdkCfg := buildSDKConfig(cfg)
		m, err := firecracker.NewMachine(ctx, sdkCfg)
		if err != nil {
			return nil, fmt.Errorf("new Firecracker machine: %w", err)
		}
		return &sdkMachine{machine: m}, nil
	}
}

func buildSDKConfig(cfg Config) firecracker.Config {
	root, writable, readOnly := true, false, true
	kernelArgs := cfg.KernelArgs
	if kernelArgs == "" {
		kernelArgs = "console=ttyS0 reboot=k panic=1 pci=off root=/dev/vda rw"
	}
	drives := []models.Drive{
		{DriveID: firecracker.String("rootfs"), PathOnHost: &cfg.RootDrive, IsRootDevice: &root, IsReadOnly: &writable},
		{DriveID: firecracker.String("data"), PathOnHost: &cfg.DataDrive, IsRootDevice: &writable, IsReadOnly: &writable},
	}
	if cfg.SeedDrive != "" {
		drives = append(drives, models.Drive{DriveID: firecracker.String("seed"), PathOnHost: &cfg.SeedDrive, IsRootDevice: &writable, IsReadOnly: &readOnly})
	}
	// Jailer interprets the socket as a name relative to its chroot. The
	// public sandbox Config retains the absolute jail path for OpenAPI calls.
	socketPath := filepath.Base(cfg.SocketPath)
	sdkConfig := firecracker.Config{
		SocketPath:      socketPath,
		LogPath:         cfg.LogPath,
		LogLevel:        "Warning",
		MetricsPath:     cfg.MetricsPath,
		KernelImagePath: cfg.KernelImage,
		KernelArgs:      kernelArgs,
		VMID:            cfg.ID,
		NetNS:           cfg.NetworkNamespace,
		MachineCfg:      models.MachineConfiguration{VcpuCount: &cfg.VCPU, MemSizeMib: &cfg.MemoryMiB},
		Drives:          drives,
	}
	uid, gid, numa := os.Getuid(), os.Getgid(), 0
	sdkConfig.JailerCfg = &firecracker.JailerConfig{ID: cfg.ID, UID: &uid, GID: &gid, NumaNode: &numa, ExecFile: cfg.FirecrackerBinary, JailerBinary: cfg.JailerBinary, ChrootBaseDir: filepath.Join(cfg.StateRoot, cfg.ID, "jailer"), CgroupVersion: "2", ChrootStrategy: firecracker.NewNaiveChrootStrategy(cfg.KernelImage)}
	if cfg.TapName != "" {
		sdkConfig.NetworkInterfaces = []firecracker.NetworkInterface{{StaticConfiguration: &firecracker.StaticNetworkConfiguration{
			HostDevName: cfg.TapName,
			MacAddress:  cfg.GuestMAC,
		}}}
	}
	return sdkConfig
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
