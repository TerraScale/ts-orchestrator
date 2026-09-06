//go:build sandboxvm

package vmqualruntime

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"

	"terrascale.tech/orchestrator/src/orchestrator/sandboxvm"
)

var ioFaultIdentifier = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*$`)

type dmCommand func(context.Context, string, ...string) error

// deviceMapperIOFault exposes a private device-mapper error target. The
// source is validated before creating the mapping, but is never opened by the
// target: every sector returns EIO. The provider later verifies the resulting
// block-device identity before it can enter a jail.
type deviceMapperIOFault struct {
	dmPath string
	name   string
	path   string
	bytes  int64
	run    bool
	cmd    dmCommand
}

func newDeviceMapperIOFaultAdapter() (sandboxvm.DataDriveFaultAdapter, error) {
	dmPath, err := exec.LookPath("dmsetup")
	if err != nil {
		return nil, fmt.Errorf("vmqual: resolve dmsetup: %w", err)
	}
	dmPath, err = filepath.Abs(dmPath)
	if err != nil {
		return nil, err
	}
	return &deviceMapperIOFault{dmPath: dmPath, cmd: runDMCommand}, nil
}

func runDMCommand(ctx context.Context, path string, args ...string) error {
	command := exec.CommandContext(ctx, path, args...)
	if output, err := command.CombinedOutput(); err != nil {
		return fmt.Errorf("dmsetup %v: %w: %s", args, err, output)
	}
	return nil
}

func (a *deviceMapperIOFault) Prepare(ctx context.Context, request sandboxvm.DataDriveFaultRequest) (sandboxvm.DataDriveFaultAttachment, error) {
	if a == nil || a.dmPath == "" || a.cmd == nil {
		return nil, errors.New("vmqual: I/O fault adapter is not configured")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if request.VMID == "" || !ioFaultIdentifier.MatchString(request.VMID) || request.Generation == 0 || request.UID <= 0 || request.GID <= 0 {
		return nil, errors.New("vmqual: invalid I/O fault identity")
	}
	if request.StateDir == "" || !filepath.IsAbs(request.StateDir) || filepath.Clean(request.StateDir) != request.StateDir {
		return nil, errors.New("vmqual: I/O fault state directory must be clean and absolute")
	}
	info, err := os.Lstat(request.SourcePath)
	if err != nil {
		return nil, fmt.Errorf("vmqual: inspect I/O fault source: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() <= 0 || info.Size()%512 != 0 {
		return nil, errors.New("vmqual: I/O fault source must be a positive 512-byte-aligned regular file")
	}
	name := "terrascale-vmqual-" + request.VMID + "-io-" + strconv.FormatUint(request.Generation, 10)
	path := filepath.Join("/dev/mapper", name)
	sectors := info.Size() / 512
	args := []string{"create", name, "--table", fmt.Sprintf("0 %d error", sectors), "--uid", strconv.Itoa(request.UID), "--gid", strconv.Itoa(request.GID), "--mode", "0600"}
	if err := a.cmd(ctx, a.dmPath, args...); err != nil {
		return nil, fmt.Errorf("vmqual: create bounded data-drive I/O fault: %w", err)
	}
	return &deviceMapperIOFault{dmPath: a.dmPath, name: name, path: path, bytes: info.Size(), run: true, cmd: a.cmd}, nil
}

func (a *deviceMapperIOFault) Path() string { return a.path }

func (a *deviceMapperIOFault) Cleanup(ctx context.Context) error {
	if a == nil || !a.run {
		return nil
	}
	if ctx == nil {
		return errors.New("vmqual: I/O fault cleanup context is nil")
	}
	if err := a.cmd(ctx, a.dmPath, "remove", "--retry", a.name); err != nil {
		return fmt.Errorf("vmqual: remove bounded data-drive I/O fault: %w", err)
	}
	a.run = false
	return nil
}

var _ sandboxvm.DataDriveFaultAttachment = (*deviceMapperIOFault)(nil)
var _ sandboxvm.DataDriveFaultAdapter = (*deviceMapperIOFault)(nil)
