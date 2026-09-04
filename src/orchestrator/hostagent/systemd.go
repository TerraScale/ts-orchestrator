// This file defines the systemd seams of the host agent: SystemdController
// is the interface the agent drives units through (the live spelling shells
// out to systemctl, tests inject a fake), and UserProvisioner creates the
// dedicated system account of a component. ts-node runs as root under the
// cloud-init system unit because writing system units and accounts is
// exactly its D-69 job; the components it launches run unprivileged.
package hostagent

import (
	"context"
	"fmt"
	"os/exec"
	"os/user"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// SystemdController is the real-systemd seam. Production uses
// SystemctlController; tests inject a recording fake, because the
// filesystem assertions in this package render and check unit FILES, never a
// live systemd.
type SystemdController interface {
	// DaemonReload reloads unit definitions.
	DaemonReload(ctx context.Context) error
	// EnableUnit enables one unit to start at boot.
	EnableUnit(ctx context.Context, unit string) error
	// DisableUnit removes one unit from boot start.
	DisableUnit(ctx context.Context, unit string) error
	// StartUnit starts one inactive unit.
	StartUnit(ctx context.Context, unit string) error
	// StopUnit stops one running unit gracefully.
	StopUnit(ctx context.Context, unit string) error
	// RestartUnit restarts one unit.
	RestartUnit(ctx context.Context, unit string) error
	// UnitActive reports whether one unit is active (running).
	UnitActive(ctx context.Context, unit string) (bool, error)
}

// SystemctlController drives the host systemd through systemctl.
type SystemctlController struct {
	// SystemctlBinary is the absolute path of systemctl.
	SystemctlBinary string
	// Timeout bounds every invocation.
	Timeout time.Duration
}

// NewSystemctlController validates the controller configuration.
func NewSystemctlController(systemctlBinary string, timeout time.Duration) (*SystemctlController, error) {
	if !strings.HasPrefix(systemctlBinary, "/") {
		return nil, &InvalidOperationError{Message: "The systemctl binary path must be absolute."}
	}
	if timeout <= 0 {
		return nil, &InvalidOperationError{Message: "The systemctl timeout must be positive."}
	}
	return &SystemctlController{SystemctlBinary: systemctlBinary, Timeout: timeout}, nil
}

func (c *SystemctlController) run(ctx context.Context, args ...string) error {
	command := exec.CommandContext(ctx, c.SystemctlBinary, args...)
	output, err := command.CombinedOutput()
	if err != nil {
		return fmt.Errorf("systemctl %s failed: %s: %s",
			strings.Join(args, " "), err.Error(), strings.TrimSpace(string(output)))
	}
	return nil
}

// DaemonReload reloads unit definitions.
func (c *SystemctlController) DaemonReload(ctx context.Context) error {
	return c.run(ctx, "daemon-reload")
}

// EnableUnit enables one unit to start at boot.
func (c *SystemctlController) EnableUnit(ctx context.Context, unit string) error {
	return c.run(ctx, "enable", unit)
}

// DisableUnit removes one unit from boot start.
func (c *SystemctlController) DisableUnit(ctx context.Context, unit string) error {
	return c.run(ctx, "disable", unit)
}

// StartUnit starts one inactive unit.
func (c *SystemctlController) StartUnit(ctx context.Context, unit string) error {
	return c.run(ctx, "start", unit)
}

// StopUnit stops one running unit gracefully.
func (c *SystemctlController) StopUnit(ctx context.Context, unit string) error {
	return c.run(ctx, "stop", unit)
}

// RestartUnit restarts one unit.
func (c *SystemctlController) RestartUnit(ctx context.Context, unit string) error {
	return c.run(ctx, "restart", unit)
}

// UnitActive reports whether one unit is active.
func (c *SystemctlController) UnitActive(ctx context.Context, unit string) (bool, error) {
	command := exec.CommandContext(ctx, c.SystemctlBinary, "is-active", "--quiet", unit)
	return command.Run() == nil, nil
}

// detachedCommand builds one command that survives its caller: it runs in
// its own process group, so the ts-node self-restart is not killed when the
// agent process it replaces exits.
func detachedCommand(_ context.Context, name string, args ...string) *exec.Cmd {
	command := exec.Command(name, args...)
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	return command
}

// UserProvisioner ensures the dedicated system account of a component
// exists and owns its data volume. Production uses UseraddProvisioner; tests
// inject a fake.
type UserProvisioner interface {
	// EnsureUser creates the system account when it is missing. It is
	// idempotent.
	EnsureUser(ctx context.Context, user string) error
	// OwnDirectory chowns one existing directory to the account so the
	// component's ReadWritePaths grant is usable.
	OwnDirectory(ctx context.Context, user, path string) error
}

// UseraddProvisioner creates system accounts through useradd and chowns
// data volumes to them.
type UseraddProvisioner struct {
	// UseraddBinary is the absolute path of useradd.
	UseraddBinary string
	// Timeout bounds every invocation.
	Timeout time.Duration
}

// EnsureUser creates the dedicated system account of one component: system
// account, no login shell, no home directory, matching group.
func (p UseraddProvisioner) EnsureUser(ctx context.Context, user string) error {
	if _, err := requireHostAgentName(user, "user",
		"The component user must be a canonical token."); err != nil {
		return err
	}
	command := exec.CommandContext(ctx, p.UseraddBinary,
		"--system", "--no-create-home", "--home-dir", "/nonexistent",
		"--shell", "/usr/sbin/nologin", "--user-group", user)
	output, err := command.CombinedOutput()
	if err != nil {
		// useradd exit code 9 is "username already in use", the idempotent
		// success path of this provisioner.
		if command.ProcessState != nil && command.ProcessState.ExitCode() == 9 {
			return nil
		}
		return fmt.Errorf("useradd %s failed: %s: %s",
			user, err.Error(), strings.TrimSpace(string(output)))
	}
	return nil
}

// OwnDirectory chowns one directory to the account.
func (p UseraddProvisioner) OwnDirectory(ctx context.Context, name, path string) error {
	account, err := user.Lookup(name)
	if err != nil {
		return fmt.Errorf("the account %s cannot be resolved: %w", name, err)
	}
	uid, err := strconv.Atoi(account.Uid)
	if err != nil {
		return err
	}
	gid, err := strconv.Atoi(account.Gid)
	if err != nil {
		return err
	}
	return unix.Chown(path, uid, gid)
}
