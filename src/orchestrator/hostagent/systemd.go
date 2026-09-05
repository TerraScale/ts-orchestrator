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
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"strings"
	"syscall"
	"terrascale.tech/orchestrator/src/orchestrator/hostmanifest"
	"time"

	"golang.org/x/sys/unix"
)

// SystemdController is the real-systemd seam. Production uses
// hostplatform.SystemctlController; tests inject a recording fake, because the
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
	if _, err := hostmanifest.RequireName(user, "user",
		"The component user must be a canonical token."); err != nil {
		return err
	}
	if user == hostmanifest.RootAccountName || user == hostmanifest.TsNodeComponentName {
		return &InvalidOperationError{Message: "The component account must be dedicated and unprivileged."}
	}
	operationContext, cancel, err := p.invocationContext(ctx)
	if err != nil {
		return err
	}
	defer cancel()
	command := exec.CommandContext(operationContext, p.UseraddBinary,
		"--system", "--no-create-home", "--home-dir", "/nonexistent",
		"--shell", "/usr/sbin/nologin", "--user-group", "--no-log-init", user)
	output, err := command.CombinedOutput()
	if err != nil {
		if contextError := operationContext.Err(); contextError != nil {
			return fmt.Errorf("useradd %s failed: %w", user, contextError)
		}
		// useradd exit code 9 is "username already in use", the idempotent
		// path only when the existing account is the same dedicated system
		// identity this provisioner would have created.
		if command.ProcessState != nil && command.ProcessState.ExitCode() == 9 {
			return validateExistingComponentUser(user)
		}
		return fmt.Errorf("useradd %s failed: %s: %s",
			user, err.Error(), strings.TrimSpace(string(output)))
	}
	return nil
}

// OwnDirectory chowns one directory to the account.
func (p UseraddProvisioner) OwnDirectory(ctx context.Context, name, path string) error {
	operationContext, cancel, err := p.invocationContext(ctx)
	if err != nil {
		return err
	}
	defer cancel()
	if err := operationContext.Err(); err != nil {
		return err
	}
	if !hostmanifest.SafeAbsolutePath(path) {
		return &InvalidOperationError{Message: "The owned directory must be an absolute safe path."}
	}
	if _, err := hostmanifest.RequireName(name, "name", "The component user must be a canonical token."); err != nil {
		return err
	}
	if name == hostmanifest.RootAccountName || name == hostmanifest.TsNodeComponentName {
		return &InvalidOperationError{Message: "The component account must be dedicated and unprivileged."}
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return &InvalidOperationError{Message: "The owned path must be a real directory."}
	}
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

func validateExistingComponentUser(name string) error {
	account, err := user.Lookup(name)
	if err != nil {
		return fmt.Errorf("the existing account %s cannot be resolved: %w", name, err)
	}
	group, err := user.LookupGroup(name)
	if err != nil {
		return fmt.Errorf("the existing group %s cannot be resolved: %w", name, err)
	}
	uid, uidErr := strconv.Atoi(account.Uid)
	gid, gidErr := strconv.Atoi(account.Gid)
	groupGid, groupErr := strconv.Atoi(group.Gid)
	if uidErr != nil || gidErr != nil || groupErr != nil || uid == 0 || gid == 0 || gid != groupGid || account.HomeDir != "/nonexistent" {
		return &InvalidOperationError{Message: fmt.Sprintf("The existing account %s is not the dedicated system identity ts-node requires.", name)}
	}
	passwd, err := readRegularFileBounded("/etc/passwd", 4<<20)
	if err != nil {
		return fmt.Errorf("the local account database cannot be read: %w", err)
	}
	matches := 0
	for _, line := range strings.Split(string(passwd), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) != 7 || fields[0] != name {
			continue
		}
		matches++
		if fields[2] != account.Uid || fields[3] != account.Gid ||
			fields[5] != "/nonexistent" || fields[6] != "/usr/sbin/nologin" {
			return &InvalidOperationError{Message: fmt.Sprintf("The existing account %s is not the dedicated system identity ts-node requires.", name)}
		}
	}
	if matches != 1 {
		return &InvalidOperationError{Message: fmt.Sprintf("The existing account %s must be one local nologin identity.", name)}
	}
	return nil
}

func (p UseraddProvisioner) invocationContext(ctx context.Context) (context.Context, context.CancelFunc, error) {
	if ctx == nil {
		return nil, nil, &InvalidOperationError{Message: "The user provisioner context is required."}
	}
	if !hostmanifest.SafeAbsolutePath(p.UseraddBinary) {
		return nil, nil, &InvalidOperationError{Message: "The useradd binary path must be absolute and safe."}
	}
	if p.Timeout <= 0 {
		return nil, nil, &InvalidOperationError{Message: "The useradd timeout must be positive."}
	}
	operationContext, cancel := context.WithTimeout(ctx, p.Timeout)
	return operationContext, cancel, nil
}
