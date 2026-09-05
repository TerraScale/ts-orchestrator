package hostplatform

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"terrascale.tech/orchestrator/src/orchestrator/hostmanifest"
	"time"
)

// SystemctlController drives the host systemd through systemctl.
type SystemctlController struct {
	// SystemctlBinary is the absolute path of systemctl.
	SystemctlBinary string
	// Timeout bounds every invocation.
	Timeout time.Duration
}

// NewSystemctlController validates the controller configuration.
func NewSystemctlController(systemctlBinary string, timeout time.Duration) (*SystemctlController, error) {
	if !hostmanifest.SafeAbsolutePath(systemctlBinary) {
		return nil, &InvalidOperationError{Message: "The systemctl binary path must be absolute and safe."}
	}
	if timeout <= 0 {
		return nil, &InvalidOperationError{Message: "The systemctl timeout must be positive."}
	}
	return &SystemctlController{SystemctlBinary: systemctlBinary, Timeout: timeout}, nil
}

// invocationContext validates the controller and gives one systemctl
// invocation its own deadline. A child context preserves cancellation of the
// caller while also bounding a command that does not return on its own.
func (c *SystemctlController) invocationContext(ctx context.Context) (context.Context, context.CancelFunc, error) {
	if c == nil {
		return nil, nil, &InvalidOperationError{Message: "The systemctl controller is required."}
	}
	if c.Timeout <= 0 {
		return nil, nil, &InvalidOperationError{Message: "The systemctl timeout must be positive."}
	}
	if ctx == nil {
		return nil, nil, &InvalidOperationError{Message: "The systemctl context is required."}
	}
	operationContext, cancel := context.WithTimeout(ctx, c.Timeout)
	return operationContext, cancel, nil
}

func (c *SystemctlController) runOutput(ctx context.Context, args ...string) ([]byte, error) {
	operationContext, cancel, err := c.invocationContext(ctx)
	if err != nil {
		return nil, err
	}
	defer cancel()

	command := exec.CommandContext(operationContext, c.SystemctlBinary, args...)
	output, err := command.CombinedOutput()
	if err == nil {
		return output, nil
	}
	// CommandContext kills the process when the context is canceled. Return the
	// context error itself (wrapped for operation details), since the process
	// exit error does not identify whether the caller canceled or our deadline
	// fired.
	if contextError := operationContext.Err(); contextError != nil {
		return output, fmt.Errorf("systemctl %s failed: %w", strings.Join(args, " "), contextError)
	}
	return output, fmt.Errorf("systemctl %s failed: %w: %s",
		strings.Join(args, " "), err, strings.TrimSpace(string(output)))
}

func (c *SystemctlController) run(ctx context.Context, args ...string) error {
	_, err := c.runOutput(ctx, args...)
	return err
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
	_, err := c.runOutput(ctx, "is-active", "--quiet", unit)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false, err
	}
	// systemctl uses exit status 3 for a known inactive unit. That is a
	// reliable negative answer; every other failure means the state could not
	// be established and must not be treated as safely stopped.
	var exitError *exec.ExitError
	if errors.As(err, &exitError) && exitError.ExitCode() == 3 {
		return false, nil
	}
	return false, err
}
