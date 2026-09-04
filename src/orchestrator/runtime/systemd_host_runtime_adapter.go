package runtime

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/errs"
)

// HostCommandResult is one captured host command execution.
type HostCommandResult struct {
	ExitCode       int
	StandardOutput string
	StandardError  string
}

// HostCommandRunner ports the internal IHostCommandRunner seam.
type HostCommandRunner interface {
	Run(ctx context.Context, executable string, arguments []string) (HostCommandResult, error)
}

// ProcessHostCommandRunner runs host commands via argument lists (never a
// shell) and bounds captured output.
type ProcessHostCommandRunner struct{}

const hostCommandMaximumCapturedCharacters = 64 * 1024

// boundedOutputWriter keeps the host command's output bounded while the
// process is running. Four bytes per character covers UTF-8's maximum encoded
// width; the final character bound is applied when the result is converted to
// a string.
type boundedOutputWriter struct {
	buffer bytes.Buffer
	limit  int
}

func (w *boundedOutputWriter) Write(value []byte) (int, error) {
	originalLength := len(value)
	if w.buffer.Len() < w.limit {
		remaining := w.limit - w.buffer.Len()
		if len(value) > remaining {
			value = value[:remaining]
		}
		_, _ = w.buffer.Write(value)
	}

	// Always report the complete input as consumed. Dropping excess diagnostic
	// output must not turn an otherwise successful host command into an I/O
	// failure.
	return originalLength, nil
}

func (w *boundedOutputWriter) String() string { return w.buffer.String() }

// Run executes one host command and captures its bounded output.
func (ProcessHostCommandRunner) Run(ctx context.Context, executable string, arguments []string) (HostCommandResult, error) {
	if ctx == nil {
		return HostCommandResult{}, errors.New("host command context must not be nil")
	}

	command := exec.CommandContext(ctx, executable, arguments...)
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	// Mirror ProcessLifecycle.WaitForExitAsync: cancellation kills the whole
	// process tree, then the wait result surfaces the cancellation.
	command.Cancel = func() error {
		if command.Process != nil {
			// A negative PID addresses the process group created by Setpgid,
			// including descendants spawned by the host command.
			_ = syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
		}
		return nil
	}
	command.WaitDelay = 2 * time.Second
	var stdout, stderr boundedOutputWriter
	stdout.limit = hostCommandMaximumCapturedCharacters * 4
	stderr.limit = hostCommandMaximumCapturedCharacters * 4
	command.Stdout = &stdout
	command.Stderr = &stderr
	runErr := command.Run()
	if ctx.Err() != nil {
		return HostCommandResult{}, ctx.Err()
	}
	if runErr != nil {
		var exitError *exec.ExitError
		if !errors.As(runErr, &exitError) || command.ProcessState == nil {
			// Start failures (for example, an absent executable) do not create a
			// ProcessState. Return the error before attempting to inspect it.
			return HostCommandResult{}, runErr
		}
	}
	if command.ProcessState == nil {
		return HostCommandResult{}, errors.New("host command exited without process state")
	}
	result := HostCommandResult{
		ExitCode:       command.ProcessState.ExitCode(),
		StandardOutput: boundCapturedCharacters(stdout.String()),
		StandardError:  boundCapturedCharacters(stderr.String()),
	}
	return result, nil
}

func boundCapturedCharacters(value string) string {
	runes := []rune(value)
	if len(runes) <= hostCommandMaximumCapturedCharacters {
		return value
	}
	return string(runes[:hostCommandMaximumCapturedCharacters])
}

// SystemdAllocationState is the observed systemd unit state.
type SystemdAllocationState int

const (
	SystemdAllocationStateAbsent SystemdAllocationState = iota
	SystemdAllocationStateStarting
	SystemdAllocationStateRunning
	SystemdAllocationStateStopping
	SystemdAllocationStateStopped
	SystemdAllocationStateFailed
)

func (s SystemdAllocationState) String() string {
	names := [...]string{"Absent", "Starting", "Running", "Stopping", "Stopped", "Failed"}
	if s >= 0 && int(s) < len(names) {
		return names[s]
	}
	return fmt.Sprintf("SystemdAllocationState(%d)", int(s))
}

// SystemdAllocationObservation is one fenced systemd unit observation.
type SystemdAllocationObservation struct {
	UnitName      string
	State         SystemdAllocationState
	MainProcessId *int
	Result        string
}

// SystemdHostRuntimeAdapter converges canonical native systemd plans using
// fixed systemctl/systemd-run paths.
type SystemdHostRuntimeAdapter struct {
	commandRunner HostCommandRunner
	userManager   bool
}

// NewSystemdHostRuntimeAdapter composes the adapter with its runner.
func NewSystemdHostRuntimeAdapter(commandRunner HostCommandRunner, userManager bool) *SystemdHostRuntimeAdapter {
	return &SystemdHostRuntimeAdapter{commandRunner: commandRunner, userManager: userManager}
}

// Converge brings the unit to the running state.
func (a *SystemdHostRuntimeAdapter) Converge(ctx context.Context, plan HostRuntimePlan) error {
	if ctx == nil {
		return &errs.Argument{Param: "ctx", Message: "The systemd context must not be nil."}
	}
	if a == nil || a.commandRunner == nil {
		return &InvalidOperationError{Message: "The systemd command runner is unavailable."}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	systemd, err := requireCanonicalSystemdPlan(plan)
	if err != nil {
		return err
	}
	observation, err := a.Observe(ctx, plan)
	if err != nil {
		return err
	}
	if observation.State == SystemdAllocationStateRunning || observation.State == SystemdAllocationStateStarting {
		return nil
	}
	if observation.State != SystemdAllocationStateAbsent {
		start, err := a.commandRunner.Run(ctx, "/usr/bin/systemctl",
			a.managerArguments("start", systemd.UnitName))
		if err != nil {
			return err
		}
		if start.ExitCode != 0 {
			return &InvalidOperationError{
				Message: fmt.Sprintf("systemd could not start allocation %s; exit code %d.",
					plan.AllocationId, start.ExitCode),
			}
		}
		return nil
	}

	arguments := make([]string, 0, 12+len(systemd.Properties)*2)
	if a.userManager {
		arguments = append(arguments, "--user")
	}
	arguments = append(arguments,
		"--unit", systemd.UnitName,
		"--collect",
		"--property", "Description="+systemdPlanDescription(plan))
	for _, property := range systemd.Properties {
		arguments = append(arguments, "--property", property)
	}
	arguments = append(arguments, "--", systemd.Executable)
	arguments = append(arguments, systemd.Arguments...)
	result, err := a.commandRunner.Run(ctx, "/usr/bin/systemd-run", arguments)
	if err != nil {
		return err
	}
	if result.ExitCode != 0 {
		return &InvalidOperationError{
			Message: fmt.Sprintf("systemd refused allocation %s with exit code %d.",
				plan.AllocationId, result.ExitCode),
		}
	}
	return nil
}

// Observe parses one fenced systemctl show observation.
func (a *SystemdHostRuntimeAdapter) Observe(ctx context.Context, plan HostRuntimePlan) (SystemdAllocationObservation, error) {
	if ctx == nil {
		return SystemdAllocationObservation{}, &errs.Argument{Param: "ctx", Message: "The systemd context must not be nil."}
	}
	if a == nil || a.commandRunner == nil {
		return SystemdAllocationObservation{}, &InvalidOperationError{Message: "The systemd command runner is unavailable."}
	}
	if err := ctx.Err(); err != nil {
		return SystemdAllocationObservation{}, err
	}
	systemd, err := requireCanonicalSystemdPlan(plan)
	if err != nil {
		return SystemdAllocationObservation{}, err
	}
	result, err := a.commandRunner.Run(ctx, "/usr/bin/systemctl", a.managerArguments(
		"show",
		systemd.UnitName,
		"--property=LoadState",
		"--property=ActiveState",
		"--property=SubState",
		"--property=MainPID",
		"--property=Result",
		"--property=Description"))
	if err != nil {
		return SystemdAllocationObservation{}, err
	}
	values := make(map[string]string)
	for _, line := range strings.Split(result.StandardOutput, "\n") {
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			values[parts[0]] = parts[1]
		}
	}
	if values["LoadState"] == "not-found" {
		return SystemdAllocationObservation{
			UnitName: systemd.UnitName,
			State:    SystemdAllocationStateAbsent,
			Result:   "not-found",
		}, nil
	}
	if result.ExitCode != 0 {
		return SystemdAllocationObservation{}, &InvalidOperationError{
			Message: fmt.Sprintf("systemd could not inspect allocation %s; exit code %d.",
				plan.AllocationId, result.ExitCode),
		}
	}
	if values["LoadState"] != "loaded" || values["Description"] != systemdPlanDescription(plan) {
		return SystemdAllocationObservation{}, &InvalidOperationError{
			Message: fmt.Sprintf("Existing systemd allocation '%s' is not owned by the canonical plan.",
				systemd.UnitName),
		}
	}
	var state SystemdAllocationState
	switch values["ActiveState"] {
	case "active":
		state = SystemdAllocationStateRunning
	case "activating", "reloading":
		state = SystemdAllocationStateStarting
	case "deactivating":
		state = SystemdAllocationStateStopping
	case "inactive":
		state = SystemdAllocationStateStopped
	case "failed":
		state = SystemdAllocationStateFailed
	default:
		return SystemdAllocationObservation{}, &InvalidOperationError{
			Message: fmt.Sprintf("systemd returned an unknown state for allocation %s.",
				plan.AllocationId),
		}
	}
	var pid *int
	if parsedPid, parseErr := strconv.Atoi(values["MainPID"]); parseErr == nil && parsedPid > 0 {
		pid = &parsedPid
	}
	observedResult := "unknown"
	if value, present := values["Result"]; present {
		observedResult = value
	}
	return SystemdAllocationObservation{
		UnitName:      systemd.UnitName,
		State:         state,
		MainProcessId: pid,
		Result:        observedResult,
	}, nil
}

// Stop stops a running unit.
func (a *SystemdHostRuntimeAdapter) Stop(ctx context.Context, plan HostRuntimePlan) error {
	if ctx == nil {
		return &errs.Argument{Param: "ctx", Message: "The systemd context must not be nil."}
	}
	if a == nil || a.commandRunner == nil {
		return &InvalidOperationError{Message: "The systemd command runner is unavailable."}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	systemd, err := requireCanonicalSystemdPlan(plan)
	if err != nil {
		return err
	}
	observation, err := a.Observe(ctx, plan)
	if err != nil {
		return err
	}
	switch observation.State {
	case SystemdAllocationStateAbsent, SystemdAllocationStateStopped,
		SystemdAllocationStateFailed, SystemdAllocationStateStopping:
		return nil
	}
	result, err := a.commandRunner.Run(ctx, "/usr/bin/systemctl",
		a.managerArguments("stop", systemd.UnitName))
	if err != nil {
		return err
	}
	if result.ExitCode != 0 {
		return &InvalidOperationError{
			Message: fmt.Sprintf("systemd could not stop allocation %s; exit code %d.",
				plan.AllocationId, result.ExitCode),
		}
	}
	return nil
}

func systemdPlanDescription(plan HostRuntimePlan) string {
	fingerprint, _ := CanonicalPlanFingerprint.Compute(plan)
	return fmt.Sprintf("TerraScale allocation %s plan %s", plan.AllocationId, fingerprint)
}

func (a *SystemdHostRuntimeAdapter) managerArguments(arguments ...string) []string {
	if !a.userManager {
		return arguments
	}
	withUser := make([]string, 0, len(arguments)+1)
	withUser = append(withUser, "--user")
	return append(withUser, arguments...)
}

func requireCanonicalSystemdPlan(plan HostRuntimePlan) (*SystemdExecutionPlan, error) {
	if plan.Driver != RuntimeDriverNativeSystemd || plan.Systemd == nil {
		return nil, &errs.Argument{
			Param:   "plan",
			Message: "The systemd adapter requires a native systemd plan.",
		}
	}
	expected, err := NewHostRuntimePlan(
		plan.Role,
		plan.Driver,
		plan.AllocationId,
		plan.ArtifactDigest,
		plan.Architecture,
		&plan.Resources)
	if err != nil {
		return nil, err
	}
	expectedSystemd := expected.Systemd
	if expectedSystemd == nil {
		return nil, &InvalidOperationError{
			Message: "The systemd execution plan could not be reconstructed from the admitted role.",
		}
	}
	systemd := plan.Systemd
	if !canonicalPlanFieldsMatch(plan, expected) ||
		systemd.UnitName != expectedSystemd.UnitName ||
		systemd.Executable != expectedSystemd.Executable ||
		!stringSlicesEqual(systemd.Arguments, expectedSystemd.Arguments) ||
		!stringSlicesEqual(systemd.Properties, expectedSystemd.Properties) ||
		plan.Resources != expected.Resources {
		return nil, &InvalidOperationError{
			Message: "The systemd execution plan is not canonical for the admitted role.",
		}
	}
	return systemd, nil
}
