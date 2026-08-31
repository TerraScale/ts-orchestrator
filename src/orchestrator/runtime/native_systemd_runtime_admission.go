// This file ports Runtime/NativeSystemdRuntimeAdmission.cs.
package runtime

import (
	"context"
	"os"
	"strings"

	goruntime "runtime"

	"terrascale.tech/orchestrator/src/orchestrator/errs"
)

func isLinuxHost() bool { return goruntime.GOOS == "linux" }

// SystemdHostProbeResult is the read-only evidence collected from the host
// before a native systemd executor is constructed. A host is admitted only when
// every value is true.
type SystemdHostProbeResult struct {
	IsLinux       bool
	IsSystemdPid1 bool
	HasCgroupV2   bool
	HasSystemctl  bool
	HasSystemdRun bool
}

// IsAdmitted reports whether every admission evidence bit is set.
func (p SystemdHostProbeResult) IsAdmitted() bool {
	return p.IsLinux && p.IsSystemdPid1 && p.HasCgroupV2 && p.HasSystemctl && p.HasSystemdRun
}

// SystemdHostProbe ports the internal ISystemdHostProbe seam.
type SystemdHostProbe interface {
	Probe() SystemdHostProbeResult
}

// Fixed admission paths probed by the production Linux probe.
const (
	LinuxSystemdHostProbeSystemdPid1CommPath     = "/proc/1/comm"
	LinuxSystemdHostProbeCgroupV2ControllersPath = "/sys/fs/cgroup/cgroup.controllers"
	LinuxSystemdHostProbeSystemctlPath           = "/usr/bin/systemctl"
	LinuxSystemdHostProbeSystemdRunPath          = "/usr/bin/systemd-run"
)

// LinuxSystemdHostProbe is the production host probe. It reads kernel/proc
// filesystem state and fixed binary paths only; it never invokes a shell,
// systemctl, systemd-run, or another process.
type LinuxSystemdHostProbe struct{}

// Probe collects the read-only host admission evidence.
func (LinuxSystemdHostProbe) Probe() SystemdHostProbeResult {
	if !isLinuxHost() {
		return SystemdHostProbeResult{}
	}
	return SystemdHostProbeResult{
		IsLinux:       true,
		IsSystemdPid1: linuxSystemdHostProbeReadSystemdPid1(),
		HasCgroupV2:   linuxSystemdHostProbeIsReadableRegularFile(LinuxSystemdHostProbeCgroupV2ControllersPath),
		HasSystemctl:  linuxSystemdHostProbeIsExecutableRegularFile(LinuxSystemdHostProbeSystemctlPath),
		HasSystemdRun: linuxSystemdHostProbeIsExecutableRegularFile(LinuxSystemdHostProbeSystemdRunPath),
	}
}

func linuxSystemdHostProbeReadSystemdPid1() bool {
	content, err := os.ReadFile(LinuxSystemdHostProbeSystemdPid1CommPath)
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(content)) == "systemd"
}

func linuxSystemdHostProbeIsReadableRegularFile(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return info.Mode().IsRegular()
}

func linuxSystemdHostProbeIsExecutableRegularFile(path string) bool {
	if !linuxSystemdHostProbeIsReadableRegularFile(path) {
		return false
	}
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return info.Mode().Perm()&0o111 != 0
}

// NativeSystemdRuntimeAdmission is the fail-closed native-systemd admission
// and adapter-composition primitive.
//
// This primitive is intentionally not wired to Program or to a production
// lifecycle coordinator. A future coordinator must supply a plan that has
// already passed the persisted RuntimeDecisionEngine and operation-authorization
// workflow. This boundary performs only host/runtime admission and
// canonical-plan fencing; it does not authorize operations, provide
// operation-journal/idempotency/recovery semantics, parse CLI input, or expose
// a production mutation route on its own.
type NativeSystemdRuntimeAdmission struct {
	plan    HostRuntimePlan
	adapter *SystemdHostRuntimeAdapter
}

// NewNativeSystemdRuntimeAdmission admits a canonical native-systemd plan with
// the production probe; no current production lifecycle path calls it.
func NewNativeSystemdRuntimeAdmission(plan HostRuntimePlan) (*NativeSystemdRuntimeAdmission, error) {
	return NewNativeSystemdRuntimeAdmissionWithRunner(plan, LinuxSystemdHostProbe{}, nil)
}

// NewNativeSystemdRuntimeAdmissionWithRunner is the injectable
// admission/composition seam for deterministic and zero-execution tests.
func NewNativeSystemdRuntimeAdmissionWithRunner(
	plan HostRuntimePlan,
	hostProbe SystemdHostProbe,
	commandRunner HostCommandRunner,
) (*NativeSystemdRuntimeAdmission, error) {
	canonicalPlan, err := requireCanonicalNativePlan(plan)
	if err != nil {
		return nil, err
	}
	if hostProbe == nil {
		return nil, &errs.Argument{Param: "hostProbe"}
	}

	var probeFailed bool
	hostEvidence := func() SystemdHostProbeResult {
		var evidence SystemdHostProbeResult
		func() {
			// The C# seam wraps any probe failure as a host-admission failure.
			defer func() {
				if recovered := recover(); recovered != nil {
					probeFailed = true
				}
			}()
			evidence = hostProbe.Probe()
		}()
		return evidence
	}()
	if probeFailed {
		return nil, &InvalidOperationError{
			Message: "Native systemd host admission could not be established.",
		}
	}
	if !hostEvidence.IsAdmitted() {
		return nil, &InvalidOperationError{
			Message: "Native systemd host admission requires Linux, systemd as PID 1, cgroup v2, " +
				"and executable /usr/bin/systemctl and /usr/bin/systemd-run.",
		}
	}

	// Keep executor construction after both read-only host admission and the
	// complete plan fence. This adapter remains unwired until a persisted
	// authorized runtime coordinator owns the operation boundary.
	if commandRunner == nil {
		commandRunner = ProcessHostCommandRunner{}
	}
	runtimeAdapter := NewSystemdHostRuntimeAdapter(commandRunner, false)
	return &NativeSystemdRuntimeAdmission{plan: canonicalPlan, adapter: runtimeAdapter}, nil
}

// Plan returns the immutable canonical snapshot admitted at composition time.
func (a *NativeSystemdRuntimeAdmission) Plan() HostRuntimePlan { return a.plan }

// Converge converges the admitted plan.
func (a *NativeSystemdRuntimeAdmission) Converge(ctx context.Context) error {
	return a.adapter.Converge(ctx, a.plan)
}

// Observe observes the admitted plan.
func (a *NativeSystemdRuntimeAdmission) Observe(ctx context.Context) (SystemdAllocationObservation, error) {
	return a.adapter.Observe(ctx, a.plan)
}

// Stop stops the admitted plan.
func (a *NativeSystemdRuntimeAdmission) Stop(ctx context.Context) error {
	return a.adapter.Stop(ctx, a.plan)
}

func requireCanonicalNativePlan(candidate HostRuntimePlan) (HostRuntimePlan, error) {
	if candidate.SchemaVersion != 2 {
		return HostRuntimePlan{}, &InvalidOperationError{
			Message: "The host runtime plan schema is not supported.",
		}
	}
	if !candidate.Role.defined() {
		return HostRuntimePlan{}, &InvalidOperationError{
			Message: "The host runtime plan role is not admitted.",
		}
	}
	if !candidate.Driver.defined() || candidate.Driver != RuntimeDriverNativeSystemd {
		return HostRuntimePlan{}, &InvalidOperationError{
			Message: "Native systemd admission requires a native systemd plan.",
		}
	}
	if !candidate.Architecture.defined() {
		return HostRuntimePlan{}, &InvalidOperationError{
			Message: "The host runtime plan architecture is not admitted.",
		}
	}
	if candidate.Systemd == nil || candidate.Oci != nil {
		return HostRuntimePlan{}, &InvalidOperationError{
			Message: "The host runtime plan is incomplete.",
		}
	}

	// This closes the role boundary before any executor exists. In particular,
	// OCI-only roles cannot be converted to a native plan by a caller changing
	// only the driver or nested execution object.
	if _, err := AdmittedRoleCatalog.Admit(candidate.Role, RuntimeDriverNativeSystemd); err != nil {
		return HostRuntimePlan{}, err
	}

	resources := candidate.Resources
	expected, err := NewHostRuntimePlan(
		candidate.Role,
		RuntimeDriverNativeSystemd,
		candidate.AllocationId,
		candidate.ArtifactDigest,
		candidate.Architecture,
		&resources)
	if err != nil {
		return HostRuntimePlan{}, &InvalidOperationError{
			Message: "The host runtime plan could not be reconstructed from the closed catalog.",
		}
	}

	actualSystemd := candidate.Systemd
	expectedSystemd := expected.Systemd
	if actualSystemd == nil || expectedSystemd == nil {
		return HostRuntimePlan{}, &InvalidOperationError{
			Message: "The systemd execution plan is incomplete.",
		}
	}
	if candidate.SchemaVersion != expected.SchemaVersion ||
		candidate.Role != expected.Role ||
		candidate.Driver != expected.Driver ||
		candidate.AllocationId.Value != expected.AllocationId.Value ||
		candidate.ArtifactDigest.Value != expected.ArtifactDigest.Value ||
		candidate.Architecture != expected.Architecture ||
		candidate.Resources != expected.Resources ||
		actualSystemd.UnitName != expectedSystemd.UnitName ||
		actualSystemd.Executable != expectedSystemd.Executable ||
		!stringSlicesEqual(actualSystemd.Arguments, expectedSystemd.Arguments) ||
		!stringSlicesEqual(actualSystemd.Properties, expectedSystemd.Properties) {
		return HostRuntimePlan{}, &InvalidOperationError{
			Message: "The systemd execution plan is not canonical for the admitted role, allocation, or digest.",
		}
	}

	return expected, nil
}
