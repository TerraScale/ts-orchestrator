// Port of src/TerraScale.Orchestrator/ControlPlane/Runtime/NativeSystemdRuntimeLifecycleExecutor.cs
package control

import (
	"context"
	"strconv"
	"strings"

	"terrascale.tech/orchestrator/src/orchestrator/runtime"
)

// INativeSystemdRuntimeLifecycleAdmission is the narrow test seam around the
// already fail-closed native-systemd admission boundary. Production
// construction retains its Linux/PID-1/cgroup-v2/fixed-binary checks.
type INativeSystemdRuntimeLifecycleAdmission interface {
	ConvergeAsync(ctx context.Context) error
	ObserveAsync(ctx context.Context) (runtime.SystemdAllocationObservation, error)
	StopAsync(ctx context.Context) error
}

type INativeSystemdRuntimeLifecycleAdmissionFactory interface {
	Admit(plan HostRuntimePlan) (INativeSystemdRuntimeLifecycleAdmission, error)
}

type NativeSystemdRuntimeLifecycleAdmissionFactory struct{}

func (NativeSystemdRuntimeLifecycleAdmissionFactory) Admit(
	plan HostRuntimePlan) (INativeSystemdRuntimeLifecycleAdmission, error) {
	admission, err := runtime.NewNativeSystemdRuntimeAdmission(plan)
	if err != nil {
		return nil, err
	}
	return &NativeSystemdRuntimeLifecycleAdmissionAdapter{admission: admission}, nil
}

type NativeSystemdRuntimeLifecycleAdmissionAdapter struct {
	admission *runtime.NativeSystemdRuntimeAdmission
}

func (a *NativeSystemdRuntimeLifecycleAdmissionAdapter) ConvergeAsync(ctx context.Context) error {
	return a.admission.Converge(ctx)
}

func (a *NativeSystemdRuntimeLifecycleAdmissionAdapter) ObserveAsync(
	ctx context.Context) (runtime.SystemdAllocationObservation, error) {
	return a.admission.Observe(ctx)
}

func (a *NativeSystemdRuntimeLifecycleAdmissionAdapter) StopAsync(ctx context.Context) error {
	return a.admission.Stop(ctx)
}

// NativeSystemdRuntimeLifecycleExecutor is the native-systemd implementation
// of the persisted lifecycle executor contract. It performs exactly one
// admitted host action per durable dispatch and always leaves completion to a
// separate, read-only observation; it is intentionally not composed into a
// production lifecycle route yet.
type NativeSystemdRuntimeLifecycleExecutor struct {
	admissionFactory INativeSystemdRuntimeLifecycleAdmissionFactory
}

func NewNativeSystemdRuntimeLifecycleExecutor() *NativeSystemdRuntimeLifecycleExecutor {
	return &NativeSystemdRuntimeLifecycleExecutor{admissionFactory: NativeSystemdRuntimeLifecycleAdmissionFactory{}}
}

func NewNativeSystemdRuntimeLifecycleExecutorWithFactory(
	admissionFactory INativeSystemdRuntimeLifecycleAdmissionFactory) (*NativeSystemdRuntimeLifecycleExecutor, error) {
	if admissionFactory == nil {
		return nil, argumentNil("admissionFactory")
	}
	return &NativeSystemdRuntimeLifecycleExecutor{admissionFactory: admissionFactory}, nil
}

func (e *NativeSystemdRuntimeLifecycleExecutor) ExecuteAsync(ctx context.Context,
	request RuntimeLifecycleExecutionRequest) (*RuntimeLifecycleExecutorResponse, error) {
	if err := nativeSystemdLifecycleValidate(request.Plan, request.Action,
		request.PlanFingerprintForValidation()); err != nil {
		return nil, err
	}
	admission, err := e.admissionFactory.Admit(request.Plan)
	if err != nil {
		return nil, err
	}
	switch request.Action {
	case LifecycleActionConverge:
		if err := admission.ConvergeAsync(ctx); err != nil {
			return nil, err
		}
	case LifecycleActionDrain, LifecycleActionStop:
		if err := admission.StopAsync(ctx); err != nil {
			return nil, err
		}
	default:
		return nil, argumentOutOfRangeError("request",
			"The lifecycle action is not supported by native systemd.")
	}

	// A completed systemd command is not convergence evidence. The coordinator
	// must persist and invoke ObserveAsync before reporting a terminal outcome.
	return &RuntimeLifecycleExecutorResponse{Status: RuntimeLifecycleExecutorStatusCompleted}, nil
}

func (e *NativeSystemdRuntimeLifecycleExecutor) ObserveAsync(ctx context.Context,
	request RuntimeLifecycleObservationRequest) (*RuntimeLifecycleObservation, error) {
	if err := nativeSystemdLifecycleValidate(request.Plan, request.Action, request.PlanFingerprint); err != nil {
		return nil, err
	}
	if request.PreviousObservationWatermark == ^uint64(0) {
		return nil, argumentOutOfRange("request")
	}
	watermark := request.PreviousObservationWatermark + 1

	var state *runtime.SystemdAllocationState
	var status RuntimeLifecycleObservationStatus
	admission, err := e.admissionFactory.Admit(request.Plan)
	if err != nil {
		status = RuntimeLifecycleObservationStatusUnknown
	} else {
		observation, observeErr := admission.ObserveAsync(ctx)
		if observeErr != nil {
			if isContextCancellation(ctx, observeErr) {
				return nil, observeErr
			}
			// Admission and ownership/adapter failures have no safe positive
			// claim. Deliberately avoid carrying exception or host material
			// into the durable observation contract.
			status = RuntimeLifecycleObservationStatusUnknown
		} else {
			stateValue := observation.State
			state = &stateValue
			status = nativeSystemdMapObservation(request.Action, observation.State)
		}
	}

	fingerprint, err := NewRuntimeLifecycleHostObservationFingerprint(
		nativeSystemdObservationFingerprint(request, status, state))
	if err != nil {
		return nil, err
	}
	return &RuntimeLifecycleObservation{
		OperationKey:    request.OperationKey,
		AllocationId:    request.Plan.AllocationId.Value,
		PlanFingerprint: request.PlanFingerprint,
		Action:          request.Action,
		Fingerprint:     fingerprint,
		Watermark:       watermark,
		Status:          status,
	}, nil
}

// PlanFingerprintForValidation binds an execution request to its plan
// fingerprint the way the C# property chain did.
func (r RuntimeLifecycleExecutionRequest) PlanFingerprintForValidation() RuntimeLifecyclePlanFingerprint {
	fingerprint, err := RuntimeLifecycleFingerprint.Plan(r.Plan)
	if err != nil {
		return RuntimeLifecyclePlanFingerprint{}
	}
	return fingerprint
}

func nativeSystemdLifecycleValidate(plan HostRuntimePlan, action LifecycleAction,
	expectedPlanFingerprint RuntimeLifecyclePlanFingerprint) error {
	if expectedPlanFingerprint.Value == "" {
		return argumentNil("expectedPlanFingerprint")
	}
	if !lifecycleActionIsDefined(action) || action == LifecycleActionCleanup {
		return argumentOutOfRangeError("action",
			"Destructive cleanup is not supported by native systemd lifecycle execution.")
	}
	if plan.Driver != runtime.RuntimeDriverNativeSystemd {
		return invalidArgument("Native systemd lifecycle execution requires a native systemd plan.")
	}
	fingerprint, err := RuntimeLifecycleFingerprint.Plan(plan)
	if err != nil {
		return err
	}
	if fingerprint != expectedPlanFingerprint {
		return invalidOperation("The lifecycle request plan fingerprint does not bind the supplied plan.")
	}
	return nil
}

func nativeSystemdMapObservation(action LifecycleAction, state runtime.SystemdAllocationState) RuntimeLifecycleObservationStatus {
	switch action {
	case LifecycleActionConverge:
		if state == runtime.SystemdAllocationStateRunning {
			return RuntimeLifecycleObservationStatusConverged
		}
	case LifecycleActionDrain, LifecycleActionStop:
		if state == runtime.SystemdAllocationStateAbsent || state == runtime.SystemdAllocationStateStopped {
			return RuntimeLifecycleObservationStatusStopped
		}
	}
	if state == runtime.SystemdAllocationStateStarting || state == runtime.SystemdAllocationStateStopping {
		if action == LifecycleActionConverge || action == LifecycleActionDrain || action == LifecycleActionStop {
			return RuntimeLifecycleObservationStatusNotObserved
		}
	}
	return RuntimeLifecycleObservationStatusUnknown
}

const nativeSystemdObservationFingerprintDomain = "native-systemd-runtime-lifecycle-observation-v1"

func nativeSystemdObservationFingerprint(request RuntimeLifecycleObservationRequest,
	status RuntimeLifecycleObservationStatus, state *runtime.SystemdAllocationState) string {
	// The canonical input uses only already-hashed bindings and finite enum
	// values. Raw unit names, PIDs, systemd Result values, plans, and arguments
	// are intentionally absent from both the fingerprint and returned contract.
	stateText := "unknown"
	if state != nil {
		stateText = strconv.Itoa(int(*state))
	}
	values := []string{
		nativeSystemdObservationFingerprintDomain,
		request.OperationKey.Value,
		request.PlanFingerprint.Value,
		strconv.Itoa(int(runtime.RuntimeDriverNativeSystemd)),
		strconv.Itoa(int(request.Action)),
		strconv.Itoa(int(status)),
		stateText,
	}
	var canonical strings.Builder
	canonicalStrings(&canonical, values)
	return RuntimeLifecycleFingerprint.Hash(canonical.String())
}
