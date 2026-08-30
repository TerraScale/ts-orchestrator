// This file implements the node-side workload executor of the
// rootless-hosting and autoscaling lane: it decodes serialized canonical
// runtime plans, dispatches them by driver to the rootless execution
// adapters, tracks the served allocations, and answers with the typed
// receipts of contracts.go carrying the canonical plan fingerprint.
package hostagent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"sync/atomic"

	"terrascale.tech/orchestrator/src/orchestrator/runtime"
)

// NativePlanAdapter is the execution seam of the native systemd driver. The
// runtime package's SystemdHostRuntimeAdapter composed with userManager=true
// satisfies it; every plan is fenced against the canonical plan inside the
// adapter itself, so the executor never re-implements the fencing.
type NativePlanAdapter interface {
	// Converge brings the allocation of one canonical native plan to running.
	Converge(ctx context.Context, plan runtime.HostRuntimePlan) error
	// Observe returns one fenced systemd observation of the allocation.
	Observe(ctx context.Context, plan runtime.HostRuntimePlan) (runtime.SystemdAllocationObservation, error)
	// Stop stops the allocation of one canonical native plan.
	Stop(ctx context.Context, plan runtime.HostRuntimePlan) error
}

// ContainerPlanAdapter is the execution seam of the OCI container driver. The
// runtime package's PodmanRootlessHostRuntimeAdapter satisfies it; containers
// are fenced by the terrascale.allocation and terrascale.fingerprint labels
// inside the adapter itself.
type ContainerPlanAdapter interface {
	// Converge brings the allocation of one canonical OCI plan to running.
	Converge(ctx context.Context, plan runtime.HostRuntimePlan) error
	// Observe returns one fenced podman observation of the allocation.
	Observe(ctx context.Context, plan runtime.HostRuntimePlan) (runtime.PodmanAllocationObservation, error)
	// Stop stops the allocation of one canonical OCI plan.
	Stop(ctx context.Context, plan runtime.HostRuntimePlan) error
	// Delete removes the allocation of one canonical OCI plan.
	Delete(ctx context.Context, plan runtime.HostRuntimePlan) error
}

// WorkloadExecutorConfig is the fully explicit executor configuration. The
// caller wires both adapters; nothing is read from the environment here.
type WorkloadExecutorConfig struct {
	// NodeId identifies the node the executor serves; it appears in receipts.
	NodeId NodeId
	// Systemd executes native systemd plans and must be composed in
	// user-manager mode, so units run under the unprivileged node account.
	Systemd NativePlanAdapter
	// Container executes OCI container plans through rootless podman.
	Container ContainerPlanAdapter
}

// allocationRecord is the executor's tracked state of one served allocation.
type allocationRecord struct {
	plan        runtime.HostRuntimePlan
	fingerprint string
	pending     bool
	state       string
	running     bool
}

// WorkloadExecutor executes workload commands against the node's rootless
// adapters. Converge fails closed while the node is cordoned; Observe, Stop,
// and Delete keep answering so a drain can finish.
type WorkloadExecutor struct {
	nodeId    NodeId
	systemd   NativePlanAdapter
	container ContainerPlanAdapter
	cordoned  atomic.Bool
	mutex     sync.Mutex
	records   map[string]allocationRecord
}

// NewWorkloadExecutor validates the configuration and composes the executor.
func NewWorkloadExecutor(config WorkloadExecutorConfig) (*WorkloadExecutor, error) {
	nodeId, err := NewNodeId(config.NodeId.Value)
	if err != nil {
		return nil, err
	}
	if config.Systemd == nil {
		return nil, &ArgumentError{
			Param:   "Systemd",
			Message: "A native systemd adapter wired in user-manager mode is required.",
		}
	}
	if config.Container == nil {
		return nil, &ArgumentError{
			Param:   "Container",
			Message: "A rootless OCI container adapter is required.",
		}
	}
	return &WorkloadExecutor{
		nodeId:    nodeId,
		systemd:   config.Systemd,
		container: config.Container,
		records:   make(map[string]allocationRecord),
	}, nil
}

// Converge decodes one serialized canonical plan and drives its allocation to
// running through the driver it names. The returned receipt is always the
// typed answer the transport replies with; the error additionally carries the
// underlying failure when the command was rejected or the adapter failed. A
// cordoned node refuses new work fail closed while the fingerprint of the
// decoded plan is still reported.
func (e *WorkloadExecutor) Converge(ctx context.Context, command WorkloadCommandRequest) (ConvergeReceipt, error) {
	if ctx == nil {
		return ConvergeReceipt{}, &ArgumentError{Param: "ctx", Message: "The executor context must not be nil."}
	}
	decoded, err := decodeWorkloadPlan(command)
	if err != nil {
		return convergeReply(command, false,
			"The plan payload is not a canonical runtime plan: "+err.Error(), "", err)
	}
	if e.Cordoned() {
		return convergeReply(command, false,
			fmt.Sprintf("Node %s is cordoned and refuses new work.", e.nodeId.Value),
			decoded.fingerprint, nil)
	}
	switch decoded.plan.Driver {
	case runtime.RuntimeDriverOciContainer:
		err = e.container.Converge(ctx, decoded.plan)
	case runtime.RuntimeDriverNativeSystemd:
		err = e.systemd.Converge(ctx, decoded.plan)
	default:
		err = &InvalidDataError{Message: fmt.Sprintf(
			"The runtime driver %s is not executed by this node.", decoded.plan.Driver)}
	}
	if err != nil {
		e.recordState(decoded, "ConvergeFailed", false, false)
		return convergeReply(command, false, err.Error(), decoded.fingerprint, err)
	}
	e.recordState(decoded, "Converged", false, true)
	return convergeReply(command, true,
		fmt.Sprintf("Allocation %s converged through the %s driver.",
			decoded.plan.AllocationId.Value, decoded.plan.Driver),
		decoded.fingerprint, nil)
}

// Observe decodes one serialized canonical plan and returns its fenced
// observation. Observing keeps answering while the node is cordoned, because
// drain decisions consume observations.
func (e *WorkloadExecutor) Observe(ctx context.Context, command WorkloadCommandRequest) (ObserveReceipt, error) {
	if ctx == nil {
		return ObserveReceipt{}, &ArgumentError{Param: "ctx", Message: "The executor context must not be nil."}
	}
	decoded, err := decodeWorkloadPlan(command)
	if err != nil {
		return observeReply(command, false,
			"The plan payload is not a canonical runtime plan: "+err.Error(), "", err)
	}
	observation, err := e.observeDecoded(ctx, decoded)
	if err != nil {
		e.recordState(decoded, "ObserveFailed", false, false)
		return observeReply(command, false, err.Error(), decoded.fingerprint, err)
	}
	e.recordObserved(decoded, observation)
	return observeReply(command, true,
		fmt.Sprintf("Allocation %s is %s.", decoded.plan.AllocationId.Value, observation.state),
		decoded.fingerprint, nil)
}

// Stop decodes one serialized canonical plan and stops its allocation.
// Stopping keeps answering while the node is cordoned, because the drain
// sequence depends on it.
func (e *WorkloadExecutor) Stop(ctx context.Context, command WorkloadCommandRequest) (StopReceipt, error) {
	if ctx == nil {
		return StopReceipt{}, &ArgumentError{Param: "ctx", Message: "The executor context must not be nil."}
	}
	decoded, err := decodeWorkloadPlan(command)
	if err != nil {
		return stopReply(command, false,
			"The plan payload is not a canonical runtime plan: "+err.Error(), "", err)
	}
	switch decoded.plan.Driver {
	case runtime.RuntimeDriverOciContainer:
		err = e.container.Stop(ctx, decoded.plan)
	case runtime.RuntimeDriverNativeSystemd:
		err = e.systemd.Stop(ctx, decoded.plan)
	default:
		err = &InvalidDataError{Message: fmt.Sprintf(
			"The runtime driver %s is not executed by this node.", decoded.plan.Driver)}
	}
	if err != nil {
		e.recordState(decoded, "StopFailed", false, false)
		return stopReply(command, false, err.Error(), decoded.fingerprint, err)
	}
	e.recordState(decoded, "Stopped", false, false)
	return stopReply(command, true,
		fmt.Sprintf("Allocation %s stopped.", decoded.plan.AllocationId.Value), decoded.fingerprint, nil)
}

// Delete decodes one serialized canonical plan and removes its allocation.
// Native systemd plans are transient units created with --collect, so their
// deletion is the stop itself followed by one confirming observation; OCI
// plans are deleted through the container adapter, which stops them first.
func (e *WorkloadExecutor) Delete(ctx context.Context, command WorkloadCommandRequest) (DeleteReceipt, error) {
	if ctx == nil {
		return DeleteReceipt{}, &ArgumentError{Param: "ctx", Message: "The executor context must not be nil."}
	}
	decoded, err := decodeWorkloadPlan(command)
	if err != nil {
		return deleteReply(command, false,
			"The plan payload is not a canonical runtime plan: "+err.Error(), "", err)
	}
	switch decoded.plan.Driver {
	case runtime.RuntimeDriverOciContainer:
		err = e.container.Delete(ctx, decoded.plan)
		if err == nil {
			e.forgetAllocation(decoded.plan.AllocationId.Value)
			return deleteReply(command, true,
				fmt.Sprintf("Allocation %s deleted.", decoded.plan.AllocationId.Value),
				decoded.fingerprint, nil)
		}
	case runtime.RuntimeDriverNativeSystemd:
		err = e.systemd.Stop(ctx, decoded.plan)
		if err == nil {
			var observation normalizedObservation
			observation, err = e.observeDecoded(ctx, decoded)
			if err == nil {
				switch observation.state {
				case runtime.SystemdAllocationStateAbsent.String(),
					runtime.SystemdAllocationStateStopped.String(),
					runtime.SystemdAllocationStateFailed.String():
					e.forgetAllocation(decoded.plan.AllocationId.Value)
					return deleteReply(command, true,
						fmt.Sprintf("Allocation %s stopped and its transient unit collected.",
							decoded.plan.AllocationId.Value), decoded.fingerprint, nil)
				default:
					err = &InvalidOperationError{Message: fmt.Sprintf(
						"Allocation %s is still %s after deletion.", decoded.plan.AllocationId.Value,
						observation.state)}
				}
			}
		}
	default:
		err = &InvalidDataError{Message: fmt.Sprintf(
			"The runtime driver %s is not executed by this node.", decoded.plan.Driver)}
	}
	e.recordState(decoded, "DeleteFailed", false, false)
	return deleteReply(command, false, err.Error(), decoded.fingerprint, err)
}

// AllocationObservation is one normalized observation of an allocation the
// executor has served, as carried in the drain-status report.
type AllocationObservation struct {
	AllocationId    string `json:"allocationId"`
	Driver          string `json:"driver"`
	State           string `json:"state"`
	Running         bool   `json:"running"`
	PlanFingerprint string `json:"planFingerprint"`
}

// allocationStateUnknown marks an allocation whose observation failed, so a
// drain decision treats it fail closed instead of trusting a stale state.
const allocationStateUnknown = "Unknown"

// ObserveAllocations observes every allocation the executor has served and
// returns the observations ordered by allocation id. An allocation whose
// observation fails is reported with the Unknown state, and the joined error
// carries every failure; callers must treat Unknown as not drained.
func (e *WorkloadExecutor) ObserveAllocations(ctx context.Context) ([]AllocationObservation, error) {
	if ctx == nil {
		return nil, &ArgumentError{Param: "ctx", Message: "The executor context must not be nil."}
	}
	type observedPair struct {
		decoded    decodedWorkloadPlan
		normalized normalizedObservation
		err        error
	}
	decodedPlans := e.snapshotRecords()
	observed := make([]observedPair, 0, len(decodedPlans))
	for _, decoded := range decodedPlans {
		normalized, err := e.observeDecoded(ctx, decoded)
		observed = append(observed, observedPair{decoded: decoded, normalized: normalized, err: err})
	}
	observations := make([]AllocationObservation, 0, len(observed))
	var failures []error
	for _, pair := range observed {
		state := pair.normalized.state
		running := pair.normalized.running
		if pair.err != nil {
			state = allocationStateUnknown
			running = false
			failures = append(failures, pair.err)
		} else {
			e.recordObserved(pair.decoded, pair.normalized)
		}
		observations = append(observations, AllocationObservation{
			AllocationId:    pair.decoded.plan.AllocationId.Value,
			Driver:          pair.decoded.plan.Driver.String(),
			State:           state,
			Running:         running,
			PlanFingerprint: pair.decoded.fingerprint,
		})
	}
	slices.SortFunc(observations, func(left, right AllocationObservation) int {
		return strings.Compare(left.AllocationId, right.AllocationId)
	})
	return observations, errors.Join(failures...)
}

// Drained reports whether the node is cordoned and every observed allocation
// has stopped. Unknown observations never count as drained, because the next
// drain step must not trust a state it could not observe.
func (e *WorkloadExecutor) Drained(observations []AllocationObservation) bool {
	if !e.Cordoned() {
		return false
	}
	for _, observation := range observations {
		if observation.Running || observation.State == allocationStateUnknown {
			return false
		}
	}
	return true
}

// SetCordoned flips the atomic cordon flag of the node. Cording makes Converge
// refuse new work fail closed; Observe, Stop, and Delete keep answering.
func (e *WorkloadExecutor) SetCordoned(cordoned bool) {
	e.cordoned.Store(cordoned)
}

// Cordoned reports the cordon flag of the node.
func (e *WorkloadExecutor) Cordoned() bool {
	return e.cordoned.Load()
}

// PendingAllocations reports how many accepted allocations have not been
// observed running yet; it feeds the heartbeat metric sample.
func (e *WorkloadExecutor) PendingAllocations() int {
	e.mutex.Lock()
	defer e.mutex.Unlock()
	pending := 0
	for _, record := range e.records {
		if record.pending {
			pending++
		}
	}
	return pending
}

// normalizedObservation is one driver-normalized observation.
type normalizedObservation struct {
	state   string
	running bool
}

// decodedWorkloadPlan is one decoded command plan with its fingerprint.
type decodedWorkloadPlan struct {
	plan        runtime.HostRuntimePlan
	fingerprint string
}

// decodeWorkloadPlan decodes the plan payload of one command and computes its
// canonical fingerprint. The decode revalidates every token and re-admits the
// role and driver pair, mirroring the trust boundary of NewHostRuntimePlan.
func decodeWorkloadPlan(command WorkloadCommandRequest) (decodedWorkloadPlan, error) {
	var plan runtime.HostRuntimePlan
	if err := json.Unmarshal(command.PlanJson, &plan); err != nil {
		return decodedWorkloadPlan{}, &InvalidDataError{Message: err.Error()}
	}
	fingerprint, err := runtime.CanonicalPlanFingerprint.Compute(plan)
	if err != nil {
		return decodedWorkloadPlan{}, err
	}
	return decodedWorkloadPlan{plan: plan, fingerprint: fingerprint}, nil
}

// observeDecoded dispatches one fenced observation by driver and normalizes
// the driver-specific observation vocabulary.
func (e *WorkloadExecutor) observeDecoded(ctx context.Context, decoded decodedWorkloadPlan) (normalizedObservation, error) {
	switch decoded.plan.Driver {
	case runtime.RuntimeDriverOciContainer:
		observation, err := e.container.Observe(ctx, decoded.plan)
		if err != nil {
			return normalizedObservation{}, err
		}
		return normalizedObservation{state: observation.State.String(), running: observation.Running}, nil
	case runtime.RuntimeDriverNativeSystemd:
		observation, err := e.systemd.Observe(ctx, decoded.plan)
		if err != nil {
			return normalizedObservation{}, err
		}
		return normalizedObservation{
			state:   observation.State.String(),
			running: observation.State == runtime.SystemdAllocationStateRunning,
		}, nil
	default:
		return normalizedObservation{}, &InvalidDataError{Message: fmt.Sprintf(
			"The runtime driver %s is not executed by this node.", decoded.plan.Driver)}
	}
}

// recordState stores one allocation record under its allocation id, marking
// whether the allocation is pending observation of its running state.
func (e *WorkloadExecutor) recordState(decoded decodedWorkloadPlan, state string, running bool, pending bool) {
	e.mutex.Lock()
	defer e.mutex.Unlock()
	e.records[decoded.plan.AllocationId.Value] = allocationRecord{
		plan:        decoded.plan,
		fingerprint: decoded.fingerprint,
		pending:     pending,
		state:       state,
		running:     running,
	}
}

// recordObserved stores one observation, keeping the pending mark of an
// accepted allocation until it is observed running.
func (e *WorkloadExecutor) recordObserved(decoded decodedWorkloadPlan, observation normalizedObservation) {
	e.mutex.Lock()
	defer e.mutex.Unlock()
	previous := e.records[decoded.plan.AllocationId.Value]
	e.records[decoded.plan.AllocationId.Value] = allocationRecord{
		plan:        decoded.plan,
		fingerprint: decoded.fingerprint,
		pending:     previous.pending && !observation.running,
		state:       observation.state,
		running:     observation.running,
	}
}

// forgetAllocation removes one allocation record after a successful delete.
func (e *WorkloadExecutor) forgetAllocation(allocationId string) {
	e.mutex.Lock()
	defer e.mutex.Unlock()
	delete(e.records, allocationId)
}

// snapshotRecords copies the decoded plans of every tracked allocation.
func (e *WorkloadExecutor) snapshotRecords() []decodedWorkloadPlan {
	e.mutex.Lock()
	defer e.mutex.Unlock()
	snapshot := make([]decodedWorkloadPlan, 0, len(e.records))
	for _, record := range e.records {
		snapshot = append(snapshot, decodedWorkloadPlan{plan: record.plan, fingerprint: record.fingerprint})
	}
	slices.SortFunc(snapshot, func(left, right decodedWorkloadPlan) int {
		return strings.Compare(left.plan.AllocationId.Value, right.plan.AllocationId.Value)
	})
	return snapshot
}

// convergeReply builds one converge receipt with a log-safe detail and returns
// it together with its cause.
func convergeReply(
	command WorkloadCommandRequest,
	accepted bool,
	detail string,
	fingerprint string,
	cause error,
) (ConvergeReceipt, error) {
	receipt, err := NewConvergeReceipt(command.CommandId, accepted, boundedReceiptDetail(detail), fingerprint)
	if err != nil {
		return ConvergeReceipt{}, err
	}
	return receipt, cause
}

// observeReply builds one observe receipt with a log-safe detail and returns it
// together with its cause.
func observeReply(
	command WorkloadCommandRequest,
	accepted bool,
	detail string,
	fingerprint string,
	cause error,
) (ObserveReceipt, error) {
	receipt, err := NewObserveReceipt(command.CommandId, accepted, boundedReceiptDetail(detail), fingerprint)
	if err != nil {
		return ObserveReceipt{}, err
	}
	return receipt, cause
}

// stopReply builds one stop receipt with a log-safe detail and returns it
// together with its cause.
func stopReply(
	command WorkloadCommandRequest,
	accepted bool,
	detail string,
	fingerprint string,
	cause error,
) (StopReceipt, error) {
	receipt, err := NewStopReceipt(command.CommandId, accepted, boundedReceiptDetail(detail), fingerprint)
	if err != nil {
		return StopReceipt{}, err
	}
	return receipt, cause
}

// deleteReply builds one delete receipt with a log-safe detail and returns it
// together with its cause.
func deleteReply(
	command WorkloadCommandRequest,
	accepted bool,
	detail string,
	fingerprint string,
	cause error,
) (DeleteReceipt, error) {
	receipt, err := NewDeleteReceipt(command.CommandId, accepted, boundedReceiptDetail(detail), fingerprint)
	if err != nil {
		return DeleteReceipt{}, err
	}
	return receipt, cause
}

// boundedReceiptDetail sanitizes one detail string into the bounded,
// control-free shape the receipts require: control characters are dropped or
// spaced, and the result never exceeds the receipt detail bound.
func boundedReceiptDetail(detail string) string {
	var builder strings.Builder
	for _, symbol := range detail {
		if symbol == '\n' || symbol == '\r' || symbol == '\t' {
			symbol = ' '
		}
		if isControlRune(symbol) {
			continue
		}
		builder.WriteRune(symbol)
		if builder.Len() >= hostAgentMaximumDetailLength {
			break
		}
	}
	return builder.String()
}
