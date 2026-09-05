package vmqualsuite

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/vmnet"
	"terrascale.tech/orchestrator/src/orchestrator/vmqual"
)

// QualifyRecoveryFaults proves criterion 11 against one live non-control
// member. A stack without the fault capability fails qualification rather than
// receiving synthetic evidence.
func QualifyRecoveryFaults(ctx context.Context, stack *vmqual.Stack) (vmqual.RecoveryFaultResult, error) {
	var result vmqual.RecoveryFaultResult
	if err := validateFaultStack(ctx, stack); err != nil {
		return result, err
	}
	contract, ok := stack.Config().VMFactory.(vmqual.RecoveryFaultContract)
	if !ok {
		return result, errors.New("vmqual: VM factory does not implement the recovery fault contract")
	}
	guest, err := faultTargetGuest(stack)
	if err != nil {
		return result, err
	}
	result.Guest = guest
	result.Host, err = contract.KillReplaceAndCatchUp(ctx, guest)
	if err != nil {
		return result, fmt.Errorf("vmqual: kill and replace %s: %w", guest.ID, err)
	}
	if err := validateHostRecovery(guest, result.Host); err != nil {
		return result, err
	}
	for _, mode := range vmqual.RequiredDiskFaultModes() {
		observation, faultErr := contract.ExerciseDiskFault(ctx, guest, mode)
		result.Disk = append(result.Disk, observation)
		if faultErr != nil {
			return result, fmt.Errorf("vmqual: exercise %s disk fault: %w", mode, faultErr)
		}
		if err := validateDiskFault(guest, mode, observation); err != nil {
			return result, err
		}
	}
	result.Certificate, err = contract.ExpireAndRotateCertificate(ctx, guest)
	if err != nil {
		return result, fmt.Errorf("vmqual: expire certificate: %w", err)
	}
	if err := ValidateCertificateRotation(result.Certificate); err != nil {
		return result, err
	}
	result.Shape, err = contract.ExhaustA1AndFallback(ctx, guest)
	if err != nil {
		return result, fmt.Errorf("vmqual: exhaust A1 capacity: %w", err)
	}
	if err := ValidateShapeFallback(result.Shape); err != nil {
		return result, err
	}
	result.Clock, err = contract.SkewClockAndRepair(ctx, guest)
	if err != nil {
		return result, fmt.Errorf("vmqual: skew clock: %w", err)
	}
	if err := validateClockFence(result.Clock); err != nil {
		return result, err
	}
	return result, nil
}

// QualifyControlOutage proves criterion 12 using a full control-plane outage,
// which is stronger than loss of GRU alone. The admitted data request must be
// served without consulting unavailable control state.
func QualifyControlOutage(ctx context.Context, stack *vmqual.Stack) (result vmqual.ControlOutageResult, err error) {
	if err = validateFaultStack(ctx, stack); err != nil {
		return result, err
	}
	contract, ok := stack.Config().VMFactory.(vmqual.ControlOutageContract)
	if !ok {
		return result, errors.New("vmqual: VM factory does not implement the control outage contract")
	}
	result.Identity, err = contract.PrepareAdmittedData(ctx)
	if err != nil {
		return result, fmt.Errorf("vmqual: prepare admitted data request: %w", err)
	}
	if strings.TrimSpace(result.Identity.RequestID) == "" || strings.TrimSpace(result.Identity.PayloadDigest) == "" || result.Identity.ControlEpoch == 0 {
		return result, errors.New("vmqual: admitted data identity is incomplete")
	}
	result.Before, err = contract.ObserveControlState(ctx, vmqual.ControlOutageFull)
	if err != nil {
		return result, fmt.Errorf("vmqual: observe control before outage: %w", err)
	}
	if err = validateControlState(result.Before, vmqual.ControlOutageFull, true); err != nil {
		return result, fmt.Errorf("vmqual: control before outage: %w", err)
	}
	if err = contract.SetControlOutage(ctx, vmqual.ControlOutageFull, true); err != nil {
		return result, fmt.Errorf("vmqual: start control outage: %w", err)
	}
	outageActive := true
	defer func() {
		if !outageActive {
			return
		}
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		err = errors.Join(err, contract.SetControlOutage(cleanupCtx, vmqual.ControlOutageFull, false))
	}()
	result.During, err = contract.ObserveControlState(ctx, vmqual.ControlOutageFull)
	if err != nil {
		return result, fmt.Errorf("vmqual: observe control during outage: %w", err)
	}
	if err = validateControlState(result.During, vmqual.ControlOutageFull, false); err != nil {
		return result, fmt.Errorf("vmqual: control during outage: %w", err)
	}
	result.Probe, err = contract.ServeAdmittedData(ctx, result.Identity)
	if err != nil {
		return result, fmt.Errorf("vmqual: serve admitted data during outage: %w", err)
	}
	if !result.Probe.Served || result.Probe.ContactedControl || result.Probe.RequestID != result.Identity.RequestID || result.Probe.PayloadDigest != result.Identity.PayloadDigest {
		return result, errors.New("vmqual: admitted data path was not independently served during control outage")
	}
	if err = contract.SetControlOutage(ctx, vmqual.ControlOutageFull, false); err != nil {
		return result, fmt.Errorf("vmqual: heal control outage: %w", err)
	}
	result.After, err = contract.ObserveControlState(ctx, vmqual.ControlOutageFull)
	if err != nil {
		return result, fmt.Errorf("vmqual: observe control after outage: %w", err)
	}
	if err = validateControlState(result.After, vmqual.ControlOutageFull, true); err != nil {
		return result, fmt.Errorf("vmqual: control after outage: %w", err)
	}
	if result.After.AcceptedEpoch < result.Before.AcceptedEpoch {
		return result, errors.New("vmqual: accepted control epoch regressed after outage")
	}
	outageActive = false
	return result, nil
}

var partitionMutationSequence atomic.Uint64

// QualifyCrossRegionPartitions proves criterion 13 for all three Region pairs.
// Each partition is healed on every exit path, including cancellation and a
// failed assertion.
func QualifyCrossRegionPartitions(ctx context.Context, stack *vmqual.Stack) (vmqual.PartitionFaultResult, error) {
	var result vmqual.PartitionFaultResult
	if err := validateFaultStack(ctx, stack); err != nil {
		return result, err
	}
	contract, ok := stack.Config().Network.(vmqual.CrossRegionPartitionContract)
	if !ok {
		return result, errors.New("vmqual: network controller does not implement the cross-Region partition contract")
	}
	for _, pair := range vmqual.RequiredCrossRegionPairs() {
		pairResult, err := qualifyRegionPair(ctx, contract, pair)
		result.Pairs = append(result.Pairs, pairResult)
		if err != nil {
			return result, err
		}
	}
	return result, nil
}

func qualifyRegionPair(ctx context.Context, contract vmqual.CrossRegionPartitionContract, pair vmqual.RegionPair) (result vmqual.PartitionPairResult, err error) {
	result.Pair = pair
	result.Before, err = contract.ObserveRegionalControl(ctx)
	if err != nil {
		return result, fmt.Errorf("vmqual: observe control before %s-%s partition: %w", pair.From, pair.To, err)
	}
	beforeEpoch, err := validateConvergedRegionalControl(result.Before, "", false)
	if err != nil {
		return result, fmt.Errorf("vmqual: control before %s-%s partition: %w", pair.From, pair.To, err)
	}
	if err = contract.PartitionRegions(ctx, pair); err != nil {
		return result, fmt.Errorf("vmqual: partition %s-%s: %w", pair.From, pair.To, err)
	}
	partitionActive := true
	defer func() {
		if !partitionActive {
			return
		}
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		err = errors.Join(err, contract.HealRegions(cleanupCtx, pair))
	}()
	result.LinkDuring, err = contract.ObservePartitionLink(ctx, pair)
	if err != nil {
		return result, fmt.Errorf("vmqual: observe %s-%s partition: %w", pair.From, pair.To, err)
	}
	if result.LinkDuring.Pair != pair || !result.LinkDuring.Blocked {
		return result, fmt.Errorf("vmqual: %s-%s link was not observed blocked", pair.From, pair.To)
	}
	for _, region := range []vmnet.RegionCode{vmnet.GRU, vmnet.SFO, vmnet.FRA} {
		probe, probeErr := contract.ProbeLocalService(ctx, region)
		result.Local = append(result.Local, probe)
		if probeErr != nil {
			return result, fmt.Errorf("vmqual: probe local service in %s: %w", region, probeErr)
		}
		if !probe.Served || probe.RequestedRegion != region || probe.ServedByRegion != region || strings.TrimSpace(probe.Endpoint) == "" || strings.TrimSpace(probe.ResponseDigest) == "" {
			return result, fmt.Errorf("vmqual: Region %s did not serve its local path during partition", region)
		}
	}
	result.MutationID = fmt.Sprintf("vmqual-partition-%s-%s-%d-%d", pair.From, pair.To, time.Now().UnixNano(), partitionMutationSequence.Add(1))
	for attempt := 0; attempt < 2; attempt++ {
		if err = contract.SubmitPreauthorizedMutation(ctx, pair.From, result.MutationID); err != nil {
			return result, fmt.Errorf("vmqual: submit duplicate-safe mutation for %s-%s: %w", pair.From, pair.To, err)
		}
	}
	result.During, err = contract.ObserveRegionalControl(ctx)
	if err != nil {
		return result, fmt.Errorf("vmqual: observe control during %s-%s partition: %w", pair.From, pair.To, err)
	}
	if err = validateRegionalSet(result.During); err != nil {
		return result, fmt.Errorf("vmqual: control during %s-%s partition: %w", pair.From, pair.To, err)
	}
	var fromState, toState vmqual.RegionalControlObservation
	for _, regional := range result.During {
		applications := regional.MutationApplications[result.MutationID]
		if applications > 1 {
			return result, fmt.Errorf("vmqual: mutation %s was applied more than once in %s during partition", result.MutationID, regional.Region)
		}
		if regional.Region == pair.From {
			fromState = regional
		}
		if regional.Region == pair.To {
			toState = regional
		}
	}
	if fromState.MutationApplications[result.MutationID] != 1 || toState.MutationApplications[result.MutationID] != 0 || fromState.StateDigest == toState.StateDigest {
		return result, fmt.Errorf("vmqual: %s-%s partition did not isolate the preauthorized mutation", pair.From, pair.To)
	}
	if err = contract.HealRegions(ctx, pair); err != nil {
		return result, fmt.Errorf("vmqual: heal %s-%s partition: %w", pair.From, pair.To, err)
	}
	result.LinkAfter, err = contract.ObservePartitionLink(ctx, pair)
	if err != nil {
		return result, fmt.Errorf("vmqual: observe healed %s-%s link: %w", pair.From, pair.To, err)
	}
	if result.LinkAfter.Pair != pair || result.LinkAfter.Blocked {
		return result, fmt.Errorf("vmqual: %s-%s link was not observed healed", pair.From, pair.To)
	}
	partitionActive = false
	if err = contract.AwaitPartitionConvergence(ctx, pair); err != nil {
		return result, fmt.Errorf("vmqual: await %s-%s convergence: %w", pair.From, pair.To, err)
	}
	result.After, err = contract.ObserveRegionalControl(ctx)
	if err != nil {
		return result, fmt.Errorf("vmqual: observe control after %s-%s heal: %w", pair.From, pair.To, err)
	}
	afterEpoch, err := validateConvergedRegionalControl(result.After, result.MutationID, true)
	if err != nil {
		return result, fmt.Errorf("vmqual: control after %s-%s heal: %w", pair.From, pair.To, err)
	}
	if afterEpoch < beforeEpoch {
		return result, fmt.Errorf("vmqual: control epoch regressed across %s-%s partition", pair.From, pair.To)
	}
	return result, nil
}

// QualifyCleanupFaults proves criterion 16 for both cancellation and a failed
// assertion. Any observed VM, process, network object, socket, cgroup, or state
// path causes qualification to fail.
func QualifyCleanupFaults(ctx context.Context, stack *vmqual.Stack) (vmqual.CleanupFaultResult, error) {
	var result vmqual.CleanupFaultResult
	if err := validateFaultStack(ctx, stack); err != nil {
		return result, err
	}
	contract, ok := stack.Config().VMFactory.(vmqual.CleanupFaultContract)
	if !ok {
		if networkContract, networkOK := stack.Config().Network.(vmqual.CleanupFaultContract); networkOK {
			contract = networkContract
			ok = true
		}
	}
	if !ok {
		return result, errors.New("vmqual: stack does not implement the cleanup fault contract")
	}
	for _, cause := range vmqual.RequiredCleanupCauses() {
		exercise, err := contract.ExerciseCleanup(ctx, cause)
		result.Exercises = append(result.Exercises, exercise)
		if err != nil {
			return result, fmt.Errorf("vmqual: exercise cleanup after %s: %w", cause, err)
		}
		if exercise.Cause != cause || !exercise.CauseObserved || !exercise.CleanupCompleted {
			return result, fmt.Errorf("vmqual: cleanup did not observe and complete after %s", cause)
		}
		observation, err := contract.InspectOwnedResources(ctx, cause)
		result.Observations = append(result.Observations, observation)
		if err != nil {
			return result, fmt.Errorf("vmqual: inspect cleanup after %s: %w", cause, err)
		}
		if err := validateCleanupObservation(cause, observation); err != nil {
			return result, err
		}
	}
	return result, nil
}

func validateFaultStack(ctx context.Context, stack *vmqual.Stack) error {
	if ctx == nil {
		return errors.New("vmqual: fault qualification context is nil")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if stack == nil {
		return errors.New("vmqual: fault qualification stack is nil")
	}
	snapshot := stack.Snapshot()
	if !snapshot.Started || (len(snapshot.Guests) != 6 && len(snapshot.Guests) != 8) || len(snapshot.VMs) != len(snapshot.Guests) {
		return errors.New("vmqual: fault qualification requires the complete admitted VM stack")
	}
	for _, guest := range snapshot.Guests {
		if snapshot.VMs[guest.ID] == nil {
			return fmt.Errorf("vmqual: fault qualification VM %s is missing", guest.ID)
		}
	}
	return nil
}

func faultTargetGuest(stack *vmqual.Stack) (vmqual.Guest, error) {
	snapshot := stack.Snapshot()
	for _, guest := range snapshot.Guests {
		if !guest.Control {
			return guest, nil
		}
	}
	return vmqual.Guest{}, errors.New("vmqual: fault qualification has no non-control member")
}

func validateHostRecovery(guest vmqual.Guest, observation vmqual.HostRecoveryObservation) error {
	if observation.FailedVMID != guest.ID || strings.TrimSpace(observation.ReplacementVMID) == "" || observation.ReplacementVMID == observation.FailedVMID {
		return errors.New("vmqual: replacement did not have a distinct observed identity")
	}
	if !observation.FailedVMStopped || !observation.ReplacementRunning || !observation.ReplacementReady {
		return errors.New("vmqual: failed VM stop and ready replacement were not observed")
	}
	if observation.CatchUpTarget == 0 || observation.ReplacementCommit < observation.CatchUpTarget || !observation.ReplacementCaughtUp {
		return errors.New("vmqual: replacement did not catch up to the observed commit target")
	}
	return nil
}

func validateDiskFault(guest vmqual.Guest, mode vmqual.DiskFaultMode, observation vmqual.DiskFaultObservation) error {
	if observation.VMID != guest.ID || observation.Mode != mode || !observation.GuestVisible {
		return fmt.Errorf("vmqual: %s disk outcome was not observed in guest %s", mode, guest.ID)
	}
	if mode != vmqual.DiskFaultExpansion && !observation.FailureObserved {
		return fmt.Errorf("vmqual: %s disk failure was not observed", mode)
	}
	if mode == vmqual.DiskFaultMissingAtBoot && !observation.RestartObserved {
		return errors.New("vmqual: missing disk was not observed on boot")
	}
	if mode == vmqual.DiskFaultExpansion && (observation.CapacityBeforeBytes == 0 || observation.CapacityAfterBytes <= observation.CapacityBeforeBytes) {
		return errors.New("vmqual: disk expansion did not increase guest-visible capacity")
	}
	if mode == vmqual.DiskFaultExpansion && observation.Disposition != vmqual.FaultDispositionRepaired {
		return errors.New("vmqual: expanded disk did not return through the verified repair path")
	}
	if mode == vmqual.DiskFaultCorruption && !observation.CorruptionDetected {
		return errors.New("vmqual: disk corruption was not detected by the guest repair path")
	}
	switch observation.Disposition {
	case vmqual.FaultDispositionRepaired:
		if !observation.RepairAttempted || !observation.HealthyAfterRepair || !observation.WritesAdmittedAfter || observation.FailClosed {
			return fmt.Errorf("vmqual: %s did not complete its declared repair path", mode)
		}
	case vmqual.FaultDispositionFailClosed:
		if !observation.FailClosed || observation.WritesAdmittedAfter {
			return fmt.Errorf("vmqual: %s did not remain fail-closed", mode)
		}
	default:
		return fmt.Errorf("vmqual: %s has no declared repair or fail-closed disposition", mode)
	}
	return nil
}

func ValidateCertificateRotation(observation vmqual.CertificateRotationObservation) error {
	if strings.TrimSpace(observation.ExpiredSerial) == "" || strings.TrimSpace(observation.RotatedSerial) == "" || observation.ExpiredSerial == observation.RotatedSerial {
		return errors.New("vmqual: certificate rotation did not change serial identity")
	}
	if observation.ObservedAt.IsZero() || observation.ExpiredNotAfter.IsZero() || observation.RotatedNotAfter.IsZero() || observation.ExpiredNotAfter.After(observation.ObservedAt) || !observation.RotatedNotAfter.After(observation.ObservedAt) {
		return errors.New("vmqual: certificate validity window does not prove expiry and rotation")
	}
	if !observation.ExpiredRejected || !observation.RotatedAccepted || !observation.ServiceHealthy {
		return errors.New("vmqual: expired certificate rejection and healthy rotation were not observed")
	}
	return nil
}

func ValidateShapeFallback(observation vmqual.ShapeFallbackObservation) error {
	if len(observation.Attempts) != 2 || observation.Attempts[0] != "VM.Standard.A1.Flex" || observation.Attempts[1] != "VM.Standard.E5.Flex" {
		return errors.New("vmqual: shape attempts did not follow A1 then E5 fallback order")
	}
	if !observation.A1CapacityExhausted || observation.SelectedShape != "VM.Standard.E5.Flex" || observation.SelectedArchitecture != "amd64" || !observation.ReplacementReady {
		return errors.New("vmqual: A1 exhaustion did not select a ready amd64 E5 replacement")
	}
	return nil
}

func validateClockFence(observation vmqual.ClockFenceObservation) error {
	const fence = 500 * time.Millisecond
	if observation.InjectedOffset <= fence && observation.InjectedOffset >= -fence {
		return errors.New("vmqual: injected clock offset did not exceed the 500 ms fence")
	}
	if !observation.WritesFenced || observation.SuspectHLCMinted {
		return errors.New("vmqual: skewed clock did not fence writes and HLC minting")
	}
	if !observation.TimeSynchronized || observation.RepairedOffset > fence || observation.RepairedOffset < -fence || !observation.WritesAdmittedAfter {
		return errors.New("vmqual: clock repair did not restore bounded write admission")
	}
	return nil
}

func validateControlState(observation vmqual.ControlStateObservation, scope vmqual.ControlOutageScope, available bool) error {
	if observation.Scope != scope || observation.AcceptedEpoch == 0 {
		return errors.New("control observation has invalid scope or epoch")
	}
	if available {
		if !observation.ControlAvailable || observation.AvailableReplicas <= 0 {
			return errors.New("control was not observed available")
		}
		return nil
	}
	if observation.ControlAvailable || observation.AvailableReplicas != 0 {
		return errors.New("control was not observed unavailable")
	}
	return nil
}

func validateRegionalSet(observations []vmqual.RegionalControlObservation) error {
	if len(observations) != 3 {
		return fmt.Errorf("expected three regional control observations, got %d", len(observations))
	}
	seen := make(map[vmnet.RegionCode]bool, 3)
	for _, observation := range observations {
		if observation.Region != vmnet.GRU && observation.Region != vmnet.SFO && observation.Region != vmnet.FRA {
			return fmt.Errorf("unexpected Region %q", observation.Region)
		}
		if seen[observation.Region] || observation.AcceptedEpoch == 0 || strings.TrimSpace(observation.StateDigest) == "" {
			return fmt.Errorf("invalid control observation for Region %s", observation.Region)
		}
		seen[observation.Region] = true
	}
	return nil
}

func validateConvergedRegionalControl(observations []vmqual.RegionalControlObservation, mutationID string, requireMutation bool) (uint64, error) {
	if err := validateRegionalSet(observations); err != nil {
		return 0, err
	}
	digest := observations[0].StateDigest
	epoch := observations[0].AcceptedEpoch
	for _, observation := range observations {
		if observation.StateDigest != digest || observation.AcceptedEpoch != epoch {
			return 0, errors.New("regional control state did not converge")
		}
		if requireMutation && observation.MutationApplications[mutationID] != 1 {
			return 0, fmt.Errorf("mutation %s application count in %s is %d, want 1", mutationID, observation.Region, observation.MutationApplications[mutationID])
		}
	}
	return epoch, nil
}

func validateCleanupObservation(cause vmqual.CleanupCause, observation vmqual.CleanupObservation) error {
	if observation.Cause != cause {
		return fmt.Errorf("vmqual: cleanup inspection cause is %s, want %s", observation.Cause, cause)
	}
	remaining := len(observation.RunningVMIDs) + len(observation.OwnedVMIDs) + len(observation.ProcessIDs) +
		len(observation.NetworkNamespaces) + len(observation.TAPDevices) + len(observation.Cgroups) +
		len(observation.APISockets) + len(observation.StatePaths) + len(observation.OwnedResources)
	if remaining != 0 {
		return fmt.Errorf("vmqual: cleanup after %s left %d owned resources", cause, remaining)
	}
	return nil
}
