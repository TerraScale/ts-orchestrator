package vmqual

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/vmnet"
)

// DiskFaultMode identifies a guest-visible storage condition that the VM
// qualification suite must induce. These are effects observed by the guest,
// not merely mutations of a host-side backing file.
type DiskFaultMode string

const (
	DiskFaultENOSPC        DiskFaultMode = "enospc"
	DiskFaultIOFailure     DiskFaultMode = "io-failure"
	DiskFaultReadOnly      DiskFaultMode = "read-only"
	DiskFaultMissingAtBoot DiskFaultMode = "missing-at-boot"
	DiskFaultExpansion     DiskFaultMode = "expansion"
	DiskFaultCorruption    DiskFaultMode = "corruption"
)

var requiredDiskFaultModes = [...]DiskFaultMode{
	DiskFaultENOSPC,
	DiskFaultIOFailure,
	DiskFaultReadOnly,
	DiskFaultMissingAtBoot,
	DiskFaultExpansion,
	DiskFaultCorruption,
}

// RequiredDiskFaultModes returns a defensive copy of the complete storage
// fault matrix required by the qualification goal.
func RequiredDiskFaultModes() []DiskFaultMode {
	return append([]DiskFaultMode(nil), requiredDiskFaultModes[:]...)
}

type FaultDisposition string

const (
	FaultDispositionRepaired   FaultDisposition = "repaired"
	FaultDispositionFailClosed FaultDisposition = "fail-closed"
)

type HostRecoveryObservation struct {
	FailedVMID          string
	ReplacementVMID     string
	FailedVMStopped     bool
	ReplacementRunning  bool
	ReplacementReady    bool
	CatchUpTarget       uint64
	ReplacementCommit   uint64
	ReplacementCaughtUp bool
}

type DiskFaultObservation struct {
	VMID                string
	Mode                DiskFaultMode
	GuestVisible        bool
	FailureObserved     bool
	RestartObserved     bool
	CorruptionDetected  bool
	CapacityBeforeBytes uint64
	CapacityAfterBytes  uint64
	Disposition         FaultDisposition
	RepairAttempted     bool
	HealthyAfterRepair  bool
	WritesAdmittedAfter bool
	FailClosed          bool
}

type CertificateRotationObservation struct {
	ExpiredSerial   string
	RotatedSerial   string
	ExpiredNotAfter time.Time
	RotatedNotAfter time.Time
	ObservedAt      time.Time
	ExpiredRejected bool
	RotatedAccepted bool
	ServiceHealthy  bool
}

type ShapeFallbackObservation struct {
	Attempts             []string
	A1CapacityExhausted  bool
	SelectedShape        string
	SelectedArchitecture string
	ReplacementReady     bool
}

type ClockFenceObservation struct {
	InjectedOffset      time.Duration
	WritesFenced        bool
	SuspectHLCMinted    bool
	TimeSynchronized    bool
	RepairedOffset      time.Duration
	WritesAdmittedAfter bool
}

// RecoveryFaultContract is an optional capability of the VM factory used by
// the real stack. Returning observations is not sufficient on its own: the
// qualification helper below validates identities, state transitions, and
// every required disk mode.
type RecoveryFaultContract interface {
	KillReplaceAndCatchUp(context.Context, Guest) (HostRecoveryObservation, error)
	ExerciseDiskFault(context.Context, Guest, DiskFaultMode) (DiskFaultObservation, error)
	ExpireAndRotateCertificate(context.Context, Guest) (CertificateRotationObservation, error)
	ExhaustA1AndFallback(context.Context, Guest) (ShapeFallbackObservation, error)
	SkewClockAndRepair(context.Context, Guest) (ClockFenceObservation, error)
}

type RecoveryFaultResult struct {
	Guest       Guest
	Host        HostRecoveryObservation
	Disk        []DiskFaultObservation
	Certificate CertificateRotationObservation
	Shape       ShapeFallbackObservation
	Clock       ClockFenceObservation
}

// QualifyRecoveryFaults proves criterion 11 against one live non-control
// member. A stack without the fault capability fails qualification rather than
// receiving synthetic evidence.
func QualifyRecoveryFaults(ctx context.Context, stack *Stack) (RecoveryFaultResult, error) {
	var result RecoveryFaultResult
	if err := validateFaultStack(ctx, stack); err != nil {
		return result, err
	}
	contract, ok := stack.config.VMFactory.(RecoveryFaultContract)
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
	for _, mode := range requiredDiskFaultModes {
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
	if err := validateCertificateRotation(result.Certificate); err != nil {
		return result, err
	}
	result.Shape, err = contract.ExhaustA1AndFallback(ctx, guest)
	if err != nil {
		return result, fmt.Errorf("vmqual: exhaust A1 capacity: %w", err)
	}
	if err := validateShapeFallback(result.Shape); err != nil {
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

type ControlOutageScope string

const ControlOutageFull ControlOutageScope = "full-control-plane"

type AdmittedDataIdentity struct {
	RequestID     string
	PayloadDigest string
	ControlEpoch  uint64
}

type ControlStateObservation struct {
	Scope             ControlOutageScope
	ControlAvailable  bool
	AvailableReplicas int
	AcceptedEpoch     uint64
}

type AdmittedDataObservation struct {
	RequestID        string
	PayloadDigest    string
	Served           bool
	ContactedControl bool
}

// ControlOutageContract separates fault injection from state observation, so
// a provider cannot qualify merely because an outage method returned nil.
type ControlOutageContract interface {
	PrepareAdmittedData(context.Context) (AdmittedDataIdentity, error)
	SetControlOutage(context.Context, ControlOutageScope, bool) error
	ObserveControlState(context.Context, ControlOutageScope) (ControlStateObservation, error)
	ServeAdmittedData(context.Context, AdmittedDataIdentity) (AdmittedDataObservation, error)
}

type ControlOutageResult struct {
	Identity AdmittedDataIdentity
	Before   ControlStateObservation
	During   ControlStateObservation
	Probe    AdmittedDataObservation
	After    ControlStateObservation
}

// QualifyControlOutage proves criterion 12 using a full control-plane outage,
// which is stronger than loss of GRU alone. The admitted data request must be
// served without consulting unavailable control state.
func QualifyControlOutage(ctx context.Context, stack *Stack) (result ControlOutageResult, err error) {
	if err = validateFaultStack(ctx, stack); err != nil {
		return result, err
	}
	contract, ok := stack.config.VMFactory.(ControlOutageContract)
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
	result.Before, err = contract.ObserveControlState(ctx, ControlOutageFull)
	if err != nil {
		return result, fmt.Errorf("vmqual: observe control before outage: %w", err)
	}
	if err = validateControlState(result.Before, ControlOutageFull, true); err != nil {
		return result, fmt.Errorf("vmqual: control before outage: %w", err)
	}
	if err = contract.SetControlOutage(ctx, ControlOutageFull, true); err != nil {
		return result, fmt.Errorf("vmqual: start control outage: %w", err)
	}
	outageActive := true
	defer func() {
		if !outageActive {
			return
		}
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		err = errors.Join(err, contract.SetControlOutage(cleanupCtx, ControlOutageFull, false))
	}()
	result.During, err = contract.ObserveControlState(ctx, ControlOutageFull)
	if err != nil {
		return result, fmt.Errorf("vmqual: observe control during outage: %w", err)
	}
	if err = validateControlState(result.During, ControlOutageFull, false); err != nil {
		return result, fmt.Errorf("vmqual: control during outage: %w", err)
	}
	result.Probe, err = contract.ServeAdmittedData(ctx, result.Identity)
	if err != nil {
		return result, fmt.Errorf("vmqual: serve admitted data during outage: %w", err)
	}
	if !result.Probe.Served || result.Probe.ContactedControl || result.Probe.RequestID != result.Identity.RequestID || result.Probe.PayloadDigest != result.Identity.PayloadDigest {
		return result, errors.New("vmqual: admitted data path was not independently served during control outage")
	}
	if err = contract.SetControlOutage(ctx, ControlOutageFull, false); err != nil {
		return result, fmt.Errorf("vmqual: heal control outage: %w", err)
	}
	result.After, err = contract.ObserveControlState(ctx, ControlOutageFull)
	if err != nil {
		return result, fmt.Errorf("vmqual: observe control after outage: %w", err)
	}
	if err = validateControlState(result.After, ControlOutageFull, true); err != nil {
		return result, fmt.Errorf("vmqual: control after outage: %w", err)
	}
	if result.After.AcceptedEpoch < result.Before.AcceptedEpoch {
		return result, errors.New("vmqual: accepted control epoch regressed after outage")
	}
	outageActive = false
	return result, nil
}

type RegionPair struct {
	From vmnet.RegionCode
	To   vmnet.RegionCode
}

var requiredRegionPairs = [...]RegionPair{
	{From: vmnet.GRU, To: vmnet.SFO},
	{From: vmnet.GRU, To: vmnet.FRA},
	{From: vmnet.SFO, To: vmnet.FRA},
}

func RequiredCrossRegionPairs() []RegionPair {
	return append([]RegionPair(nil), requiredRegionPairs[:]...)
}

type PartitionLinkObservation struct {
	Pair    RegionPair
	Blocked bool
}

type LocalServiceObservation struct {
	RequestedRegion vmnet.RegionCode
	ServedByRegion  vmnet.RegionCode
	Served          bool
	Endpoint        string
	ResponseDigest  string
}

type RegionalControlObservation struct {
	Region               vmnet.RegionCode
	AcceptedEpoch        uint64
	StateDigest          string
	MutationApplications map[string]uint64
}

// CrossRegionPartitionContract must expose link state and independently
// observed regional state. SubmitPreauthorizedMutation represents only the
// regional work allowed while isolated; it must not bypass the global-mutation
// fence. AwaitPartitionConvergence is only a wait primitive: the helper always
// observes and validates convergence after it returns.
type CrossRegionPartitionContract interface {
	PartitionRegions(context.Context, RegionPair) error
	HealRegions(context.Context, RegionPair) error
	ObservePartitionLink(context.Context, RegionPair) (PartitionLinkObservation, error)
	ProbeLocalService(context.Context, vmnet.RegionCode) (LocalServiceObservation, error)
	SubmitPreauthorizedMutation(context.Context, vmnet.RegionCode, string) error
	ObserveRegionalControl(context.Context) ([]RegionalControlObservation, error)
	AwaitPartitionConvergence(context.Context, RegionPair) error
}

type PartitionPairResult struct {
	Pair       RegionPair
	MutationID string
	Before     []RegionalControlObservation
	LinkDuring PartitionLinkObservation
	Local      []LocalServiceObservation
	During     []RegionalControlObservation
	LinkAfter  PartitionLinkObservation
	After      []RegionalControlObservation
}

type PartitionFaultResult struct {
	Pairs []PartitionPairResult
}

var partitionMutationSequence atomic.Uint64

// QualifyCrossRegionPartitions proves criterion 13 for all three Region pairs.
// Each partition is healed on every exit path, including cancellation and a
// failed assertion.
func QualifyCrossRegionPartitions(ctx context.Context, stack *Stack) (PartitionFaultResult, error) {
	var result PartitionFaultResult
	if err := validateFaultStack(ctx, stack); err != nil {
		return result, err
	}
	contract, ok := stack.config.Network.(CrossRegionPartitionContract)
	if !ok {
		return result, errors.New("vmqual: network controller does not implement the cross-Region partition contract")
	}
	for _, pair := range requiredRegionPairs {
		pairResult, err := qualifyRegionPair(ctx, contract, pair)
		result.Pairs = append(result.Pairs, pairResult)
		if err != nil {
			return result, err
		}
	}
	return result, nil
}

func qualifyRegionPair(ctx context.Context, contract CrossRegionPartitionContract, pair RegionPair) (result PartitionPairResult, err error) {
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
	var fromState, toState RegionalControlObservation
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

type CleanupCause string

const (
	CleanupCauseCancellation     CleanupCause = "cancellation"
	CleanupCauseAssertionFailure CleanupCause = "assertion-failure"
)

var requiredCleanupCauses = [...]CleanupCause{CleanupCauseCancellation, CleanupCauseAssertionFailure}

type CleanupExerciseObservation struct {
	Cause            CleanupCause
	CauseObserved    bool
	CleanupCompleted bool
}

type CleanupObservation struct {
	Cause             CleanupCause
	RunningVMIDs      []string
	OwnedVMIDs        []string
	ProcessIDs        []int
	NetworkNamespaces []string
	TAPDevices        []string
	Cgroups           []string
	APISockets        []string
	StatePaths        []string
	OwnedResources    []string
}

// CleanupFaultContract owns isolated probes so exercising an assertion failure
// cannot tear down the six-VM qualification stack itself. Its returned state
// must come from post-cleanup inspection of the host.
type CleanupFaultContract interface {
	ExerciseCleanup(context.Context, CleanupCause) (CleanupExerciseObservation, error)
	InspectOwnedResources(context.Context, CleanupCause) (CleanupObservation, error)
}

type CleanupFaultResult struct {
	Exercises    []CleanupExerciseObservation
	Observations []CleanupObservation
}

// QualifyCleanupFaults proves criterion 16 for both cancellation and a failed
// assertion. Any observed VM, process, network object, socket, cgroup, or state
// path causes qualification to fail.
func QualifyCleanupFaults(ctx context.Context, stack *Stack) (CleanupFaultResult, error) {
	var result CleanupFaultResult
	if err := validateFaultStack(ctx, stack); err != nil {
		return result, err
	}
	contract, ok := stack.config.VMFactory.(CleanupFaultContract)
	if !ok {
		if networkContract, networkOK := stack.config.Network.(CleanupFaultContract); networkOK {
			contract = networkContract
			ok = true
		}
	}
	if !ok {
		return result, errors.New("vmqual: stack does not implement the cleanup fault contract")
	}
	for _, cause := range requiredCleanupCauses {
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

func validateFaultStack(ctx context.Context, stack *Stack) error {
	if ctx == nil {
		return errors.New("vmqual: fault qualification context is nil")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if stack == nil {
		return errors.New("vmqual: fault qualification stack is nil")
	}
	stack.mu.Lock()
	defer stack.mu.Unlock()
	if !stack.started || len(stack.guests) != 6 || len(stack.vms) != 6 {
		return errors.New("vmqual: fault qualification requires the live six-VM stack")
	}
	for _, guest := range stack.guests {
		if stack.vms[guest.ID] == nil {
			return fmt.Errorf("vmqual: fault qualification VM %s is missing", guest.ID)
		}
	}
	return nil
}

func faultTargetGuest(stack *Stack) (Guest, error) {
	stack.mu.Lock()
	defer stack.mu.Unlock()
	for _, guest := range stack.guests {
		if !guest.Control {
			return guest, nil
		}
	}
	return Guest{}, errors.New("vmqual: fault qualification has no non-control member")
}

func validateHostRecovery(guest Guest, observation HostRecoveryObservation) error {
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

func validateDiskFault(guest Guest, mode DiskFaultMode, observation DiskFaultObservation) error {
	if observation.VMID != guest.ID || observation.Mode != mode || !observation.GuestVisible {
		return fmt.Errorf("vmqual: %s disk outcome was not observed in guest %s", mode, guest.ID)
	}
	if mode != DiskFaultExpansion && !observation.FailureObserved {
		return fmt.Errorf("vmqual: %s disk failure was not observed", mode)
	}
	if mode == DiskFaultMissingAtBoot && !observation.RestartObserved {
		return errors.New("vmqual: missing disk was not observed on boot")
	}
	if mode == DiskFaultExpansion && (observation.CapacityBeforeBytes == 0 || observation.CapacityAfterBytes <= observation.CapacityBeforeBytes) {
		return errors.New("vmqual: disk expansion did not increase guest-visible capacity")
	}
	if mode == DiskFaultExpansion && observation.Disposition != FaultDispositionRepaired {
		return errors.New("vmqual: expanded disk did not return through the verified repair path")
	}
	if mode == DiskFaultCorruption && !observation.CorruptionDetected {
		return errors.New("vmqual: disk corruption was not detected by the guest repair path")
	}
	switch observation.Disposition {
	case FaultDispositionRepaired:
		if !observation.RepairAttempted || !observation.HealthyAfterRepair || !observation.WritesAdmittedAfter || observation.FailClosed {
			return fmt.Errorf("vmqual: %s did not complete its declared repair path", mode)
		}
	case FaultDispositionFailClosed:
		if !observation.FailClosed || observation.WritesAdmittedAfter {
			return fmt.Errorf("vmqual: %s did not remain fail-closed", mode)
		}
	default:
		return fmt.Errorf("vmqual: %s has no declared repair or fail-closed disposition", mode)
	}
	return nil
}

func validateCertificateRotation(observation CertificateRotationObservation) error {
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

func validateShapeFallback(observation ShapeFallbackObservation) error {
	if len(observation.Attempts) != 2 || observation.Attempts[0] != "VM.Standard.A1.Flex" || observation.Attempts[1] != "VM.Standard.E5.Flex" {
		return errors.New("vmqual: shape attempts did not follow A1 then E5 fallback order")
	}
	if !observation.A1CapacityExhausted || observation.SelectedShape != "VM.Standard.E5.Flex" || observation.SelectedArchitecture != "amd64" || !observation.ReplacementReady {
		return errors.New("vmqual: A1 exhaustion did not select a ready amd64 E5 replacement")
	}
	return nil
}

func validateClockFence(observation ClockFenceObservation) error {
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

func validateControlState(observation ControlStateObservation, scope ControlOutageScope, available bool) error {
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

func validateRegionalSet(observations []RegionalControlObservation) error {
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

func validateConvergedRegionalControl(observations []RegionalControlObservation, mutationID string, requireMutation bool) (uint64, error) {
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

func validateCleanupObservation(cause CleanupCause, observation CleanupObservation) error {
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
