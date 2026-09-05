package vmqual

import (
	"context"
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

func RequiredCleanupCauses() []CleanupCause {
	return append([]CleanupCause(nil), requiredCleanupCauses[:]...)
}
