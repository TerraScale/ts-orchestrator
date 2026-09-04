package vmqual

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/vmnet"
)

type faultContractVM struct{ guest Guest }

func (v *faultContractVM) StartReady(context.Context) error { return nil }
func (v *faultContractVM) Stop(context.Context) error       { return nil }
func (v *faultContractVM) Delete(context.Context) error     { return nil }
func (v *faultContractVM) Inspect(context.Context) (VMObservation, error) {
	return VMObservation{ID: v.guest.ID, Region: v.guest.Region, Running: true, Ready: true, MemoryMiB: v.guest.MemoryMiB}, nil
}

type plainFaultFactory struct{}

func (*plainFaultFactory) Create(_ context.Context, guest Guest) (VM, error) {
	return &faultContractVM{guest: guest}, nil
}

type faultContractFactory struct {
	plainFaultFactory
	invalidRecovery string
	outage          bool
	badOutageProbe  bool
	cleanupLeftover bool
}

func (f *faultContractFactory) KillReplaceAndCatchUp(_ context.Context, guest Guest) (HostRecoveryObservation, error) {
	replacement := guest.ID + "-replacement"
	if f.invalidRecovery == "host" {
		replacement = guest.ID
	}
	return HostRecoveryObservation{
		FailedVMID:          guest.ID,
		ReplacementVMID:     replacement,
		FailedVMStopped:     true,
		ReplacementRunning:  true,
		ReplacementReady:    true,
		CatchUpTarget:       41,
		ReplacementCommit:   41,
		ReplacementCaughtUp: true,
	}, nil
}

func (f *faultContractFactory) ExerciseDiskFault(_ context.Context, guest Guest, mode DiskFaultMode) (DiskFaultObservation, error) {
	observation := DiskFaultObservation{
		VMID:                guest.ID,
		Mode:                mode,
		GuestVisible:        true,
		FailureObserved:     mode != DiskFaultExpansion,
		RestartObserved:     mode == DiskFaultMissingAtBoot,
		CorruptionDetected:  mode == DiskFaultCorruption,
		Disposition:         FaultDispositionRepaired,
		RepairAttempted:     true,
		HealthyAfterRepair:  true,
		WritesAdmittedAfter: true,
	}
	if mode == DiskFaultExpansion {
		observation.CapacityBeforeBytes = 1 << 30
		observation.CapacityAfterBytes = 2 << 30
	}
	if mode == DiskFaultIOFailure {
		observation.Disposition = FaultDispositionFailClosed
		observation.RepairAttempted = false
		observation.HealthyAfterRepair = false
		observation.WritesAdmittedAfter = false
		observation.FailClosed = true
	}
	if f.invalidRecovery == string(mode) {
		observation.GuestVisible = false
	}
	return observation, nil
}

func (f *faultContractFactory) ExpireAndRotateCertificate(context.Context, Guest) (CertificateRotationObservation, error) {
	now := time.Unix(1_800_000_000, 0).UTC()
	observation := CertificateRotationObservation{
		ExpiredSerial:   "expired-serial",
		RotatedSerial:   "rotated-serial",
		ExpiredNotAfter: now.Add(-time.Minute),
		RotatedNotAfter: now.Add(time.Hour),
		ObservedAt:      now,
		ExpiredRejected: true,
		RotatedAccepted: true,
		ServiceHealthy:  true,
	}
	if f.invalidRecovery == "certificate" {
		observation.RotatedSerial = observation.ExpiredSerial
	}
	return observation, nil
}

func (f *faultContractFactory) ExhaustA1AndFallback(context.Context, Guest) (ShapeFallbackObservation, error) {
	observation := ShapeFallbackObservation{
		Attempts:             []string{"VM.Standard.A1.Flex", "VM.Standard.E5.Flex"},
		A1CapacityExhausted:  true,
		SelectedShape:        "VM.Standard.E5.Flex",
		SelectedArchitecture: "amd64",
		ReplacementReady:     true,
	}
	if f.invalidRecovery == "shape" {
		observation.Attempts = observation.Attempts[:1]
	}
	return observation, nil
}

func (f *faultContractFactory) SkewClockAndRepair(context.Context, Guest) (ClockFenceObservation, error) {
	observation := ClockFenceObservation{
		InjectedOffset:      750 * time.Millisecond,
		WritesFenced:        true,
		TimeSynchronized:    true,
		RepairedOffset:      10 * time.Millisecond,
		WritesAdmittedAfter: true,
	}
	if f.invalidRecovery == "clock" {
		observation.SuspectHLCMinted = true
	}
	return observation, nil
}

func (f *faultContractFactory) PrepareAdmittedData(context.Context) (AdmittedDataIdentity, error) {
	return AdmittedDataIdentity{RequestID: "admitted-1", PayloadDigest: "sha256:data", ControlEpoch: 3}, nil
}

func (f *faultContractFactory) SetControlOutage(_ context.Context, scope ControlOutageScope, unavailable bool) error {
	if scope != ControlOutageFull {
		return errors.New("unexpected scope")
	}
	f.outage = unavailable
	return nil
}

func (f *faultContractFactory) ObserveControlState(_ context.Context, scope ControlOutageScope) (ControlStateObservation, error) {
	available := !f.outage
	replicas := 3
	if !available {
		replicas = 0
	}
	return ControlStateObservation{Scope: scope, ControlAvailable: available, AvailableReplicas: replicas, AcceptedEpoch: 3}, nil
}

func (f *faultContractFactory) ServeAdmittedData(_ context.Context, identity AdmittedDataIdentity) (AdmittedDataObservation, error) {
	return AdmittedDataObservation{
		RequestID:        identity.RequestID,
		PayloadDigest:    identity.PayloadDigest,
		Served:           true,
		ContactedControl: f.badOutageProbe,
	}, nil
}

func (*faultContractFactory) ExerciseCleanup(_ context.Context, cause CleanupCause) (CleanupExerciseObservation, error) {
	return CleanupExerciseObservation{Cause: cause, CauseObserved: true, CleanupCompleted: true}, nil
}

func (f *faultContractFactory) InspectOwnedResources(_ context.Context, cause CleanupCause) (CleanupObservation, error) {
	observation := CleanupObservation{Cause: cause}
	if f.cleanupLeftover {
		observation.APISockets = []string{"/owned/firecracker.sock"}
	}
	return observation, nil
}

type plainFaultNetwork struct{}

func (*plainFaultNetwork) Apply(context.Context) error   { return nil }
func (*plainFaultNetwork) Cleanup(context.Context) error { return nil }

type faultContractNetwork struct {
	plainFaultNetwork
	active         bool
	pair           RegionPair
	mutationIDs    []string
	mutationOrigin vmnet.RegionCode
	badLocal       bool
	duplicateApply bool
	badHeal        bool
}

func (n *faultContractNetwork) PartitionRegions(_ context.Context, pair RegionPair) error {
	n.active = true
	n.pair = pair
	return nil
}

func (n *faultContractNetwork) HealRegions(_ context.Context, pair RegionPair) error {
	if pair != n.pair {
		return errors.New("wrong pair")
	}
	if !n.badHeal {
		n.active = false
	}
	return nil
}

func (n *faultContractNetwork) ObservePartitionLink(_ context.Context, pair RegionPair) (PartitionLinkObservation, error) {
	return PartitionLinkObservation{Pair: pair, Blocked: n.active && n.pair == pair}, nil
}

func (n *faultContractNetwork) ProbeLocalService(_ context.Context, region vmnet.RegionCode) (LocalServiceObservation, error) {
	servedBy := region
	if n.badLocal && region == vmnet.SFO {
		servedBy = vmnet.GRU
	}
	return LocalServiceObservation{
		RequestedRegion: region,
		ServedByRegion:  servedBy,
		Served:          true,
		Endpoint:        "http://" + strings.ToLower(string(region)) + ".local/health",
		ResponseDigest:  "sha256:healthy",
	}, nil
}

func (n *faultContractNetwork) SubmitPreauthorizedMutation(_ context.Context, region vmnet.RegionCode, mutationID string) error {
	n.mutationOrigin = region
	for _, current := range n.mutationIDs {
		if current == mutationID {
			return nil
		}
	}
	n.mutationIDs = append(n.mutationIDs, mutationID)
	return nil
}

func (n *faultContractNetwork) ObserveRegionalControl(context.Context) ([]RegionalControlObservation, error) {
	result := make([]RegionalControlObservation, 0, 3)
	for _, region := range []vmnet.RegionCode{vmnet.GRU, vmnet.SFO, vmnet.FRA} {
		applications := make(map[string]uint64, len(n.mutationIDs))
		for _, mutationID := range n.mutationIDs {
			if !n.active || region == n.mutationOrigin {
				applications[mutationID] = 1
			}
		}
		digest := fmt.Sprintf("state-%d", len(n.mutationIDs))
		if n.active && region != n.mutationOrigin {
			digest += "-partitioned"
		}
		if n.duplicateApply && len(n.mutationIDs) != 0 {
			applications[n.mutationIDs[len(n.mutationIDs)-1]] = 2
		}
		result = append(result, RegionalControlObservation{
			Region: region, AcceptedEpoch: 3, StateDigest: digest, MutationApplications: applications,
		})
	}
	return result, nil
}

func (*faultContractNetwork) AwaitPartitionConvergence(context.Context, RegionPair) error {
	return nil
}

func newFaultContractStack(t *testing.T, factory VMFactory, network NetworkController) *Stack {
	t.Helper()
	stack, err := NewStack(StackConfig{Guests: LaunchGuests(256), VMFactory: factory, Network: network})
	if err != nil {
		t.Fatal(err)
	}
	if err := stack.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := stack.Cleanup(context.Background()); err != nil {
			t.Errorf("stack cleanup: %v", err)
		}
	})
	return stack
}

func TestFaultContractsQualifyStateTransitions(t *testing.T) {
	factory := &faultContractFactory{}
	network := &faultContractNetwork{}
	stack := newFaultContractStack(t, factory, network)

	recovery, err := QualifyRecoveryFaults(context.Background(), stack)
	if err != nil {
		t.Fatalf("recovery faults: %v", err)
	}
	if recovery.Host.ReplacementVMID == recovery.Host.FailedVMID || len(recovery.Disk) != len(requiredDiskFaultModes) {
		t.Fatalf("recovery result = %+v", recovery)
	}
	outage, err := QualifyControlOutage(context.Background(), stack)
	if err != nil {
		t.Fatalf("control outage: %v", err)
	}
	if outage.During.ControlAvailable || !outage.Probe.Served || !outage.After.ControlAvailable {
		t.Fatalf("outage result = %+v", outage)
	}
	partitions, err := QualifyCrossRegionPartitions(context.Background(), stack)
	if err != nil {
		t.Fatalf("partitions: %v", err)
	}
	if len(partitions.Pairs) != len(requiredRegionPairs) || network.active {
		t.Fatalf("partition result = %+v, active=%v", partitions, network.active)
	}
	cleanup, err := QualifyCleanupFaults(context.Background(), stack)
	if err != nil {
		t.Fatalf("cleanup faults: %v", err)
	}
	if len(cleanup.Exercises) != len(requiredCleanupCauses) || len(cleanup.Observations) != len(requiredCleanupCauses) {
		t.Fatalf("cleanup result = %+v", cleanup)
	}
}

func TestFaultContractsRequireRealCapabilities(t *testing.T) {
	stack := newFaultContractStack(t, &plainFaultFactory{}, &plainFaultNetwork{})
	checks := []struct {
		name string
		run  func() error
	}{
		{name: "recovery", run: func() error { _, err := QualifyRecoveryFaults(context.Background(), stack); return err }},
		{name: "control outage", run: func() error { _, err := QualifyControlOutage(context.Background(), stack); return err }},
		{name: "partition", run: func() error { _, err := QualifyCrossRegionPartitions(context.Background(), stack); return err }},
		{name: "cleanup", run: func() error { _, err := QualifyCleanupFaults(context.Background(), stack); return err }},
	}
	for _, check := range checks {
		t.Run(check.name, func(t *testing.T) {
			if err := check.run(); err == nil || !strings.Contains(err.Error(), "contract") {
				t.Fatalf("error = %v, want missing contract", err)
			}
		})
	}
}

func TestRecoveryFaultContractRejectsUnprovenOutcomes(t *testing.T) {
	cases := []string{"host", string(DiskFaultENOSPC), string(DiskFaultIOFailure), string(DiskFaultReadOnly), string(DiskFaultMissingAtBoot), string(DiskFaultExpansion), string(DiskFaultCorruption), "certificate", "shape", "clock"}
	for _, invalid := range cases {
		t.Run(invalid, func(t *testing.T) {
			factory := &faultContractFactory{invalidRecovery: invalid}
			stack := newFaultContractStack(t, factory, &faultContractNetwork{})
			if _, err := QualifyRecoveryFaults(context.Background(), stack); err == nil {
				t.Fatal("unproven recovery outcome passed")
			}
		})
	}
}

func TestControlOutageRejectsControlDependentProbeAndAlwaysHeals(t *testing.T) {
	factory := &faultContractFactory{badOutageProbe: true}
	stack := newFaultContractStack(t, factory, &faultContractNetwork{})
	if _, err := QualifyControlOutage(context.Background(), stack); err == nil {
		t.Fatal("control-dependent data path passed")
	}
	if factory.outage {
		t.Fatal("failed outage assertion left control disabled")
	}
}

func TestPartitionRejectsNonLocalServiceAndAlwaysHeals(t *testing.T) {
	network := &faultContractNetwork{badLocal: true}
	stack := newFaultContractStack(t, &faultContractFactory{}, network)
	if _, err := QualifyCrossRegionPartitions(context.Background(), stack); err == nil {
		t.Fatal("non-local service passed")
	}
	if network.active {
		t.Fatal("failed partition assertion left link blocked")
	}
}

func TestPartitionRejectsDuplicateMutationAndUnhealedLink(t *testing.T) {
	for _, test := range []struct {
		name string
		net  *faultContractNetwork
	}{
		{name: "duplicate", net: &faultContractNetwork{duplicateApply: true}},
		{name: "unhealed", net: &faultContractNetwork{badHeal: true}},
	} {
		t.Run(test.name, func(t *testing.T) {
			stack := newFaultContractStack(t, &faultContractFactory{}, test.net)
			if _, err := QualifyCrossRegionPartitions(context.Background(), stack); err == nil {
				t.Fatal("unsafe partition outcome passed")
			}
		})
	}
}

func TestCleanupRejectsAnyOwnedResource(t *testing.T) {
	factory := &faultContractFactory{cleanupLeftover: true}
	stack := newFaultContractStack(t, factory, &faultContractNetwork{})
	if _, err := QualifyCleanupFaults(context.Background(), stack); err == nil {
		t.Fatal("cleanup with owned API socket passed")
	}
}

func TestFaultContractsRequireLiveStackAndContext(t *testing.T) {
	if _, err := QualifyRecoveryFaults(nil, nil); err == nil {
		t.Fatal("nil context and stack passed")
	}
	stack, err := NewStack(StackConfig{Guests: LaunchGuests(256), VMFactory: &faultContractFactory{}, Network: &faultContractNetwork{}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := QualifyRecoveryFaults(context.Background(), stack); err == nil {
		t.Fatal("unstarted stack passed")
	}
}
