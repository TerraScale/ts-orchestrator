package vmqualsuite

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/vmnet"
	"terrascale.tech/orchestrator/src/orchestrator/vmqual"
)

type faultContractVM struct{ guest vmqual.Guest }

func (v *faultContractVM) StartReady(context.Context) error { return nil }
func (v *faultContractVM) Stop(context.Context) error       { return nil }
func (v *faultContractVM) Delete(context.Context) error     { return nil }
func (v *faultContractVM) Inspect(context.Context) (vmqual.VMObservation, error) {
	return vmqual.VMObservation{ID: v.guest.ID, Region: v.guest.Region, Running: true, Ready: true, MemoryMiB: v.guest.MemoryMiB}, nil
}

type plainFaultFactory struct{}

func (*plainFaultFactory) Create(_ context.Context, guest vmqual.Guest) (vmqual.VM, error) {
	return &faultContractVM{guest: guest}, nil
}

type faultContractFactory struct {
	plainFaultFactory
	invalidRecovery string
	outage          bool
	badOutageProbe  bool
	cleanupLeftover bool
}

func (f *faultContractFactory) KillReplaceAndCatchUp(_ context.Context, guest vmqual.Guest) (vmqual.HostRecoveryObservation, error) {
	replacement := guest.ID + "-replacement"
	if f.invalidRecovery == "host" {
		replacement = guest.ID
	}
	return vmqual.HostRecoveryObservation{
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

func (f *faultContractFactory) ExerciseDiskFault(_ context.Context, guest vmqual.Guest, mode vmqual.DiskFaultMode) (vmqual.DiskFaultObservation, error) {
	observation := vmqual.DiskFaultObservation{
		VMID:                guest.ID,
		Mode:                mode,
		GuestVisible:        true,
		FailureObserved:     mode != vmqual.DiskFaultExpansion,
		RestartObserved:     mode == vmqual.DiskFaultMissingAtBoot,
		CorruptionDetected:  mode == vmqual.DiskFaultCorruption,
		Disposition:         vmqual.FaultDispositionRepaired,
		RepairAttempted:     true,
		HealthyAfterRepair:  true,
		WritesAdmittedAfter: true,
	}
	if mode == vmqual.DiskFaultExpansion {
		observation.CapacityBeforeBytes = 1 << 30
		observation.CapacityAfterBytes = 2 << 30
	}
	if mode == vmqual.DiskFaultIOFailure {
		observation.Disposition = vmqual.FaultDispositionFailClosed
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

func (f *faultContractFactory) ExpireAndRotateCertificate(context.Context, vmqual.Guest) (vmqual.CertificateRotationObservation, error) {
	now := time.Unix(1_800_000_000, 0).UTC()
	observation := vmqual.CertificateRotationObservation{
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

func (f *faultContractFactory) ExhaustA1AndFallback(context.Context, vmqual.Guest) (vmqual.ShapeFallbackObservation, error) {
	observation := vmqual.ShapeFallbackObservation{
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

func (f *faultContractFactory) SkewClockAndRepair(context.Context, vmqual.Guest) (vmqual.ClockFenceObservation, error) {
	observation := vmqual.ClockFenceObservation{
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

func (f *faultContractFactory) PrepareAdmittedData(context.Context) (vmqual.AdmittedDataIdentity, error) {
	return vmqual.AdmittedDataIdentity{RequestID: "admitted-1", PayloadDigest: "sha256:data", ControlEpoch: 3}, nil
}

func (f *faultContractFactory) SetControlOutage(_ context.Context, scope vmqual.ControlOutageScope, unavailable bool) error {
	if scope != vmqual.ControlOutageFull {
		return errors.New("unexpected scope")
	}
	f.outage = unavailable
	return nil
}

func (f *faultContractFactory) ObserveControlState(_ context.Context, scope vmqual.ControlOutageScope) (vmqual.ControlStateObservation, error) {
	available := !f.outage
	replicas := 3
	if !available {
		replicas = 0
	}
	return vmqual.ControlStateObservation{Scope: scope, ControlAvailable: available, AvailableReplicas: replicas, AcceptedEpoch: 3}, nil
}

func (f *faultContractFactory) ServeAdmittedData(_ context.Context, identity vmqual.AdmittedDataIdentity) (vmqual.AdmittedDataObservation, error) {
	return vmqual.AdmittedDataObservation{
		RequestID:        identity.RequestID,
		PayloadDigest:    identity.PayloadDigest,
		Served:           true,
		ContactedControl: f.badOutageProbe,
	}, nil
}

func (*faultContractFactory) ExerciseCleanup(_ context.Context, cause vmqual.CleanupCause) (vmqual.CleanupExerciseObservation, error) {
	return vmqual.CleanupExerciseObservation{Cause: cause, CauseObserved: true, CleanupCompleted: true}, nil
}

func (f *faultContractFactory) InspectOwnedResources(_ context.Context, cause vmqual.CleanupCause) (vmqual.CleanupObservation, error) {
	observation := vmqual.CleanupObservation{Cause: cause}
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
	pair           vmqual.RegionPair
	mutationIDs    []string
	mutationOrigin vmnet.RegionCode
	badLocal       bool
	duplicateApply bool
	badHeal        bool
}

func (n *faultContractNetwork) PartitionRegions(_ context.Context, pair vmqual.RegionPair) error {
	n.active = true
	n.pair = pair
	return nil
}

func (n *faultContractNetwork) HealRegions(_ context.Context, pair vmqual.RegionPair) error {
	if pair != n.pair {
		return errors.New("wrong pair")
	}
	if !n.badHeal {
		n.active = false
	}
	return nil
}

func (n *faultContractNetwork) ObservePartitionLink(_ context.Context, pair vmqual.RegionPair) (vmqual.PartitionLinkObservation, error) {
	return vmqual.PartitionLinkObservation{Pair: pair, Blocked: n.active && n.pair == pair}, nil
}

func (n *faultContractNetwork) ProbeLocalService(_ context.Context, region vmnet.RegionCode) (vmqual.LocalServiceObservation, error) {
	servedBy := region
	if n.badLocal && region == vmnet.SFO {
		servedBy = vmnet.GRU
	}
	return vmqual.LocalServiceObservation{
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

func (n *faultContractNetwork) ObserveRegionalControl(context.Context) ([]vmqual.RegionalControlObservation, error) {
	result := make([]vmqual.RegionalControlObservation, 0, 3)
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
		result = append(result, vmqual.RegionalControlObservation{
			Region: region, AcceptedEpoch: 3, StateDigest: digest, MutationApplications: applications,
		})
	}
	return result, nil
}

func (*faultContractNetwork) AwaitPartitionConvergence(context.Context, vmqual.RegionPair) error {
	return nil
}

func newFaultContractStack(t *testing.T, factory vmqual.VMFactory, network vmqual.NetworkController) *vmqual.Stack {
	t.Helper()
	stack, err := vmqual.NewStack(vmqual.StackConfig{Guests: vmqual.LaunchGuests(256), VMFactory: factory, Network: network})
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
	if recovery.Host.ReplacementVMID == recovery.Host.FailedVMID || len(recovery.Disk) != len(vmqual.RequiredDiskFaultModes()) {
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
	if len(partitions.Pairs) != len(vmqual.RequiredCrossRegionPairs()) || network.active {
		t.Fatalf("partition result = %+v, active=%v", partitions, network.active)
	}
	cleanup, err := QualifyCleanupFaults(context.Background(), stack)
	if err != nil {
		t.Fatalf("cleanup faults: %v", err)
	}
	if len(cleanup.Exercises) != len(vmqual.RequiredCleanupCauses()) || len(cleanup.Observations) != len(vmqual.RequiredCleanupCauses()) {
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
	cases := []string{"host", string(vmqual.DiskFaultENOSPC), string(vmqual.DiskFaultIOFailure), string(vmqual.DiskFaultReadOnly), string(vmqual.DiskFaultMissingAtBoot), string(vmqual.DiskFaultExpansion), string(vmqual.DiskFaultCorruption), "certificate", "shape", "clock"}
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
	stack, err := vmqual.NewStack(vmqual.StackConfig{Guests: vmqual.LaunchGuests(256), VMFactory: &faultContractFactory{}, Network: &faultContractNetwork{}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := QualifyRecoveryFaults(context.Background(), stack); err == nil {
		t.Fatal("unstarted stack passed")
	}
}
