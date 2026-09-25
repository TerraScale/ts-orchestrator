package placement

import (
	"crypto/sha256"
	"encoding/hex"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/oci"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
)

func TestDesiredSeatsContainsExactlyTwoAntiAffineMembersPerSelectedRegion(t *testing.T) {
	intent := validIntent(oci.RegionFRA, oci.RegionGRU)
	faultDomains := map[oci.Region][]string{
		oci.RegionGRU: {"FAULT-DOMAIN-1", "FAULT-DOMAIN-2"},
		oci.RegionFRA: {"FAULT-DOMAIN-2", "FAULT-DOMAIN-3"},
		oci.RegionSFO: {"FAULT-DOMAIN-1", "FAULT-DOMAIN-2"},
	}

	seats, err := DesiredSeats(intent, faultDomains)
	if err != nil {
		t.Fatal(err)
	}
	want := []Seat{
		{MemberID: "permanent-a", Region: oci.RegionGRU, FailureDomain: "FAULT-DOMAIN-1", Kind: MemberPermanent},
		{MemberID: "elastic-gru", Region: oci.RegionGRU, FailureDomain: "FAULT-DOMAIN-2", Kind: MemberElastic},
		{MemberID: "permanent-c", Region: oci.RegionFRA, FailureDomain: "FAULT-DOMAIN-2", Kind: MemberPermanent},
		{MemberID: "elastic-fra", Region: oci.RegionFRA, FailureDomain: "FAULT-DOMAIN-3", Kind: MemberElastic},
	}
	if !reflect.DeepEqual(seats, want) {
		t.Fatalf("seats = %#v, want %#v", seats, want)
	}
}

func TestDesiredSeatsRejectsSameFailureDomain(t *testing.T) {
	_, err := DesiredSeats(validIntent(oci.RegionGRU), map[oci.Region][]string{
		oci.RegionGRU: {"FAULT-DOMAIN-1", "FAULT-DOMAIN-1"},
	})
	if err == nil {
		t.Fatal("expected duplicate failure domain to be rejected")
	}
}

func TestIntentRejectsUnselectedRegionAliasesDuplicatesAndStaleGeneration(t *testing.T) {
	cases := []Intent{
		{SchemaVersion: IntentSchemaVersion, DatabaseID: "db", PartitionID: "p0", ActiveRegions: []oci.Region{"LAX"}, Generation: 1},
		{SchemaVersion: legacyIntentSchemaVersion, DatabaseID: "db", PartitionID: "p0", ActiveRegions: []oci.Region{oci.RegionGRU, oci.RegionGRU}, Generation: 1},
		{SchemaVersion: IntentSchemaVersion, DatabaseID: "db", PartitionID: "p0", ActiveRegions: []oci.Region{oci.RegionGRU}, Generation: 0},
	}
	for _, intent := range cases {
		if err := intent.Validate(); err == nil {
			t.Fatalf("intent accepted invalid target: %#v", intent)
		}
	}
}

func TestManagedIntentRoundTripsCanonicalPayloadAndRegionProfileDigest(t *testing.T) {
	intent := validIntent(oci.RegionFRA, oci.RegionGRU)
	if err := intent.ValidateForAdmission(); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(intent.ActiveRegions, []oci.Region{oci.RegionGRU, oci.RegionFRA}) ||
		len(intent.ManagedHostProfiles) != len(intent.ActiveRegions) {
		t.Fatalf("intent regions/profiles are not canonical: %+v", intent)
	}

	payload, err := protocol.EncodeJSON(intent)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeCommittedIntent(payload)
	if err != nil {
		t.Fatalf("decode canonical committed payload: %v", err)
	}
	wantPayloadDigest := sha256.Sum256(payload)
	if decoded.PayloadDigest() != hex.EncodeToString(wantPayloadDigest[:]) {
		t.Fatalf("committed payload digest = %q, want exact payload SHA-256", decoded.PayloadDigest())
	}
	if !slices.Equal(decoded.ManagedHostProfiles, intent.ManagedHostProfiles) {
		t.Fatalf("round-trip profiles = %+v, want %+v", decoded.ManagedHostProfiles, intent.ManagedHostProfiles)
	}
	profile, err := decoded.ManagedHostProfile(oci.RegionGRU)
	if err != nil {
		t.Fatal(err)
	}
	encodedProfile, err := protocol.EncodeJSON(profile)
	if err != nil {
		t.Fatal(err)
	}
	wantProfileDigest := sha256.Sum256(encodedProfile)
	gotProfileDigest, err := decoded.ProfileDigest(oci.RegionGRU)
	if err != nil || gotProfileDigest != hex.EncodeToString(wantProfileDigest[:]) {
		t.Fatalf("profile digest = %q, %v; want %x", gotProfileDigest, err, wantProfileDigest)
	}
	if _, err := decoded.ProfileDigest(oci.RegionSFO); err == nil {
		t.Fatal("profile lookup accepted an unselected region")
	}
}

func TestManagedIntentRejectsIncompleteForeignDuplicateAndUnsafeProfiles(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Intent)
	}{
		{name: "missing profile", mutate: func(intent *Intent) { intent.ManagedHostProfiles = intent.ManagedHostProfiles[:1] }},
		{name: "foreign profile", mutate: func(intent *Intent) { intent.ManagedHostProfiles[1].Region = oci.RegionSFO }},
		{name: "duplicate profile", mutate: func(intent *Intent) { intent.ManagedHostProfiles[1] = intent.ManagedHostProfiles[0] }},
		{name: "unsorted selected regions", mutate: func(intent *Intent) {
			intent.ActiveRegions[0], intent.ActiveRegions[1] = intent.ActiveRegions[1], intent.ActiveRegions[0]
		}},
		{name: "missing compute shape", mutate: func(intent *Intent) { intent.ManagedHostProfiles[0].Compute.Shape = "" }},
		{name: "fractional OCPU cannot be represented", mutate: func(intent *Intent) { intent.ManagedHostProfiles[0].Compute.WholeOCPUs = 0 }},
		{name: "missing memory tuple", mutate: func(intent *Intent) { intent.ManagedHostProfiles[0].Compute.MemoryInGBs = 0 }},
		{name: "process memory below minimum", mutate: func(intent *Intent) {
			intent.ManagedHostProfiles[0].ProcessMemoryBytes = 4*managedMemoryGiB - managedMemoryPageBytes
		}},
		{name: "headroom below quarter", mutate: func(intent *Intent) {
			profile := &intent.ManagedHostProfiles[0]
			profile.ProcessMemoryBytes = 8 * managedMemoryGiB
			profile.MemoryHeadroomBytes = managedMemoryGiB
			profile.CgroupMemoryMaxBytes = 8 * managedMemoryGiB
			profile.AllocatableMemoryBytes = 8 * managedMemoryGiB
		}},
		{name: "headroom outside process memory", mutate: func(intent *Intent) {
			intent.ManagedHostProfiles[0].MemoryHeadroomBytes = intent.ManagedHostProfiles[0].ProcessMemoryBytes
		}},
		{name: "cgroup below process limit", mutate: func(intent *Intent) {
			intent.ManagedHostProfiles[0].CgroupMemoryMaxBytes = intent.ManagedHostProfiles[0].ProcessMemoryBytes - managedMemoryPageBytes
		}},
		{name: "allocatable below cgroup", mutate: func(intent *Intent) {
			intent.ManagedHostProfiles[0].AllocatableMemoryBytes = intent.ManagedHostProfiles[0].CgroupMemoryMaxBytes - managedMemoryPageBytes
		}},
		{name: "missing system reserve", mutate: func(intent *Intent) { intent.ManagedHostProfiles[0].SystemReserveBytes = 0 }},
		{name: "non-page-aligned bytes", mutate: func(intent *Intent) { intent.ManagedHostProfiles[0].AllocatableMemoryBytes++ }},
		{name: "outside signed integer range", mutate: func(intent *Intent) {
			intent.ManagedHostProfiles[0].AllocatableMemoryBytes = maxManagedMemoryByteValue + 1
		}},
		{name: "allocatable plus reserve exceeds signed integer range", mutate: func(intent *Intent) {
			intent.ManagedHostProfiles[0].AllocatableMemoryBytes = maxManagedMemoryByteValue &^ (managedMemoryPageBytes - 1)
		}},
		{name: "allocatable plus reserve exceeds nominal compute memory", mutate: func(intent *Intent) {
			profile := &intent.ManagedHostProfiles[0]
			profile.CgroupMemoryMaxBytes = 6 * managedMemoryGiB
			profile.AllocatableMemoryBytes = 6 * managedMemoryGiB
		}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			intent := validIntent(oci.RegionGRU, oci.RegionFRA)
			test.mutate(&intent)
			if err := intent.ValidateForAdmission(); err == nil {
				t.Fatal("unsafe or noncanonical managed profile was accepted")
			}
		})
	}
}

func TestManagedProfileAcceptsAllocatablePlusReserveAtNominalComputeMemory(t *testing.T) {
	profile := testManagedHostProfile(oci.RegionGRU)
	if profile.AllocatableMemoryBytes+profile.SystemReserveBytes != uint64(profile.Compute.MemoryInGBs)*managedMemoryGiB {
		t.Fatal("test fixture does not sit exactly at the nominal compute-memory upper bound")
	}
	if err := profile.Validate(); err != nil {
		t.Fatalf("profile at nominal compute-memory upper bound was rejected: %v", err)
	}
}

func TestMemberStateManagedProfilePinsAreAdditiveAndValidated(t *testing.T) {
	state := validMemberStateForPins()
	if err := state.Validate(); err != nil {
		t.Fatalf("legacy unpinned member state should remain readable: %v", err)
	}

	profile := testManagedHostProfile(oci.RegionGRU)
	profileDigest, err := profile.ProfileDigest()
	if err != nil {
		t.Fatal(err)
	}
	payload := Intent{
		SchemaVersion: IntentSchemaVersion, DatabaseID: state.DatabaseID, PartitionID: state.PartitionID,
		ActiveRegions: []oci.Region{oci.RegionGRU}, Generation: state.IntentGeneration,
		ManagedHostProfiles: []ManagedHostProfile{profile},
	}
	encoded, err := protocol.EncodeJSON(payload)
	if err != nil {
		t.Fatal(err)
	}
	payloadDigest := sha256.Sum256(encoded)
	state.IntentPayloadDigest = hex.EncodeToString(payloadDigest[:])
	state.ManagedHostProfile = profile
	state.ManagedHostProfileDigest = profileDigest
	if err := state.Validate(); err != nil {
		t.Fatalf("valid managed member-state pins were rejected: %v", err)
	}
	encodedState, err := protocol.EncodeJSON(state)
	if err != nil {
		t.Fatal(err)
	}
	var decodedState MemberState
	if err := protocol.DecodeStrict(encodedState, &decodedState, maxStateBytes); err != nil {
		t.Fatalf("decode persisted managed member state: %v", err)
	}
	if !reflect.DeepEqual(decodedState, state) {
		t.Fatalf("persisted managed member state = %+v, want %+v", decodedState, state)
	}

	invalid := []struct {
		name   string
		mutate func(*MemberState)
	}{
		{name: "partial pins", mutate: func(state *MemberState) { state.ManagedHostProfileDigest = "" }},
		{name: "uppercase payload digest", mutate: func(state *MemberState) { state.IntentPayloadDigest = "A" + strings.Repeat("a", 63) }},
		{name: "profile digest mismatch", mutate: func(state *MemberState) { state.ManagedHostProfileDigest = strings.Repeat("0", 64) }},
		{name: "foreign profile region", mutate: func(state *MemberState) { state.ManagedHostProfile.Region = oci.RegionSFO }},
		{name: "invalid profile values", mutate: func(state *MemberState) { state.ManagedHostProfile.SystemReserveBytes = 0 }},
	}
	for _, test := range invalid {
		t.Run(test.name, func(t *testing.T) {
			candidate := state
			test.mutate(&candidate)
			if err := candidate.Validate(); err == nil {
				t.Fatal("invalid managed profile pins were accepted")
			}
		})
	}
}

func validMemberStateForPins() MemberState {
	return MemberState{
		SchemaVersion: placementSchemaVersion, DatabaseID: "db-main", PartitionID: "partition-a",
		MemberID: permanentMember(oci.RegionGRU), Region: oci.RegionGRU, FailureDomain: "fault-domain-1",
		Kind: MemberPermanent, Stage: StagePreparedHost, CreateKey: "member-create-key", HostAttempt: 1,
		IntentGeneration: 1, OperationID: "member-operation", UpdatedAt: time.Now().UTC(),
	}
}

func TestHistoricalIntentIsReadableButNotAdmissible(t *testing.T) {
	legacy := Intent{
		SchemaVersion: legacyIntentSchemaVersion, DatabaseID: "db-main", PartitionID: "partition-a",
		ActiveRegions: []oci.Region{oci.RegionGRU}, Generation: 1,
	}
	payload, err := protocol.EncodeJSON(legacy)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeCommittedIntent(payload)
	if err != nil || decoded.PayloadDigest() == "" {
		t.Fatalf("historical committed intent read = %+v, %v", decoded, err)
	}
	if err := decoded.ValidateForAdmission(); err == nil {
		t.Fatal("historical schema-1 intent authorized a new managed placement")
	}
}

func TestCanRetireRequiresEveryIndependentSafetyProof(t *testing.T) {
	intent := validIntent(oci.RegionGRU, oci.RegionSFO)
	candidate := testCandidate()
	survivors := healthyMembers(
		MemberObservation{MemberID: "permanent-a", Region: oci.RegionGRU, FailureDomain: "fd-a"},
		MemberObservation{MemberID: "elastic-gru", Region: oci.RegionGRU, FailureDomain: "fd-b"},
		MemberObservation{MemberID: "permanent-b", Region: oci.RegionSFO, FailureDomain: "fd-a"},
		MemberObservation{MemberID: "elastic-sfo", Region: oci.RegionSFO, FailureDomain: "fd-c"},
	)
	complete := RetirementEvidence{
		DatabaseID:         candidate.DatabaseID,
		PartitionID:        candidate.PartitionID,
		MemberID:           candidate.MemberID,
		InstanceID:         candidate.InstanceID,
		VolumeID:           candidate.VolumeID,
		ReplicationHealthy: true,
		QuorumSafe:         true,
		HostDrained:        true,
		WriterStopped:      true,
		WriterStopProof:    []byte("verified-proof"),
		VolumeRetained:     true,
	}
	if allowed, reason := CanRetire(intent, candidate, survivors, complete); !allowed || reason != "safe-to-retire" {
		t.Fatalf("complete proof gate = (%v, %q), want safe", allowed, reason)
	}

	checks := []struct {
		name   string
		mutate func(*RetirementEvidence)
	}{
		{name: "replication", mutate: func(proof *RetirementEvidence) { proof.ReplicationHealthy = false }},
		{name: "quorum", mutate: func(proof *RetirementEvidence) { proof.QuorumSafe = false }},
		{name: "host drain", mutate: func(proof *RetirementEvidence) { proof.HostDrained = false }},
		{name: "writer stop", mutate: func(proof *RetirementEvidence) { proof.WriterStopped = false }},
		{name: "writer evidence", mutate: func(proof *RetirementEvidence) { proof.WriterStopProof = nil }},
		{name: "volume retention", mutate: func(proof *RetirementEvidence) { proof.VolumeRetained = false }},
	}
	for _, check := range checks {
		t.Run(check.name, func(t *testing.T) {
			proof := complete
			proof.WriterStopProof = append([]byte(nil), complete.WriterStopProof...)
			check.mutate(&proof)
			if allowed, reason := CanRetire(intent, candidate, survivors, proof); allowed || reason == "safe-to-retire" {
				t.Fatalf("incomplete %s proof allowed removal", check.name)
			}
		})
	}
}

func TestCanRetireHoldsWhenReplicaFloorOrAntiAffinityIsLost(t *testing.T) {
	intent := validIntent(oci.RegionGRU, oci.RegionSFO)
	candidate := testCandidate()
	proof := RetirementEvidence{
		DatabaseID:         candidate.DatabaseID,
		PartitionID:        candidate.PartitionID,
		MemberID:           candidate.MemberID,
		InstanceID:         candidate.InstanceID,
		VolumeID:           candidate.VolumeID,
		ReplicationHealthy: true,
		QuorumSafe:         true,
		HostDrained:        true,
		WriterStopped:      true,
		WriterStopProof:    []byte("verified-proof"),
		VolumeRetained:     true,
	}

	oneShort := healthyMembers(
		MemberObservation{MemberID: "permanent-a", Region: oci.RegionGRU, FailureDomain: "fd-a"},
		MemberObservation{MemberID: "permanent-b", Region: oci.RegionSFO, FailureDomain: "fd-a"},
		MemberObservation{MemberID: "elastic-sfo", Region: oci.RegionSFO, FailureDomain: "fd-c"},
	)
	if allowed, reason := CanRetire(intent, candidate, oneShort, proof); allowed || reason != "replica-floor-or-health-not-met" {
		t.Fatalf("replica floor gate = (%v, %q)", allowed, reason)
	}

	duplicateDomain := healthyMembers(
		MemberObservation{MemberID: "permanent-a", Region: oci.RegionGRU, FailureDomain: "fd-a"},
		MemberObservation{MemberID: "elastic-gru", Region: oci.RegionGRU, FailureDomain: "fd-a"},
		MemberObservation{MemberID: "permanent-b", Region: oci.RegionSFO, FailureDomain: "fd-a"},
		MemberObservation{MemberID: "elastic-sfo", Region: oci.RegionSFO, FailureDomain: "fd-c"},
	)
	if allowed, reason := CanRetire(intent, candidate, duplicateDomain, proof); allowed || reason != "survivor-anti-affinity-violated" {
		t.Fatalf("anti-affinity gate = (%v, %q)", allowed, reason)
	}
}

func TestCanRetireNeverRemovesAStillDesiredSeat(t *testing.T) {
	intent := validIntent(oci.RegionGRU)
	candidate := testCandidate()
	candidate.MemberID = "permanent-a"
	candidate.Region = oci.RegionGRU
	proof := RetirementEvidence{
		DatabaseID:         candidate.DatabaseID,
		PartitionID:        candidate.PartitionID,
		MemberID:           candidate.MemberID,
		InstanceID:         candidate.InstanceID,
		VolumeID:           candidate.VolumeID,
		ReplicationHealthy: true,
		QuorumSafe:         true,
		HostDrained:        true,
		WriterStopped:      true,
		WriterStopProof:    []byte("verified-proof"),
		VolumeRetained:     true,
	}
	if allowed, reason := CanRetire(intent, candidate, healthyMembers(
		MemberObservation{MemberID: "permanent-a", Region: oci.RegionGRU, FailureDomain: "fd-a"},
		MemberObservation{MemberID: "elastic-gru", Region: oci.RegionGRU, FailureDomain: "fd-b"},
	), proof); allowed || reason != "candidate-still-desired" {
		t.Fatalf("desired member retirement gate = (%v, %q)", allowed, reason)
	}
}

func TestCanRetireDoesNotCountPreparedOrAwaitingMembersAsServing(t *testing.T) {
	intent := validIntent(oci.RegionGRU)
	candidate := testCandidate()
	candidate.MemberID = "extra-member"
	candidate.Region = oci.RegionFRA
	survivors := healthyMembers(
		MemberObservation{MemberID: "permanent-a", Region: oci.RegionGRU, FailureDomain: "fd-a"},
		MemberObservation{MemberID: "elastic-gru", Region: oci.RegionGRU, FailureDomain: "fd-b"},
	)
	survivors[1].Stage = StageAwaitingHealthy
	proof := RetirementEvidence{
		DatabaseID:         candidate.DatabaseID,
		PartitionID:        candidate.PartitionID,
		MemberID:           candidate.MemberID,
		InstanceID:         candidate.InstanceID,
		VolumeID:           candidate.VolumeID,
		ReplicationHealthy: true,
		QuorumSafe:         true,
		HostDrained:        true,
		WriterStopped:      true,
		WriterStopProof:    []byte("verified-proof"),
		VolumeRetained:     true,
	}
	if allowed, reason := CanRetire(intent, candidate, survivors, proof); allowed || reason != "replica-floor-or-health-not-met" {
		t.Fatalf("non-serving survivor was counted: (%v, %q)", allowed, reason)
	}
}

func healthyMembers(members ...MemberObservation) []MemberObservation {
	for index := range members {
		members[index].DatabaseID = "db-main"
		members[index].PartitionID = "partition-a"
		members[index].Healthy = true
		members[index].CurrentSession = true
		members[index].Stage = StageServing
	}
	return members
}

func testCandidate() MemberObservation {
	return MemberObservation{
		DatabaseID: "db-main", PartitionID: "partition-a", MemberID: "elastic-fra", Region: oci.RegionFRA,
		InstanceID: "instance-fra", VolumeID: "volume-fra", Stage: StageServing,
	}
}

func TestCanRetireDoesNotCountHealthySurvivorsFromAnotherPartition(t *testing.T) {
	intent := validIntent(oci.RegionGRU)
	candidate := testCandidate()
	proof := RetirementEvidence{
		DatabaseID: candidate.DatabaseID, PartitionID: candidate.PartitionID, MemberID: candidate.MemberID,
		InstanceID: candidate.InstanceID, VolumeID: candidate.VolumeID,
		ReplicationHealthy: true, QuorumSafe: true, HostDrained: true, WriterStopped: true,
		WriterStopProof: []byte("verified-proof"), VolumeRetained: true,
	}
	survivors := healthyMembers(
		MemberObservation{MemberID: "permanent-a", Region: oci.RegionGRU, FailureDomain: "fd-a"},
		MemberObservation{MemberID: "elastic-gru", Region: oci.RegionGRU, FailureDomain: "fd-b"},
	)
	for index := range survivors {
		survivors[index].PartitionID = "another-partition"
	}
	if allowed, reason := CanRetire(intent, candidate, survivors, proof); allowed || reason != "survivor-identity-mismatch" {
		t.Fatalf("another partition authorized retirement: (%v, %q)", allowed, reason)
	}
}

func validIntent(regions ...oci.Region) Intent {
	selected := make(map[oci.Region]struct{}, len(regions))
	for _, region := range regions {
		selected[region] = struct{}{}
	}
	active := make([]oci.Region, 0, len(selected))
	profiles := make([]ManagedHostProfile, 0, len(selected))
	for _, region := range regionsInOrder {
		if _, exists := selected[region]; !exists {
			continue
		}
		active = append(active, region)
		profiles = append(profiles, testManagedHostProfile(region))
	}
	return Intent{
		SchemaVersion:       IntentSchemaVersion,
		DatabaseID:          "db-main",
		PartitionID:         "partition-a",
		ActiveRegions:       active,
		Generation:          1,
		ManagedHostProfiles: profiles,
	}
}

func testManagedHostProfile(region oci.Region) ManagedHostProfile {
	return ManagedHostProfile{
		Region:             region,
		Compute:            ComputeTuple{Shape: "VM.Standard.E4.Flex", WholeOCPUs: 1, MemoryInGBs: 6},
		ProcessMemoryBytes: 4 * managedMemoryGiB, MemoryHeadroomBytes: managedMemoryGiB,
		CgroupMemoryMaxBytes: 4 * managedMemoryGiB, SystemReserveBytes: managedMemoryGiB,
		AllocatableMemoryBytes: 5 * managedMemoryGiB,
	}
}
