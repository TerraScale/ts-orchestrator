package placement

import (
	"reflect"
	"testing"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/oci"
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
		{SchemaVersion: 1, DatabaseID: "db", PartitionID: "p0", ActiveRegions: []oci.Region{"LAX"}, Generation: 1},
		{SchemaVersion: 1, DatabaseID: "db", PartitionID: "p0", ActiveRegions: []oci.Region{oci.RegionGRU, oci.RegionGRU}, Generation: 1},
		{SchemaVersion: 1, DatabaseID: "db", PartitionID: "p0", ActiveRegions: []oci.Region{oci.RegionGRU}, Generation: 0},
	}
	for _, intent := range cases {
		if err := intent.Validate(); err == nil {
			t.Fatalf("intent accepted invalid target: %#v", intent)
		}
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
	return Intent{
		SchemaVersion: 1,
		DatabaseID:    "db-main",
		PartitionID:   "partition-a",
		ActiveRegions: regions,
		Generation:    1,
	}
}
