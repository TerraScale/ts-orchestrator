package workload

import (
	_ "embed"
	"encoding/json"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/memberstatus"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/oci"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/placement"
)

func tbMember(id string, region oci.Region, domain string, kind placement.MemberKind, lag uint64) StatefulMember {
	return StatefulMember{
		Observation: placement.MemberObservation{DatabaseID: "0000000000JJVVW9EMWY1PE1VX", PartitionID: "0000000000Z3WK359G2W66CVT8", MemberID: id,
			Region: region, FailureDomain: domain, InstanceID: "ocid1.instance." + id, VolumeID: "ocid1.volume." + id,
			Stage: placement.StageServing, Healthy: true, CurrentSession: true},
		Kind:        kind,
		Replication: &memberstatus.ReplicationProof{CurrentAuthenticated: true, LocalSourceSequence: 1000, PeerAppliedSequence: 1000 - lag},
	}
}

// gruOnly is a minimal admitted intent that keeps GRU and drops SFO, so the
// SFO elastic seat is no longer desired.
//
//go:embed testdata/current-placement.json
var currentPlacement []byte

func gruOnly() placement.Intent {
	var intent placement.Intent
	if err := json.Unmarshal(currentPlacement, &intent); err != nil {
		panic(err)
	}
	return intent
}

func twoRegionMembers() []StatefulMember {
	return []StatefulMember{
		tbMember("00000000000E5NVMSGX0D07DPA", oci.RegionGRU, "fd-1", placement.MemberPermanent, 0),
		tbMember("00000000008SEAHD1YMMYV3ARR", oci.RegionGRU, "fd-2", placement.MemberElastic, 3),
		tbMember("00000000008TFNX7CNMVMM1QSK", oci.RegionSFO, "fd-1", placement.MemberPermanent, 0),
		tbMember("0000000000JY3SY711G94XJ4QD", oci.RegionSFO, "fd-2", placement.MemberElastic, 5),
	}
}

func TestStatefulScaleDownGates(t *testing.T) {
	policy := *validStateful().Stateful
	base := func() StatefulScaleDownInput {
		return StatefulScaleDownInput{Policy: policy, Intent: gruOnly(), Members: twoRegionMembers(), Now: testNow}
	}
	tests := []struct {
		name   string
		mutate func(*StatefulScaleDownInput)
		want   StatefulVerdict
	}{
		{name: "undesired elastic seat may begin retirement", want: StatefulVerdict{Allowed: true, Candidate: "0000000000JY3SY711G94XJ4QD", Reason: "safe-to-begin-retirement"}},
		{name: "managed update blocks", mutate: func(in *StatefulScaleDownInput) { in.ManagedUpdateInFlight = true }, want: StatefulVerdict{Reason: "managed-update-in-flight"}},
		{name: "backup blocks", mutate: func(in *StatefulScaleDownInput) { in.BackupInFlight = true }, want: StatefulVerdict{Reason: "backup-in-flight"}},
		{name: "topology cooldown", mutate: func(in *StatefulScaleDownInput) {
			in.Cooldown, in.LastTopologyChange = time.Hour, testNow.Add(-time.Minute)
		}, want: StatefulVerdict{Reason: "topology-cooldown"}},
		{name: "one change at a time", mutate: func(in *StatefulScaleDownInput) {
			in.Members[1].Observation.Stage = placement.StageDraining
		}, want: StatefulVerdict{Reason: "topology-change-in-flight"}},
		{name: "unknown lag blocks", mutate: func(in *StatefulScaleDownInput) { in.Members[2].Replication = nil }, want: StatefulVerdict{Reason: "replication-lag-unverified"}},
		{name: "unauthenticated proof blocks", mutate: func(in *StatefulScaleDownInput) {
			in.Members[0].Replication.CurrentAuthenticated = false
		}, want: StatefulVerdict{Reason: "replication-lag-unverified"}},
		{name: "lag above limit blocks", mutate: func(in *StatefulScaleDownInput) {
			in.Members[3].Replication.PeerAppliedSequence = 0
		}, want: StatefulVerdict{Reason: "replication-lag-exceeds-limit"}},
		{name: "policy floor above survivors blocks", mutate: func(in *StatefulScaleDownInput) {
			in.Policy.QuorumFloorPerRegion = 3
		}, want: StatefulVerdict{Reason: "quorum-floor-not-met"}},
		{name: "unhealthy survivor blocks", mutate: func(in *StatefulScaleDownInput) {
			in.Members[0].Observation.Healthy = false
		}, want: StatefulVerdict{Reason: "quorum-floor-not-met"}},
		{name: "fixed two-seat topology cannot shrink an active region", mutate: func(in *StatefulScaleDownInput) {
			in.Intent.ActiveRegions = []oci.Region{oci.RegionGRU, oci.RegionSFO}
		}, want: StatefulVerdict{Reason: "quorum-floor-not-met"}},
		{name: "extra elastic seat is retired before permanent seats", mutate: func(in *StatefulScaleDownInput) {
			in.Members = []StatefulMember{in.Members[0], in.Members[1], in.Members[2],
				tbMember("00000000003BAF1RX3SX0H8SKG", oci.RegionGRU, "fd-3", placement.MemberElastic, 1)}
		}, want: StatefulVerdict{Allowed: true, Candidate: "00000000003BAF1RX3SX0H8SKG", Reason: "safe-to-begin-retirement"}},
		{name: "permanent seats are never candidates", mutate: func(in *StatefulScaleDownInput) {
			in.Members = []StatefulMember{in.Members[0], in.Members[1], in.Members[2]}
		}, want: StatefulVerdict{Reason: "quorum-floor-not-met"}},
		{name: "placement refuses a still desired seat", mutate: func(in *StatefulScaleDownInput) {
			in.Policy.QuorumFloorPerRegion = 2
			in.Members = []StatefulMember{in.Members[0], in.Members[1], in.Members[2],
				tbMember("permanent-x", oci.RegionGRU, "fd-3", placement.MemberPermanent, 0)}
		}, want: StatefulVerdict{Reason: "candidate-still-desired"}},
		{name: "invalid policy", mutate: func(in *StatefulScaleDownInput) { in.Policy.MaxConcurrentChanges = 2 }, want: StatefulVerdict{Reason: "invalid-stateful-policy"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			in := base()
			if test.mutate != nil {
				test.mutate(&in)
			}
			if got := StatefulScaleDown(in); got != test.want {
				t.Fatalf("verdict = %#v, want %#v", got, test.want)
			}
		})
	}
}

func TestStatefulCanRetireReportsDrainTimeoutWithoutForcing(t *testing.T) {
	policy := *validStateful().Stateful
	members := twoRegionMembers()
	candidate := members[3].Observation
	survivors := []placement.MemberObservation{members[0].Observation, members[1].Observation, members[2].Observation}
	evidence := placement.RetirementEvidence{DatabaseID: candidate.DatabaseID, PartitionID: candidate.PartitionID,
		MemberID: candidate.MemberID, InstanceID: candidate.InstanceID, VolumeID: candidate.VolumeID,
		ReplicationHealthy: true, QuorumSafe: true}
	started := testNow.Add(-time.Hour)
	if allowed, reason := StatefulCanRetire(policy, gruOnly(), candidate, survivors, evidence, started, testNow); allowed || reason != "drain-timeout-exceeded" {
		t.Fatalf("timed-out drain = %v %q", allowed, reason)
	}
	if allowed, reason := StatefulCanRetire(policy, gruOnly(), candidate, survivors, evidence, testNow, testNow); allowed || reason != "host-drain-unverified" {
		t.Fatalf("draining = %v %q", allowed, reason)
	}
	evidence.HostDrained, evidence.WriterStopped, evidence.WriterStopProof, evidence.VolumeRetained = true, true, []byte("proof"), true
	if allowed, reason := StatefulCanRetire(policy, gruOnly(), candidate, survivors, evidence, started, testNow); !allowed || reason != "safe-to-retire" {
		t.Fatalf("complete evidence = %v %q", allowed, reason)
	}
}

func TestReplicationLagSaturates(t *testing.T) {
	if ReplicationLag(memberstatus.ReplicationProof{LocalSourceSequence: 10, PeerAppliedSequence: 4}) != 6 ||
		ReplicationLag(memberstatus.ReplicationProof{LocalSourceSequence: 4, PeerAppliedSequence: 10}) != 0 {
		t.Fatal("replication lag arithmetic")
	}
}
