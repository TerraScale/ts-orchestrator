package placement

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"

	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
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
		{MemberID: "000000000082AXF7GZQT1D126Y", Region: oci.RegionGRU, FailureDomain: "FAULT-DOMAIN-1", Kind: MemberPermanent},
		{MemberID: "0000000000XG8SBD7XGE97V28G", Region: oci.RegionGRU, FailureDomain: "FAULT-DOMAIN-2", Kind: MemberElastic},
		{MemberID: "0000000000M6NPX5VJR7J4KHXR", Region: oci.RegionFRA, FailureDomain: "FAULT-DOMAIN-2", Kind: MemberPermanent},
		{MemberID: "0000000000DRX0N2BW96GK619K", Region: oci.RegionFRA, FailureDomain: "FAULT-DOMAIN-3", Kind: MemberElastic},
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
		{SchemaVersion: IntentSchemaVersion, DatabaseID: "0000000000T8H7NEY8XQ530245", PartitionID: "00000000003K6TBW31R91GBDRD", ActiveRegions: []oci.Region{"LAX"}, Generation: 1},
		{SchemaVersion: IntentSchemaVersion, DatabaseID: "0000000000T8H7NEY8XQ530245", PartitionID: "00000000003K6TBW31R91GBDRD", ActiveRegions: []oci.Region{oci.RegionGRU, oci.RegionGRU}, Generation: 1},
		{SchemaVersion: IntentSchemaVersion, DatabaseID: "0000000000T8H7NEY8XQ530245", PartitionID: "00000000003K6TBW31R91GBDRD", ActiveRegions: []oci.Region{oci.RegionGRU}, Generation: 0},
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

func TestManagedIntentRequiresCompleteOrderedRuntimeManifests(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*Intent)
	}{
		{"missing seat", func(intent *Intent) { intent.RuntimeManifests = intent.RuntimeManifests[:1] }},
		{"out of seat order", func(intent *Intent) {
			intent.RuntimeManifests[0], intent.RuntimeManifests[1] = intent.RuntimeManifests[1], intent.RuntimeManifests[0]
		}},
		{"duplicate filesystem UUID", func(intent *Intent) {
			intent.RuntimeManifests[1].FileSystemUUID = intent.RuntimeManifests[0].FileSystemUUID
		}},
		{"wrong trusted key", func(intent *Intent) { intent.RuntimeManifests[0].TrustedKeySHA256 = strings.Repeat("f", 64) }},
		{"missing artifact digest", func(intent *Intent) { intent.RuntimeManifests[0].ArtifactDigest = "" }},
		{"invalid SQL schema bundle digest", func(intent *Intent) {
			intent.RuntimeManifests[0].SQLSchemaBundleSHA256 = "bad"
		}},
		{"missing managed HTTPS manifest", func(intent *Intent) { intent.RuntimeManifests[0].ClientManagedMaterialManifestSHA256 = "" }},
		{"missing outbound peer", func(intent *Intent) {
			intent.RuntimeManifests[0].ReplicationPeerMemberID = ""
			intent.RuntimeManifests[0].ReplicationPeerAddress = ""
			intent.RuntimeManifests[0].ReplicationServerCASHA256 = ""
		}},
		{"incomplete peer", func(intent *Intent) {
			intent.RuntimeManifests[0].ReplicationPeerAddress = ""
		}},
		{"loopback replication listener", func(intent *Intent) {
			intent.RuntimeManifests[0].ReplicationListenAddress = "127.0.0.1:7000"
		}},
		{"public replication listener", func(intent *Intent) {
			intent.RuntimeManifests[0].ReplicationListenAddress = "198.51.100.11:7000"
		}},
		{"wildcard replication listener", func(intent *Intent) {
			intent.RuntimeManifests[0].ReplicationListenAddress = "0.0.0.0:7000"
		}},
		{"IPv6 replication listener", func(intent *Intent) {
			intent.RuntimeManifests[0].ReplicationListenAddress = "[fd00::11]:7000"
		}},
		{"public replication peer", func(intent *Intent) {
			intent.RuntimeManifests[0].ReplicationPeerAddress = "198.51.100.12:7001"
		}},
		{"foreign peer", func(intent *Intent) {
			intent.RuntimeManifests[0].ReplicationPeerMemberID = "01HW000000E00800000000000P"
			intent.RuntimeManifests[0].ReplicationPeerAddress = "10.0.0.12:7001"
			intent.RuntimeManifests[0].ReplicationServerCASHA256 = strings.Repeat("a", 64)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			intent := validIntent(oci.RegionGRU)
			test.change(&intent)
			if err := intent.ValidateForAdmission(); err == nil {
				t.Fatal("incomplete signed runtime manifest was admitted")
			}
		})
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

func TestCanonicalRosterDigestLookupAndValidation(t *testing.T) {
	intent := validIntent(oci.RegionGRU, oci.RegionFRA)
	if err := intent.ValidateForAdmission(); err != nil {
		t.Fatalf("valid canonical roster rejected: %v", err)
	}
	digest, err := intent.CanonicalRosterDigest()
	if err != nil || !validLowerSHA256Digest(digest) {
		t.Fatalf("canonical roster digest = %q, %v", digest, err)
	}
	row, err := intent.RosterRowForSeat(Seat{
		MemberID: permanentMember(oci.RegionGRU), Region: oci.RegionGRU,
		FailureDomain: "FAULT-DOMAIN-1", Kind: MemberPermanent,
	})
	if err != nil || row.MemberID != intent.CanonicalRoster.Rows[0].MemberID {
		t.Fatalf("lookup exact placement seat = %+v, %v", row, err)
	}
	if _, err := intent.RosterRowForSeat(Seat{
		MemberID: permanentMember(oci.RegionGRU), Region: oci.RegionGRU,
		FailureDomain: "wrong-domain", Kind: MemberPermanent,
	}); err == nil {
		t.Fatal("roster lookup accepted a failure domain that differs from the configured seat")
	}

	changed := intent
	changed.CanonicalRoster = testCanonicalRoster(changed.ActiveRegions)
	changed.CanonicalRoster.Rows[0].ServerName = "rotated-gru.tb.example"
	changedDigest, err := changed.CanonicalRosterDigest()
	if err != nil || changedDigest == digest {
		t.Fatalf("roster digest failed to bind row changes: digest=%q err=%v", changedDigest, err)
	}

	cases := []struct {
		name   string
		mutate func(*Intent)
	}{
		{name: "wrong cluster ID", mutate: func(intent *Intent) { intent.CanonicalRoster.ClusterID = strings.Repeat("0", 32) }},
		{name: "noncanonical roster database UUID", mutate: func(intent *Intent) {
			intent.CanonicalRoster.DatabaseID = strings.ToLower(intent.CanonicalRoster.DatabaseID)
		}},
		{name: "unknown authority version", mutate: func(intent *Intent) { intent.CanonicalRoster.Authority.Version = 1 }},
		{name: "zero authority epoch", mutate: func(intent *Intent) { intent.CanonicalRoster.Authority.Epoch = 0 }},
		{name: "wrong seat order", mutate: func(intent *Intent) {
			intent.CanonicalRoster.Rows[0], intent.CanonicalRoster.Rows[1] = intent.CanonicalRoster.Rows[1], intent.CanonicalRoster.Rows[0]
		}},
		{name: "duplicate member ID", mutate: func(intent *Intent) {
			intent.CanonicalRoster.Rows[1].MemberID = intent.CanonicalRoster.Rows[0].MemberID
		}},
		{name: "duplicate leaf hash", mutate: func(intent *Intent) {
			intent.CanonicalRoster.Rows[1].TLSLeafSHA256 = intent.CanonicalRoster.Rows[0].TLSLeafSHA256
		}},
		{name: "duplicate server name", mutate: func(intent *Intent) {
			intent.CanonicalRoster.Rows[1].ServerName = intent.CanonicalRoster.Rows[0].ServerName
		}},
		{name: "zero incarnation", mutate: func(intent *Intent) { intent.CanonicalRoster.Rows[0].Incarnation = strings.Repeat("0", 32) }},
		{name: "invalid failure domain", mutate: func(intent *Intent) { intent.CanonicalRoster.Rows[0].FailureDomain = "FAULT DOMAIN" }},
		{name: "uppercase server name", mutate: func(intent *Intent) { intent.CanonicalRoster.Rows[0].ServerName = "Member.example" }},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			candidate := validIntent(oci.RegionGRU, oci.RegionFRA)
			test.mutate(&candidate)
			if err := candidate.ValidateForAdmission(); err == nil {
				t.Fatal("invalid canonical roster was accepted")
			}
		})
	}
}

func TestMemberStateManagedProfilePinsAreAdditiveAndValidated(t *testing.T) {
	state := validMemberStateForPins(t)
	if err := state.Validate(); err != nil {
		t.Fatalf("valid member-state V2 pins were rejected: %v", err)
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
		{name: "missing roster digest", mutate: func(state *MemberState) { state.CanonicalRosterDigest = "" }},
		{name: "changed roster seat", mutate: func(state *MemberState) { state.CanonicalRosterRow.SeatID = elasticMember(oci.RegionGRU) }},
		{name: "invalid authority reference", mutate: func(state *MemberState) { state.AuthorityReference.Epoch = 0 }},
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

func validMemberStateForPins(t *testing.T) MemberState {
	intent := committedTestIntent(t, validIntent(oci.RegionGRU))
	seat := Seat{MemberID: permanentMember(oci.RegionGRU), Region: oci.RegionGRU, FailureDomain: "FAULT-DOMAIN-1", Kind: MemberPermanent}
	return testMemberState(t, intent, seat, StagePreparedHost)
}

func TestCanRetireRequiresEveryIndependentSafetyProof(t *testing.T) {
	intent := validIntent(oci.RegionGRU, oci.RegionSFO)
	candidate := testCandidate()
	survivors := healthyMembers(
		MemberObservation{MemberID: "000000000082AXF7GZQT1D126Y", Region: oci.RegionGRU, FailureDomain: "fd-a"},
		MemberObservation{MemberID: "0000000000XG8SBD7XGE97V28G", Region: oci.RegionGRU, FailureDomain: "fd-b"},
		MemberObservation{MemberID: "000000000031KRKJZMCK6VE679", Region: oci.RegionSFO, FailureDomain: "fd-a"},
		MemberObservation{MemberID: "0000000000684PWEEY0RSW7AJQ", Region: oci.RegionSFO, FailureDomain: "fd-c"},
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
		MemberObservation{MemberID: "000000000082AXF7GZQT1D126Y", Region: oci.RegionGRU, FailureDomain: "fd-a"},
		MemberObservation{MemberID: "000000000031KRKJZMCK6VE679", Region: oci.RegionSFO, FailureDomain: "fd-a"},
		MemberObservation{MemberID: "0000000000684PWEEY0RSW7AJQ", Region: oci.RegionSFO, FailureDomain: "fd-c"},
	)
	if allowed, reason := CanRetire(intent, candidate, oneShort, proof); allowed || reason != "replica-floor-or-health-not-met" {
		t.Fatalf("replica floor gate = (%v, %q)", allowed, reason)
	}

	duplicateDomain := healthyMembers(
		MemberObservation{MemberID: "000000000082AXF7GZQT1D126Y", Region: oci.RegionGRU, FailureDomain: "fd-a"},
		MemberObservation{MemberID: "0000000000XG8SBD7XGE97V28G", Region: oci.RegionGRU, FailureDomain: "fd-a"},
		MemberObservation{MemberID: "000000000031KRKJZMCK6VE679", Region: oci.RegionSFO, FailureDomain: "fd-a"},
		MemberObservation{MemberID: "0000000000684PWEEY0RSW7AJQ", Region: oci.RegionSFO, FailureDomain: "fd-c"},
	)
	if allowed, reason := CanRetire(intent, candidate, duplicateDomain, proof); allowed || reason != "survivor-anti-affinity-violated" {
		t.Fatalf("anti-affinity gate = (%v, %q)", allowed, reason)
	}
}

func TestCanRetireNeverRemovesAStillDesiredSeat(t *testing.T) {
	intent := validIntent(oci.RegionGRU)
	candidate := testCandidate()
	candidate.MemberID = "000000000082AXF7GZQT1D126Y"
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
		MemberObservation{MemberID: "000000000082AXF7GZQT1D126Y", Region: oci.RegionGRU, FailureDomain: "fd-a"},
		MemberObservation{MemberID: "0000000000XG8SBD7XGE97V28G", Region: oci.RegionGRU, FailureDomain: "fd-b"},
	), proof); allowed || reason != "candidate-still-desired" {
		t.Fatalf("desired member retirement gate = (%v, %q)", allowed, reason)
	}
}

func TestCanRetireDoesNotCountPreparedOrAwaitingMembersAsServing(t *testing.T) {
	intent := validIntent(oci.RegionGRU)
	candidate := testCandidate()
	candidate.MemberID = "0000000000J62EWD8ZF4E1V9MV"
	candidate.Region = oci.RegionFRA
	survivors := healthyMembers(
		MemberObservation{MemberID: "000000000082AXF7GZQT1D126Y", Region: oci.RegionGRU, FailureDomain: "fd-a"},
		MemberObservation{MemberID: "0000000000XG8SBD7XGE97V28G", Region: oci.RegionGRU, FailureDomain: "fd-b"},
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
		members[index].DatabaseID = "0000000000JJVVW9EMWY1PE1VX"
		members[index].PartitionID = "0000000000Z3WK359G2W66CVT8"
		members[index].Healthy = true
		members[index].CurrentSession = true
		members[index].Stage = StageServing
	}
	return members
}

func testCandidate() MemberObservation {
	return MemberObservation{
		DatabaseID: "0000000000JJVVW9EMWY1PE1VX", PartitionID: "0000000000Z3WK359G2W66CVT8", MemberID: "0000000000DRX0N2BW96GK619K", Region: oci.RegionFRA,
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
		MemberObservation{MemberID: "000000000082AXF7GZQT1D126Y", Region: oci.RegionGRU, FailureDomain: "fd-a"},
		MemberObservation{MemberID: "0000000000XG8SBD7XGE97V28G", Region: oci.RegionGRU, FailureDomain: "fd-b"},
	)
	for index := range survivors {
		survivors[index].PartitionID = "0000000000Q6JWK5HSVBS382F2"
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
	roster := testCanonicalRoster(active)
	manifests := make([]RuntimeManifest, 0, len(roster.Rows))
	for index, row := range roster.Rows {
		peer := roster.Rows[index^1]
		manifests = append(manifests, RuntimeManifest{
			Region: row.Region, SeatID: row.SeatID,
			ArtifactDigest: strings.Repeat("d", 64), SourceDigest: strings.Repeat("e", 64),
			ManagedRuntimeRoot: "/srv/terrascale-managed",
			FileSystemUUID:     fmt.Sprintf("%08x-1234-1234-1234-123456789abc", index+1),
			FileSystemType:     "ext4", TrustedKeySHA256: roster.Authority.TrustedKeySHA256,
			ServerCertificateSHA256:             strings.Repeat("1", 64),
			ServerPrivateKeySHA256:              strings.Repeat("2", 64),
			ClientCARootsSHA256:                 strings.Repeat("3", 64),
			ClientManagedMaterialManifestSHA256: strings.Repeat("4", 64),
			LiveS3ConfigSHA256:                  strings.Repeat("5", 64),
			LiveS3TargetSHA256:                  strings.Repeat("6", 64),
			LiveS3Credential:                    oci.SecretVersionReference{SecretOCID: "ocid1.vaultsecret.oc1.sa-saopaulo-1.alpha", VersionNumber: 3},
			ReplicationListenAddress:            fmt.Sprintf("10.0.0.%d:%d", 11+index, 7000+index),
			ReplicationPeerMemberID:             peer.MemberID,
			ReplicationPeerAddress:              fmt.Sprintf("10.0.0.%d:%d", 11+(index^1), 7000+(index^1)),
			ReplicationServerCASHA256:           strings.Repeat("a", 64),
		})
	}
	return Intent{
		SchemaVersion:       IntentSchemaVersion,
		DatabaseID:          testDatabaseID,
		PartitionID:         "0000000000Z3WK359G2W66CVT8",
		ActiveRegions:       active,
		Generation:          1,
		CanonicalRoster:     roster,
		ManagedHostProfiles: profiles,
		RuntimeManifests:    manifests,
	}
}

const testDatabaseID = "0000000000JJVVW9EMWY1PE1VX"

func testCanonicalRoster(regions []oci.Region) CanonicalRoster {
	rows := make([]CanonicalRosterRow, 0, len(regions)*2)
	for regionIndex, region := range regions {
		rows = append(rows,
			CanonicalRosterRow{
				Region: region, SeatID: permanentMember(region), FailureDomain: "FAULT-DOMAIN-1",
				MemberID:    entityid.Derive("fixture-member", fmt.Sprint(regionIndex*2+1)),
				Incarnation: fmt.Sprintf("%032x", regionIndex*2+1), TLSLeafSHA256: fmt.Sprintf("%064x", regionIndex*2+1),
				ServerName: fmt.Sprintf("permanent-%s.tb.example", strings.ToLower(string(region))),
			},
			CanonicalRosterRow{
				Region: region, SeatID: elasticMember(region), FailureDomain: "FAULT-DOMAIN-2",
				MemberID:    entityid.Derive("fixture-member", fmt.Sprint(regionIndex*2+2)),
				Incarnation: fmt.Sprintf("%032x", regionIndex*2+2), TLSLeafSHA256: fmt.Sprintf("%064x", regionIndex*2+2),
				ServerName: fmt.Sprintf("elastic-%s.tb.example", strings.ToLower(string(region))),
			},
		)
	}
	return CanonicalRoster{
		ClusterID: "0123456789abcdef0123456789abcdef", TenantID: "01HW000000E008000000000080",
		DatabaseID: "01HW000000E008000000000081", ShardID: 1,
		Authority: AuthorityReference{
			Version: 2, Epoch: 7, ConfigurationID: strings.Repeat("a", 64),
			CertificateSHA256: strings.Repeat("b", 64), TrustedKeySHA256: strings.Repeat("c", 64),
		},
		Rows: rows,
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

func TestRejectsObsoletePlacementSchemas(t *testing.T) {
	for schema := 1; schema < IntentSchemaVersion; schema++ {
		intent := validIntent(oci.RegionGRU)
		intent.SchemaVersion = schema
		payload, err := protocol.EncodeJSON(intent)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := DecodeCommittedIntent(payload); err == nil {
			t.Fatalf("accepted obsolete schema %d", schema)
		}
	}
	state := validMemberStateForPins(t)
	state.SchemaVersion = 4
	if state.Validate() == nil {
		t.Fatal("accepted obsolete member schema")
	}
}
