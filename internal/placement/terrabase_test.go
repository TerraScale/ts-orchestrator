package placement

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
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
		{name: "noncanonical roster database ULID", mutate: func(intent *Intent) {
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

func TestRosterSupersessionPreservesScopeSeatIdentityAndRetirementGate(t *testing.T) {
	previous := validIntent(oci.RegionGRU)
	unchanged := validIntent(oci.RegionGRU)
	unchanged.Generation = previous.Generation + 1
	if err := unchanged.ValidateSupersession(previous); err != nil {
		t.Fatalf("later generation with unchanged roster row rejected: %v", err)
	}
	addition := validIntent(oci.RegionGRU, oci.RegionFRA)
	addition.Generation = previous.Generation + 1
	if err := addition.ValidateSupersession(previous); err != nil {
		t.Fatalf("signed added seats with continuous existing identity rejected: %v", err)
	}

	removed := validIntent(oci.RegionGRU)
	removed.Generation = 2
	if err := removed.ValidateSupersession(validIntent(oci.RegionGRU, oci.RegionFRA)); err == nil {
		t.Fatal("seat removal was accepted without verified retirement evidence")
	}

	rotatedMember := validIntent(oci.RegionGRU)
	rotatedMember.Generation = 2
	rotatedMember.CanonicalRoster.Rows[0].MemberID = "01ARZ3NDEKTSV4RRFFQ69G5FA0"
	if err := rotatedMember.ValidateSupersession(previous); err == nil {
		t.Fatal("ordinary generation increment authorized member identity rotation")
	}

	rotatedIncarnation := validIntent(oci.RegionGRU)
	rotatedIncarnation.Generation = 2
	rotatedIncarnation.CanonicalRoster.Rows[0].Incarnation = strings.Repeat("d", 32)
	if err := rotatedIncarnation.ValidateSupersession(previous); err == nil {
		t.Fatal("ordinary generation increment authorized member incarnation rotation")
	}
	for _, test := range []struct {
		name   string
		mutate func(*CanonicalRosterRow)
	}{
		{name: "failure domain", mutate: func(row *CanonicalRosterRow) { row.FailureDomain = "FAULT-DOMAIN-3" }},
		{name: "TLS leaf", mutate: func(row *CanonicalRosterRow) { row.TLSLeafSHA256 = strings.Repeat("e", 64) }},
		{name: "server name", mutate: func(row *CanonicalRosterRow) { row.ServerName = "renewed-permanent-gru.tb.example" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate := validIntent(oci.RegionGRU)
			candidate.Generation = previous.Generation + 1
			test.mutate(&candidate.CanonicalRoster.Rows[0])
			if err := candidate.ValidateForAdmission(); err != nil {
				t.Fatalf("changed row is not otherwise admissible: %v", err)
			}
			if err := candidate.ValidateSupersession(previous); err == nil {
				t.Fatal("supersession accepted a changed row for a continuing seat")
			}
		})
	}

	changedScope := validIntent(oci.RegionGRU)
	changedScope.Generation = 2
	changedScope.CanonicalRoster.ShardID++
	if err := changedScope.ValidateSupersession(previous); err == nil {
		t.Fatal("supersession changed the canonical shared scope")
	}

	legacy := Intent{SchemaVersion: profileIntentSchemaVersion, DatabaseID: "db-main", PartitionID: "partition-a",
		ActiveRegions: []oci.Region{oci.RegionGRU}, Generation: 1,
		ManagedHostProfiles: []ManagedHostProfile{testManagedHostProfile(oci.RegionGRU)}}
	if err := addition.ValidateSupersession(legacy); err == nil {
		t.Fatal("schema-2 history without a roster authorized schema-3 supersession")
	}
}

func TestMemberStateManagedProfilePinsAreAdditiveAndValidated(t *testing.T) {
	legacyState := validMemberStateForPins()
	legacyState.SchemaVersion = legacyMemberStateSchemaVersion
	legacyState.DatabaseID = "db-main"
	if err := legacyState.Validate(); err != nil {
		t.Fatalf("legacy unpinned member state should remain readable: %v", err)
	}

	state := validMemberStateForPins()
	intent := validIntent(oci.RegionGRU)
	profile := intent.ManagedHostProfiles[0]
	profileDigest, err := profile.ProfileDigest()
	if err != nil {
		t.Fatal(err)
	}
	intent.Generation = state.IntentGeneration
	encoded, err := protocol.EncodeJSON(intent)
	if err != nil {
		t.Fatal(err)
	}
	payloadDigest := sha256.Sum256(encoded)
	state.IntentPayloadDigest = hex.EncodeToString(payloadDigest[:])
	state.ManagedHostProfile = profile
	state.ManagedHostProfileDigest = profileDigest
	state.CanonicalRosterRow = intent.CanonicalRoster.Rows[0]
	state.CanonicalRosterDigest, err = intent.CanonicalRosterDigest()
	if err != nil {
		t.Fatal(err)
	}
	state.AuthorityReference = intent.CanonicalRoster.Authority
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

func validMemberStateForPins() MemberState {
	return MemberState{
		SchemaVersion: placementSchemaVersion, DatabaseID: testDatabaseID, PartitionID: "partition-a",
		MemberID: permanentMember(oci.RegionGRU), Region: oci.RegionGRU, FailureDomain: "FAULT-DOMAIN-1",
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

func TestPreV3CanonicalPayloadBytesRemainReadableAsHeldHistory(t *testing.T) {
	// These golden bytes match the V1 and V2 Intent field sets at clean source
	// checkpoint 49f7506; they intentionally omit canonical_roster.
	v1Payload := []byte(`{"schema_version":1,"database_id":"db-legacy-v1","partition_id":"partition-a","active_regions":["GRU"],"generation":1}`)
	v2Payload := []byte(`{"schema_version":2,"database_id":"db-legacy-v2","partition_id":"partition-a","active_regions":["GRU"],"generation":1,"managed_host_profiles":[{"region":"GRU","compute":{"shape":"VM.Standard.E4.Flex","whole_ocpus":1,"memory_in_gbs":6},"process_memory_bytes":4294967296,"memory_headroom_bytes":1073741824,"cgroup_memory_max_bytes":4294967296,"system_reserve_bytes":1073741824,"allocatable_memory_bytes":5368709120}]}`)
	historicalPayloads := [][]byte{v1Payload, v2Payload}
	historical := make([]Intent, 0, len(historicalPayloads))
	for index, payload := range historicalPayloads {
		intent, err := DecodeCommittedIntent(payload)
		if err != nil {
			t.Fatalf("decode pre-v3 canonical payload %d: %v", index+1, err)
		}
		wantDigest := sha256.Sum256(payload)
		if intent.PayloadDigest() != hex.EncodeToString(wantDigest[:]) {
			t.Fatalf("pre-v3 schema %d payload digest = %q, want exact golden-byte SHA-256", intent.SchemaVersion, intent.PayloadDigest())
		}
		if err := intent.ValidateForAdmission(); err == nil {
			t.Fatalf("historical schema %d authorized a new placement", intent.SchemaVersion)
		}
		historical = append(historical, intent)
	}

	current := committedIntentForTest(t, validIntent(oci.RegionGRU))
	store := &jetStreamStore{cell: "gru", intents: intentReaderFunc(func(context.Context, string) ([]Intent, error) {
		return []Intent{current, historical[1], historical[0]}, nil
	})}
	got, err := store.ListIntents(context.Background())
	if err != nil || len(got) != 3 {
		t.Fatalf("list historical held intents alongside schema 3: count=%d err=%v", len(got), err)
	}
	if got[0].SchemaVersion != legacyIntentSchemaVersion || got[1].SchemaVersion != profileIntentSchemaVersion ||
		got[2].SchemaVersion != IntentSchemaVersion {
		t.Fatalf("mixed historical/current schema order = %d, %d, %d", got[0].SchemaVersion, got[1].SchemaVersion, got[2].SchemaVersion)
	}
	for _, intent := range got {
		if !validLowerSHA256Digest(intent.PayloadDigest()) {
			t.Fatalf("committed schema %d lost its payload digest", intent.SchemaVersion)
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
		DatabaseID:          testDatabaseID,
		PartitionID:         "partition-a",
		ActiveRegions:       active,
		Generation:          1,
		CanonicalRoster:     testCanonicalRoster(active),
		ManagedHostProfiles: profiles,
	}
}

const testDatabaseID = "db-main"

func testCanonicalRoster(regions []oci.Region) CanonicalRoster {
	rows := make([]CanonicalRosterRow, 0, len(regions)*2)
	memberSuffixes := "VWXYZ0"
	for regionIndex, region := range regions {
		rows = append(rows,
			CanonicalRosterRow{
				Region: region, SeatID: permanentMember(region), FailureDomain: "FAULT-DOMAIN-1",
				MemberID:    fmt.Sprintf("01ARZ3NDEKTSV4RRFFQ69G5FA%c", memberSuffixes[regionIndex*2]),
				Incarnation: fmt.Sprintf("%032x", regionIndex*2+1), TLSLeafSHA256: fmt.Sprintf("%064x", regionIndex*2+1),
				ServerName: fmt.Sprintf("permanent-%s.tb.example", strings.ToLower(string(region))),
			},
			CanonicalRosterRow{
				Region: region, SeatID: elasticMember(region), FailureDomain: "FAULT-DOMAIN-2",
				MemberID:    fmt.Sprintf("01ARZ3NDEKTSV4RRFFQ69G5FA%c", memberSuffixes[regionIndex*2+1]),
				Incarnation: fmt.Sprintf("%032x", regionIndex*2+2), TLSLeafSHA256: fmt.Sprintf("%064x", regionIndex*2+2),
				ServerName: fmt.Sprintf("elastic-%s.tb.example", strings.ToLower(string(region))),
			},
		)
	}
	return CanonicalRoster{
		ClusterID: "0123456789abcdef0123456789abcdef", TenantID: "01ARZ3NDEKTSV4RRFFQ69G5FAS",
		DatabaseID: "01ARZ3NDEKTSV4RRFFQ69G5FAR", ShardID: 1,
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
