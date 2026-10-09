package app

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/entityid"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/natscell"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/oci"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/placement"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
)

func TestPlacementAdmissionCommitsSignedCanonicalV5AndExposesDigests(t *testing.T) {
	policy, privateKey := newPlacementAdmissionPolicy(t)
	control := newPlacementAdmissionControl()
	intent := testManagedPlacementIntent()
	wire := signedPlacementEnvelope(t, intent, privateKey, protocol.EncodeJSON)

	response, err := verifyAndApplyPlacement(t.Context(), wire, "gru", policy, control)
	if err != nil {
		t.Fatalf("admit signed managed placement: %v", err)
	}
	if response.DatabaseID != intent.DatabaseID || response.PartitionID != intent.PartitionID ||
		response.Generation != intent.Generation || response.Sequence != 1 {
		t.Fatalf("placement response = %+v", response)
	}
	entry := control.entries[intent.DatabaseID+"."+intent.PartitionID]
	wantPayload, err := protocol.EncodeJSON(intent)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(entry.Payload, wantPayload) {
		t.Fatalf("committed payload = %s, want exact canonical payload %s", entry.Payload, wantPayload)
	}

	readback, err := (admittedPlacementReader{cell: "gru", store: control}).ListPlacementIntents(t.Context(), "gru")
	if err != nil || len(readback) != 1 {
		t.Fatalf("read admitted placement: count=%d err=%v", len(readback), err)
	}
	wantPayloadHash := sha256.Sum256(wantPayload)
	if readback[0].PayloadDigest() != hex.EncodeToString(wantPayloadHash[:]) {
		t.Fatalf("readback payload digest = %q, want exact ordered-log SHA-256", readback[0].PayloadDigest())
	}
	wantProfileDigest, err := intent.ProfileDigest(oci.RegionGRU)
	if err != nil || wantProfileDigest == "" {
		t.Fatalf("compute profile digest = %q, %v", wantProfileDigest, err)
	}
	gotProfile, err := readback[0].ProfileDigest(oci.RegionGRU)
	if err != nil || gotProfile != wantProfileDigest {
		t.Fatalf("readback profile digest = %q, %v; want %q", gotProfile, err, wantProfileDigest)
	}

	duplicate, err := verifyAndApplyPlacement(t.Context(), wire, "gru", policy, control)
	if err != nil || duplicate.Sequence != response.Sequence {
		t.Fatalf("idempotent exact signed admission = %+v, %v", duplicate, err)
	}
}

func TestPlacementAdmissionRejectsSignedLegacyAndNoncanonicalPayload(t *testing.T) {
	policy, privateKey := newPlacementAdmissionPolicy(t)
	intent := testManagedPlacementIntent()
	legacy := placement.Intent{
		SchemaVersion: 1, DatabaseID: "0000000000JJVVW9EMWY1PE1VX", PartitionID: intent.PartitionID,
		ActiveRegions: []oci.Region{oci.RegionGRU}, Generation: intent.Generation,
	}

	t.Run("legacy v1 cannot authorize new managed placement", func(t *testing.T) {
		control := newPlacementAdmissionControl()
		wire := signedPlacementEnvelope(t, legacy, privateKey, protocol.EncodeJSON)
		if _, err := verifyAndApplyPlacement(t.Context(), wire, "gru", policy, control); err == nil {
			t.Fatal("valid operator signature made schema-1 placement admissible")
		}
		if len(control.entries) != 0 {
			t.Fatalf("rejected historical intent was committed: %+v", control.entries)
		}
	})

	t.Run("signed but noncanonical object order is rejected", func(t *testing.T) {
		control := newPlacementAdmissionControl()
		canonical, err := protocol.EncodeJSON(intent)
		if err != nil {
			t.Fatal(err)
		}
		var object map[string]any
		if err := json.Unmarshal(canonical, &object); err != nil {
			t.Fatal(err)
		}
		noncanonical, err := json.Marshal(object, json.Deterministic(true))
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Equal(noncanonical, canonical) {
			t.Fatal("test fixture unexpectedly preserved struct field order")
		}
		wire := signPlacementPayload(t, intent, privateKey, noncanonical)
		if _, err := verifyAndApplyPlacement(t.Context(), wire, "gru", policy, control); err == nil {
			t.Fatal("signed noncanonical payload was admitted")
		}
		if len(control.entries) != 0 {
			t.Fatalf("rejected noncanonical intent was committed: %+v", control.entries)
		}
	})

	t.Run("tampered signature payload is rejected", func(t *testing.T) {
		control := newPlacementAdmissionControl()
		wire := signedPlacementEnvelope(t, intent, privateKey, protocol.EncodeJSON)
		var envelope protocol.Envelope
		if err := protocol.DecodeStrict(wire, &envelope, maxPlacementWireBytes); err != nil {
			t.Fatal(err)
		}
		originalPayload := bytes.Clone(envelope.Payload)
		envelope.Payload = bytes.Replace(originalPayload, []byte(`"generation":7`), []byte(`"generation":8`), 1)
		if bytes.Equal(envelope.Payload, originalPayload) {
			t.Fatal("tampered payload fixture did not change the signed generation")
		}
		tampered, err := protocol.EncodeJSON(envelope)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := verifyAndApplyPlacement(t.Context(), tampered, "gru", policy, control); err == nil {
			t.Fatal("tampered signed placement was admitted")
		}
		if len(control.entries) != 0 {
			t.Fatalf("rejected tampered intent was committed: %+v", control.entries)
		}
	})
}

func TestPlacementAdmissionCreatesPlacementOnlyOnce(t *testing.T) {
	policy, privateKey := newPlacementAdmissionPolicy(t)
	for _, test := range []struct {
		name   string
		mutate func(*placement.Intent)
	}{
		{name: "removed region", mutate: func(intent *placement.Intent) {
			*intent = testManagedPlacementIntentForRegions(oci.RegionGRU)
		}},
		{name: "member rotation", mutate: func(intent *placement.Intent) {
			intent.CanonicalRoster.Rows[0].MemberID = "01HW000000E00800000000000G"
		}},
		{name: "incarnation rotation", mutate: func(intent *placement.Intent) {
			intent.CanonicalRoster.Rows[0].Incarnation = strings.Repeat("d", 32)
		}},
		{name: "shared shard change", mutate: func(intent *placement.Intent) {
			intent.CanonicalRoster.ShardID++
		}},
		{name: "authority reference change", mutate: func(intent *placement.Intent) {
			intent.CanonicalRoster.Authority.Epoch++
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			control := newPlacementAdmissionControl()
			previous := testManagedPlacementIntentForRegions(oci.RegionGRU, oci.RegionFRA)
			if _, err := verifyAndApplyPlacement(t.Context(), signedPlacementEnvelope(t, previous, privateKey, protocol.EncodeJSON), "gru", policy, control); err != nil {
				t.Fatalf("seed existing committed placement: %v", err)
			}
			candidate := previous
			test.mutate(&candidate)
			candidate.Generation = previous.Generation + 1
			_, err := verifyAndApplyPlacement(t.Context(), signedPlacementEnvelope(t, candidate, privateKey, protocol.EncodeJSON), "gru", policy, control)
			if err == nil {
				t.Fatal("placement replacement was committed after initial admission")
			}
			entry := control.entries[previous.DatabaseID+"."+previous.PartitionID]
			if entry.Sequence != 1 {
				t.Fatalf("rejected replacement changed committed sequence to %d", entry.Sequence)
			}
		})
	}

	t.Run("added seats require a separate lifecycle operation", func(t *testing.T) {
		control := newPlacementAdmissionControl()
		previous := testManagedPlacementIntentForRegions(oci.RegionGRU)
		if _, err := verifyAndApplyPlacement(t.Context(), signedPlacementEnvelope(t, previous, privateKey, protocol.EncodeJSON), "gru", policy, control); err != nil {
			t.Fatalf("seed existing committed placement: %v", err)
		}
		candidate := testManagedPlacementIntentForRegions(oci.RegionGRU, oci.RegionFRA)
		candidate.Generation = previous.Generation + 1
		if _, err := verifyAndApplyPlacement(t.Context(), signedPlacementEnvelope(t, candidate, privateKey, protocol.EncodeJSON), "gru", policy, control); err == nil {
			t.Fatal("placement admission accepted a replacement that adds seats")
		}
		entry := control.entries[previous.DatabaseID+"."+previous.PartitionID]
		if entry.Sequence != 1 {
			t.Fatalf("rejected seat addition changed committed sequence to %d", entry.Sequence)
		}
	})

	for _, test := range []struct {
		name   string
		mutate func(*placement.Intent)
	}{
		{name: "lower generation", mutate: func(intent *placement.Intent) { intent.Generation-- }},
		{name: "changed same-generation payload", mutate: func(intent *placement.Intent) {
			intent.RuntimeManifests[0].SourceDigest = strings.Repeat("f", 64)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			control := newPlacementAdmissionControl()
			previous := testManagedPlacementIntent()
			if _, err := verifyAndApplyPlacement(t.Context(), signedPlacementEnvelope(t, previous, privateKey, protocol.EncodeJSON), "gru", policy, control); err != nil {
				t.Fatalf("seed original placement: %v", err)
			}
			candidate := previous
			test.mutate(&candidate)
			if _, err := verifyAndApplyPlacement(t.Context(), signedPlacementEnvelope(t, candidate, privateKey, protocol.EncodeJSON), "gru", policy, control); err == nil {
				t.Fatal("placement admission accepted a lower generation or changed signed payload")
			}
			entry := control.entries[previous.DatabaseID+"."+previous.PartitionID]
			if entry.Sequence != 1 {
				t.Fatalf("rejected placement changed committed sequence to %d", entry.Sequence)
			}
		})
	}
}

func newPlacementAdmissionPolicy(t *testing.T) (signerPolicy, ed25519.PrivateKey) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := buildSignerPolicy(Config{
		NATS: natscell.Config{Cell: "gru"},
		Controller: ControllerConfig{TrustedSigners: []TrustedSignerConfig{{
			Actor: "ops", PublicKey: base64.StdEncoding.EncodeToString(publicKey),
			Roles: []string{"terrabase"}, Environments: []string{"production"}, CanPlaceTerraBase: true,
		}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return policy, privateKey
}

func testManagedPlacementIntent() placement.Intent {
	return testManagedPlacementIntentForRegions(oci.RegionGRU)
}

func testPlacementAdmittedArtifact(intent placement.Intent) placement.ArtifactResolver {
	return func(_ context.Context, digest, role, environment string) (placement.AdmittedArtifact, error) {
		if role != "terrabase" || environment != "production" {
			return placement.AdmittedArtifact{}, fmt.Errorf("unexpected runtime artifact scope %s/%s", role, environment)
		}
		for _, manifest := range intent.RuntimeManifests {
			if manifest.ArtifactDigest == digest {
				return placement.AdmittedArtifact{Digest: digest, SourceDigest: manifest.SourceDigest}, nil
			}
		}
		return placement.AdmittedArtifact{}, fmt.Errorf("runtime artifact %s is not in signed fixture", digest)
	}
}

func testManagedPlacementIntentForRegions(regions ...oci.Region) placement.Intent {
	selected := make(map[oci.Region]struct{}, len(regions))
	for _, region := range regions {
		selected[region] = struct{}{}
	}
	active := make([]oci.Region, 0, len(selected))
	profiles := make([]placement.ManagedHostProfile, 0, len(selected))
	rows := make([]placement.CanonicalRosterRow, 0, len(selected)*2)
	regionOrder := [...]oci.Region{oci.RegionGRU, oci.RegionSFO, oci.RegionFRA}
	for _, region := range regionOrder {
		if _, exists := selected[region]; !exists {
			continue
		}
		index := len(active)
		active = append(active, region)
		profiles = append(profiles, placement.ManagedHostProfile{
			Region:             region,
			Compute:            placement.ComputeTuple{Shape: "VM.Standard.E4.Flex", WholeOCPUs: 1, MemoryInGBs: 6},
			ProcessMemoryBytes: 4 << 30, MemoryHeadroomBytes: 1 << 30,
			CgroupMemoryMaxBytes: 4 << 30, SystemReserveBytes: 1 << 30,
			AllocatableMemoryBytes: 5 << 30,
		})
		rows = append(rows,
			placement.CanonicalRosterRow{
				Region: region, SeatID: permanentSeatID(region), FailureDomain: "FAULT-DOMAIN-1",
				MemberID:    entityid.Derive("test-member", fmt.Sprint(index*2+1)),
				Incarnation: fmt.Sprintf("%032x", index*2+1), TLSLeafSHA256: fmt.Sprintf("%064x", index*2+1),
				ServerName: fmt.Sprintf("permanent-%s.tb.example", strings.ToLower(string(region))),
			},
			placement.CanonicalRosterRow{
				Region: region, SeatID: elasticSeatID(region), FailureDomain: "FAULT-DOMAIN-2",
				MemberID:    entityid.Derive("test-member", fmt.Sprint(index*2+2)),
				Incarnation: fmt.Sprintf("%032x", index*2+2), TLSLeafSHA256: fmt.Sprintf("%064x", index*2+2),
				ServerName: fmt.Sprintf("elastic-%s.tb.example", strings.ToLower(string(region))),
			},
		)
	}
	databaseID := "0000000000JJVVW9EMWY1PE1VX"
	manifests := make([]placement.RuntimeManifest, 0, len(rows))
	for index, row := range rows {
		peer := rows[index^1]
		manifests = append(manifests, placement.RuntimeManifest{
			Region: row.Region, SeatID: row.SeatID,
			ArtifactDigest: strings.Repeat("d", 64), SourceDigest: strings.Repeat("e", 64),
			ManagedRuntimeRoot: "/srv/terrascale-managed",
			FileSystemUUID:     fmt.Sprintf("%08x-1234-1234-1234-123456789abc", index+1),
			FileSystemType:     "ext4", TrustedKeySHA256: strings.Repeat("c", 64),
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
	return placement.Intent{
		SchemaVersion: placement.IntentSchemaVersion, DatabaseID: databaseID, PartitionID: "0000000000Z3WK359G2W66CVT8",
		ActiveRegions: active, Generation: 7,
		CanonicalRoster: placement.CanonicalRoster{
			ClusterID: "0123456789abcdef0123456789abcdef", TenantID: "01HW000000E008000000000080",
			DatabaseID: "01HW000000E008000000000081", ShardID: 1,
			Authority: placement.AuthorityReference{
				Version: 2, Epoch: 7, ConfigurationID: strings.Repeat("a", 64),
				CertificateSHA256: strings.Repeat("b", 64), TrustedKeySHA256: strings.Repeat("c", 64),
			},
			Rows: rows,
		},
		ManagedHostProfiles: profiles,
		RuntimeManifests:    manifests,
	}
}

func permanentSeatID(region oci.Region) string {
	ids, _ := placement.RegionSeatIDs(region)
	return ids[0]
}

func elasticSeatID(region oci.Region) string {
	ids, _ := placement.RegionSeatIDs(region)
	return ids[1]
}

func signedPlacementEnvelope(
	t *testing.T,
	intent placement.Intent,
	privateKey ed25519.PrivateKey,
	encode func(any) ([]byte, error),
) []byte {
	t.Helper()
	payload, err := encode(intent)
	if err != nil {
		t.Fatal(err)
	}
	return signPlacementPayload(t, intent, privateKey, payload)
}

func signPlacementPayload(t *testing.T, intent placement.Intent, privateKey ed25519.PrivateKey, payload []byte) []byte {
	t.Helper()
	now := time.Now().UTC()
	envelope, err := protocol.SignEnvelope(payload, protocol.EnvelopeScope{
		Region: "gru", Kind: "placement.intent", Actor: "ops",
		OperationID: intent.OperationID(), Generation: intent.Generation, Epoch: 3,
	}, now, now.Add(time.Minute), privateKey)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := protocol.EncodeJSON(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

type placementAdmissionTestControl struct {
	snapshot authority.Snapshot
	entries  map[string]authority.LogEntry
	terminal map[string]authority.LogEntry
	nextSeq  uint64
}

func newPlacementAdmissionControl() *placementAdmissionTestControl {
	return &placementAdmissionTestControl{
		snapshot: authority.Snapshot{Scope: "gru", CandidateID: "0000000000GR3712FB1A87M2H7", Leader: true, Ready: true,
			Epoch: 3, Revision: 1, ExpiresAt: time.Now().Add(time.Minute)},
		entries:  make(map[string]authority.LogEntry),
		terminal: make(map[string]authority.LogEntry),
	}
}

func (control *placementAdmissionTestControl) Current() authority.Snapshot { return control.snapshot }

func (control *placementAdmissionTestControl) ReadPlacementIntent(_ context.Context, databaseID, partitionID string) (authority.LogEntry, error) {
	entry, exists := control.entries[databaseID+"."+partitionID]
	if !exists {
		return authority.LogEntry{}, authority.ErrNotFound
	}
	entry.Payload = bytes.Clone(entry.Payload)
	return entry, nil
}

func (control *placementAdmissionTestControl) ReadTerminalIntent(_ context.Context, databaseID, partitionID string) (authority.LogEntry, error) {
	entry, exists := control.terminal[databaseID+"."+partitionID]
	if !exists {
		return authority.LogEntry{}, authority.ErrNotFound
	}
	entry.Payload = bytes.Clone(entry.Payload)
	return entry, nil
}

func (*placementAdmissionTestControl) ReadManagedUpdate(context.Context, string, string) (authority.LogEntry, error) {
	return authority.LogEntry{}, authority.ErrNotFound
}

func (*placementAdmissionTestControl) ReadManagedUpdateOperation(context.Context, string, string, string) ([]authority.LogEntry, error) {
	return nil, authority.ErrNotFound
}

func (*placementAdmissionTestControl) ListManagedUpdates(context.Context, string, string) ([]authority.LogEntry, error) {
	return []authority.LogEntry{}, nil
}

func (control *placementAdmissionTestControl) ConfirmActivePlacementIntent(ctx context.Context, epoch uint64,
	databaseID, partitionID string, payload []byte,
) (uint64, error) {
	if epoch != control.snapshot.Epoch {
		return 0, authority.ErrFenced
	}
	if _, err := control.ReadTerminalIntent(ctx, databaseID, partitionID); err == nil {
		return 0, authority.ErrFenced
	} else if !errors.Is(err, authority.ErrNotFound) {
		return 0, err
	}
	entry, err := control.ReadPlacementIntent(ctx, databaseID, partitionID)
	if err != nil {
		return 0, err
	}
	if !bytes.Equal(entry.Payload, payload) {
		return 0, authority.ErrConflict
	}
	return entry.Sequence, nil
}

func (control *placementAdmissionTestControl) CommitPlacementIntent(
	_ context.Context,
	expectedEpoch uint64,
	databaseID string,
	partitionID string,
	operationID string,
	expectedSequence uint64,
	payload []byte,
) (uint64, error) {
	if expectedEpoch != control.snapshot.Epoch {
		return 0, authority.ErrFenced
	}
	key := databaseID + "." + partitionID
	current, exists := control.entries[key]
	if exists && current.Sequence != expectedSequence || !exists && expectedSequence != 0 {
		return 0, authority.ErrConflict
	}
	control.nextSeq++
	control.entries[key] = authority.LogEntry{
		Kind: authority.MutationPlacementIntent, SubjectKey: key, OperationID: operationID,
		Epoch: expectedEpoch, Sequence: control.nextSeq, CreatedAt: time.Now().UTC(), Payload: bytes.Clone(payload),
	}
	return control.nextSeq, nil
}

func (control *placementAdmissionTestControl) ListPlacementIntents(context.Context) ([]authority.LogEntry, error) {
	entries := make([]authority.LogEntry, 0, len(control.entries))
	for _, entry := range control.entries {
		entry.Payload = bytes.Clone(entry.Payload)
		entries = append(entries, entry)
	}
	return entries, nil
}

var _ placementAdmissionControl = (*placementAdmissionTestControl)(nil)
var _ authority.PlacementIntentStore = (*placementAdmissionTestControl)(nil)
var _ authority.ManagedUpdateReader = (*placementAdmissionTestControl)(nil)
