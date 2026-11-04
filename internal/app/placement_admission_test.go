package app

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/natscell"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/placement"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
)

func TestPlacementAdmissionRejectsSignedLegacyAndNoncanonicalPayload(t *testing.T) {
	policy, privateKey := newPlacementAdmissionPolicy(t)
	intent := testManagedPlacementIntent()
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
	regionOrder := [...]oci.Region{oci.RegionGRU, oci.RegionSJC, oci.RegionFRA}
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
		snapshot: authority.Snapshot{DeploymentID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", Scope: "gru", CandidateID: "0000000000GR3712FB1A87M2H7", Leader: true, Ready: true,
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
