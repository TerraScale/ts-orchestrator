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
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/natscell"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/oci"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/placement"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
)

func TestPlacementAdmissionCommitsSignedCanonicalV2AndExposesDigests(t *testing.T) {
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
		SchemaVersion: 1, DatabaseID: intent.DatabaseID, PartitionID: intent.PartitionID,
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
	return placement.Intent{
		SchemaVersion: placement.IntentSchemaVersion, DatabaseID: "db-main", PartitionID: "partition-a",
		ActiveRegions: []oci.Region{oci.RegionGRU}, Generation: 7,
		ManagedHostProfiles: []placement.ManagedHostProfile{{
			Region:             oci.RegionGRU,
			Compute:            placement.ComputeTuple{Shape: "VM.Standard.E4.Flex", WholeOCPUs: 1, MemoryInGBs: 6},
			ProcessMemoryBytes: 4 << 30, MemoryHeadroomBytes: 1 << 30,
			CgroupMemoryMaxBytes: 4 << 30, SystemReserveBytes: 1 << 30,
			AllocatableMemoryBytes: 5 << 30,
		}},
	}
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
	nextSeq  uint64
}

func newPlacementAdmissionControl() *placementAdmissionTestControl {
	return &placementAdmissionTestControl{
		snapshot: authority.Snapshot{Scope: "gru", CandidateID: "controller-a", Leader: true, Ready: true,
			Epoch: 3, Revision: 1, ExpiresAt: time.Now().Add(time.Minute)},
		entries: make(map[string]authority.LogEntry),
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
