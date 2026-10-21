package app

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json/v2"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/natscell"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/placement"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/nats-io/nats.go"
)

func TestManagedUpdatePrepareProducerRegionMatchesLowercaseCell(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	root := t.TempDir()
	cell := "gru"
	broker, err := newAuthenticatedNATS(t, cell).start(t, ctx, natscell.Config{
		Cell: cell, Instance: "managed-update-admission", Replicas: 1,
		Embedded: &natscell.Embedded{Host: "127.0.0.1", Port: -1, StoreDir: filepath.Join(root, "nats")},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = broker.Close() })
	control, err := authority.Start(ctx, broker.JetStream(), authority.Config{DeploymentID: "01ARZ3NDEKTSV4RRFFQ69G5FAV",
		Scope: cell, CandidateID: "0000000000EA3538G44CHCDVJH", Replicas: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = control.Close() })
	if !control.Current().CanMutate() {
		t.Fatal("regional authority did not acquire a mutable lease")
	}

	operatorPublic, _ := testEd25519(t, root, "operator.key")
	grant := TrustedSignerConfig{Actor: "ops", PublicKey: base64.StdEncoding.EncodeToString(operatorPublic),
		Roles: []string{"terrabase"}, Environments: []string{"production"},
		CanPlaceTerraBase: true, CanUpdateTerraBaseRuntime: true}
	intent := signedManagedUpdateIntent(t, control.Current().Epoch)
	path := testJSONFile(t, root, "managed-update.json", intent)
	cfg := Config{NATS: natscell.Config{Cell: cell},
		Controller: ControllerConfig{TrustedSigners: []TrustedSignerConfig{grant}},
		Operator:   OperatorConfig{Actor: grant.Actor, SigningKeyFile: filepath.Join(root, "operator.key")}}

	wireCh := make(chan []byte, 1)
	subscription, err := broker.Conn().Subscribe(managedUpdatePrepareSubject(cell), func(message *nats.Msg) {
		wireCh <- bytes.Clone(message.Data)
		response, _ := json.Marshal(managedUpdatePrepareResponse{
			DatabaseID: intent.DatabaseID, PartitionID: intent.PartitionID, OperationID: intent.OperationID,
			Phase: string(authority.ManagedUpdatePrepared), Sequence: 42,
		})
		_ = message.Respond(response)
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = subscription.Unsubscribe() })
	if err := broker.Conn().Flush(); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := operatorManagedUpdatePrepare(ctx, cfg, broker, path, &output); err != nil {
		t.Fatalf("operator Prepare request failed: %v", err)
	}
	var wire []byte
	select {
	case wire = <-wireCh:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	var envelope protocol.Envelope
	if err := protocol.DecodeStrict(wire, &envelope, managedUpdateRequestMaxBytes); err != nil {
		t.Fatalf("decode operator signed Prepare: %v", err)
	}
	if envelope.Region != "GRU" {
		t.Fatalf("operator signed Prepare region = %q, want canonical GRU", envelope.Region)
	}
	var signedIntent placement.ManagedUpdateIntent
	if err := protocol.DecodeStrict(envelope.Payload, &signedIntent, protocol.MaxPayloadBytes); err != nil {
		t.Fatalf("decode operator Prepare payload: %v", err)
	}
	if err := protocol.VerifyEnvelope(envelope, protocol.EnvelopeScope{
		Region: cell, Kind: placement.ManagedUpdateEnvelopeKind, Actor: grant.Actor,
		OperationID: intent.OperationID, Generation: intent.CanaryDesiredGeneration, Epoch: intent.AuthorityEpoch,
	}, operatorPublic, time.Now().UTC(), protocol.VerifyPolicy{MaxLifetime: 5 * time.Minute, ClockSkew: 30 * time.Second}); err != nil {
		t.Fatalf("verify producer's actual signed Prepare: %v", err)
	}
	if err := validateManagedUpdateEnvelopeScope(signedIntent, envelope, cell); err != nil {
		t.Fatalf("regional admission rejected lowercase configured cell: %v", err)
	}

	policy, err := buildSignerPolicy(Config{Controller: ControllerConfig{TrustedSigners: []TrustedSignerConfig{grant}}})
	if err != nil {
		t.Fatal(err)
	}
	policy.signers.Store(&signerSet{grants: map[string]TrustedSignerConfig{grant.Actor: grant}})
	if _, err := verifyAndPrepareManagedUpdate(ctx, wire, cell, policy, control, nil, nil); err == nil ||
		err.Error() != "managed update signing key is untrusted" {
		t.Fatalf("signed Prepare did not pass regional scope validation before signer lookup: %v", err)
	}
}

func signedManagedUpdateIntent(t *testing.T, epoch uint64) placement.ManagedUpdateIntent {
	t.Helper()
	const (
		oldArtifact       = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
		candidateArtifact = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	)
	profile := placement.ManagedUpdateDurabilityProfile{
		SchemaVersion: placement.ManagedUpdateSchemaVersion, Region: oci.RegionGRU,
		SQLSchemaBundleSHA256: strings.Repeat("a", 64), LiveS3ConfigSHA256: strings.Repeat("b", 64),
		LiveS3TargetSHA256: strings.Repeat("c", 64),
		LiveS3Credential: oci.SecretVersionReference{
			SecretOCID: "ocid1.vaultsecret.oc1.sa-saopaulo-1.secret-a", VersionNumber: 1,
		},
		Volumes: []placement.ManagedUpdateVolumeProfile{
			{SeatID: "0000000000XG8SBD7XGE97V28G", VolumeID: "ocid1.volume.oc1..volume-a",
				FileSystemUUID: "123e4567-e89b-12d3-a456-426614174000", FileSystemType: "ext4"},
			{SeatID: "000000000082AXF7GZQT1D126Y", VolumeID: "ocid1.volume.oc1..volume-b",
				FileSystemUUID: "123e4567-e89b-12d3-a456-426614174001", FileSystemType: "xfs"},
		},
	}
	slices.SortFunc(profile.Volumes, func(a, b placement.ManagedUpdateVolumeProfile) int { return strings.Compare(a.SeatID, b.SeatID) })
	profileDigest, err := profile.Digest()
	if err != nil {
		t.Fatal(err)
	}
	intent := placement.ManagedUpdateIntent{
		SchemaVersion: placement.ManagedUpdateSchemaVersion, Cell: "gru", DatabaseID: "0000000000JJVVW9EMWY1PE1VX",
		PartitionID: "0000000000Z3WK359G2W66CVT8", PlacementGeneration: 7, PlacementPayloadDigest: strings.Repeat("d", 64),
		PlacementSequence: 18, AuthorityEpoch: epoch, OperationID: "0000000000E44GT0K557ASV7P0", Role: "terrabase",
		Environment: "production", OldArtifactDigest: oldArtifact, CandidateArtifactDigest: candidateArtifact,
		CandidateManifestDigest: strings.Repeat("1", 64), CandidateSourceDigest: strings.Repeat("2", 64),
		CanarySeatID: "0000000000XG8SBD7XGE97V28G", CanaryDesiredGeneration: 5, DurabilityProfile: profile,
		Seats: []placement.ManagedUpdateSeat{
			{SeatID: "0000000000XG8SBD7XGE97V28G", Region: oci.RegionGRU, MemberID: "0J7S2PFT4V2B9T8NJ2CRA1EG00",
				Incarnation: "33333333333333333333333333333333", TLSLeafSHA256: strings.Repeat("4", 64),
				RuntimeManifestDigest: strings.Repeat("5", 64), HostNode: "node-a", HostGeneration: 2,
				HostAttempt: 1, OCIInstanceID: "ocid1.instance.oc1..instance-a", OCIOwner: "owner-a",
				OCIFleetGeneration: 3, CreateKey: "0000000000R58Y74PAABAQ7X2V", VolumeID: "ocid1.volume.oc1..volume-a",
				AttachmentID: "ocid1.volumeattachment.oc1..attachment-a", AttachmentETag: "etag-a",
				AttachmentDevice: "/dev/oracleoci/oraclevda", DesiredGeneration: 4, ArtifactDigest: oldArtifact},
			{SeatID: "000000000082AXF7GZQT1D126Y", Region: oci.RegionGRU, MemberID: "0J7S2PFT4V2B9T8NJ2CRA1EG01",
				Incarnation: "66666666666666666666666666666666", TLSLeafSHA256: strings.Repeat("7", 64),
				RuntimeManifestDigest: strings.Repeat("8", 64), HostNode: "node-b", HostGeneration: 4,
				HostAttempt: 1, OCIInstanceID: "ocid1.instance.oc1..instance-b", OCIOwner: "owner-a",
				OCIFleetGeneration: 3, CreateKey: "0000000000GTA7T55FAST9ZNW4", VolumeID: "ocid1.volume.oc1..volume-b",
				AttachmentID: "ocid1.volumeattachment.oc1..attachment-b", AttachmentETag: "etag-b",
				AttachmentDevice: "/dev/oracleoci/oraclevdb", DesiredGeneration: 8, ArtifactDigest: oldArtifact},
		},
	}
	slices.SortFunc(intent.Seats, func(a, b placement.ManagedUpdateSeat) int { return strings.Compare(a.SeatID, b.SeatID) })
	statement := placement.ManagedCompatibilityEvidence{
		SchemaVersion: placement.ManagedCompatibilitySchemaVersion, Cell: intent.Cell,
		OperationID: intent.OperationID, OldArtifactDigest: intent.OldArtifactDigest,
		CandidateArtifactDigest: intent.CandidateArtifactDigest,
		CandidateManifestDigest: intent.CandidateManifestDigest, DurabilityProfileSHA256: profileDigest,
		MixedVersionReplicationSupported: true, ClientDataCompatibilitySupported: true,
		PersistentFormatReadSupported: true, PersistentFormatWriteSupported: true,
	}
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := protocol.EncodeJSON(statement)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	intent.CompatibilityEvidence, err = protocol.SignEnvelope(payload, protocol.EnvelopeScope{
		Region: intent.Cell, Kind: placement.ManagedCompatibilityEnvelopeKind, Actor: "compat",
		OperationID: intent.OperationID, Generation: intent.CanaryDesiredGeneration, Epoch: epoch,
	}, now, now.Add(time.Minute), private)
	if err != nil {
		t.Fatal(err)
	}
	if err := intent.Validate(); err != nil {
		t.Fatalf("managed update intent fixture is invalid: %v", err)
	}
	return intent
}
