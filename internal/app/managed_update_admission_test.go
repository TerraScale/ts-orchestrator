package app

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json/v2"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/natscell"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/oci"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/placement"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/nats-io/nats.go"
)

func TestManagedUpdatePrepareProducerRegionMatchesLowercaseCell(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	root := t.TempDir()
	cell := "gru"
	broker, err := natscell.Start(ctx, natscell.Config{
		Cell: cell, Instance: "managed-update-admission", Replicas: 1, Lab: true,
		Embedded: &natscell.Embedded{Host: "127.0.0.1", Port: -1, StoreDir: filepath.Join(root, "nats")},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = broker.Close() })
	control, err := authority.Start(ctx, broker.JetStream(), authority.Config{
		Scope: cell, CandidateID: "managed-update-admission", Replicas: 1,
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
			{SeatID: "elastic-gru", VolumeID: "ocid1.volume.oc1..volume-a",
				FileSystemUUID: "123e4567-e89b-12d3-a456-426614174000", FileSystemType: "ext4"},
			{SeatID: "permanent-a", VolumeID: "ocid1.volume.oc1..volume-b",
				FileSystemUUID: "123e4567-e89b-12d3-a456-426614174001", FileSystemType: "xfs"},
		},
	}
	profileDigest, err := profile.Digest()
	if err != nil {
		t.Fatal(err)
	}
	intent := placement.ManagedUpdateIntent{
		SchemaVersion: placement.ManagedUpdateSchemaVersion, Cell: "gru", DatabaseID: "db-main",
		PartitionID: "partition-a", PlacementGeneration: 7, PlacementPayloadDigest: strings.Repeat("d", 64),
		PlacementSequence: 18, AuthorityEpoch: epoch, OperationID: "managed-update-a", Role: "terrabase",
		Environment: "production", OldArtifactDigest: oldArtifact, CandidateArtifactDigest: candidateArtifact,
		CandidateManifestDigest: strings.Repeat("1", 64), CandidateSourceDigest: strings.Repeat("2", 64),
		CanarySeatID: "elastic-gru", CanaryDesiredGeneration: 5, DurabilityProfile: profile,
		Seats: []placement.ManagedUpdateSeat{
			{SeatID: "elastic-gru", Region: oci.RegionGRU, MemberID: "123e4567-e89b-12d3-a456-426614174000",
				Incarnation: strings.Repeat("3", 32), TLSLeafSHA256: strings.Repeat("4", 64),
				RuntimeManifestDigest: strings.Repeat("5", 64), HostNode: "node-a", HostGeneration: 2,
				HostAttempt: 1, OCIInstanceID: "ocid1.instance.oc1..instance-a", OCIOwner: "owner-a",
				OCIFleetGeneration: 3, CreateKey: "host-a", VolumeID: "ocid1.volume.oc1..volume-a",
				AttachmentID: "ocid1.volumeattachment.oc1..attachment-a", AttachmentETag: "etag-a",
				AttachmentDevice: "/dev/oracleoci/oraclevda", DesiredGeneration: 4, ArtifactDigest: oldArtifact},
			{SeatID: "permanent-a", Region: oci.RegionGRU, MemberID: "123e4567-e89b-12d3-a456-426614174001",
				Incarnation: strings.Repeat("6", 32), TLSLeafSHA256: strings.Repeat("7", 64),
				RuntimeManifestDigest: strings.Repeat("8", 64), HostNode: "node-b", HostGeneration: 4,
				HostAttempt: 1, OCIInstanceID: "ocid1.instance.oc1..instance-b", OCIOwner: "owner-a",
				OCIFleetGeneration: 3, CreateKey: "host-b", VolumeID: "ocid1.volume.oc1..volume-b",
				AttachmentID: "ocid1.volumeattachment.oc1..attachment-b", AttachmentETag: "etag-b",
				AttachmentDevice: "/dev/oracleoci/oraclevdb", DesiredGeneration: 8, ArtifactDigest: oldArtifact},
		},
	}
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
