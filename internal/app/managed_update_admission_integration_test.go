package app

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/delivery"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/host"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/hostboot"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/memberstatus"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/natscell"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/oci"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/placement"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
)

func TestTrustedOperatorManagedUpdatePrepareCommitsThroughAppToR3(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()
	root := t.TempDir()
	const cell = "gru"

	broker, err := natscell.Start(ctx, natscell.Config{Cell: cell, Instance: "managed-update-app-integration",
		Replicas: 1, Lab: true,
		Embedded: &natscell.Embedded{Host: "127.0.0.1", Port: -1, StoreDir: filepath.Join(root, "nats")}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = broker.Close() })
	control, err := authority.Start(ctx, broker.JetStream(), authority.Config{
		Scope: cell, CandidateID: "managed-update-app-integration", Replicas: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = control.Close() })
	if !control.Current().CanMutate() {
		t.Fatal("regional authority did not acquire a mutable lease")
	}
	epoch := control.Current().Epoch

	operatorPublic, operatorPrivate := testEd25519(t, root, "operator.key")
	compatibilityPublic, compatibilityPrivate := testEd25519(t, root, "compatibility.key")
	operatorGrant := TrustedSignerConfig{Actor: "ops", PublicKey: base64.StdEncoding.EncodeToString(operatorPublic),
		Roles: []string{"terrabase"}, Environments: []string{"production"},
		CanPlaceTerraBase: true, CanUpdateTerraBaseRuntime: true}
	compatibilityGrant := TrustedSignerConfig{Actor: "compat", PublicKey: base64.StdEncoding.EncodeToString(compatibilityPublic),
		Roles: []string{"terrabase"}, Environments: []string{"production"},
		CanCertifyTerraBaseCompatibility: true}
	policy, err := buildSignerPolicy(Config{NATS: natscell.Config{Cell: cell},
		Controller: ControllerConfig{TrustedSigners: []TrustedSignerConfig{operatorGrant, compatibilityGrant}}})
	if err != nil {
		t.Fatal(err)
	}

	artifactCodec := delivery.Ed25519Codec{Cell: cell, Actor: operatorGrant.Actor,
		PrivateKey: operatorPrivate, Lookup: policy.codec.Lookup, Lifetime: time.Minute, MaxLifetime: 5 * time.Minute}
	artifacts, err := delivery.Open(ctx, delivery.Config{Conn: broker.Conn(), JS: broker.JetStream(), Cell: cell,
		Replicas: 1, ArtifactSigner: artifactCodec, ArtifactVerifier: artifactCodec,
		AuthorizeArtifact: func(context.Context, string, delivery.ArtifactRecord) error { return nil }})
	if err != nil {
		t.Fatal(err)
	}
	artifact, claim, err := artifacts.PrepareArtifact(ctx, bytes.NewReader([]byte("candidate runtime bytes")),
		delivery.ArtifactClaimRequest{Source: delivery.ArtifactSource{
			Repository: "https://example.com/terrascale/terrabase", Commit: strings.Repeat("a", 40),
			TreeDigest: strings.Repeat("b", 64),
		}, Cell: cell, Role: "terrabase", Environment: "production"})
	if err != nil {
		t.Fatal(err)
	}
	if accepted, err := artifacts.AcceptArtifactClaim(ctx, claim); err != nil || accepted != artifact {
		t.Fatalf("admit candidate bytes before managed update: record=%+v err=%v", accepted, err)
	}
	admittedArtifact, err := artifacts.ResolveAdmittedArtifact(ctx, artifact.Digest, "terrabase", "production")
	if err != nil {
		t.Fatalf("read back admitted candidate: %v", err)
	}
	if admittedArtifact.Digest != artifact.Digest || admittedArtifact.ManifestDigest != artifact.ManifestDigest ||
		admittedArtifact.Source.TreeDigest != artifact.Source.TreeDigest {
		t.Fatalf("admitted candidate readback changed its signed pins: got=%+v want=%+v", admittedArtifact, artifact)
	}

	initial := testManagedPlacementIntentForRegions(oci.RegionGRU)
	for index := range initial.RuntimeManifests {
		initial.RuntimeManifests[index].SQLSchemaBundleSHA256 = strings.Repeat("c", 64)
	}
	if err := initial.ValidateForAdmission(); err != nil {
		t.Fatalf("managed placement fixture is invalid: %v", err)
	}
	placementPayload, err := protocol.EncodeJSON(initial)
	if err != nil {
		t.Fatal(err)
	}
	placementSequence, err := control.CommitPlacementIntent(ctx, epoch, initial.DatabaseID, initial.PartitionID,
		initial.OperationID(), 0, placementPayload)
	if err != nil {
		t.Fatalf("commit immutable baseline placement in R3: %v", err)
	}
	committedPlacement, err := placement.DecodeCommittedIntent(placementPayload)
	if err != nil {
		t.Fatal(err)
	}
	placementEntry, err := control.ReadPlacementIntent(ctx, initial.DatabaseID, initial.PartitionID)
	if err != nil || placementEntry.Sequence != placementSequence {
		t.Fatalf("read baseline placement sequence: entry=%+v err=%v", placementEntry, err)
	}

	intentReader, err := placement.NewAuthorityIntentReader(control, cell, oci.RegionGRU)
	if err != nil {
		t.Fatal(err)
	}
	stateStore, err := placement.NewJetStreamStore(ctx, broker.JetStream(), cell, 1, intentReader)
	if err != nil {
		t.Fatal(err)
	}
	states, instances, statuses, desired := managedUpdateAppBaseline(t, committedPlacement, epoch)
	for _, state := range states {
		if err := state.Validate(); err != nil {
			t.Fatalf("serving baseline member %s is invalid: %v", state.MemberID, err)
		}
		if _, err := stateStore.CompareAndSwap(ctx, 0, state); err != nil {
			t.Fatalf("persist serving baseline member %s: %v", state.MemberID, err)
		}
	}

	fleet := &managedUpdateAppFleet{instances: instances}
	hosts := &managedUpdateAppHosts{statuses: statuses, desired: desired}
	placementController, err := placement.StartController(ctx, placement.Config{
		Cell: cell, Region: oci.RegionGRU, FaultDomains: []string{"FAULT-DOMAIN-1", "FAULT-DOMAIN-2"},
		ManagedOwner: "regional-owner", FleetGeneration: 3, ImageID: "ocid1.image.oc1..image-a",
		Environment: "production", MemberRole: "terrabase",
		Resources: placement.Resources{CPU: 1, MemoryBytes: 1 << 30, DiskBytes: 32 << 30},
	}, stateStore, control, fleet, hosts, hosts, func(_ context.Context, digest, role, environment string) (placement.AdmittedArtifact, error) {
		if role != "terrabase" || environment != "production" {
			return placement.AdmittedArtifact{}, fmt.Errorf("unexpected baseline artifact %s/%s/%s", digest, role, environment)
		}
		if digest == artifact.Digest {
			return placement.AdmittedArtifact{Digest: artifact.Digest, ManifestDigest: artifact.ManifestDigest,
				SourceDigest: artifact.Source.TreeDigest}, nil
		}
		if digest != initial.RuntimeManifests[0].ArtifactDigest {
			return placement.AdmittedArtifact{}, fmt.Errorf("unexpected baseline artifact digest %s", digest)
		}
		return placement.AdmittedArtifact{Digest: digest, SourceDigest: initial.RuntimeManifests[0].SourceDigest}, nil
	})
	if err != nil {
		t.Fatal(err)
	}

	update := managedUpdateAppIntent(t, committedPlacement, placementSequence, epoch, artifact,
		states, compatibilityPrivate)
	if err := update.Validate(); err != nil {
		t.Fatalf("trusted operator update fixture is invalid: %v", err)
	}
	intentPath := testJSONFile(t, root, "managed-update.json", update)
	operatorConfig := Config{NATS: natscell.Config{Cell: cell},
		Controller: ControllerConfig{TrustedSigners: []TrustedSignerConfig{operatorGrant, compatibilityGrant}},
		Operator:   OperatorConfig{Actor: operatorGrant.Actor, SigningKeyFile: filepath.Join(root, "operator.key")}}

	subscription, err := serveManagedUpdateAdmission(ctx, broker.Conn(), cell, policy, control,
		placementController, artifacts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = subscription.Unsubscribe() })
	if err := broker.Conn().Flush(); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := operatorManagedUpdatePrepare(ctx, operatorConfig, broker, intentPath, &output); err != nil {
		t.Fatalf("trusted operator → app admission → R3 Prepare failed: %v", err)
	}
	var receipt managedUpdatePrepareResponse
	if err := json.Unmarshal(output.Bytes(), &receipt); err != nil {
		t.Fatalf("decode operator Prepare receipt: %v", err)
	}
	if receipt.DatabaseID != update.DatabaseID || receipt.PartitionID != update.PartitionID ||
		receipt.OperationID != update.OperationID || receipt.Phase != string(authority.ManagedUpdatePrepared) ||
		receipt.Sequence <= placementSequence {
		t.Fatalf("operator Prepare returned an unexpected R3 receipt: %+v", receipt)
	}
	entries, err := control.ReadManagedUpdateOperation(ctx, update.DatabaseID, update.PartitionID, update.OperationID)
	if err != nil || len(entries) != 1 || entries[0].Sequence != receipt.Sequence {
		t.Fatalf("R3 operation history = %+v, err=%v; want exact committed Prepare", entries, err)
	}
	var committed authority.ManagedUpdateRecord
	if err := json.Unmarshal(entries[0].Payload, &committed); err != nil {
		t.Fatal(err)
	}
	var signed protocol.Envelope
	if err := protocol.DecodeStrict(committed.SignedRequest, &signed, managedUpdateRequestMaxBytes); err != nil {
		t.Fatal(err)
	}
	if err := protocol.VerifyEnvelope(signed, protocol.EnvelopeScope{
		Region: cell, Kind: placement.ManagedUpdateEnvelopeKind, Actor: operatorGrant.Actor,
		OperationID: update.OperationID, Generation: update.CanaryDesiredGeneration, Epoch: epoch,
	}, operatorPublic, time.Now().UTC(), protocol.VerifyPolicy{MaxLifetime: 5 * time.Minute, ClockSkew: 30 * time.Second}); err != nil {
		t.Fatalf("verify exact signed request retained in R3 Prepare: %v", err)
	}
	if signed.Actor != operatorGrant.Actor || signed.KeyID == "" ||
		!bytes.Equal(signed.Payload, mustEncodeManagedUpdate(t, update)) ||
		committed.CandidateArtifactDigest != artifact.Digest ||
		committed.CandidateManifestDigest != artifact.ManifestDigest ||
		committed.CandidateSourceDigest != artifact.Source.TreeDigest {
		t.Fatalf("R3 Prepare did not retain the trusted operator request and admitted candidate pins: %+v", committed)
	}
}

func mustEncodeManagedUpdate(t *testing.T, intent placement.ManagedUpdateIntent) []byte {
	t.Helper()
	wire, err := protocol.EncodeJSON(intent)
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

func managedUpdateAppIntent(t *testing.T, initial placement.Intent, sequence, epoch uint64,
	artifact delivery.ArtifactRecord, states []placement.MemberState, compatibilityPrivate ed25519.PrivateKey,
) placement.ManagedUpdateIntent {
	t.Helper()
	stateBySeat := make(map[string]placement.MemberState, len(states))
	for _, state := range states {
		stateBySeat[state.MemberID] = state
	}
	seats := make([]placement.ManagedUpdateSeat, 0, len(states))
	volumes := make([]placement.ManagedUpdateVolumeProfile, 0, len(states))
	for _, state := range states {
		row := state.CanonicalRosterRow
		seats = append(seats, placement.ManagedUpdateSeat{
			SeatID: state.MemberID, Region: state.Region, MemberID: row.MemberID, Incarnation: row.Incarnation,
			TLSLeafSHA256: row.TLSLeafSHA256, RuntimeManifestDigest: state.RuntimeManifestDigest,
			HostNode: state.HostNode, HostGeneration: state.HostGeneration, HostAttempt: state.HostAttempt,
			OCIInstanceID: state.InstanceID, OCIOwner: "regional-owner", OCIFleetGeneration: 3,
			CreateKey: state.CreateKey, VolumeID: state.VolumeID, AttachmentID: state.AttachmentID,
			AttachmentETag: state.AttachmentETag, AttachmentDevice: state.AttachmentDevice,
			DesiredGeneration: state.DesiredGeneration, ArtifactDigest: state.RuntimeManifest.ArtifactDigest,
		})
		volumes = append(volumes, placement.ManagedUpdateVolumeProfile{SeatID: state.MemberID,
			VolumeID: state.VolumeID, FileSystemUUID: state.RuntimeManifest.FileSystemUUID,
			FileSystemType: state.RuntimeManifest.FileSystemType})
	}
	slices.SortFunc(seats, func(left, right placement.ManagedUpdateSeat) int { return strings.Compare(left.SeatID, right.SeatID) })
	slices.SortFunc(volumes, func(left, right placement.ManagedUpdateVolumeProfile) int {
		return strings.Compare(left.SeatID, right.SeatID)
	})
	canary := stateBySeat[permanentSeatID(oci.RegionGRU)]
	profile := placement.ManagedUpdateDurabilityProfile{SchemaVersion: placement.ManagedUpdateSchemaVersion,
		Region: oci.RegionGRU, Volumes: volumes,
		SQLSchemaBundleSHA256: canary.RuntimeManifest.SQLSchemaBundleSHA256,
		LiveS3ConfigSHA256:    canary.RuntimeManifest.LiveS3ConfigSHA256,
		LiveS3TargetSHA256:    canary.RuntimeManifest.LiveS3TargetSHA256,
		LiveS3Credential:      canary.RuntimeManifest.LiveS3Credential}
	profileDigest, err := profile.Digest()
	if err != nil {
		t.Fatal(err)
	}
	intent := placement.ManagedUpdateIntent{
		SchemaVersion: placement.ManagedUpdateSchemaVersion, Cell: "gru", DatabaseID: initial.DatabaseID,
		PartitionID: initial.PartitionID, PlacementGeneration: initial.Generation,
		PlacementPayloadDigest: initial.PayloadDigest(), PlacementSequence: sequence, AuthorityEpoch: epoch,
		OperationID: "managed-update-app-integration", Role: "terrabase", Environment: "production",
		OldArtifactDigest: canary.RuntimeManifest.ArtifactDigest, CandidateArtifactDigest: artifact.Digest,
		CandidateManifestDigest: artifact.ManifestDigest, CandidateSourceDigest: artifact.Source.TreeDigest,
		CanarySeatID: canary.MemberID, CanaryDesiredGeneration: canary.DesiredGeneration + 1,
		DurabilityProfile: profile, Seats: seats,
	}
	evidence := placement.ManagedCompatibilityEvidence{SchemaVersion: placement.ManagedCompatibilitySchemaVersion,
		Cell: intent.Cell, OperationID: intent.OperationID, OldArtifactDigest: intent.OldArtifactDigest,
		CandidateArtifactDigest: intent.CandidateArtifactDigest,
		CandidateManifestDigest: intent.CandidateManifestDigest, DurabilityProfileSHA256: profileDigest,
		MixedVersionReplicationSupported: true, ClientDataCompatibilitySupported: true,
		PersistentFormatReadSupported: true, PersistentFormatWriteSupported: true}
	payload, err := protocol.EncodeJSON(evidence)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	intent.CompatibilityEvidence, err = protocol.SignEnvelope(payload, protocol.EnvelopeScope{
		Region: "gru", Kind: placement.ManagedCompatibilityEnvelopeKind, Actor: "compat",
		OperationID: intent.OperationID, Generation: intent.CanaryDesiredGeneration, Epoch: epoch,
	}, now, now.Add(time.Minute), compatibilityPrivate)
	if err != nil {
		t.Fatal(err)
	}
	return intent
}

func managedUpdateAppBaseline(t *testing.T, intent placement.Intent, epoch uint64,
) ([]placement.MemberState, []oci.Instance, []host.HostStatus, []host.Desired) {
	t.Helper()
	now := time.Now().UTC()
	rosterDigest, err := intent.CanonicalRosterDigest()
	if err != nil {
		t.Fatal(err)
	}
	profile, err := intent.ManagedHostProfile(oci.RegionGRU)
	if err != nil {
		t.Fatal(err)
	}
	profileDigest, err := profile.ProfileDigest()
	if err != nil {
		t.Fatal(err)
	}
	states := make([]placement.MemberState, 0, 2)
	instances := make([]oci.Instance, 0, 2)
	statuses := make([]host.HostStatus, 0, 2)
	desired := make([]host.Desired, 0, 2)

	for index, seatID := range []string{permanentSeatID(oci.RegionGRU), elasticSeatID(oci.RegionGRU)} {
		seat := placement.Seat{MemberID: seatID, Region: oci.RegionGRU, Kind: placement.MemberPermanent,
			FailureDomain: "FAULT-DOMAIN-1"}
		if index == 1 {
			seat.Kind = placement.MemberElastic
			seat.FailureDomain = "FAULT-DOMAIN-2"
		}
		row, err := intent.RosterRowForSeat(seat)
		if err != nil {
			t.Fatal(err)
		}
		manifest, err := intent.RuntimeManifestForSeat(seat)
		if err != nil {
			t.Fatal(err)
		}
		manifestDigest, err := manifest.Digest()
		if err != nil {
			t.Fatal(err)
		}
		hostNode := fmt.Sprintf("managed-host-%c", 'a'+rune(index))
		instanceID := fmt.Sprintf("ocid1.instance.oc1..managed-%c", 'a'+rune(index))
		volumeID := fmt.Sprintf("ocid1.volume.oc1..managed-%c", 'a'+rune(index))
		attachmentID := fmt.Sprintf("ocid1.volumeattachment.oc1..managed-%c", 'a'+rune(index))
		createKey := fmt.Sprintf("managed-create-%c", 'a'+rune(index))
		attachmentETag := fmt.Sprintf("attachment-etag-%c", 'a'+rune(index))
		attachmentDevice := fmt.Sprintf("/dev/oracleoci/oraclevd%c", 'a'+rune(index))
		hostGeneration := uint64(2 + index*2)
		desiredGeneration := uint64(4 + index*4)
		state := placement.MemberState{
			SchemaVersion: 5, DatabaseID: intent.DatabaseID, PartitionID: intent.PartitionID,
			MemberID: seatID, Region: oci.RegionGRU, FailureDomain: seat.FailureDomain, Kind: seat.Kind,
			Stage: placement.StageServing, CreateKey: createKey, HostNode: hostNode, InstanceID: instanceID,
			InstanceETag: fmt.Sprintf("instance-etag-%c", 'a'+rune(index)), VolumeID: volumeID,
			AttachmentID: attachmentID, AttachmentDevice: attachmentDevice, AttachmentETag: attachmentETag,
			HostAttempt: 1, IntentGeneration: intent.Generation, IntentPayloadDigest: intent.PayloadDigest(),
			ManagedHostProfile: profile, ManagedHostProfileDigest: profileDigest, CanonicalRosterRow: row,
			CanonicalRosterDigest: rosterDigest, AuthorityReference: intent.CanonicalRoster.Authority,
			RuntimeManifest: manifest, RuntimeManifestDigest: manifestDigest,
			DesiredGeneration: desiredGeneration, HostGeneration: hostGeneration,
			OperationID: fmt.Sprintf("serving-member-%c", 'a'+rune(index)), UpdatedAt: now,
		}
		if err := state.Validate(); err != nil {
			t.Fatalf("build member %s serving state: %v", seatID, err)
		}
		descriptor := hostboot.Descriptor{SchemaVersion: hostboot.SchemaVersion, Cell: "gru", Region: string(oci.RegionGRU),
			Node: hostNode, Owner: "regional-owner", FleetGeneration: 3, CreateKey: createKey,
			ImageID: "ocid1.image.oc1..image-a", DatabaseID: state.DatabaseID, PartitionID: state.PartitionID,
			SeatID: state.MemberID, HostAttempt: state.HostAttempt, IntentGeneration: state.IntentGeneration,
			IntentPayloadDigest: state.IntentPayloadDigest, CanonicalRosterDigest: rosterDigest,
			ManagedHostProfileDigest: profileDigest, RuntimeManifestDigest: manifestDigest}
		bootDigest, err := descriptor.Digest()
		if err != nil {
			t.Fatal(err)
		}
		instance := oci.Instance{ID: instanceID, Node: hostNode, CreateKey: createKey, Region: oci.RegionGRU,
			Generation: 3, Owner: "regional-owner", PrivateIP: strings.Split(manifest.ReplicationListenAddress, ":")[0],
			FaultDomain: seat.FailureDomain, Shape: profile.Compute.Shape, WholeOCPUs: profile.Compute.WholeOCPUs,
			MemoryInGBs: profile.Compute.MemoryInGBs, PlacementProfileDigest: profileDigest,
			PlacementGeneration: intent.Generation, ImageID: "ocid1.image.oc1..image-a", BootDescriptorSHA256: bootDigest,
			ETag: state.InstanceETag, State: "RUNNING", DataVolumes: []string{volumeID},
			Attachments: []oci.Attachment{{ID: attachmentID, VolumeID: volumeID, InstanceID: instanceID,
				ETag: attachmentETag, State: "ATTACHED", Device: attachmentDevice,
				IsPvEncryptionInTransitEnabled: true}}}
		binding := host.ManagedMemberBinding{Scope: host.MemberScope{ClusterID: intent.CanonicalRoster.ClusterID,
			TenantID: intent.CanonicalRoster.TenantID, DatabaseID: intent.CanonicalRoster.DatabaseID,
			ShardID: intent.CanonicalRoster.ShardID, MemberID: row.MemberID, Incarnation: row.Incarnation},
			HostAttempt: state.HostAttempt}
		mountPath, err := host.ManagedMountPath(manifest.ManagedRuntimeRoot, binding)
		if err != nil {
			t.Fatal(err)
		}
		authorityPin := host.MemberAuthority{Epoch: intent.CanonicalRoster.Authority.Epoch,
			ConfigurationID:   intent.CanonicalRoster.Authority.ConfigurationID,
			CertificateSHA256: intent.CanonicalRoster.Authority.CertificateSHA256,
			TLSLeafSHA256:     row.TLSLeafSHA256}
		ociPin := host.ManagedOCIBinding{Region: string(oci.RegionGRU), InstanceID: instanceID,
			Owner: "regional-owner", FleetGeneration: 3, CreateKey: createKey}
		runtimePins := &host.ManagedRuntimePins{DevicePath: attachmentDevice, MountPath: mountPath,
			FileSystemUUID: manifest.FileSystemUUID, FileSystemType: manifest.FileSystemType,
			TrustedKeySHA256:                    manifest.TrustedKeySHA256,
			ServerCertificateSHA256:             manifest.ServerCertificateSHA256,
			ServerPrivateKeySHA256:              manifest.ServerPrivateKeySHA256,
			ClientCARootsSHA256:                 manifest.ClientCARootsSHA256,
			ClientManagedMaterialManifestSHA256: manifest.ClientManagedMaterialManifestSHA256,
			SQLSchemaBundleSHA256:               manifest.SQLSchemaBundleSHA256,
			LiveS3ConfigSHA256:                  manifest.LiveS3ConfigSHA256, LiveS3TargetSHA256: manifest.LiveS3TargetSHA256,
			LiveS3Credential:          manifest.LiveS3Credential,
			ReplicationListenAddress:  manifest.ReplicationListenAddress,
			ReplicationPeerMemberID:   manifest.ReplicationPeerMemberID,
			ReplicationPeerAddress:    manifest.ReplicationPeerAddress,
			ReplicationServerCASHA256: manifest.ReplicationServerCASHA256}
		desiredMember := &host.ManagedMemberLaunch{OCI: ociPin, Member: binding, Authority: authorityPin,
			SourceDigest: manifest.SourceDigest, VolumeID: volumeID, AttachmentID: attachmentID,
			AttachmentETag: attachmentETag, ProcessMemoryBytes: profile.ProcessMemoryBytes,
			MemoryHeadroomBytes: profile.MemoryHeadroomBytes, CgroupMemoryMaxBytes: profile.CgroupMemoryMaxBytes,
			SystemReserveBytes: profile.SystemReserveBytes, Runtime: runtimePins}
		desired = append(desired, host.Desired{Cell: "gru", Node: hostNode, Environment: "production",
			Role: "terrabase", Digest: manifest.ArtifactDigest, Generation: desiredGeneration,
			AuthorityEpoch: epoch, ManagedMember: desiredMember})

		peer := intent.CanonicalRoster.Rows[index^1]
		proof := memberstatus.ServingProof{SchemaVersion: 1, Nonce: strings.Repeat(string('1'+rune(index)), 32),
			Process: memberstatus.Process{PID: 100 + index, StartNonce: strings.Repeat(string('a'+rune(index)), 32)},
			Scope: memberstatus.Scope{ClusterID: intent.CanonicalRoster.ClusterID,
				TenantID: intent.CanonicalRoster.TenantID, DatabaseID: intent.CanonicalRoster.DatabaseID,
				ShardID: intent.CanonicalRoster.ShardID, MemberID: row.MemberID, Incarnation: row.Incarnation},
			Authority: memberstatus.Authority{Epoch: authorityPin.Epoch,
				ConfigurationID: authorityPin.ConfigurationID, CertificateSHA256: authorityPin.CertificateSHA256,
				TLSLeafSHA256: authorityPin.TLSLeafSHA256},
			Serving: true, Listeners: memberstatus.Listeners{Client: true, Replication: true},
			Object: memberstatus.ObjectProof{RootSHA256: strings.Repeat("1", 64), TargetSHA256: strings.Repeat("2", 64),
				InboxArchiveSHA256AtRecovery: strings.Repeat("3", 64), LocalSourceSequence: 4,
				RemoteInboxDurableSequence: 4, RemoteAppliedSequence: 4},
			Replication: memberstatus.ReplicationProof{LocalSourceSequence: 4,
				PeerMemberID: peer.MemberID, PeerIncarnation: peer.Incarnation, CurrentAuthenticated: true,
				PeerDurableSequence: 4, PeerAppliedSequence: 4, LocalInboxDurableSequence: 4}}
		managedReport := &host.ManagedRuntimeReport{Member: binding, Authority: authorityPin, OCI: ociPin,
			VolumeID: volumeID, AttachmentID: attachmentID, AttachmentETag: attachmentETag,
			FileSystemUUID: manifest.FileSystemUUID, FileSystemType: manifest.FileSystemType,
			MountDevice: attachmentDevice, MountPath: mountPath, MountID: 17,
			ProcessPID: proof.Process.PID, ProcessStart: "kernel-start-time", ProcessCgroup: "/terrascale/terrabase",
			ProcessBootID: proof.Process.StartNonce, StorageRecovered: true, ListenerReady: true, ServingProof: &proof}
		placementPin := &host.ManagedPlacementBinding{DatabaseID: state.DatabaseID, PartitionID: state.PartitionID,
			SeatID: seatID, IntentGeneration: state.IntentGeneration, IntentPayloadDigest: state.IntentPayloadDigest,
			CanonicalRosterDigest: rosterDigest, ManagedHostProfileDigest: profileDigest}
		memberPin := new(host.ManagedMemberBinding)
		*memberPin = binding
		ociPinPointer := new(host.ManagedOCIBinding)
		*ociPinPointer = ociPin
		registration := host.Registration{Cell: "gru", Node: hostNode, FailureDomain: seat.FailureDomain,
			Environment: "production", Roles: []string{"terrabase"}, Generation: hostGeneration,
			Capacity:         host.Capacity{CPU: 1, MemoryBytes: int64(profile.AllocatableMemoryBytes), DiskBytes: 32 << 30},
			ManagedPlacement: placementPin, ManagedOCI: ociPinPointer, ManagedMember: memberPin,
			SystemReserveBytes: int64(profile.SystemReserveBytes)}
		statuses = append(statuses, host.HostStatus{Registration: registration, SessionExpiresAt: now.Add(time.Hour),
			Verified: true, Reports: []host.Report{{Cell: "gru", Node: hostNode, Environment: "production",
				Role: "terrabase", Digest: manifest.ArtifactDigest, Generation: desiredGeneration,
				SessionID: "session-current", Epoch: epoch, State: "running", ObservedAt: now,
				Managed: managedReport}}})
		states = append(states, state)
		instances = append(instances, instance)
	}
	return states, instances, statuses, desired
}

type managedUpdateAppFleet struct {
	instances []oci.Instance
}

func (*managedUpdateAppFleet) Region() oci.Region                      { return oci.RegionGRU }
func (*managedUpdateAppFleet) VerifyPinnedImage(context.Context) error { return nil }
func (fleet *managedUpdateAppFleet) Observe(context.Context) ([]oci.Instance, error) {
	return slices.Clone(fleet.instances), nil
}
func (*managedUpdateAppFleet) EnsureHost(context.Context, oci.EnsureRequest) (oci.Instance, error) {
	return oci.Instance{}, errors.New("unexpected host launch in admission test")
}
func (*managedUpdateAppFleet) CreateRetainedVolume(context.Context, oci.VolumeCreateRequest) (oci.RetainedVolume, error) {
	return oci.RetainedVolume{}, errors.New("unexpected volume creation in admission test")
}
func (*managedUpdateAppFleet) Cordon(context.Context, string, string) error {
	return errors.New("unexpected host cordon in admission test")
}
func (*managedUpdateAppFleet) RequestDrain(context.Context, string, string) error {
	return errors.New("unexpected host drain in admission test")
}
func (*managedUpdateAppFleet) AttachRetainedVolume(context.Context, oci.VolumeAttachRequest) (oci.Attachment, error) {
	return oci.Attachment{}, errors.New("unexpected volume attachment in admission test")
}
func (*managedUpdateAppFleet) Detach(context.Context, string, string, string, oci.WriterStopEvidence) error {
	return errors.New("unexpected volume detach in admission test")
}
func (*managedUpdateAppFleet) Terminate(context.Context, string, string, oci.WriterStopEvidence) error {
	return errors.New("unexpected host termination in admission test")
}

type managedUpdateAppHosts struct {
	statuses []host.HostStatus
	desired  []host.Desired
}

func (hosts *managedUpdateAppHosts) ListHosts(context.Context) ([]host.HostStatus, error) {
	return slices.Clone(hosts.statuses), nil
}

func (hosts *managedUpdateAppHosts) ListDesired(context.Context, string) ([]host.Desired, error) {
	return slices.Clone(hosts.desired), nil
}

func (hosts *managedUpdateAppHosts) ApplyDesired(context.Context, host.Desired) (host.Receipt, error) {
	return host.Receipt{}, errors.New("unexpected desired write in admission test")
}

var _ oci.Fleet = (*managedUpdateAppFleet)(nil)
var _ placement.HostView = (*managedUpdateAppHosts)(nil)
var _ placement.DesiredWriter = (*managedUpdateAppHosts)(nil)
