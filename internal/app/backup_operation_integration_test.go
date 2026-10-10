package app

import (
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/entityid"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/host"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/managedmaterial"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/natscell"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/oci"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/placement"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
)

func TestBackupAdmissionRechecksRosterAtFinalR3Commit(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()
	root := t.TempDir()
	const cell = "gru"

	broker, err := natscell.Start(ctx, natscell.Config{Cell: cell, Instance: "backup-roster-r3-integration",
		Replicas: 1, Lab: true,
		Embedded: &natscell.Embedded{Host: "127.0.0.1", Port: -1, StoreDir: filepath.Join(root, "nats")}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = broker.Close() })
	control, err := authority.Start(ctx, broker.JetStream(), authority.Config{DeploymentID: "01ARZ3NDEKTSV4RRFFQ69G5FAV",
		Scope: cell, CandidateID: "0000000000G3799641MSM6590R", Replicas: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = control.Close() })
	if !control.Current().CanMutate() {
		t.Fatal("regional authority did not acquire a mutable lease")
	}
	epoch := control.Current().Epoch

	operatorPublic, operatorPrivate := testEd25519(t, root, "backup-operator.key")
	_, controllerPrivate := testEd25519(t, root, "backup-controller.key")
	grant := TrustedSignerConfig{Actor: "ops", PublicKey: base64.StdEncoding.EncodeToString(operatorPublic),
		Roles: []string{"terrabase"}, Environments: []string{"production"}, CanOperateBackup: true}
	policy, err := buildSignerPolicy(Config{NATS: natscell.Config{Cell: cell},
		Controller: ControllerConfig{TrustedSigners: []TrustedSignerConfig{grant}}})
	if err != nil {
		t.Fatal(err)
	}

	baseline := testManagedPlacementIntent()
	spec, recipientSigner := backupAdmissionSpec(t, baseline)
	bundle, err := managedmaterial.GenerateInitial(spec, recipientSigner, time.Now().UTC())
	if err != nil {
		t.Fatalf("generate signed backup material: %v", err)
	}
	objects := new(preparationTestObjects)
	repository, err := managedmaterial.NewRepository(managedmaterial.RepositoryConfig{
		Region: oci.RegionGRU, Cell: cell, Namespace: "terrascale", Bucket: "material",
		KMSKeyID: "ocid1.key.oc1.sa-saopaulo-1.material",
	}, objects, control)
	if err != nil {
		t.Fatal(err)
	}
	materialNow := time.Now().UTC()
	object, err := repository.CreateInitial(ctx, epoch, spec.PartitionID, spec, bundle, controllerPrivate)
	if err != nil {
		t.Fatalf("write exact initial material object: %v", err)
	}
	receipt, err := managedmaterial.SignPreparationReceipt(cell, spec.PartitionID, spec, bundle,
		object, controllerPrivate, materialNow)
	if err != nil {
		t.Fatal(err)
	}
	receiptPayload, err := protocol.EncodeJSON(receipt)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := control.CommitMaterialReceipt(ctx, epoch, spec.PlacementDatabaseID,
		spec.PartitionID, entityid.Derive("material-receipt", receipt.SpecSHA256), 0, receiptPayload); err != nil {
		t.Fatalf("commit exact material receipt to R3: %v", err)
	}
	preparation := managedmaterial.PreparationService{Cell: cell, Repository: repository, Receipts: control,
		Fencer: control, ControllerKey: controllerPrivate, RecipientSigner: recipientSigner,
		AllowedSubnetCIDR: "10.0.0.0/24"}

	intent := backupAdmissionIntent(t, baseline, receipt)
	intentPayload, err := protocol.EncodeJSON(intent)
	if err != nil {
		t.Fatal(err)
	}
	intent, err = placement.DecodeCommittedIntent(intentPayload)
	if err != nil {
		t.Fatalf("decode committed baseline placement: %v", err)
	}
	placementSequence, err := control.CommitPlacementIntent(ctx, epoch, intent.DatabaseID, intent.PartitionID,
		entityid.Derive("test", "backup-roster-integration-placement"), 0, intentPayload)
	if err != nil {
		t.Fatalf("commit exact baseline placement to R3: %v", err)
	}
	store := &backupAdmissionChangingRoster{databaseID: intent.DatabaseID, partitionID: intent.PartitionID,
		states: [2][]placement.VersionedMemberState{
			backupAdmissionServingStates(intent, []string{"managed-host-a", "managed-host-b"}),
			backupAdmissionServingStates(intent, []string{"managed-host-a-replaced", "managed-host-b"}),
		}}
	if placementSequence == 0 {
		t.Fatal("R3 placement sequence is zero")
	}

	runtime := backupOperationRuntime{cell: cell, memberRole: "terrabase", control: control,
		placements: store,
		producer:   managedmaterial.BackupOperationProducer{Preparation: preparation, Store: control},
		policy:     policy, responseKey: controllerPrivate}
	request := backupOperationRequest{Action: "start", DatabaseID: intent.DatabaseID,
		PartitionID: intent.PartitionID}
	payload, err := protocol.EncodeJSON(request)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	envelope, err := protocol.SignEnvelope(payload, protocol.EnvelopeScope{
		Region: cell, Kind: "backup.operation", Actor: grant.Actor, OperationID: entityid.New(),
		Generation: 1, Epoch: epoch,
	}, now, now.Add(time.Minute), operatorPrivate)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runtime.admit(ctx, envelope); !errors.Is(err, authority.ErrFenced) {
		t.Fatalf("backup Prepare with changed final serving roster = %v, want ErrFenced", err)
	}
	if store.calls != 2 {
		t.Fatalf("current roster reads = %d, want initial read and final R3 verification", store.calls)
	}
	if _, _, err := control.ReadBackupOperation(ctx, intent.DatabaseID, intent.PartitionID); !errors.Is(err, authority.ErrNotFound) {
		t.Fatalf("R3 retained backup operation after final roster mismatch: %v", err)
	}
}

func backupAdmissionSpec(t *testing.T, baseline placement.Intent) (managedmaterial.InitialSpec, ed25519.PublicKey) {
	t.Helper()
	now := time.Now().UTC()
	recipient, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	recipientPublic, recipientPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	firstCatalog, err := managedmaterial.InitialCatalog("1G000000000000000000000001", nil)
	if err != nil {
		t.Fatal(err)
	}
	secondCatalog, err := managedmaterial.InitialCatalog("1G000000000000000000000002", nil)
	if err != nil {
		t.Fatal(err)
	}
	spec := managedmaterial.InitialSpec{PlacementDatabaseID: baseline.DatabaseID, PartitionID: baseline.PartitionID,
		Scope: managedmaterial.AuthorityScope{ClusterID: baseline.CanonicalRoster.ClusterID,
			TenantID: baseline.CanonicalRoster.TenantID, DatabaseID: baseline.CanonicalRoster.DatabaseID,
			ShardID: baseline.CanonicalRoster.ShardID, Epoch: 1},
		LiveS3: managedmaterial.LiveS3Target{Bucket: "alpha-live", Region: "sa-saopaulo-1",
			Endpoint:   "https://alpha.compat.objectstorage.sa-saopaulo-1.oci.customer-oci.com",
			Credential: oci.SecretVersionReference{SecretOCID: "ocid1.vaultsecret.oc1.sa-saopaulo-1.alpha", VersionNumber: 3}},
		Catalogs: []managedmaterial.InitialCatalogInput{
			{CollectionID: firstCatalog.CollectionID, CanonicalCatalog: firstCatalog.Bytes},
			{CollectionID: secondCatalog.CollectionID, CanonicalCatalog: secondCatalog.Bytes},
		},
		Recipient: managedmaterial.RecipientGrant{PublicKey: recipient.PublicKey().Bytes(),
			ExpiresAt: now.Add(time.Hour).UTC().Truncate(time.Second)},
	}
	backupTarget := managedmaterial.BackupS3Target{Bucket: "alpha-backup", Region: "sa-saopaulo-1",
		Endpoint:         "https://backup.compat.objectstorage.sa-saopaulo-1.oci.customer-oci.com",
		Credential:       oci.SecretVersionReference{SecretOCID: "ocid1.vaultsecret.oc1.sa-saopaulo-1.backup", VersionNumber: 4},
		CredentialSHA256: strings.Repeat("9", 64)}
	spec.Backup = &managedmaterial.InitialBackupSpec{Target: backupTarget,
		OwnerMemberID: baseline.CanonicalRoster.Rows[0].MemberID,
		DataKey:       oci.SecretVersionReference{SecretOCID: "ocid1.vaultsecret.oc1.sa-saopaulo-1.backupkey", VersionNumber: 5},
		DataKeyID:     entityid.Derive("test-key", "backup-key-v1"), DataKeySHA256: strings.Repeat("a", 64),
		RetentionPolicyID: entityid.Derive("test-retention", "retention-30d"), RetentionUntilUnixMS: uint64(now.Add(30 * 24 * time.Hour).UnixMilli()),
		MaxPointCadenceMS: 60_000}

	for index, row := range baseline.CanonicalRoster.Rows {
		manifest, err := baseline.RuntimeManifestForSeat(placement.Seat{MemberID: row.SeatID, Region: row.Region})
		if err != nil {
			t.Fatalf("baseline manifest for seat %s is unavailable: %v", row.SeatID, err)
		}
		ip, portText, err := net.SplitHostPort(manifest.ReplicationListenAddress)
		if err != nil {
			t.Fatalf("parse baseline replication address: %v", err)
		}
		port, err := strconv.Atoi(portText)
		if err != nil {
			t.Fatalf("parse baseline replication port: %v", err)
		}
		binding := host.ManagedMemberBinding{Scope: host.MemberScope{ClusterID: spec.Scope.ClusterID,
			TenantID: spec.Scope.TenantID, DatabaseID: spec.Scope.DatabaseID, ShardID: spec.Scope.ShardID,
			MemberID: row.MemberID, Incarnation: row.Incarnation}, HostAttempt: 1}
		materialPath, err := host.ManagedMaterialPath("/srv/terrascale-managed", binding)
		if err != nil {
			t.Fatal(err)
		}
		spec.Members[index] = managedmaterial.InitialMember{SeatID: row.SeatID, MemberID: row.MemberID,
			Incarnation: row.Incarnation, ServerName: row.ServerName, FailureDomain: row.FailureDomain,
			MaterialDirectory: materialPath, ReplicationIP: ip, ReplicationPort: uint16(port),
			ClientIP: ip, ClientPort: 9465}
	}
	slices.SortFunc(spec.Members[:], func(a, b managedmaterial.InitialMember) int {
		return strings.Compare(a.MemberID, b.MemberID)
	})
	spec.Recipient.Signature = ed25519.Sign(recipientPrivate, managedmaterial.RecipientGrantMessage(spec))
	return spec, recipientPublic
}

func backupAdmissionIntent(t *testing.T, baseline placement.Intent,
	receipt managedmaterial.PreparationReceipt,
) placement.Intent {
	t.Helper()
	intent := baseline
	intent.Generation = 1
	intent.CanonicalRoster = baseline.CanonicalRoster
	intent.CanonicalRoster.ClusterID = receipt.Spec.Scope.ClusterID
	intent.CanonicalRoster.TenantID = receipt.Spec.Scope.TenantID
	intent.CanonicalRoster.DatabaseID = receipt.Spec.Scope.DatabaseID
	intent.CanonicalRoster.ShardID = receipt.Spec.Scope.ShardID
	intent.CanonicalRoster.Authority = placement.AuthorityReference{Version: 2, Epoch: receipt.Spec.Scope.Epoch,
		ConfigurationID: receipt.AuthorityConfigurationID, CertificateSHA256: receipt.AuthoritySHA256,
		TrustedKeySHA256: receipt.TrustedKeySHA256}
	backupTargetDigest, err := receipt.Spec.Backup.Target.Digest()
	if err != nil {
		t.Fatal(err)
	}
	for index := range intent.CanonicalRoster.Rows {
		row := &intent.CanonicalRoster.Rows[index]
		memberIndex := -1
		for candidate, member := range receipt.Spec.Members {
			if member.SeatID == row.SeatID {
				memberIndex = candidate
				break
			}
		}
		if memberIndex < 0 {
			t.Fatalf("receipt member for seat %s is absent", row.SeatID)
		}
		member, pins := receipt.Spec.Members[memberIndex], receipt.Members[memberIndex]
		row.MemberID, row.Incarnation, row.ServerName = member.MemberID, member.Incarnation, member.ServerName
		row.FailureDomain, row.TLSLeafSHA256 = member.FailureDomain, pins.TLSLeafSHA256
		manifestIndex := -1
		for candidate := range intent.RuntimeManifests {
			if intent.RuntimeManifests[candidate].SeatID == row.SeatID {
				manifestIndex = candidate
				break
			}
		}
		if manifestIndex < 0 {
			t.Fatalf("baseline runtime manifest for seat %s is absent", row.SeatID)
		}
		manifest := &intent.RuntimeManifests[manifestIndex]
		manifest.TrustedKeySHA256 = receipt.TrustedKeySHA256
		manifest.ServerCertificateSHA256 = pins.Files["server.crt"]
		manifest.ServerPrivateKeySHA256 = pins.Files["server.key"]
		manifest.ClientCARootsSHA256 = pins.Files["client-ca.pem"]
		manifest.ClientManagedMaterialManifestSHA256 = pins.Files["client-managed-manifest.json"]
		manifest.SQLSchemaBundleSHA256 = pins.Files["sql-schema.bundle"]
		manifest.LiveS3ConfigSHA256 = pins.Files["signed-v2-s3-config.json"]
		manifest.LiveS3TargetSHA256, err = receipt.Spec.LiveS3.Digest()
		if err != nil {
			t.Fatal(err)
		}
		manifest.LiveS3Credential = receipt.Spec.LiveS3.Credential
		manifest.BackupManifestSHA256 = pins.Files["backup-managed-manifest.json"]
		manifest.BackupS3ConfigSHA256 = pins.Files["backup-s3-config.json"]
		manifest.BackupS3TargetSHA256 = backupTargetDigest
		manifest.BackupS3CredentialSHA256 = receipt.Spec.Backup.Target.CredentialSHA256
		manifest.BackupDataKeySHA256 = receipt.Spec.Backup.DataKeySHA256
		manifest.BackupOwner = member.MemberID == receipt.Spec.Backup.OwnerMemberID
		manifest.BackupS3Credential, manifest.BackupDataKey = oci.SecretVersionReference{}, oci.SecretVersionReference{}
		if manifest.BackupOwner {
			manifest.BackupS3Credential = receipt.Spec.Backup.Target.Credential
			manifest.BackupDataKey = receipt.Spec.Backup.DataKey
		}
		manifest.ReplicationServerCASHA256 = pins.Files["server-ca.pem"]
		manifest.ReplicationListenAddress = net.JoinHostPort(member.ReplicationIP, strconv.Itoa(int(member.ReplicationPort)))
		peer := receipt.Spec.Members[memberIndex^1]
		manifest.ReplicationPeerMemberID = peer.MemberID
		manifest.ReplicationPeerAddress = net.JoinHostPort(peer.ReplicationIP, strconv.Itoa(int(peer.ReplicationPort)))
	}
	if err := intent.ValidateForAdmission(); err != nil {
		t.Fatalf("backup baseline placement is invalid: %v", err)
	}
	if err := managedmaterial.VerifyIntentAgainstReceipt(intent, receipt); err != nil {
		t.Fatalf("backup placement does not match the material receipt: %v", err)
	}
	return intent
}

type backupAdmissionChangingRoster struct {
	placement.Store
	databaseID  string
	partitionID string
	calls       int
	states      [2][]placement.VersionedMemberState
}

func (store *backupAdmissionChangingRoster) ListMembers(_ context.Context, databaseID, partitionID string,
) ([]placement.VersionedMemberState, error) {
	if databaseID != store.databaseID || partitionID != store.partitionID {
		return nil, fmt.Errorf("unexpected roster scope %s/%s", databaseID, partitionID)
	}
	index := min(store.calls, len(store.states)-1)
	store.calls++
	return append([]placement.VersionedMemberState(nil), store.states[index]...), nil
}

func backupAdmissionServingStates(intent placement.Intent, hosts []string) []placement.VersionedMemberState {
	states := make([]placement.VersionedMemberState, 0, len(intent.CanonicalRoster.Rows))
	for index, row := range intent.CanonicalRoster.Rows {
		states = append(states, placement.VersionedMemberState{State: placement.MemberState{
			DatabaseID: intent.DatabaseID, PartitionID: intent.PartitionID, MemberID: row.SeatID,
			Stage: placement.StageServing, HostNode: hosts[index], HostAttempt: 1,
			IntentGeneration: intent.Generation, IntentPayloadDigest: intent.PayloadDigest(),
			CanonicalRosterRow: row,
		}})
	}
	return states
}
