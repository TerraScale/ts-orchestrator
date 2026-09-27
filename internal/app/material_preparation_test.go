package app

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/host"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/managedmaterial"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/natscell"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/oci"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"
)

type preparationTestFencer struct{}

type appNativeMaterialValidator struct{}

func (appNativeMaterialValidator) ValidateManagedMaterial(_ context.Context, input managedmaterial.NativeMaterialInput, pin string) error {
	if len(input.Certificate) == 0 || len(input.SignedV2S3Config) == 0 || input.ExpectedS3TargetDigest == "" || pin == "" {
		return errors.New("native material request is incomplete")
	}
	return nil
}

func (preparationTestFencer) Current() authority.Snapshot {
	return authority.Snapshot{Ready: true, Leader: true, Epoch: 9, Revision: 1,
		ExpiresAt: time.Now().Add(time.Minute)}
}
func (preparationTestFencer) Guard(_ context.Context, epoch uint64) error {
	if epoch != 9 {
		return authority.ErrFenced
	}
	return nil
}

type preparationTestObjects struct {
	contents []byte
	name     string
	puts     int
}

func (client *preparationTestObjects) PutObject(_ context.Context,
	request objectstorage.PutObjectRequest,
) (objectstorage.PutObjectResponse, error) {
	client.puts++
	if request.ObjectName == nil || request.IfNoneMatch == nil || *request.IfNoneMatch != "*" ||
		request.OpcSseKmsKeyId == nil || request.PutObjectBody == nil || client.contents != nil {
		return objectstorage.PutObjectResponse{}, errors.New("material object was not create-only with KMS")
	}
	data, err := io.ReadAll(request.PutObjectBody)
	if err != nil {
		return objectstorage.PutObjectResponse{}, err
	}
	client.name, client.contents = *request.ObjectName, bytes.Clone(data)
	return objectstorage.PutObjectResponse{VersionId: new("version-one"), ETag: new("etag-one")}, nil
}

func (client *preparationTestObjects) GetObject(_ context.Context,
	request objectstorage.GetObjectRequest,
) (objectstorage.GetObjectResponse, error) {
	if client.contents == nil {
		return objectstorage.GetObjectResponse{}, preparationNotFound{}
	}
	if request.ObjectName == nil || *request.ObjectName != client.name ||
		request.VersionId != nil && *request.VersionId != "version-one" ||
		request.IfMatch != nil && *request.IfMatch != "etag-one" {
		return objectstorage.GetObjectResponse{}, errors.New("material exact version changed")
	}
	return objectstorage.GetObjectResponse{Content: io.NopCloser(bytes.NewReader(client.contents)),
		ContentLength: new(int64(len(client.contents))), VersionId: new("version-one"), ETag: new("etag-one")}, nil
}

type preparationNotFound struct{}

func (preparationNotFound) Error() string          { return "not found" }
func (preparationNotFound) GetHTTPStatusCode() int { return 404 }

type preparationTestReceipts struct{ entry *authority.LogEntry }

func (store *preparationTestReceipts) ReadMaterialReceipt(_ context.Context, database, partition string) (authority.LogEntry, error) {
	if store.entry == nil || store.entry.SubjectKey != database+"."+partition {
		return authority.LogEntry{}, authority.ErrNotFound
	}
	return *store.entry, nil
}
func (store *preparationTestReceipts) CommitMaterialReceipt(_ context.Context, epoch uint64,
	database, partition, operation string, expected uint64, payload []byte,
) (uint64, error) {
	if epoch != 9 || expected != 0 || store.entry != nil {
		return 0, authority.ErrConflict
	}
	store.entry = &authority.LogEntry{Kind: authority.MutationMaterialReceipt,
		SubjectKey: database + "." + partition, OperationID: operation, Epoch: epoch,
		Sequence: 1, Payload: bytes.Clone(payload)}
	return 1, nil
}

func TestSignedOperatorPreparationCommitsExactMaterialAndReturnsCiphertext(t *testing.T) {
	operatorPublic, operatorPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	recipientPublic, recipientPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, controllerPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	customer, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	firstCatalog, err := managedmaterial.EmptyInitialCatalog("30000000-0000-0000-0000-000000000001")
	if err != nil {
		t.Fatal(err)
	}
	secondCatalog, err := managedmaterial.EmptyInitialCatalog("30000000-0000-0000-0000-000000000002")
	if err != nil {
		t.Fatal(err)
	}
	spec := managedmaterial.InitialSpec{PlacementDatabaseID: "db-main", PartitionID: "partition-a",
		Scope: managedmaterial.AuthorityScope{ClusterID: "0102030405060708090a0b0c0d0e0f10",
			TenantID: "10000000-0000-0000-0000-000000000001", DatabaseID: "20000000-0000-0000-0000-000000000001",
			ShardID: 7, Epoch: 1},
		LiveS3: managedmaterial.LiveS3Target{Bucket: "alpha-live", Region: "sa-saopaulo-1",
			Endpoint:   "https://alpha.compat.objectstorage.sa-saopaulo-1.oci.customer-oci.com",
			Credential: oci.SecretVersionReference{SecretOCID: "ocid1.vaultsecret.oc1.sa-saopaulo-1.alpha", VersionNumber: 3}},
		Catalogs: []managedmaterial.InitialCatalogInput{
			{CollectionID: firstCatalog.CollectionID, CanonicalCatalog: firstCatalog.Bytes},
			{CollectionID: secondCatalog.CollectionID, CanonicalCatalog: secondCatalog.Bytes},
		},
		Members: [2]managedmaterial.InitialMember{
			{SeatID: "permanent-a", MemberID: "40000000-0000-0000-0000-000000000001", Incarnation: "01010101010101010101010101010101",
				ServerName: "a.replication.example", FailureDomain: "FAULT-DOMAIN-1", ReplicationIP: "10.0.0.11", ReplicationPort: 9443,
				ClientIP: "10.0.0.11", ClientPort: 9465},
			{SeatID: "elastic-gru", MemberID: "40000000-0000-0000-0000-000000000002", Incarnation: "02020202020202020202020202020202",
				ServerName: "b.replication.example", FailureDomain: "FAULT-DOMAIN-2", ReplicationIP: "10.0.0.12", ReplicationPort: 9443,
				ClientIP: "10.0.0.12", ClientPort: 9465},
		},
		Recipient: managedmaterial.RecipientGrant{PublicKey: customer.PublicKey().Bytes(),
			ExpiresAt: time.Now().UTC().Add(time.Hour).Truncate(time.Second)}}
	for index, member := range spec.Members {
		path, err := host.ManagedMaterialPath("/srv/terrabase-managed", host.ManagedMemberBinding{Scope: host.MemberScope{
			ClusterID: spec.Scope.ClusterID, TenantID: spec.Scope.TenantID, DatabaseID: spec.Scope.DatabaseID,
			ShardID: spec.Scope.ShardID, MemberID: member.MemberID, Incarnation: member.Incarnation,
		}, HostAttempt: 1})
		if err != nil {
			t.Fatal(err)
		}
		spec.Members[index].MaterialDirectory = path
	}
	spec.Recipient.Signature = ed25519.Sign(recipientPrivate, managedmaterial.RecipientGrantMessage(spec))
	objects := new(preparationTestObjects)
	receipts := new(preparationTestReceipts)
	repository, err := managedmaterial.NewRepository(managedmaterial.RepositoryConfig{
		Region: oci.RegionGRU, Cell: "gru", Namespace: "terrascale", Bucket: "material",
		KMSKeyID: "ocid1.key.oc1.sa-saopaulo-1.material"}, objects, preparationTestFencer{})
	if err != nil {
		t.Fatal(err)
	}
	service := managedmaterial.PreparationService{Cell: "gru", Repository: repository, Receipts: receipts,
		Fencer: preparationTestFencer{}, ControllerKey: controllerPrivate, RecipientSigner: recipientPublic,
		AllowedSubnetCIDR: "10.0.0.0/24", NativeValidator: appNativeMaterialValidator{},
		NativeVerifierSHA256: strings.Repeat("a", 64)}
	policy, err := buildSignerPolicy(Config{NATS: natscell.Config{Cell: "gru"}, Controller: ControllerConfig{
		TrustedSigners: []TrustedSignerConfig{{Actor: "ops", PublicKey: base64.StdEncoding.EncodeToString(operatorPublic),
			Roles: []string{"terrabase"}, Environments: []string{"production"}, CanPrepareManagedMaterial: true}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := protocol.EncodeJSON(spec)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	envelope, err := protocol.SignEnvelope(payload, protocol.EnvelopeScope{Region: "gru", Kind: "material.prepare",
		Actor: "ops", OperationID: materialPrepareOperationID(payload), Generation: 1, Epoch: 9},
		now, now.Add(time.Minute), operatorPrivate)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := protocol.EncodeJSON(envelope)
	if err != nil {
		t.Fatal(err)
	}
	reply, err := verifyAndPrepareMaterial(t.Context(), wire, "gru", policy, service)
	if err != nil || receipts.entry == nil || objects.puts != 1 || reply.Receipt.Object.VersionID == "" ||
		reply.Customer.Version != 2 || reply.Customer.Ciphertext == "" {
		t.Fatalf("signed preparation did not commit and return encrypted customer material: %+v, %v", reply, err)
	}
	controllerPublic := controllerPrivate.Public().(ed25519.PublicKey)
	if err := verifyMaterialPrepareReply(reply, controllerPublic, "gru", spec); err != nil {
		t.Fatalf("authentic reply was rejected: %v", err)
	}
	tamperedReply := reply
	tamperedReply.Customer.Ciphertext += "A"
	if err := verifyMaterialPrepareReply(tamperedReply, controllerPublic, "gru", spec); err == nil {
		t.Fatal("substituted customer ciphertext was accepted")
	}
	tamperedReply = reply
	tamperedReply.Receipt.Members[0].TLSLeafSHA256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if err := verifyMaterialPrepareReply(tamperedReply, controllerPublic, "gru", spec); err == nil {
		t.Fatal("substituted signed member pin was accepted")
	}
	otherSpec := spec
	otherSpec.Scope.Epoch++
	if err := verifyMaterialPrepareReply(reply, controllerPublic, "gru", otherSpec); err == nil {
		t.Fatal("reply for another requested spec was accepted")
	}
	wrongPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyMaterialPrepareReply(reply, wrongPublic, "gru", spec); err == nil {
		t.Fatal("reply from an untrusted controller was accepted")
	}
	retry, err := verifyAndPrepareMaterial(t.Context(), wire, "gru", policy, service)
	if err != nil || objects.puts != 1 || retry.Receipt.Signature != reply.Receipt.Signature {
		t.Fatalf("signed retry changed immutable material: %v", err)
	}
	policy.grants["ops"] = TrustedSignerConfig{Actor: "ops"}
	if _, err := verifyAndPrepareMaterial(t.Context(), wire, "gru", policy, service); err == nil {
		t.Fatal("preparation without a dedicated operator grant was accepted")
	}
}
