package managedmaterial

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/oci"
)

type fakePreparationReceipts struct {
	entry       *authority.LogEntry
	commitCount int
	loseAck     bool
}

func (store *fakePreparationReceipts) ReadMaterialReceipt(_ context.Context, database, partition string) (authority.LogEntry, error) {
	if store.entry == nil {
		return authority.LogEntry{}, authority.ErrNotFound
	}
	if store.entry.SubjectKey != database+"."+partition {
		return authority.LogEntry{}, authority.ErrNotFound
	}
	return *store.entry, nil
}

func (store *fakePreparationReceipts) CommitMaterialReceipt(_ context.Context, epoch uint64,
	database, partition, operation string, expected uint64, payload []byte,
) (uint64, error) {
	store.commitCount++
	if epoch != 9 || expected != 0 || store.entry != nil {
		return 0, authority.ErrConflict
	}
	store.entry = &authority.LogEntry{Kind: authority.MutationMaterialReceipt,
		SubjectKey: database + "." + partition, OperationID: operation, Epoch: epoch,
		Sequence: 11, Payload: bytes.Clone(payload)}
	if store.loseAck {
		return 0, authority.ErrOutcomeUnknown
	}
	return 11, nil
}

func preparationFixture(t *testing.T) (PreparationService, InitialSpec, *fakeMaterialObjectClient, *fakePreparationReceipts) {
	t.Helper()
	spec, recipientSigner, _ := initialFixture(t)
	_, controllerKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	objects := new(fakeMaterialObjectClient)
	fencer := new(repositoryFencer)
	repository, err := NewRepository(RepositoryConfig{Region: oci.RegionGRU, Cell: "gru",
		Namespace: "terrascale", Bucket: "material", KMSKeyID: "ocid1.key.oc1.sa-saopaulo-1.material"},
		objects, fencer)
	if err != nil {
		t.Fatal(err)
	}
	receipts := new(fakePreparationReceipts)
	return PreparationService{Cell: "gru", Repository: repository, Receipts: receipts, Fencer: fencer,
		ControllerKey: controllerKey, RecipientSigner: recipientSigner, AllowedSubnetCIDR: "10.0.0.0/24"}, spec, objects, receipts
}

func TestPrepareInitialRequiresR3ReceiptAndReusesCommittedGeneration(t *testing.T) {
	service, spec, objects, receipts := preparationFixture(t)
	now := time.Now().UTC()
	receipt, err := service.PrepareInitial(t.Context(), 9, "partition-a", spec, now)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Object.VersionID == "" || receipts.entry == nil || receipts.commitCount != 1 || objects.putCount != 1 {
		t.Fatal("preparation did not produce a versioned object and durable R3 receipt")
	}
	retry, err := service.PrepareInitial(t.Context(), 9, "partition-a", spec, now)
	if err != nil || retry.Signature != receipt.Signature || objects.putCount != 1 || receipts.commitCount != 1 {
		t.Fatalf("idempotent preparation regenerated keys or rewrote R3 receipt: %v", err)
	}
	foreign := spec
	foreign.Members[0].ClientIP = "10.0.0.99"
	foreign.Members[0].ReplicationIP = foreign.Members[0].ClientIP
	if _, err := service.PrepareInitial(t.Context(), 9, "partition-a", foreign, now); !errors.Is(err, ErrMaterialConflict) {
		t.Fatalf("same shard was prepared with a different signed IP: %v", err)
	}
	receipts.entry.Payload = []byte("foreign")
	if _, err := service.PrepareInitial(t.Context(), 9, "partition-a", spec, now); !errors.Is(err, ErrMaterialConflict) {
		t.Fatalf("tampered R3 receipt was accepted: %v", err)
	}
}

func TestPrepareInitialRecoversOrphanOnlyThroughNewR3CAS(t *testing.T) {
	service, spec, objects, receipts := preparationFixture(t)
	now := time.Now().UTC()
	bundle, err := GenerateInitial(spec, service.RecipientSigner, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Repository.CreateInitial(t.Context(), 9, "partition-a", spec, bundle, service.ControllerKey); err != nil {
		t.Fatal(err)
	}
	if receipts.entry != nil {
		t.Fatal("orphan object unexpectedly granted R3 authority")
	}
	receipts.loseAck = true
	receipt, err := service.PrepareInitial(t.Context(), 9, "partition-a", spec, now)
	if err != nil || receipt.Object.VersionID == "" || receipts.entry == nil || objects.putCount != 1 {
		t.Fatalf("orphan recovery did not validate exact bytes and commit R3: %v", err)
	}
}
