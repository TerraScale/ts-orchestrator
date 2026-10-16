package managedmaterial

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
)

type fakePreparationReceipts struct {
	entry       *authority.LogEntry
	commitCount int
	loseAck     bool
}

type acceptingNativeMaterialValidator struct{}

func (acceptingNativeMaterialValidator) ValidateManagedMaterial(_ context.Context, input NativeMaterialInput, pin string) error {
	if len(input.Certificate) == 0 || len(input.TrustedKey) != 32 || len(input.SignedV2S3Config) == 0 ||
		input.ExpectedS3TargetDigest == "" || pin == "" {
		return errors.New("native material request is incomplete")
	}
	return nil
}

type nativeValidatorFunc func(context.Context, NativeMaterialInput, string) error

func (validate nativeValidatorFunc) ValidateManagedMaterial(ctx context.Context, input NativeMaterialInput, pin string) error {
	return validate(ctx, input, pin)
}

func TestNativeRejectionPrecedesObjectPutAndOrphanReceipt(t *testing.T) {
	service, spec, objects, receipts := preparationFixture(t)
	service.NativeValidator = nativeValidatorFunc(func(context.Context, NativeMaterialInput, string) error {
		return errors.New("native rejected authority")
	})
	now := time.Now().UTC()
	if _, err := service.PrepareInitial(t.Context(), 9, spec.PartitionID, spec, now); err == nil ||
		objects.putCount != 0 || receipts.commitCount != 0 {
		t.Fatalf("native rejection reached OCI Put or R3: %v, puts=%d commits=%d", err, objects.putCount, receipts.commitCount)
	}
	bundle, err := GenerateInitial(spec, service.RecipientSigner, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Repository.CreateInitial(t.Context(), 9, spec.PartitionID, spec, bundle, service.ControllerKey); err != nil {
		t.Fatal(err)
	}
	if _, err := service.PrepareInitial(t.Context(), 9, spec.PartitionID, spec, now); err == nil ||
		objects.putCount != 1 || receipts.commitCount != 0 {
		t.Fatalf("orphan bypassed native rejection: %v, puts=%d commits=%d", err, objects.putCount, receipts.commitCount)
	}
}

func TestPrepareInitialRejectsForeignLiveS3RegionBeforeObjectPut(t *testing.T) {
	service, spec, objects, receipts := preparationFixture(t)
	spec.LiveS3.Region = "us-sanjose-1"
	if _, err := service.PrepareInitial(t.Context(), 9, spec.PartitionID, spec, time.Now().UTC()); err == nil ||
		objects.putCount != 0 || receipts.commitCount != 0 {
		t.Fatalf("foreign live S3 region reached OCI Put or R3: %v", err)
	}
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
		ControllerKey: controllerKey, RecipientSigner: recipientSigner, AllowedSubnetCIDR: "10.0.0.0/24",
		NativeValidator: acceptingNativeMaterialValidator{}, NativeVerifierSHA256: strings.Repeat("a", 64)}, spec, objects, receipts
}

func TestPrepareInitialRequiresR3ReceiptAndReusesCommittedGeneration(t *testing.T) {
	service, spec, objects, receipts := preparationFixture(t)
	now := time.Now().UTC()
	receipt, err := service.PrepareInitial(t.Context(), 9, "0000000000Z3WK359G2W66CVT8", spec, now)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Object.VersionID == "" || receipts.entry == nil || receipts.commitCount != 1 || objects.putCount != 1 {
		t.Fatal("preparation did not produce a versioned object and durable R3 receipt")
	}
	retry, err := service.PrepareInitial(t.Context(), 9, "0000000000Z3WK359G2W66CVT8", spec, now)
	if err != nil || retry.Signature != receipt.Signature || objects.putCount != 1 || receipts.commitCount != 1 {
		t.Fatalf("idempotent preparation regenerated keys or rewrote R3 receipt: %v", err)
	}
	foreign := spec
	foreign.Members[0].ClientIP = "10.0.0.99"
	foreign.Members[0].ReplicationIP = foreign.Members[0].ClientIP
	if _, err := service.PrepareInitial(t.Context(), 9, "0000000000Z3WK359G2W66CVT8", foreign, now); !errors.Is(err, ErrMaterialConflict) {
		t.Fatalf("same shard was prepared with a different signed IP: %v", err)
	}
	receipts.entry.Payload = []byte("foreign")
	if _, err := service.PrepareInitial(t.Context(), 9, "0000000000Z3WK359G2W66CVT8", spec, now); !errors.Is(err, ErrMaterialConflict) {
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
	if _, err := service.Repository.CreateInitial(t.Context(), 9, "0000000000Z3WK359G2W66CVT8", spec, bundle, service.ControllerKey); err != nil {
		t.Fatal(err)
	}
	if receipts.entry != nil {
		t.Fatal("orphan object unexpectedly granted R3 authority")
	}
	receipts.loseAck = true
	receipt, err := service.PrepareInitial(t.Context(), 9, "0000000000Z3WK359G2W66CVT8", spec, now)
	if err != nil || receipt.Object.VersionID == "" || receipts.entry == nil || objects.putCount != 1 {
		t.Fatalf("orphan recovery did not validate exact bytes and commit R3: %v", err)
	}
}
