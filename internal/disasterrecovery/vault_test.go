package disasterrecovery

import (
	"context"
	"testing"
	"testing/synctest"
	"time"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/keymanagement"
)

const (
	vaultTestSource = "sa-saopaulo-1"
	vaultTestTarget = "us-sanjose-1"
	vaultTestID     = "ocid1.vault.oc1.sa-saopaulo-1.testvault.aaaaaa"
	vaultTestCrypto = "https://replica-crypto.kms.us-sanjose-1.oraclecloud.com"
)

type fakeVaultReplicaClient struct {
	t               *testing.T
	vault           keymanagement.Vault
	pages           []keymanagement.ListVaultReplicasResponse
	getErr, listErr error
	createErr       error
	gets, lists     int
	creates         []keymanagement.CreateVaultReplicaRequest
	onGet           func(int)
	onList          func(context.Context)
}

func newFakeVaultReplicaClient(t *testing.T) *fakeVaultReplicaClient {
	return &fakeVaultReplicaClient{t: t, vault: keymanagement.Vault{
		Id: common.String(vaultTestID), LifecycleState: keymanagement.VaultLifecycleStateActive,
		VaultType: keymanagement.VaultVaultTypeDefault, IsVaultReplicable: common.Bool(true), IsPrimary: common.Bool(true),
	}}
}

func (f *fakeVaultReplicaClient) GetVault(ctx context.Context, request keymanagement.GetVaultRequest) (keymanagement.GetVaultResponse, error) {
	f.t.Helper()
	if request.VaultId == nil || *request.VaultId != vaultTestID {
		f.t.Fatalf("GetVault addressed a different source: %v", request.VaultId)
	}
	if _, ok := ctx.Deadline(); !ok {
		f.t.Fatal("GetVault received an unbounded context")
	}
	f.gets++
	if f.onGet != nil {
		f.onGet(f.gets)
	}
	return keymanagement.GetVaultResponse{Vault: f.vault, Etag: common.String("source-etag")}, f.getErr
}

func (f *fakeVaultReplicaClient) ListVaultReplicas(ctx context.Context, request keymanagement.ListVaultReplicasRequest) (keymanagement.ListVaultReplicasResponse, error) {
	f.t.Helper()
	if request.VaultId == nil || *request.VaultId != vaultTestID {
		f.t.Fatalf("ListVaultReplicas addressed a different source: %v", request.VaultId)
	}
	f.lists++
	if f.onList != nil {
		f.onList(ctx)
	}
	if f.listErr != nil || len(f.pages) == 0 {
		return keymanagement.ListVaultReplicasResponse{}, f.listErr
	}
	response := f.pages[0]
	if len(f.pages) > 1 {
		f.pages = f.pages[1:]
	}
	return response, nil
}

func (f *fakeVaultReplicaClient) CreateVaultReplica(ctx context.Context, request keymanagement.CreateVaultReplicaRequest) (keymanagement.CreateVaultReplicaResponse, error) {
	f.creates = append(f.creates, request)
	return keymanagement.CreateVaultReplicaResponse{}, f.createErr
}

func vaultTestReplica(status keymanagement.VaultReplicaSummaryStatusEnum) keymanagement.VaultReplicaSummary {
	return keymanagement.VaultReplicaSummary{Region: common.String(vaultTestTarget), Status: status, CryptoEndpoint: common.String(vaultTestCrypto)}
}

func TestVaultReplicaCreation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		fake := newFakeVaultReplicaClient(t)
		fake.pages = []keymanagement.ListVaultReplicasResponse{
			{}, {},
			{Items: []keymanagement.VaultReplicaSummary{vaultTestReplica("")}},
			{Items: []keymanagement.VaultReplicaSummary{vaultTestReplica(keymanagement.VaultReplicaSummaryStatusCreating)}},
			{Items: []keymanagement.VaultReplicaSummary{vaultTestReplica(keymanagement.VaultReplicaSummaryStatusCreated)}},
		}
		started := time.Now()
		report, err := ensureVaultReplica(t.Context(), fake, vaultTestID, vaultTestSource, vaultTestTarget, true)
		if err != nil || report.Status != "CREATED" || report.CryptoEndpoint != vaultTestCrypto || len(fake.creates) != 1 || fake.gets != 5 || time.Since(started) != 6*time.Second {
			t.Fatalf("create = %+v, %v; writes = %d, reads = %d", report, err, len(fake.creates), fake.gets)
		}
		request := fake.creates[0]
		if request.VaultId == nil || *request.VaultId != vaultTestID || request.ReplicaRegion == nil || *request.ReplicaRegion != vaultTestTarget ||
			request.OpcRetryToken == nil || *request.OpcRetryToken == "" || request.IfMatch == nil || *request.IfMatch != "source-etag" {
			t.Fatalf("create request lost its source/target/retry identity: %+v", request)
		}
	})
}
