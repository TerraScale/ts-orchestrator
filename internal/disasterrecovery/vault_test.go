package disasterrecovery

import (
	"context"
	"errors"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociclient"
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

func TestVaultReplicaPlanNoWrite(t *testing.T) {
	fake := newFakeVaultReplicaClient(t)
	report, err := ensureVaultReplica(t.Context(), fake, vaultTestID, vaultTestSource, vaultTestTarget, false)
	want := VaultReplicaReport{VaultID: vaultTestID, TargetRegion: vaultTestTarget, Status: "MISSING"}
	if err != nil || report != want || len(fake.creates) != 0 || fake.gets != 1 || fake.lists != 1 {
		t.Fatalf("plan = %+v, %v; reads = %d/%d, writes = %d", report, err, fake.gets, fake.lists, len(fake.creates))
	}
}

func TestVaultReplicaReuse(t *testing.T) {
	for _, apply := range []bool{false, true} {
		t.Run(map[bool]string{false: "plan", true: "apply"}[apply], func(t *testing.T) {
			fake := newFakeVaultReplicaClient(t)
			fake.pages = []keymanagement.ListVaultReplicasResponse{{Items: []keymanagement.VaultReplicaSummary{vaultTestReplica(keymanagement.VaultReplicaSummaryStatusCreated)}}}
			report, err := ensureVaultReplica(t.Context(), fake, vaultTestID, vaultTestSource, vaultTestTarget, apply)
			if err != nil || report.Status != "CREATED" || report.CryptoEndpoint != vaultTestCrypto || len(fake.creates) != 0 {
				t.Fatalf("reuse = %+v, %v; writes = %d", report, err, len(fake.creates))
			}
		})
	}
}

func TestVaultReplicaConflicts(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*keymanagement.VaultReplicaSummary)
	}{
		{"different region", func(r *keymanagement.VaultReplicaSummary) { r.Region = common.String("eu-frankfurt-1") }},
		{"missing region", func(r *keymanagement.VaultReplicaSummary) { r.Region = nil }},
		{"creating", func(r *keymanagement.VaultReplicaSummary) { r.Status = keymanagement.VaultReplicaSummaryStatusCreating }},
		{"deleting", func(r *keymanagement.VaultReplicaSummary) { r.Status = keymanagement.VaultReplicaSummaryStatusDeleting }},
		{"deleted", func(r *keymanagement.VaultReplicaSummary) { r.Status = keymanagement.VaultReplicaSummaryStatusDeleted }},
		{"listed without status", func(r *keymanagement.VaultReplicaSummary) { r.Status = "" }},
		{"missing endpoint", func(r *keymanagement.VaultReplicaSummary) { r.CryptoEndpoint = nil }},
		{"source endpoint", func(r *keymanagement.VaultReplicaSummary) {
			r.CryptoEndpoint = common.String("https://replica-crypto.kms.sa-saopaulo-1.oraclecloud.com")
		}},
		{"untrusted endpoint", func(r *keymanagement.VaultReplicaSummary) {
			r.CryptoEndpoint = common.String(vaultTestCrypto + ".example.com")
		}},
		{"endpoint credentials", func(r *keymanagement.VaultReplicaSummary) {
			r.CryptoEndpoint = common.String(strings.Replace(vaultTestCrypto, "https://", "https://user@", 1))
		}},
		{"endpoint query", func(r *keymanagement.VaultReplicaSummary) {
			r.CryptoEndpoint = common.String(vaultTestCrypto + "?token=hidden")
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			fake := newFakeVaultReplicaClient(t)
			replica := vaultTestReplica(keymanagement.VaultReplicaSummaryStatusCreated)
			test.change(&replica)
			fake.pages = []keymanagement.ListVaultReplicasResponse{{Items: []keymanagement.VaultReplicaSummary{replica}}}
			report, err := ensureVaultReplica(t.Context(), fake, vaultTestID, vaultTestSource, vaultTestTarget, true)
			if err == nil || len(fake.creates) != 0 {
				t.Fatalf("conflict error = %v; writes = %d", err, len(fake.creates))
			}
			// A replica an interrupted run left mid-creation asks for a re-run.
			if creating := test.name == "creating" || test.name == "listed without status"; creating != strings.Contains(err.Error(), "re-run") ||
				creating != (report.Status == "CREATING") {
				t.Fatalf("in-progress replica report = %+v, %v", report, err)
			}
		})
	}
}

func TestVaultReplicaSourceGuards(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*keymanagement.Vault)
	}{
		{"missing ID", func(v *keymanagement.Vault) { v.Id = nil }},
		{"wrong ID", func(v *keymanagement.Vault) { v.Id = common.String(vaultTestID + "0000000000V4MRM46HP1SNGDYW") }},
		{"inactive", func(v *keymanagement.Vault) { v.LifecycleState = keymanagement.VaultLifecycleStateDeleting }},
		{"not replicable", func(v *keymanagement.Vault) { v.IsVaultReplicable = common.Bool(false) }},
		{"unknown replicability", func(v *keymanagement.Vault) { v.IsVaultReplicable = nil }},
		{"replica source", func(v *keymanagement.Vault) { v.IsPrimary = common.Bool(false) }},
		{"empty replication ID", func(v *keymanagement.Vault) { v.ReplicaDetails = &keymanagement.VaultReplicaDetails{} }},
		{"unlisted replication ID", func(v *keymanagement.Vault) {
			v.ReplicaDetails = &keymanagement.VaultReplicaDetails{ReplicationId: common.String("replication-1")}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			fake := newFakeVaultReplicaClient(t)
			test.change(&fake.vault)
			if _, err := ensureVaultReplica(t.Context(), fake, vaultTestID, vaultTestSource, vaultTestTarget, true); err == nil || len(fake.creates) != 0 {
				t.Fatalf("source error = %v; writes = %d", err, len(fake.creates))
			}
		})
	}
}

func TestVaultReplicaTargetValidation(t *testing.T) {
	for _, test := range []struct{ id, source, target string }{
		{vaultTestID, vaultTestSource, vaultTestSource},
		{vaultTestID, vaultTestSource, "eu-frankfurt-1"},
		{vaultTestID, "us-sanjose-1", vaultTestSource},
		{"ocid1.vault.oc1.sa-saopaulo-1.", vaultTestSource, vaultTestTarget},
		{strings.Replace(vaultTestID, ".vault.", ".key.", 1), vaultTestSource, vaultTestTarget},
		{vaultTestID + "/actions", vaultTestSource, vaultTestTarget},
	} {
		fake := newFakeVaultReplicaClient(t)
		if _, err := ensureVaultReplica(t.Context(), fake, test.id, test.source, test.target, true); err == nil || fake.gets != 0 || fake.lists != 0 || len(fake.creates) != 0 {
			t.Fatalf("invalid input %+v: error = %v; reads = %d/%d, writes = %d", test, err, fake.gets, fake.lists, len(fake.creates))
		}
	}
	if err := validateVaultReplicaTarget(t.Context(), strings.Replace(vaultTestID, vaultTestSource, vaultTestTarget, 1), vaultTestTarget, vaultTestSource); err != nil {
		t.Fatalf("reverse region pair: %v", err)
	}
	if _, err := EnsureVaultReplica(t.Context(), nil, vaultTestID, vaultTestTarget, true); err == nil {
		t.Fatal("nil factory accepted")
	}
}

func TestVaultReplicaRefusesUnsafeSDKEnvironment(t *testing.T) {
	provider := common.NewRawConfigurationProvider("tenancy", "user", "eu-frankfurt-1", "fingerprint", "invalid-key", nil)
	factory, err := ociclient.New(provider, ociclient.Options{Region: vaultTestSource})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range ociclient.SecretUnsafeEnv {
		t.Run(name, func(t *testing.T) {
			t.Setenv(name, "")
			if _, err := EnsureVaultReplica(t.Context(), factory, vaultTestID, vaultTestTarget, true); err == nil || !strings.Contains(err.Error(), name) {
				t.Fatalf("unsafe SDK setting: %v", err)
			}
		})
	}
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

func TestVaultReplicaCancelledPoll(t *testing.T) {
	for _, name := range []string{"waiting", "during ready read"} {
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				fake := newFakeVaultReplicaClient(t)
				if name == "during ready read" {
					fake.pages = []keymanagement.ListVaultReplicasResponse{{}, {Items: []keymanagement.VaultReplicaSummary{vaultTestReplica(keymanagement.VaultReplicaSummaryStatusCreated)}}}
					fake.onList = func(context.Context) {
						if fake.lists == 2 {
							cancel()
						}
					}
				} else {
					go func() { time.Sleep(time.Second); cancel() }()
				}
				report, err := ensureVaultReplica(ctx, fake, vaultTestID, vaultTestSource, vaultTestTarget, true)
				if !errors.Is(err, context.Canceled) || report.Status != "CREATING" || len(fake.creates) != 1 {
					t.Fatalf("cancelled poll = %+v, %v; writes = %d", report, err, len(fake.creates))
				}
			})
		})
	}
}

func TestVaultReplicaPollTimeout(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		fake := newFakeVaultReplicaClient(t)
		started := time.Now()
		report, err := ensureVaultReplica(t.Context(), fake, vaultTestID, vaultTestSource, vaultTestTarget, true)
		if !errors.Is(err, context.DeadlineExceeded) || report.Status != "CREATING" || len(fake.creates) != 1 || time.Since(started) != vaultReplicaTimeout {
			t.Fatalf("bounded poll = %+v, %v; elapsed = %s, writes = %d", report, err, time.Since(started), len(fake.creates))
		}
	})
}

func TestVaultReplicaPollConflicts(t *testing.T) {
	for _, name := range []string{"source ID", "replication ID", "region", "state"} {
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				fake := newFakeVaultReplicaClient(t)
				fake.onGet = func(call int) {
					if call < 2 {
						return
					}
					switch name {
					case "source ID":
						fake.vault.Id = common.String(vaultTestID + "0000000000V4MRM46HP1SNGDYW")
					case "replication ID":
						fake.vault.ReplicaDetails = &keymanagement.VaultReplicaDetails{ReplicationId: common.String(map[bool]string{false: "replication-1", true: "replication-2"}[call > 2])}
					}
				}
				replica := vaultTestReplica(keymanagement.VaultReplicaSummaryStatusCreating)
				if name == "region" {
					replica.Region = common.String("eu-frankfurt-1")
				}
				if name == "state" {
					replica.Status = keymanagement.VaultReplicaSummaryStatusDeleting
				}
				fake.pages = []keymanagement.ListVaultReplicasResponse{{}, {Items: []keymanagement.VaultReplicaSummary{replica}}}
				if _, err := ensureVaultReplica(t.Context(), fake, vaultTestID, vaultTestSource, vaultTestTarget, true); err == nil || len(fake.creates) != 1 {
					t.Fatalf("poll conflict error = %v; writes = %d", err, len(fake.creates))
				}
			})
		})
	}
}

func TestVaultReplicaPaginationConflicts(t *testing.T) {
	for _, repeatedToken := range []bool{false, true} {
		t.Run(map[bool]string{false: "multiple replicas", true: "repeated page"}[repeatedToken], func(t *testing.T) {
			fake := newFakeVaultReplicaClient(t)
			page := keymanagement.ListVaultReplicasResponse{Items: []keymanagement.VaultReplicaSummary{vaultTestReplica(keymanagement.VaultReplicaSummaryStatusCreated)}}
			if repeatedToken {
				page.Items = nil
				page.OpcNextPage = common.String("page-2")
			}
			fake.pages = []keymanagement.ListVaultReplicasResponse{
				{Items: []keymanagement.VaultReplicaSummary{vaultTestReplica(keymanagement.VaultReplicaSummaryStatusCreated)}, OpcNextPage: common.String("page-2")}, page,
			}
			if _, err := ensureVaultReplica(t.Context(), fake, vaultTestID, vaultTestSource, vaultTestTarget, true); err == nil || len(fake.creates) != 0 || fake.lists != 2 {
				t.Fatalf("pagination conflict error = %v; reads = %d, writes = %d", err, fake.lists, len(fake.creates))
			}
		})
	}
}

func TestVaultReplicaSDKFailuresDoNotRepeatCreation(t *testing.T) {
	failed := errors.New("fake SDK failure")
	for _, operation := range []string{"get", "list", "create"} {
		t.Run(operation, func(t *testing.T) {
			fake := newFakeVaultReplicaClient(t)
			switch operation {
			case "get":
				fake.getErr = failed
			case "list":
				fake.listErr = failed
			case "create":
				fake.createErr = failed
			}
			_, err := ensureVaultReplica(t.Context(), fake, vaultTestID, vaultTestSource, vaultTestTarget, true)
			wantCreates := 0
			if operation == "create" {
				wantCreates = 1
			}
			if !errors.Is(err, failed) || len(fake.creates) != wantCreates {
				t.Fatalf("SDK error = %v; writes = %d", err, len(fake.creates))
			}
		})
	}
}
