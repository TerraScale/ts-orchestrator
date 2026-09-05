package ocireconcile

import "terrascale.tech/orchestrator/src/orchestrator/provider"

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"terrascale.tech/orchestrator/src/orchestrator/estate"
)

func testVaultRegion() estate.Region {
	region := testNetworkRegion()
	region.VaultKeys = []estate.VaultKey{
		{Name: "region-kek", Purpose: "wrap-database-deks", RotationHours: 720},
		{Name: "capability-hmac", Purpose: "reactive-capabilities", RotationHours: 24},
	}
	return region
}

// fakeVaultGateway models asynchronous vault and key creation.
type fakeVaultGateway struct {
	vault      *ObservedVault
	keys       []ObservedKey
	activate   bool // when true, creations land ACTIVE/ENABLED immediately
	creates    []string
	keyCreates []string
}

func (f *fakeVaultGateway) ListVaults(ctx context.Context) ([]ObservedVault, error) {
	if f.vault == nil {
		return nil, nil
	}
	return []ObservedVault{*f.vault}, nil
}

func (f *fakeVaultGateway) CreateVault(ctx context.Context, name string) (ObservedVault, error) {
	f.creates = append(f.creates, name)
	state := "CREATING"
	if f.activate {
		state = "ACTIVE"
	}
	created := ObservedVault{ID: "ocid1.vault.oc1.x", DisplayName: name, VaultType: vaultTypeDefault, LifecycleState: state, ManagementEndpoint: "https://abc123-management.kms.sa-saopaulo-1.oraclecloud.com"}
	f.vault = &created
	return created, nil
}

func (f *fakeVaultGateway) ListKeys(ctx context.Context, vault ObservedVault) ([]ObservedKey, error) {
	return f.keys, nil
}

func (f *fakeVaultGateway) CreateKey(ctx context.Context, vault ObservedVault, keyName string) (ObservedKey, error) {
	f.keyCreates = append(f.keyCreates, keyName)
	state := "CREATING"
	if f.activate {
		state = "ENABLED"
	}
	created := ObservedKey{ID: "ocid1.key.oc1.x." + keyName, DisplayName: keyName, LifecycleState: state, Algorithm: vaultKeyAlgorithmAES, LengthBits: vaultKeyLengthBits, Protection: vaultKeyProtectionSecret}
	f.keys = append(f.keys, created)
	return created, nil
}

func TestVaultReconcilePlans(t *testing.T) {
	declared := testVaultRegion()
	cases := []struct {
		name      string
		observed  VaultObserved
		wantKinds []OCIActionKind
		wantErr   bool
	}{
		{
			name:      "no vault plans only the vault",
			observed:  VaultObserved{},
			wantKinds: []OCIActionKind{OCIActionCreateVault},
		},
		{
			name: "creating vault plans nothing until active",
			observed: VaultObserved{Vault: &ObservedVault{
				ID: "ocid1.vault.oc1.x", DisplayName: "terrascale-gru-vault", VaultType: vaultTypeDefault, LifecycleState: "CREATING",
			}},
			wantKinds: nil,
		},
		{
			name: "active vault with no keys plans both keys",
			observed: VaultObserved{Vault: &ObservedVault{
				ID: "ocid1.vault.oc1.x", DisplayName: "terrascale-gru-vault", VaultType: vaultTypeDefault, LifecycleState: "ACTIVE",
			}},
			wantKinds: []OCIActionKind{OCIActionCreateVaultKey, OCIActionCreateVaultKey},
		},
		{
			name: "virtual private vault is refused",
			observed: VaultObserved{Vault: &ObservedVault{
				ID: "ocid1.vault.oc1.x", DisplayName: "terrascale-gru-vault", VaultType: "VIRTUAL_PRIVATE", LifecycleState: "ACTIVE",
			}},
			wantErr: true,
		},
		{
			name: "converged vault plans nothing",
			observed: VaultObserved{
				Vault: &ObservedVault{ID: "ocid1.vault.oc1.x", DisplayName: "terrascale-gru-vault", VaultType: vaultTypeDefault, LifecycleState: "ACTIVE"},
				Keys: []ObservedKey{
					{ID: "ocid1.key.oc1.x.1", DisplayName: "region-kek", LifecycleState: "ENABLED", Algorithm: vaultKeyAlgorithmAES, LengthBits: vaultKeyLengthBits, Protection: vaultKeyProtectionSecret},
					{ID: "ocid1.key.oc1.x.2", DisplayName: "capability-hmac", LifecycleState: "ENABLED", Algorithm: vaultKeyAlgorithmAES, LengthBits: vaultKeyLengthBits, Protection: vaultKeyProtectionSecret},
				},
			},
			wantKinds: nil,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reconciler := &VaultReconciler{Vault: &fakeVaultGateway{}}
			plan, err := reconciler.Reconcile(context.Background(), declared, tc.observed)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("Reconcile() = %v, want refusal", plan.Kinds())
				}
				return
			}
			if err != nil {
				t.Fatalf("Reconcile() failed: %v", err)
			}
			got := plan.Kinds()
			if len(got) != len(tc.wantKinds) {
				t.Fatalf("Reconcile() kinds = %v, want %v", got, tc.wantKinds)
			}
			for i := range got {
				if got[i] != tc.wantKinds[i] {
					t.Fatalf("Reconcile() kinds = %v, want %v", got, tc.wantKinds)
				}
			}
		})
	}
}

func TestVaultApplyConvergesAcrossAsyncCreation(t *testing.T) {
	declared := testVaultRegion()
	gateway := &fakeVaultGateway{activate: true}
	reconciler := &VaultReconciler{Vault: gateway}
	ctx := context.Background()
	for pass := 0; pass < 3; pass++ {
		observed, err := reconciler.Observe(ctx, declared)
		if err != nil {
			t.Fatalf("observe failed: %v", err)
		}
		plan, err := reconciler.Reconcile(ctx, declared, observed)
		if err != nil {
			t.Fatalf("reconcile failed: %v", err)
		}
		if plan.Empty() {
			if len(gateway.creates) != 1 || len(gateway.keyCreates) != 2 {
				t.Fatalf("vault creates = %v, key creates = %v, want one and two (idempotent)", gateway.creates, gateway.keyCreates)
			}
			for _, key := range gateway.keys {
				if key.LifecycleState != "ENABLED" {
					t.Fatalf("key %+v not enabled", key)
				}
			}
			return
		}
		if err := reconciler.Apply(ctx, declared, observed, plan); err != nil {
			t.Fatalf("apply failed: %v", err)
		}
	}
	t.Fatal("vault did not converge in three passes")
}

func TestVaultApplyRefusesKeysWithoutActiveVault(t *testing.T) {
	declared := testVaultRegion()
	reconciler := &VaultReconciler{Vault: &fakeVaultGateway{}}
	err := reconciler.Apply(context.Background(), declared, VaultObserved{}, OCIPlan{Actions: []OCIAction{CreateVaultKeyAction{VaultName: DefaultVaultName("gru"), KeyName: "region-kek"}}})
	if err == nil {
		t.Fatal("key create without a vault accepted")
	}
	var invalid *provider.InvalidOperationError
	if !errors.As(err, &invalid) {
		t.Fatalf("Apply() = %v, want invalid operation", err)
	}
}

func TestVaultPendingAndFailedStatesAreNotConverged(t *testing.T) {
	declared := testVaultRegion()
	reconciler := &VaultReconciler{Vault: &fakeVaultGateway{}}
	pending := VaultObserved{Vault: &ObservedVault{DisplayName: DefaultVaultName("gru"), VaultType: vaultTypeDefault, LifecycleState: "ACTIVE"}, Keys: []ObservedKey{
		{DisplayName: "region-kek", LifecycleState: "CREATING", Algorithm: vaultKeyAlgorithmAES, LengthBits: vaultKeyLengthBits, Protection: vaultKeyProtectionSecret},
		{DisplayName: "capability-hmac", LifecycleState: "ENABLED", Algorithm: vaultKeyAlgorithmAES, LengthBits: vaultKeyLengthBits, Protection: vaultKeyProtectionSecret},
	}}
	plan, err := reconciler.Reconcile(context.Background(), declared, pending)
	if err != nil || !plan.Empty() {
		t.Fatalf("pending key reconcile = %v, %v; want empty retry plan", plan.Kinds(), err)
	}
	converged, err := reconciler.bootstrapConverged(pending, declared)
	if err != nil || converged {
		t.Fatalf("pending key convergence = %v, %v; want false", converged, err)
	}
	failed := pending
	failed.Vault = &ObservedVault{DisplayName: DefaultVaultName("gru"), VaultType: vaultTypeDefault, LifecycleState: "FAILED"}
	if _, err := reconciler.Reconcile(context.Background(), declared, failed); err == nil {
		t.Fatal("failed vault accepted")
	}
}

func TestVaultDuplicateKeyIsRefused(t *testing.T) {
	declared := testVaultRegion()
	observed := VaultObserved{Vault: &ObservedVault{DisplayName: DefaultVaultName("gru"), VaultType: vaultTypeDefault, LifecycleState: "ACTIVE"}, Keys: []ObservedKey{
		{DisplayName: "region-kek", LifecycleState: "ENABLED", Algorithm: vaultKeyAlgorithmAES, LengthBits: vaultKeyLengthBits, Protection: vaultKeyProtectionSecret},
		{DisplayName: "region-kek", LifecycleState: "ENABLED", Algorithm: vaultKeyAlgorithmAES, LengthBits: vaultKeyLengthBits, Protection: vaultKeyProtectionSecret},
	}}
	if _, err := (&VaultReconciler{Vault: &fakeVaultGateway{}}).Reconcile(context.Background(), declared, observed); err == nil {
		t.Fatal("duplicate vault key accepted")
	}
}

// A declared-name key with any other shape was never ours: adopting it
// would put the Region on a paid tier (HSM) the estate never declares
// (D-65/D-70), exactly like a Virtual Private Vault.
func TestVaultForeignShapeKeyIsRefused(t *testing.T) {
	declared := testVaultRegion()
	reconciler := &VaultReconciler{Vault: &fakeVaultGateway{}}
	shapes := []ObservedKey{
		{DisplayName: "region-kek", LifecycleState: "ENABLED", Algorithm: "AES", LengthBits: 256, Protection: "HSM"},
		{DisplayName: "region-kek", LifecycleState: "ENABLED", Algorithm: "RSA", LengthBits: 2048, Protection: "SOFTWARE"},
		{DisplayName: "region-kek", LifecycleState: "ENABLED", Algorithm: "AES", LengthBits: 128, Protection: "SOFTWARE"},
		{DisplayName: "region-kek", LifecycleState: "CREATING", Algorithm: "AES", LengthBits: 256, Protection: "HSM"},
	}
	for _, key := range shapes {
		observed := VaultObserved{Vault: &ObservedVault{DisplayName: DefaultVaultName("gru"), VaultType: vaultTypeDefault, LifecycleState: "ACTIVE"}, Keys: []ObservedKey{key}}
		_, err := reconciler.Reconcile(context.Background(), declared, observed)
		if err == nil {
			t.Fatalf("key %+v adopted", key)
		}
		var invalid *provider.InvalidDataError
		if !errors.As(err, &invalid) {
			t.Fatalf("Reconcile() = %v, want invalid data", err)
		}
		converged, err := reconciler.bootstrapConverged(observed, declared)
		if err != nil || converged {
			t.Fatalf("key %+v converged = %v, %v; want false", key, converged, err)
		}
	}
}

func vaultTestGateway(t *testing.T, roundTrip roundTripFunc) *OCIVaultGateway {
	t.Helper()
	management, err := provider.NewOCIServiceTransportConfig(provider.OCIServiceVaultManagement, "sa-saopaulo-1", "https://test-management.kms.sa-saopaulo-1.oraclecloud.com")
	if err != nil {
		t.Fatal(err)
	}
	managementTransport, err := provider.NewOCIHTTPTransport(management, &http.Client{Transport: roundTrip}, nil)
	if err != nil {
		t.Fatal(err)
	}
	gateway, err := NewOCIVaultGateway(
		testOCITransport(t, provider.OCIServiceVault, roundTrip),
		managementTransport,
		"sa-saopaulo-1", "ocid1.compartment.oc1.x")
	if err != nil {
		t.Fatal(err)
	}
	return gateway
}

func vaultTestVault() ObservedVault {
	return ObservedVault{
		ID: "ocid1.vault.oc1.x", DisplayName: "terrascale-gru-vault", VaultType: vaultTypeDefault, LifecycleState: "ACTIVE",
		ManagementEndpoint: "https://test-management.kms.sa-saopaulo-1.oraclecloud.com",
	}
}

func TestOCIVaultGatewayListKeysParsesShape(t *testing.T) {
	gateway := vaultTestGateway(t, func(*http.Request) (*http.Response, error) {
		return testHTTPResponse(http.StatusOK, `[{"id":"ocid1.key.oc1.x.1","displayName":"database-kek","lifecycleState":"ENABLED",`+
			`"keyShape":{"algorithm":"AES","length":256,"protectionMode":"SOFTWARE"}}]`, nil), nil
	})
	keys, err := gateway.ListKeys(context.Background(), vaultTestVault())
	if err != nil {
		t.Fatalf("ListKeys() failed: %v", err)
	}
	if len(keys) != 1 || !keys[0].matchesDeclaredKeyShape() {
		t.Fatalf("ListKeys() = %+v, want one AES-256 software key", keys)
	}
}

func TestOCIVaultGatewayListKeysRequiresShape(t *testing.T) {
	gateway := vaultTestGateway(t, func(*http.Request) (*http.Response, error) {
		return testHTTPResponse(http.StatusOK, `[{"id":"ocid1.key.oc1.x.1","displayName":"database-kek","lifecycleState":"ENABLED"}]`, nil), nil
	})
	_, err := gateway.ListKeys(context.Background(), vaultTestVault())
	if err == nil {
		t.Fatal("key without shape accepted")
	}
	var invalid *provider.InvalidDataError
	if !errors.As(err, &invalid) {
		t.Fatalf("ListKeys() = %v, want invalid data", err)
	}
}

func TestOCIVaultGatewayCreateKeyRefusesForeignShape(t *testing.T) {
	gateway := vaultTestGateway(t, func(*http.Request) (*http.Response, error) {
		return testHTTPResponse(http.StatusOK, `{"id":"ocid1.key.oc1.x.1","displayName":"database-kek","lifecycleState":"CREATING",`+
			`"keyShape":{"algorithm":"AES","length":256,"protectionMode":"HSM"}}`, nil), nil
	})
	_, err := gateway.CreateKey(context.Background(), vaultTestVault(), "database-kek")
	if err == nil {
		t.Fatal("HSM-shaped key accepted")
	}
	var invalid *provider.InvalidDataError
	if !errors.As(err, &invalid) {
		t.Fatalf("CreateKey() = %v, want invalid data", err)
	}
}

func TestOCIVaultGatewayListVaultsRequiresKnownType(t *testing.T) {
	gateway := vaultTestGateway(t, func(*http.Request) (*http.Response, error) {
		return testHTTPResponse(http.StatusOK, `[{"id":"ocid1.vault.oc1.x","displayName":"terrascale-gru-vault","lifecycleState":"ACTIVE"}]`, nil), nil
	})
	_, err := gateway.ListVaults(context.Background())
	if err == nil {
		t.Fatal("vault without a known type accepted")
	}
	var invalid *provider.InvalidDataError
	if !errors.As(err, &invalid) {
		t.Fatalf("ListVaults() = %v, want invalid data", err)
	}
}
