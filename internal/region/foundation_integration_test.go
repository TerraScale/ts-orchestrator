package region

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/v2"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/oracle/oci-go-sdk/v65/common"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapmaterial"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

// The simulator persists exact Object Storage bytes and conditional-write
// semantics on disk; clients use the actual signed OCI HTTP implementation.
func foundationProtocolStore(t *testing.T) (*ObjectFoundationStore, FoundationObjects, func(string, []byte)) {
	t.Helper()
	dir := t.TempDir()
	var mu sync.Mutex
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.Header.Get("Authorization") == "" {
			t.Error("unsigned object operation")
			w.WriteHeader(401)
			return
		}
		if r.Method == http.MethodGet && r.URL.Path == "/n" {
			w.Header().Set("content-type", "application/json")
			io.WriteString(w, `"ns"`)
			return
		}
		key := sha256.Sum256([]byte(r.URL.Path))
		path := filepath.Join(dir, hex.EncodeToString(key[:]))
		old, readErr := os.ReadFile(path)
		etag := fmt.Sprintf("%x", sha256.Sum256(old))
		if r.Method == http.MethodGet {
			if readErr != nil {
				w.WriteHeader(404)
				io.WriteString(w, `{"code":"ObjectNotFound","message":"absent"}`)
				return
			}
			w.Header().Set("etag", etag)
			w.Write(old)
			return
		}
		if r.Method != http.MethodPut {
			w.WriteHeader(405)
			return
		}
		if r.Header.Get("if-none-match") == "*" && readErr == nil || r.Header.Get("if-match") != "" && (readErr != nil || r.Header.Get("if-match") != etag) {
			w.WriteHeader(412)
			io.WriteString(w, `{"code":"PreconditionFailed","message":"changed"}`)
			return
		}
		wire, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
			w.WriteHeader(400)
			return
		}
		if err := os.WriteFile(path, wire, 0600); err != nil {
			t.Error(err)
			w.WriteHeader(500)
			return
		}
		w.Header().Set("etag", fmt.Sprintf("%x", sha256.Sum256(wire)))
	}))
	t.Cleanup(server.Close)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	provider := common.NewRawConfigurationProvider("ocid1.tenancy.oc1..test", "ocid1.user.oc1..test", "sa-saopaulo-1", "test",
		string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})), nil)
	factory, err := ociclient.New(provider, ociclient.Options{Region: "sa-saopaulo-1", Retry: ociclient.RetryOptions{MaxAttempts: 1}})
	if err != nil {
		t.Fatal(err)
	}
	client, err := factory.ObjectStorage()
	if err != nil {
		t.Fatal(err)
	}
	client.Host = server.URL
	store, err := NewObjectFoundationStore(&client, "ns", "heads")
	if err != nil {
		t.Fatal(err)
	}
	write := func(name string, wire []byte) {
		mu.Lock()
		defer mu.Unlock()
		key := sha256.Sum256([]byte("/n/ns/b/heads/o/" + name))
		if err := os.WriteFile(filepath.Join(dir, hex.EncodeToString(key[:])), wire, 0600); err != nil {
			t.Fatal(err)
		}
	}
	return store, &client, write
}

func TestFoundationRecordsPersistAndFenceConcurrentWriters(t *testing.T) {
	store, client, _ := foundationProtocolStore(t)
	now := time.Now().UTC()
	record := FoundationRecord{SchemaVersion: 1, Cell: "GRU", OCIRegion: "sa-saopaulo-1", TenancyID: "ocid1.tenancy.oc1..test",
		ParentCompartmentID: "ocid1.compartment.oc1..parent", SharedCompartmentID: "ocid1.compartment.oc1..shared",
		Generation: 1, IntentDigest: fmt.Sprintf("%064d", 0), OperationID: entityid.New(), Epoch: 1, Stage: "reconciled", StartedAt: now, UpdatedAt: now, CompletedAt: now,
		ResourceIDs: map[string]string{"vault": "ocid1.vault.oc1.sa-saopaulo-1.test"}}
	etag, err := store.CompareAndSwap(t.Context(), record, "")
	if err != nil {
		t.Fatal(err)
	}
	restarted, err := NewObjectFoundationStore(client, "ns", "heads")
	if err != nil {
		t.Fatal(err)
	}
	got, actual, err := restarted.Load(t.Context(), "GRU")
	if err != nil || actual != etag || got.ResourceIDs["vault"] != record.ResourceIDs["vault"] {
		t.Fatalf("read=%+v etag=%s err=%v", got, actual, err)
	}
	got.Epoch = 2
	if _, err := restarted.CompareAndSwap(t.Context(), got, actual); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CompareAndSwap(t.Context(), record, etag); err != ErrFoundationConflict {
		t.Fatalf("stale writer: %v", err)
	}
	if _, err := store.CompareAndSwap(t.Context(), record, ""); err != ErrFoundationConflict {
		t.Fatalf("duplicate founder: %v", err)
	}
}

func TestSignedFoundationScopeRequiresExplicitBootstrapAuthority(t *testing.T) {
	_, client, write := foundationProtocolStore(t)
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	roots, err := trust.ParseKeyring(public)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	scope := trust.Scope{Domain: foundationGrantDomain, DeploymentID: entityid.New(), Cell: "GRU", Environment: "production", Role: "foundation", Slot: entityid.New()}
	reader := &SignedFootprint{client: client, storage: bootstrap.StorageDomain{Namespace: "ns", HeadBucket: "heads", Prefix: "bootstrap", HeadKMSKeyOCID: "ocid1.key.oc1.sa-saopaulo-1.test"},
		scope: scope, expires: now.Add(2 * time.Hour), roots: roots, tenancy: "ocid1.tenancy.oc1..test", home: bootstrap.FoundationScope{InstallationID: entityid.New(), GrantGeneration: 1}}
	config := bootstrapmaterial.Config{Environment: "production", Region: "sa-saopaulo-1", Cell: "gru", DeploymentID: scope.DeploymentID, ClusterID: scope.Slot,
		SubnetCIDR: "10.251.0.0/24", ValidityHours: 24, Slots: []bootstrapmaterial.Slot{{Name: "controller-a", PrivateIP: "10.251.0.11"}, {Name: "controller-b", PrivateIP: "10.251.0.12"}, {Name: "controller-c", PrivateIP: "10.251.0.13"}}}
	configWire, _ := json.Marshal(config, json.Deterministic(true))
	digest := sha256.Sum256(configWire)
	reader.local = bootstrap.BootstrapAnchor{Cell: oci.RegionGRU, DeploymentID: config.DeploymentID, ClusterID: config.ClusterID}
	target := bootstrapmaterial.VaultTarget{CompartmentOCID: "ocid1.compartment.oc1..control", VaultOCID: "ocid1.vault.oc1.sa-saopaulo-1.test", KMSKeyOCID: reader.storage.HeadKMSKeyOCID}
	material := &BootstrapMaterialIntent{InstallationID: reader.home.InstallationID, PlanSHA256: hex.EncodeToString(digest[:]), Config: config, SourceVaultTarget: target}
	grant := FoundationGrant{InstallationID: reader.home.InstallationID, SchemaVersion: 1, Generation: 1, TenancyID: reader.tenancy, ParentCompartmentID: "ocid1.compartment.oc1..parent", SharedCompartmentID: "ocid1.compartment.oc1..shared", Currency: "USD", MonthlyLimitMinor: 10000, CleanupOwner: "scenario",
		Regions: []FoundationIntent{{Generation: 1, Plan: map[string]any{"cell": "GRU", "region": "sa-saopaulo-1", "tenancy_id": reader.tenancy, "parent_compartment_id": "ocid1.compartment.oc1..parent", "shared_compartment_id": "ocid1.compartment.oc1..shared", "resource_ids": map[string]any{"control_compartment": target.CompartmentOCID, "vault": target.VaultOCID, "key": target.KMSKeyOCID}}}}}
	publish := func(signedScope trust.Scope, expiry time.Time) {
		payload, err := trust.EncodePayload(grant)
		if err != nil {
			t.Fatal(err)
		}
		envelope, err := trust.Sign(payload, signedScope, now.Add(-time.Minute), expiry, private)
		if err != nil {
			t.Fatal(err)
		}
		wire, err := trust.EncodeEnvelope(envelope)
		if err != nil {
			t.Fatal(err)
		}
		pin := sha256.Sum256(wire)
		reader.home.GrantSHA256 = hex.EncodeToString(pin[:])
		write("bootstrap/"+foundationGrantObject, wire)
	}
	publish(scope, now.Add(time.Hour))
	if _, err := reader.AuthorizedRegions(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := reader.AuthorizedBootstrapMaterial(t.Context(), "GRU"); err == nil {
		t.Fatal("foundation-only scope authorized root generation")
	}
	if _, err := reader.InfrastructureSpend(t.Context()); err == nil {
		t.Fatal("foundation-only scope authorized fleet growth")
	}
	ownedCompartments := grant.Regions[0].Plan["resource_ids"].(map[string]any)
	ownedCompartments["network_compartment"] = "ocid1.compartment.oc1..network"
	ownedCompartments["workload_compartment"] = "ocid1.compartment.oc1..workload"
	spendDigest, err := FoundationInfrastructureScopeDigest(grant)
	if err != nil {
		t.Fatal(err)
	}
	grant.InfrastructureSpend = &InfrastructureSpendIntent{BudgetID: entityid.New(), Currency: "USD", MonthlyLimitMinor: 9000, ScopeSHA256: spendDigest}
	publish(scope, now.Add(time.Hour))
	spend, err := reader.InfrastructureSpend(t.Context())
	if err != nil || !spend.ValidAt(now) || spend.ScopeDigest() != spendDigest || spend.MonthlyLimitMinor() != 9000 || spend.GrantDigest() != reader.home.GrantSHA256 || len(spend.Footprint().Regions[0].CompartmentIDs) != 5 {
		t.Fatalf("spend=%+v err=%v", spend, err)
	}
	copyScope := spend.Footprint()
	copyScope.Regions[0].CompartmentIDs[0] = "foreign"
	if spend.Footprint().Regions[0].CompartmentIDs[0] == "foreign" {
		t.Fatal("fleet spend getter leaked mutable scope")
	}
	for _, wrong := range []InfrastructureSpendIntent{
		{BudgetID: entityid.New(), Currency: "BRL", MonthlyLimitMinor: 9000, ScopeSHA256: spendDigest},
		{BudgetID: entityid.New(), Currency: "USD", MonthlyLimitMinor: 11000, ScopeSHA256: spendDigest},
		{BudgetID: entityid.New(), Currency: "USD", MonthlyLimitMinor: 9000, ScopeSHA256: strings.Repeat("0", 64)},
	} {
		grant.InfrastructureSpend = &wrong
		publish(scope, now.Add(time.Hour))
		if _, err := reader.InfrastructureSpend(t.Context()); err == nil {
			t.Fatal("unbound or excessive fleet authority admitted")
		}
	}
	grant.InfrastructureSpend = nil
	grant.Regions[0].BootstrapMaterial = material
	publish(scope, now.Add(time.Hour))
	verified, err := reader.AuthorizedBootstrapMaterial(t.Context(), "GRU")
	if err != nil || !verified.IsVerified() || verified.PlanDigest() != material.PlanSHA256 || verified.EscrowTarget() != target || !verified.ExpiresAt().Equal(now.Add(time.Hour)) {
		t.Fatalf("verified=%+v err=%v", verified, err)
	}
	if _, err := verified.Startup(); err == nil {
		t.Fatal("generation-only scope admitted controller startup")
	}
	intentWire, err := trust.EncodePayload(oci.RegionIntent{SchemaVersion: 1, Generation: 1, BootstrapRegion: oci.RegionGRU, Regions: []oci.RegionMapping{{Cell: oci.RegionGRU, OCIRegion: "sa-saopaulo-1"}}})
	if err != nil {
		t.Fatal(err)
	}
	reader.local.InitialRegionIntentWire = intentWire
	startup, imageReceipt := foundationImageRecipe(t, private, roots, now, config)
	for i, name := range bootstrap.ControllerConfigFileNames {
		wire := []byte(`{"schemaVersion":1}`)
		if i == 0 {
			wire = intentWire
		}
		sum := sha256.Sum256(wire)
		startup.ControllerFiles = append(startup.ControllerFiles, bootstrap.ControllerConfigFile{Name: name, Bytes: wire, SHA256: hex.EncodeToString(sum[:])})
	}
	material.Startup = &startup
	ids := grant.Regions[0].Plan["resource_ids"].(map[string]any)
	ids["subnet"] = startup.Profiles[0].SubnetOCID
	ids["network_security_group"] = startup.Profiles[0].NetworkSecurityGroupOCIDs[0]
	publish(scope, now.Add(time.Hour))
	verified, err = reader.AuthorizedBootstrapMaterial(t.Context(), "GRU")
	if err != nil {
		t.Fatal(err)
	}
	image, err := verified.Image()
	if err != nil || image.Receipt().ImageSHA256 != imageReceipt.ImageSHA256 {
		t.Fatalf("image=%+v err=%v", image, err)
	}
	template, err := verified.Startup()
	if err != nil {
		t.Fatal(err)
	}
	template.Profiles[0].NetworkSecurityGroupOCIDs[0] = "changed"
	again, err := verified.Startup()
	if err != nil || again.Profiles[0].NetworkSecurityGroupOCIDs[0] == "changed" {
		t.Fatal("startup getter leaked mutable authority")
	}
	grantPin := sha256.Sum256(verified.FoundationGrantWire())
	if hex.EncodeToString(grantPin[:]) != reader.home.GrantSHA256 {
		t.Fatal("startup proof did not retain exact signed grant")
	}
	// An ordinary authenticated caller discovers the exact signed grant from a
	// fixed home location, without a host anchor, config or installed identity.
	discoveryClient := client.(foundationDiscoveryObjects)
	domain := bootstrap.StorageDomain{Namespace: "ns", HeadBucket: foundationDiscoveryBucket, LedgerBucket: "gru-1-ledger", HeadKMSKeyOCID: target.KMSKeyOCID, LedgerKMSKeyOCID: "ocid1.key.oc1.sa-saopaulo-1.ledger", Prefix: "bootstrap"}
	discoveryHome := bootstrap.FoundationScope{InstallationID: reader.home.InstallationID, DeploymentID: scope.DeploymentID, ClusterID: scope.Slot, TenancyID: reader.tenancy, OCIRegion: foundationHomeRegion, StorageDomain: domain, GrantGeneration: 1}
	publicGrant := grant
	publicGrant.Regions = slices.Clone(grant.Regions)
	publicGrant.Regions[0].BootstrapMaterial = nil
	grantPayload, err := trust.EncodePayload(publicGrant)
	if err != nil {
		t.Fatal(err)
	}
	grantEnvelope, err := trust.Sign(grantPayload, scope, now.Add(-time.Minute), now.Add(time.Hour), private)
	if err != nil {
		t.Fatal(err)
	}
	grantWire, err := trust.EncodeEnvelope(grantEnvelope)
	if err != nil {
		t.Fatal(err)
	}
	discoveryDigest := sha256.Sum256(grantWire)
	discoveryHome.GrantSHA256 = hex.EncodeToString(discoveryDigest[:])
	slots := []string{"controller-a", "controller-b", "controller-c"}
	registration := bootstrap.InitialSourceRegistration{InstallationID: discoveryHome.InstallationID, DeploymentID: scope.DeploymentID, Environment: "production", ClusterID: scope.Slot, Cell: oci.RegionGRU, Generation: 1, PlanSHA256: material.PlanSHA256, SeedSlot: slots[0], ControllerSlots: slots, StorageDomain: domain, LedgerRecordDomains: bootstrap.BootstrapLedgerCapabilityDomains()}
	intentDigest := sha256.Sum256(intentWire)
	discoveryAnchor := bootstrap.BootstrapAnchor{SchemaVersion: 1, DeploymentID: scope.DeploymentID, Environment: "production", ClusterID: scope.Slot, Cell: oci.RegionGRU, OCIRegion: foundationHomeRegion, StorageDomain: domain, FoundationScope: &discoveryHome, InitialSourceRegistration: &registration, ControllerSlots: slots, InitialRegionIntentGeneration: 1, InitialRegionIntentWire: intentWire, InitialRegionIntentSHA256: hex.EncodeToString(intentDigest[:])}
	anchorEnvelope, err := bootstrap.SignBootstrapAnchor(discoveryAnchor, now.Add(-time.Minute), now.Add(time.Hour), private)
	if err != nil {
		t.Fatal(err)
	}
	anchorWire, err := trust.EncodeEnvelope(anchorEnvelope)
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := publishFoundationDiscovery(t.Context(), discoveryClient, reader.tenancy, roots, anchorWire, grantWire); err != nil {
			t.Fatal(err)
		}
	}
	resolved, err := discoverFoundation(t.Context(), discoveryClient, reader.tenancy, roots)
	if err != nil {
		t.Fatal(err)
	}
	if approved, err := resolved.Footprint.AuthorizedRegions(t.Context()); err != nil || approved.TenancyID != reader.tenancy || len(approved.Regions) != 1 {
		t.Fatalf("ordinary caller footprint=%+v err=%v", approved, err)
	}
	if _, err := discoverFoundation(t.Context(), discoveryClient, reader.tenancy, nil); !errors.Is(err, ErrFoundationDiscoveryPending) {
		t.Fatalf("missing independent roots: %v", err)
	}
	if _, err := discoverFoundation(t.Context(), discoveryClient, "ocid1.tenancy.oc1..foreign", roots); err == nil {
		t.Fatal("foreign authenticated tenancy discovered signed installation")
	}
	if _, err := verifyDiscoveryAnchor(anchorWire, roots, reader.tenancy, "foreign"); err == nil {
		t.Fatal("foreign authenticated storage namespace discovered signed installation")
	}
	for _, scenario := range []string{"wrong scope", "expired", "wrong tenancy", "no budget", "wrong digest", "wrong escrow", "wrong local cluster", "wrong pinned digest", "wrong startup image", "wrong startup profile", "missing startup recipe"} {
		t.Run(scenario, func(t *testing.T) {
			changed := grant
			changed.Regions = append([]FoundationIntent(nil), grant.Regions...)
			badMaterial := *material
			copiedStartup := material.Startup.Clone()
			badMaterial.Startup = &copiedStartup
			changed.Regions[0].BootstrapMaterial = &badMaterial
			grant = changed
			signedScope, expires := scope, now.Add(time.Hour)
			switch scenario {
			case "wrong startup image":
				badMaterial.Startup.ImageOCID = "ocid1.image.oc1.sa-saopaulo-1.FOREIGN"
			case "wrong startup profile":
				badMaterial.Startup.Profiles[0].SubnetOCID = "ocid1.subnet.oc1.sa-saopaulo-1.foreign"
			case "missing startup recipe":
				badMaterial.Startup.ControllerConfigDerivation = ""
			case "wrong scope":
				signedScope.Cell = "FRA"
			case "expired":
				expires = now.Add(-time.Second)
			case "wrong tenancy":
				grant.TenancyID = "ocid1.tenancy.oc1..foreign"
			case "no budget":
				grant.MonthlyLimitMinor = 0
			case "wrong escrow":
				badMaterial.SourceVaultTarget.VaultOCID = "ocid1.vault.oc1.sa-saopaulo-1.foreign"
			case "wrong local cluster":
				reader.local.ClusterID = entityid.New()
			case "wrong digest":
				badMaterial.PlanSHA256 = fmt.Sprintf("%064d", 0)
			}
			publish(signedScope, expires)
			if scenario == "wrong pinned digest" {
				reader.home.GrantSHA256 = fmt.Sprintf("%064d", 0)
			}
			if _, err := reader.AuthorizedBootstrapMaterial(context.Background(), "GRU"); err == nil {
				t.Fatal("unapproved bootstrap material admitted")
			}
			reader.local.ClusterID = config.ClusterID
			grant.TenancyID = reader.tenancy
			grant.MonthlyLimitMinor = 10000
			grant.Regions[0].BootstrapMaterial = material
		})
	}
}

func foundationImageRecipe(t *testing.T, root ed25519.PrivateKey, roots trust.Keyring, now time.Time, config bootstrapmaterial.Config) (bootstrap.StartupTemplate, release.ImageReceipt) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyID, err := trust.KeyID(public)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := trust.EncodeDelegatedPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	digest := strings.Repeat("a", 64)
	receipt := release.ImageReceipt{Schema: release.ImageSchema, SourceRevision: strings.Repeat("a", 40), GoVersion: release.DefaultGoVersion, Architecture: "amd64", BinaryBytes: 13, BinarySHA256: digest, QualificationSHA256: digest, BaseImageOCID: "ocid1.image.oc1.sa-saopaulo-1.base", BaseImageRegion: "GRU", BaseImageSHA256: digest, KernelRelease: "6.1.0", KernelSHA256: digest, ImageFormat: "qcow2", ImageBytes: 1024, ImageSHA256: digest, OCIImageOCID: "ocid1.image.oc1.sa-saopaulo-1.custom", OCIRegion: "GRU"}
	scope := release.ImageScope(receipt, "production")
	delegation, err := trust.SignDelegation(trust.Delegation{SchemaVersion: trust.SchemaVersion, SubjectKeyID: keyID, SubjectPublicKey: encoded, Capabilities: []trust.Capability{{Domain: scope.Domain, DeploymentID: scope.DeploymentID, Cell: scope.Cell, Environment: scope.Environment, Role: scope.Role, Slots: []string{scope.Slot}, Actions: []string{"sign"}}}}, now.Add(-time.Minute), now.Add(time.Hour), root)
	if err != nil {
		t.Fatal(err)
	}
	image, err := release.SignImageReceipt(receipt, "production", delegation, roots, private, now, 30*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	imageWire, err := trust.EncodeEnvelope(image)
	if err != nil {
		t.Fatal(err)
	}
	delegationWire, err := trust.EncodeEnvelope(delegation)
	if err != nil {
		t.Fatal(err)
	}
	signers, err := json.Marshal([]map[string]any{{"actor": "ops", "public_key": base64.StdEncoding.EncodeToString(public), "roles": []string{"terrabase"}, "environments": []string{"production"}}})
	if err != nil {
		t.Fatal(err)
	}
	template := bootstrap.StartupTemplate{SeedSlot: config.Slots[0].Name, ImageOCID: receipt.OCIImageOCID, ImageArchitecture: "linux-amd64", ReleaseImageReceiptWire: imageWire, ReleaseDelegationWire: delegationWire, TrustedSigners: signers, ControllerConfigDerivation: bootstrap.ControllerConfigDerivationV1}
	for _, slot := range config.Slots {
		template.Profiles = append(template.Profiles, bootstrap.LaunchProfile{Slot: slot.Name, CompartmentOCID: "ocid1.compartment.oc1..control", AvailabilityDomain: "test:SA-SAOPAULO-1-AD-1", FaultDomain: "FAULT-DOMAIN-1", SubnetOCID: "ocid1.subnet.oc1.sa-saopaulo-1.test", NetworkSecurityGroupOCIDs: []string{"ocid1.networksecuritygroup.oc1.sa-saopaulo-1.test"}, Shape: "VM.Standard.E5.Flex"})
	}
	return template, receipt
}
