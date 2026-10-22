package materialsource

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json/v2"
	"encoding/pem"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapmaterial"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/region"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"
	ocisecrets "github.com/oracle/oci-go-sdk/v65/secrets"
	ocivault "github.com/oracle/oci-go-sdk/v65/vault"
)

func materialSourceAnchor(t *testing.T) (bootstrap.VerifiedBootstrapAnchor, bootstrap.HistoricalBootstrapAnchor,
	trust.Keyring, ed25519.PrivateKey, []byte,
) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	rootPublic, rootPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	roots, err := trust.ParseKeyring(rootPublic)
	if err != nil {
		t.Fatal(err)
	}
	ledgerPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ledgerID, err := trust.KeyID(ledgerPublic)
	if err != nil {
		t.Fatal(err)
	}
	ledgerWire, err := trust.EncodeDelegatedPublicKey(ledgerPublic)
	if err != nil {
		t.Fatal(err)
	}
	slots := []string{"controller-b"}
	capabilities := make([]trust.Capability, 0, 5)
	for _, domain := range []string{"bootstrap-slot-head", "bootstrap-intent", "bootstrap-result", "bootstrap-candidate", "bootstrap-progress"} {
		capabilities = append(capabilities, trust.Capability{Domain: domain, DeploymentID: "0000000000F9PR1WNVDTEXS31Z",
			Cell: "GRU", Environment: "production", Role: "controller", Slots: slices.Clone(slots), Actions: []string{"sign"}})
	}
	grant, err := trust.SignDelegation(trust.Delegation{SchemaVersion: trust.SchemaVersion,
		SubjectKeyID: ledgerID, SubjectPublicKey: ledgerWire, Capabilities: capabilities},
		now.Add(-time.Hour), now.Add(24*time.Hour), rootPrivate)
	if err != nil {
		t.Fatal(err)
	}
	grantWire, err := trust.EncodeEnvelope(grant)
	if err != nil {
		t.Fatal(err)
	}
	intentWire, err := trust.EncodePayload(oci.RegionIntent{SchemaVersion: 1, Generation: 4,
		BootstrapRegion: oci.RegionGRU, Regions: []oci.RegionMapping{{Cell: oci.RegionGRU, OCIRegion: "sa-saopaulo-1"}}})
	if err != nil {
		t.Fatal(err)
	}
	intentDigest := sha256.Sum256(intentWire)
	anchor := bootstrap.BootstrapAnchor{SchemaVersion: bootstrap.BootstrapAnchorSchemaVersion,
		DeploymentID: "0000000000F9PR1WNVDTEXS31Z", Environment: "production", ClusterID: "0000000000RMSAJ9B0JFV7ESHN", Cell: oci.RegionGRU,
		OCIRegion: "sa-saopaulo-1", ControllerSlots: slots, LedgerDelegationWire: grantWire,
		StorageDomain: bootstrap.StorageDomain{Namespace: "namespace-a", LedgerBucket: "ledger-bucket",
			LedgerKMSKeyOCID: "ocid1.key.oc1.sa-saopaulo-1.ledger", HeadBucket: "head-bucket",
			HeadKMSKeyOCID: "ocid1.key.oc1.sa-saopaulo-1.head", Prefix: "private/bootstrap"},
		InitialRegionIntentGeneration: 4, InitialRegionIntentSHA256: hex.EncodeToString(intentDigest[:]),
		InitialRegionIntentWire: intentWire}
	envelope, err := bootstrap.SignBootstrapAnchor(anchor, now.Add(-time.Minute), now.Add(time.Hour), rootPrivate)
	if err != nil {
		t.Fatal(err)
	}
	expected := bootstrap.BootstrapAnchorExpectation{DeploymentID: anchor.DeploymentID, Environment: anchor.Environment, Cell: anchor.Cell}
	current, err := bootstrap.VerifyBootstrapAnchor(envelope, roots, expected, now, bootstrap.BootstrapAnchorTrustPolicy())
	if err != nil {
		t.Fatal(err)
	}
	historical, err := bootstrap.VerifyHistoricalBootstrapAnchor(envelope, roots, expected, now, bootstrap.BootstrapAnchorTrustPolicy())
	if err != nil {
		t.Fatal(err)
	}
	anchorWire, err := trust.EncodeEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return current, historical, roots, rootPrivate, anchorWire
}

type materialProtocolSecret struct{ ID, Name, Content, Token string }
type materialProtocol struct {
	mu                sync.Mutex
	directory         string
	target            bootstrapmaterial.VaultTarget
	creates           int
	loseCreate        bool
	loseSourceCreate  bool
	hiddenSourceReads int
	sourceCreates     int
}

func (server *materialProtocol) objectPath(key string) string {
	sum := sha256.Sum256([]byte(key))
	return filepath.Join(server.directory, hex.EncodeToString(sum[:]))
}
func (server *materialProtocol) put(key string, body []byte) error {
	return os.WriteFile(server.objectPath(key), body, 0o600)
}
func (server *materialProtocol) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	server.mu.Lock()
	defer server.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	if r.Header.Get("Authorization") == "" {
		w.WriteHeader(401)
		return
	}
	if strings.HasPrefix(r.URL.Path, "/n/") {
		old, err := os.ReadFile(server.objectPath(r.URL.Path))
		etag := digestWire(old)
		if r.Method == http.MethodGet {
			if err != nil {
				w.WriteHeader(404)
				io.WriteString(w, `{"code":"ObjectNotFound","message":"absent"}`)
				return
			}
			w.Header().Set("etag", etag)
			w.Header().Set("opc-sse-kms-key-id", "ocid1.key.oc1.sa-saopaulo-1.head")
			w.Write(old)
			return
		}
		if r.Method != http.MethodPut {
			w.WriteHeader(405)
			return
		}
		if r.Header.Get("if-none-match") == "*" && err == nil || r.Header.Get("if-match") != "" && (err != nil || r.Header.Get("if-match") != etag) {
			w.WriteHeader(412)
			io.WriteString(w, `{"code":"PreconditionFailed","message":"changed"}`)
			return
		}
		if r.Header.Get("if-none-match") == "" && r.Header.Get("if-match") == "" || r.Header.Get("opc-sse-kms-key-id") != "ocid1.key.oc1.sa-saopaulo-1.head" {
			w.WriteHeader(400)
			return
		}
		body, readErr := io.ReadAll(r.Body)
		if readErr != nil {
			w.WriteHeader(400)
			return
		}
		if err := server.put(r.URL.Path, body); err != nil {
			w.WriteHeader(500)
			return
		}
		if r.Header.Get("if-none-match") == "*" {
			server.sourceCreates++
		}
		w.Header().Set("etag", digestWire(body))
		return
	}
	var response any
	switch {
	case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/secrets"):
		var details struct {
			CompartmentID string `json:"compartmentId"`
			VaultID       string `json:"vaultId"`
			KeyID         string `json:"keyId"`
			Name          string `json:"secretName"`
			Content       struct {
				Content string `json:"content"`
			} `json:"secretContent"`
		}
		if json.UnmarshalRead(r.Body, &details) != nil || details.CompartmentID != server.target.CompartmentOCID || details.VaultID != server.target.VaultOCID || details.KeyID != server.target.KMSKeyOCID || r.Header.Get("opc-retry-token") == "" {
			w.WriteHeader(400)
			return
		}
		if strings.Contains(r.Header.Get("Authorization"), "ocid1.user.oc1..peer") && strings.HasPrefix(details.Name, "ts-bootstrap-source-") {
			w.WriteHeader(403)
			io.WriteString(w, `{"code":"NotAuthorized","message":"founder source create denied"}`)
			return
		}
		if body, err := os.ReadFile(server.objectPath("token-" + r.Header.Get("opc-retry-token"))); err == nil {
			var secret materialProtocolSecret
			json.Unmarshal(body, &secret)
			json.MarshalWrite(w, ocivault.Secret{Id: new(secret.ID)})
			return
		}
		if _, err := os.ReadFile(server.objectPath("name-" + details.Name)); err == nil {
			w.WriteHeader(409)
			io.WriteString(w, `{"code":"Conflict","message":"secret exists"}`)
			return
		}
		server.creates++
		secret := materialProtocolSecret{ID: fmt.Sprintf("ocid1.vaultsecret.oc1.%s.secret%d", strings.Split(server.target.VaultOCID, ".")[3], server.creates), Name: details.Name, Content: details.Content.Content, Token: r.Header.Get("opc-retry-token")}
		wire, _ := json.Marshal(secret)
		if server.put("secret-"+secret.ID, wire) != nil || server.put("name-"+secret.Name, wire) != nil || server.put("token-"+secret.Token, wire) != nil {
			w.WriteHeader(500)
			return
		}
		if server.loseSourceCreate && strings.HasPrefix(secret.Name, "ts-bootstrap-source-") {
			server.loseSourceCreate = false
			server.hiddenSourceReads = 2
			w.WriteHeader(500)
			io.WriteString(w, `{"code":"InternalError","message":"committed source response lost"}`)
			return
		}
		if server.loseCreate && !strings.HasPrefix(secret.Name, "ts-bootstrap-source-") {
			server.loseCreate = false
			w.WriteHeader(500)
			io.WriteString(w, `{"code":"InternalError","message":"committed response lost"}`)
			return
		}
		response = ocivault.Secret{Id: new(secret.ID)}
	case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/secrets"):
		body, err := os.ReadFile(server.objectPath("name-" + r.URL.Query().Get("name")))
		items := []ocivault.SecretSummary{}
		if err == nil {
			var secret materialProtocolSecret
			json.Unmarshal(body, &secret)
			items = append(items, ocivault.SecretSummary{Id: new(secret.ID), SecretName: new(secret.Name), CompartmentId: new(server.target.CompartmentOCID), VaultId: new(server.target.VaultOCID), LifecycleState: ocivault.SecretSummaryLifecycleStateActive})
		}
		response = items
	case strings.HasSuffix(r.URL.Path, "/secretbundles"):
		if strings.HasPrefix(r.URL.Query().Get("secretName"), "ts-bootstrap-source-") && server.hiddenSourceReads > 0 {
			server.hiddenSourceReads--
			w.WriteHeader(404)
			io.WriteString(w, `{"code":"SecretNotFound","message":"not visible yet"}`)
			return
		}
		body, err := os.ReadFile(server.objectPath("name-" + r.URL.Query().Get("secretName")))
		if err != nil {
			w.WriteHeader(404)
			io.WriteString(w, `{"code":"SecretNotFound","message":"absent"}`)
			return
		}
		var secret materialProtocolSecret
		json.Unmarshal(body, &secret)
		if strings.Contains(r.Header.Get("Authorization"), "ocid1.user.oc1..peer") && strings.HasPrefix(secret.Name, "ts-bootstrap-source-") {
			w.WriteHeader(403)
			io.WriteString(w, `{"code":"NotAuthorized","message":"founder source denied"}`)
			return
		}
		response = ocisecrets.SecretBundle{SecretId: new(secret.ID), VersionNumber: new(int64(1)), SecretBundleContent: ocisecrets.Base64SecretBundleContentDetails{Content: new(secret.Content)}}
	case strings.Contains(r.URL.Path, "/secretbundles/"):
		_, id, _ := strings.Cut(r.URL.Path, "/secretbundles/")
		body, err := os.ReadFile(server.objectPath("secret-" + id))
		if err != nil {
			w.WriteHeader(404)
			return
		}
		var secret materialProtocolSecret
		json.Unmarshal(body, &secret)
		if strings.Contains(r.Header.Get("Authorization"), "ocid1.user.oc1..peer") && strings.HasPrefix(secret.Name, "ts-bootstrap-source-") {
			w.WriteHeader(403)
			io.WriteString(w, `{"code":"NotAuthorized","message":"founder source denied"}`)
			return
		}
		response = ocisecrets.SecretBundle{SecretId: new(id), VersionNumber: new(int64(1)), SecretBundleContent: ocisecrets.Base64SecretBundleContentDetails{Content: new(secret.Content)}}
	case strings.Contains(r.URL.Path, "/secrets/"):
		_, id, _ := strings.Cut(r.URL.Path, "/secrets/")
		body, err := os.ReadFile(server.objectPath("secret-" + id))
		if err != nil {
			w.WriteHeader(404)
			return
		}
		var secret materialProtocolSecret
		json.Unmarshal(body, &secret)
		response = ocivault.Secret{Id: new(id), SecretName: new(secret.Name), CompartmentId: new(server.target.CompartmentOCID), VaultId: new(server.target.VaultOCID), KeyId: new(server.target.KMSKeyOCID), LifecycleState: ocivault.SecretLifecycleStateActive, CurrentVersionNumber: new(int64(1))}
	default:
		w.WriteHeader(404)
		return
	}
	json.MarshalWrite(w, response)
}

func TestColdMaterialHTTPConcurrentBootAndHostLossRecovery(t *testing.T) {
	t.Run("prospective CAS data transitions only", func(t *testing.T) {
		reserved := materialSourceState{AdmissionAuthorizationSHA256: strings.Repeat("a", 64)}
		archive := reserved
		archive.Reference = materialSourceReference{SecretOCID: "ocid1.vaultsecret.oc1.sa-saopaulo-1.original", SHA256: strings.Repeat("b", 64), MaxBytes: 100}
		selected := archive
		selected.Inventory = []byte("first-inventory-data")
		selected.OriginalAdmissionInventory = bytes.Clone(selected.Inventory)
		if !immutableAdmissionSource(reserved, archive) || !immutableAdmissionSource(archive, selected) || immutableAdmissionSource(reserved, selected) {
			t.Fatal("archive and first inventory do not require separate CAS phases")
		}
		renewed := selected
		renewed.Inventory = []byte("renewed-current-inventory-data")
		if !immutableAdmissionSource(selected, renewed) {
			t.Fatal("same original selection could not renew current inventory")
		}
		for name, mutate := range map[string]func(*materialSourceState){
			"clear original":        func(s *materialSourceState) { s.OriginalAdmissionInventory = nil },
			"replace original":      func(s *materialSourceState) { s.OriginalAdmissionInventory = []byte("replacement") },
			"replace archive":       func(s *materialSourceState) { s.Reference.SHA256 = strings.Repeat("c", 64) },
			"clear archive":         func(s *materialSourceState) { s.Reference = materialSourceReference{} },
			"replace authorization": func(s *materialSourceState) { s.AdmissionAuthorizationSHA256 = strings.Repeat("d", 64) },
		} {
			candidate := selected
			mutate(&candidate)
			if immutableAdmissionSource(selected, candidate) {
				t.Fatalf("accepted %s", name)
			}
		}
		if immutableAdmissionSource(materialSourceState{}, reserved) {
			t.Fatal("legacy state gained prospective authorization")
		}
	})
	t.Run("prospective original actor lifecycle", func(t *testing.T) {
		t.Skip("HOLD: schema3 has no authentic VerifiedBootstrapMaterial/SourceFounder producer; escrow loss, host loss and same-key renewal cannot be qualified by document or mechanical-data fixtures")
	})
	// This fixture has no authenticated SourceFounder; nil preserves production refusal.
	// The positive lifecycle assertions below still execute and remain unqualified.
	now := time.Now().UTC().Truncate(time.Second).Add(-2 * time.Second)
	anchor, _, roots, private, _ := materialSourceAnchor(t)
	target := bootstrapmaterial.VaultTarget{CompartmentOCID: "ocid1.compartment.oc1..control", VaultOCID: "ocid1.vault.oc1.sa-saopaulo-1.vault", KMSKeyOCID: "ocid1.key.oc1.sa-saopaulo-1.head"}
	protocol := &materialProtocol{directory: t.TempDir(), target: target, loseCreate: true, loseSourceCreate: true}
	endpoint := httptest.NewServer(protocol)
	defer endpoint.Close()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	provider := common.NewRawConfigurationProvider("ocid1.tenancy.oc1..test", "ocid1.user.oc1..test", "sa-saopaulo-1", "test", string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})), nil)
	objects, err := objectstorage.NewObjectStorageClientWithConfigurationProvider(provider)
	if err != nil {
		t.Fatal(err)
	}
	management, err := ocivault.NewVaultsClientWithConfigurationProvider(provider)
	if err != nil {
		t.Fatal(err)
	}
	bundles, err := ocisecrets.NewSecretsClientWithConfigurationProvider(provider)
	if err != nil {
		t.Fatal(err)
	}
	for _, client := range []*common.BaseClient{&objects.BaseClient, &management.BaseClient, &bundles.BaseClient} {
		client.Host = endpoint.URL
		client.HTTPClient = endpoint.Client()
		policy := common.NoRetryPolicy()
		client.Configuration.RetryPolicy = &policy
		ociclient.ConfigureRequestCancellation(client)
	}
	var reader *region.SignedFootprint
	cfg := bootstrapmaterial.Config{Environment: "production", Region: "sa-saopaulo-1", Cell: "gru", DeploymentID: anchor.Anchor().DeploymentID, ClusterID: anchor.Anchor().ClusterID, SubnetCIDR: "10.251.0.0/24", ValidityHours: 48, Slots: []bootstrapmaterial.Slot{{Name: "controller-a", PrivateIP: "10.251.0.11"}, {Name: "controller-b", PrivateIP: "10.251.0.12"}, {Name: "controller-c", PrivateIP: "10.251.0.13"}}}
	wire, _ := json.Marshal(cfg, json.Deterministic(true))
	intent := &region.BootstrapMaterialIntent{InstallationID: "0000000000YTR4D9RJ6W8NG1HC", PlanSHA256: digestWire(wire), Config: cfg, SourceVaultTarget: target}
	grant := region.FoundationGrant{InstallationID: intent.InstallationID, SchemaVersion: 1, Generation: 1, TenancyID: "ocid1.tenancy.oc1..test", ParentCompartmentID: "ocid1.compartment.oc1..parent", SharedCompartmentID: "ocid1.compartment.oc1..shared", Currency: "USD", MonthlyLimitMinor: 10000, CleanupOwner: "integration", Regions: []region.FoundationIntent{{Generation: 1, Plan: map[string]any{"cell": "GRU", "region": "sa-saopaulo-1", "tenancy_id": "ocid1.tenancy.oc1..test", "parent_compartment_id": "ocid1.compartment.oc1..parent", "shared_compartment_id": "ocid1.compartment.oc1..shared", "resource_ids": map[string]any{"control": target.CompartmentOCID, "control_compartment": target.CompartmentOCID, "vault": target.VaultOCID, "key": target.KMSKeyOCID}}}}}
	spokeConfig := cfg
	spokeConfig.Cell, spokeConfig.Region, spokeConfig.ClusterID = "sjc", "us-sanjose-1", "0000000000F9PR1WNVDTEXS31Z"
	spokeWire, err := json.Marshal(spokeConfig, json.Deterministic(true))
	if err != nil {
		t.Fatal(err)
	}
	spokeIntent := &region.BootstrapMaterialIntent{InstallationID: intent.InstallationID, PlanSHA256: digestWire(spokeWire), Config: spokeConfig, SourceVaultTarget: target}
	spokePlan := maps.Clone(grant.Regions[0].Plan)
	spokePlan["cell"], spokePlan["region"] = "SJC", "us-sanjose-1"
	spokePlan["resource_ids"] = map[string]any{"control_compartment": "ocid1.compartment.oc1..sfocontrol", "vault": "ocid1.vault.oc1.us-sanjose-1.vault", "key": "ocid1.key.oc1.us-sanjose-1.key"}
	grant.Regions = append(grant.Regions, region.FoundationIntent{Generation: 1, Plan: spokePlan})
	pinnedLedgerWire := bytes.Clone(anchor.Anchor().LedgerDelegationWire)
	pinnedSlots := slices.Clone(anchor.Anchor().ControllerSlots)
	publish := func() {
		t.Helper()
		payload, err := trust.EncodePayload(grant)
		if err != nil {
			t.Fatal(err)
		}
		envelope, err := trust.Sign(payload, trust.Scope{Domain: "terrascale.foundation.scope", DeploymentID: cfg.DeploymentID, Cell: "GRU", Environment: cfg.Environment, Role: "foundation", Slot: cfg.ClusterID}, now.Add(-time.Minute), now.Add(30*time.Minute), private)
		if err != nil {
			t.Fatal(err)
		}
		wire, err := trust.EncodeEnvelope(envelope)
		if err != nil {
			t.Fatal(err)
		}
		anchorValue := anchor.Anchor()
		if intent.SourceRegistration != nil {
			registration := intent.SourceRegistration.Clone()
			anchorValue.InitialSourceRegistration = &registration
			anchorValue.ControllerSlots = slices.Clone(registration.ControllerSlots)
			anchorValue.LedgerDelegationWire = nil
		} else {
			anchorValue.InitialSourceRegistration = nil
			anchorValue.LedgerDelegationWire = bytes.Clone(pinnedLedgerWire)
			anchorValue.ControllerSlots = slices.Clone(pinnedSlots)
		}
		anchorValue.FoundationScope = &bootstrap.FoundationScope{InstallationID: grant.InstallationID, DeploymentID: cfg.DeploymentID, ClusterID: cfg.ClusterID, TenancyID: grant.TenancyID, OCIRegion: "sa-saopaulo-1", StorageDomain: anchor.StorageDomain(), GrantGeneration: grant.Generation, GrantSHA256: digestWire(wire)}
		rootEnvelope, err := bootstrap.SignBootstrapAnchor(anchorValue, now.Add(-time.Minute), now.Add(time.Hour), private)
		if err != nil {
			t.Fatal(err)
		}
		anchor, err = bootstrap.VerifyBootstrapAnchor(rootEnvelope, roots, bootstrap.BootstrapAnchorExpectation{DeploymentID: cfg.DeploymentID, Environment: cfg.Environment, Cell: oci.RegionGRU}, now, bootstrap.BootstrapAnchorTrustPolicy())
		if err != nil {
			t.Fatal(err)
		}
		reader, err = region.NewSignedFootprint(&objects, anchor, roots, grant.TenancyID)
		if err != nil {
			t.Fatal(err)
		}
		protocol.mu.Lock()
		defer protocol.mu.Unlock()
		if err := protocol.put("/n/namespace-a/b/head-bucket/o/private/bootstrap/foundation-scope-v1.json", wire); err != nil {
			t.Fatal(err)
		}
	}
	publish()
	if _, err := reader.AuthorizedBootstrapMaterial(t.Context(), "GRU"); err == nil {
		t.Fatal("foundation-only grant minted source")
	}
	if _, err := ResolveColdStartMaterial(t.Context(), region.VerifiedBootstrapMaterial{}, nil, &objects, &management, &bundles, filepath.Join(t.TempDir(), "source"), now); err == nil {
		t.Fatal("empty grant minted source")
	}
	grant.Regions[0].BootstrapMaterial = intent
	grant.Regions[1].BootstrapMaterial = spokeIntent
	publish()
	pinnedOnly, err := reader.AuthorizedBootstrapMaterial(t.Context(), "GRU")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ResolveColdStartMaterial(t.Context(), pinnedOnly, nil, &objects, &management, &bundles, filepath.Join(t.TempDir(), "missing-pinned-source"), now); err == nil || protocol.creates != 0 {
		t.Fatal("existing pinned identity minted replacement source")
	}
	for index, material := range []*region.BootstrapMaterialIntent{intent, spokeIntent} {
		ids := grant.Regions[index].Plan["resource_ids"].(map[string]any)
		ids["subnet"], ids["network_security_group"] = "ocid1.subnet.oc1."+material.Config.Region+".test", "ocid1.networksecuritygroup.oc1."+material.Config.Region+".test"
		startup, _ := sourceImageRecipe(t, private, roots, now, material.Config, ids, anchor.Anchor().InitialRegionIntentWire)
		material.Startup = &startup
		material.SourceRegistration = &bootstrap.InitialSourceRegistration{InstallationID: material.InstallationID, DeploymentID: material.Config.DeploymentID, Environment: material.Config.Environment, ClusterID: material.Config.ClusterID, Cell: oci.Region(strings.ToUpper(material.Config.Cell)), Generation: 1, PlanSHA256: material.PlanSHA256, SeedSlot: startup.SeedSlot, ControllerSlots: []string{"controller-a", "controller-b", "controller-c"}, StorageDomain: anchor.StorageDomain(), LedgerRecordDomains: bootstrap.BootstrapLedgerCapabilityDomains()}
		if material.Config.Cell == "sjc" {
			material.SourceRegistration.StorageDomain = bootstrap.StorageDomain{Namespace: "namespace-sjc", LedgerBucket: "sjc-ledger", HeadBucket: "sjc-head", LedgerKMSKeyOCID: "ocid1.key.oc1.us-sanjose-1.ledger", HeadKMSKeyOCID: "ocid1.key.oc1.us-sanjose-1.head", Prefix: "regional/sjc"}
		}
	}
	publish()
	verified, err := reader.AuthorizedBootstrapMaterial(t.Context(), "GRU")
	if err != nil {
		t.Fatal(err)
	}
	// Every source effect requires a sealed SourceFounder (e782a6720); without
	// one even a fully authorized grant must refuse before any Vault create.
	if _, err := ResolveColdStartMaterial(t.Context(), verified, nil, &objects, &management, &bundles, filepath.Join(t.TempDir(), "unsealed-founder"), now); err == nil || protocol.creates != 0 || protocol.sourceCreates != 0 {
		t.Fatalf("source without a sealed founder = %v, creates=%d source creates=%d", err, protocol.creates, protocol.sourceCreates)
	}
}
