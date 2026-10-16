//go:build fixturetest

package materialsource

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
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
	"reflect"
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
	"github.com/oracle/oci-go-sdk/v65/identity"
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
			LedgerKMSKeyOCID: "ocid1.key.oc1.sa-saopaulo-1.ledger", HeadBucket: "gru-1-head",
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
	policies          map[string]identity.Policy
	interceptObject   func(http.ResponseWriter, *http.Request) bool
	interceptIAM      func(http.ResponseWriter, *http.Request) bool
}

func (server *materialProtocol) objectPath(key string) string {
	sum := sha256.Sum256([]byte(key))
	return filepath.Join(server.directory, hex.EncodeToString(sum[:]))
}
func (server *materialProtocol) put(key string, body []byte) error {
	return os.WriteFile(server.objectPath(key), body, 0o600)
}
func (server *materialProtocol) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if server.interceptObject != nil && server.interceptObject(w, r) {
		return
	}
	server.mu.Lock()
	defer server.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	if r.Header.Get("Authorization") == "" {
		w.WriteHeader(401)
		return
	}
	if r.Method == http.MethodGet && r.URL.Path == "/n" {
		io.WriteString(w, `"namespace-a"`)
		return
	}
	if r.Method == http.MethodGet && r.URL.Path == "/n/namespace-a/b/gru-1-head" {
		json.MarshalWrite(w, objectstorage.Bucket{Id: new("ocid1.bucket.oc1.sa-saopaulo-1.head"), Name: new("gru-1-head"), Namespace: new("namespace-a"), KmsKeyId: new(server.target.KMSKeyOCID), CompartmentId: new(server.target.CompartmentOCID)})
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
		secret := materialProtocolSecret{ID: fmt.Sprintf("ocid1.vaultsecret.oc1.sa-saopaulo-1.secret%d", server.creates), Name: details.Name, Content: details.Content.Content, Token: r.Header.Get("opc-retry-token")}
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
	case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/secretbundles/actions/getByName"):
		if r.URL.Query().Get("vaultId") != server.target.VaultOCID || r.URL.Query().Get("versionNumber") != "1" {
			w.WriteHeader(400)
			return
		}
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
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
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
	spokeConfig.Cell, spokeConfig.Region, spokeConfig.ClusterID = "sfo", "us-sanjose-1", "0000000000F9PR1WNVDTEXS31Z"
	spokeWire, err := json.Marshal(spokeConfig, json.Deterministic(true))
	if err != nil {
		t.Fatal(err)
	}
	spokeIntent := &region.BootstrapMaterialIntent{InstallationID: intent.InstallationID, PlanSHA256: digestWire(spokeWire), Config: spokeConfig, SourceVaultTarget: target}
	spokePlan := maps.Clone(grant.Regions[0].Plan)
	spokePlan["cell"], spokePlan["region"] = "SFO", "us-sanjose-1"
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
		sourceFoundationRecords(t, protocol, grant)
		rootWire, err := trust.EncodeEnvelope(rootEnvelope)
		if err != nil {
			t.Fatal(err)
		}
		chainWire, err := trust.EncodeRootChain(trust.RootChain{Version: 1})
		if err != nil {
			t.Fatal(err)
		}
		protocol.mu.Lock()
		defer protocol.mu.Unlock()
		if err = protocol.put("/n/namespace-a/b/gru-1-head/o/orchestrator/foundation/v1/anchor.json", rootWire); err != nil {
			t.Fatal(err)
		}
		if err = protocol.put("/n/namespace-a/b/gru-1-head/o/orchestrator/foundation/v1/root-chain.json", chainWire); err != nil {
			t.Fatal(err)
		}
		if err := protocol.put("/n/namespace-a/b/gru-1-head/o/private/bootstrap/foundation-scope-v1.json", wire); err != nil {
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
	}
	publish()
	verified, err := reader.AuthorizedBootstrapMaterial(t.Context(), "GRU")
	if err != nil {
		t.Fatal(err)
	}
	actor := sourceFounderFixture(t, verified, anchor, roots, &objects, protocol, reader, "ocid1.instance.oc1.sa-saopaulo-1.founder")
	for attempt := range 2 {
		if _, err := ResolveColdStartMaterial(t.Context(), verified, actor, &objects, &management, &bundles, filepath.Join(t.TempDir(), "lost-source"), now.Add(time.Duration(attempt)*time.Second)); err == nil {
			t.Fatal("uncertain source response or competing candidate unexpectedly succeeded")
		}
	}
	if protocol.creates != 1 {
		t.Fatalf("uncertain source retry duplicated escrow: creates=%d", protocol.creates)
	}
	sources := make([]*ColdStartMaterial, 2)
	errs := make([]error, 2)
	var workers sync.WaitGroup
	for i := range 2 {
		directory := filepath.Join(t.TempDir(), "source")
		workers.Go(func() {
			sources[i], errs[i] = ResolveColdStartMaterial(t.Context(), verified, actor, &objects, &management, &bundles, directory, now)
			if errs[i] != nil {
				sources[i], errs[i] = ResolveColdStartMaterial(t.Context(), verified, actor, &objects, &management, &bundles, directory, now)
			}
		})
	}
	workers.Wait()
	for _, err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	committedWire, err := os.ReadFile(protocol.objectPath("secret-" + sources[0].state.Reference.SecretOCID))
	if err != nil {
		t.Fatal(err)
	}
	var committed materialProtocolSecret
	if err := json.Unmarshal(committedWire, &committed); err != nil {
		t.Fatal(err)
	}
	if committed.Token != sources[0].state.RetryToken || !sources[0].state.StartedAt.Equal(now) {
		t.Fatal("source recovery changed original retry identity")
	}
	committedBody, err := base64.StdEncoding.DecodeString(committed.Content)
	if err != nil || digestWire(committedBody) != sources[0].state.Reference.SHA256 {
		t.Fatal("source recovery changed original committed source")
	}
	clear(committedBody)
	t.Logf("founder source escrow compressed bytes=%d (Vault limit=%d)", sources[0].state.Reference.MaxBytes, materialSourceSecretLimit)
	if !reflect.DeepEqual(sources[0].Record(), sources[1].Record()) || protocol.sourceCreates != 1 {
		t.Fatal("concurrent boots selected different signing roots")
	}
	if _, err := sources[0].Provision(t.Context(), target, &management, &bundles, now); err == nil {
		t.Fatal("lost committed create response unexpectedly succeeded")
	}
	if protocol.creates != 2 {
		t.Fatalf("creates after response loss=%d", protocol.creates)
	}
	replacement, err := ResolveColdStartMaterial(t.Context(), verified, actor, &objects, &management, &bundles, filepath.Join(t.TempDir(), "replacement"), now)
	if err != nil {
		t.Fatal(err)
	}
	publication, err := replacement.Provision(t.Context(), target, &management, &bundles, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(publication.References) != 27 || protocol.creates != 28 || !reflect.DeepEqual(replacement.Record(), sources[0].Record()) {
		t.Fatalf("replacement rotated source or duplicated secrets: creates=%d refs=%d", protocol.creates, len(publication.References))
	}
	projection, err := replacement.InstallMaterial(t.Context())
	if err != nil || !projection.IsVerified() {
		t.Fatalf("sealed projection: %v", err)
	}
	clone := projection.Record()
	clone.Config.Slots[0].PrivateIP = "other"
	if projection.Record().Config.Slots[0].PrivateIP == "other" {
		t.Fatal("projection exposed mutable config")
	}
	if err := projection.VerifyCurrent(t.Context()); err != nil {
		t.Fatal(err)
	}
	for _, ref := range publication.References {
		if ref.Reference.SecretOCID == replacement.state.Reference.SecretOCID {
			t.Fatal("escrow reference leaked to normal host")
		}
	}
	body, err := os.ReadFile(protocol.objectPath("/n/namespace-a/b/gru-1-head/o/" + replacement.key))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), "\"files\"") || strings.Contains(string(body), "PRIVATE KEY") {
		t.Fatal("ObjectStorage received private source archive")
	}
	for name, secret := range replacement.archive.Files {
		if strings.HasSuffix(name, ".seed") && bytes.Contains(body, bytes.TrimSpace(secret)) {
			t.Fatal("ObjectStorage received private signing seed")
		}
	}

	peerProvider := common.NewRawConfigurationProvider("ocid1.tenancy.oc1..test", "ocid1.user.oc1..peer", "sa-saopaulo-1", "test", string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})), nil)
	peer, err := ocisecrets.NewSecretsClientWithConfigurationProvider(peerProvider)
	if err != nil {
		t.Fatal(err)
	}
	peer.Host = endpoint.URL
	peer.HTTPClient = endpoint.Client()
	noRetry := common.NoRetryPolicy()
	peer.Configuration.RetryPolicy = &noRetry
	if _, err := peer.GetSecretBundle(t.Context(), ocisecrets.GetSecretBundleRequest{SecretId: new(replacement.state.Reference.SecretOCID), VersionNumber: new(int64(1))}); err == nil {
		t.Fatal("ordinary peer read founder escrow")
	} else if service, ok := common.IsServiceError(err); !ok || service.GetHTTPStatusCode() != 403 {
		t.Fatalf("peer denial: %v", err)
	}
	peerManagement, err := ocivault.NewVaultsClientWithConfigurationProvider(peerProvider)
	if err != nil {
		t.Fatal(err)
	}
	peerManagement.Host, peerManagement.HTTPClient = endpoint.URL, endpoint.Client()
	peerManagement.Configuration.RetryPolicy = &noRetry
	_, err = peerManagement.CreateSecret(t.Context(), ocivault.CreateSecretRequest{CreateSecretDetails: ocivault.CreateSecretDetails{CompartmentId: new(target.CompartmentOCID), VaultId: new(target.VaultOCID), KeyId: new(target.KMSKeyOCID), SecretName: new(replacement.state.SecretName), SecretContent: ocivault.Base64SecretContentDetails{Content: new("eA==")}}, OpcRetryToken: new("ordinary-peer-create")})
	if service, ok := common.IsServiceError(err); !ok || service.GetHTTPStatusCode() != 403 {
		t.Fatalf("ordinary peer escrow create denial: %v", err)
	}
	if _, err := peer.GetSecretBundle(t.Context(), ocisecrets.GetSecretBundleRequest{SecretId: new(publication.References[0].Reference.SecretOCID), VersionNumber: new(int64(1))}); err != nil {
		t.Fatalf("normal host material unreadable: %v", err)
	}
	rogueDirectory := filepath.Join(t.TempDir(), "rogue-source")
	rogueRecord, err := bootstrapmaterial.Generate(rogueDirectory, cfg, now)
	if err != nil {
		t.Fatal(err)
	}
	names := []string{"material.json", "READY"}
	for _, file := range rogueRecord.Files {
		names = append(names, file.Name)
	}
	for _, name := range names {
		body, err := os.ReadFile(filepath.Join(rogueDirectory, name))
		if err != nil {
			t.Fatal(err)
		}
		err = os.WriteFile(filepath.Join(replacement.directory, name), body, 0o600)
		clear(body)
		if err != nil {
			t.Fatal(err)
		}
	}
	if _, err := replacement.Provision(t.Context(), target, &management, &bundles, now); err == nil || protocol.creates != 28 {
		t.Fatal("edited local roots caused Vault effects")
	}
	replacement, err = ResolveColdStartMaterial(t.Context(), verified, actor, &objects, &management, &bundles, replacement.directory, now)
	if err != nil || !reflect.DeepEqual(replacement.Record(), sources[0].Record()) {
		t.Fatalf("trusted source repair: %v", err)
	}
	if _, err := sources[1].Provision(t.Context(), target, &management, &bundles, now); err == nil {
		t.Fatal("stale source checkpoint was allowed")
	}
	for _, directory := range []string{replacement.directory, filepath.Join(replacement.directory, "link")} {
		if _, err := ResolveLinkSource(t.Context(), replacement, replacement, nil, &objects, &management, &bundles, directory, now); err == nil || protocol.creates != 28 {
			t.Fatal("Link restore overlapped original regional producer")
		}
	}
	link, err := ResolveLinkSource(t.Context(), replacement, replacement, nil, &objects, &management, &bundles, filepath.Join(t.TempDir(), "home-link"), now)
	if err != nil {
		t.Fatal(err)
	}
	linkRecord := link.Record()
	if linkRecord.Signer == "" || !strings.HasPrefix(link.source.state.SecretName, "ts-bootstrap-source-link-") {
		t.Fatal("missing separately escrowed Link signer")
	}
	protocol.mu.Lock()
	protocol.loseCreate = true
	protocol.mu.Unlock()
	if _, err := link.Provision(t.Context(), target, &management, &bundles, now); err == nil {
		t.Fatal("lost Link publication response unexpectedly succeeded")
	}
	recoveredLink, err := ResolveLinkSource(t.Context(), replacement, replacement, nil, &objects, &management, &bundles, filepath.Join(t.TempDir(), "recovered-home-link"), now)
	if err != nil {
		t.Fatal(err)
	}
	linkPublication, err := recoveredLink.Provision(t.Context(), target, &management, &bundles, now)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(linkRecord, recoveredLink.Record()) || protocol.creates != 37 || len(linkPublication.References) != 8 {
		t.Fatalf("Link source rotated or publication duplicated: creates=%d refs=%d", protocol.creates, len(linkPublication.References))
	}
	for _, ref := range linkPublication.References {
		if ref.Reference.TargetFile == "issuer-link.seed" || ref.Reference.SecretOCID == recoveredLink.source.state.Reference.SecretOCID {
			t.Fatal("Link founder source leaked to ordinary hosts")
		}
	}
	verifiedLink, err := recoveredLink.InstallMaterial(t.Context())
	if err != nil || !verifiedLink.IsVerified() || verifiedLink.VerifyCurrent(t.Context()) != nil {
		t.Fatalf("Link sealed projection: %v", err)
	}
	if _, err := ResolveLinkSource(t.Context(), replacement, replacement, new(LinkSource), &objects, &management, &bundles, filepath.Join(t.TempDir(), "invalid-link"), now); err == nil {
		t.Fatal("empty home Link proof admitted")
	}
	spokeGrant, err := reader.AuthorizedBootstrapMaterial(t.Context(), "SFO")
	if err != nil {
		t.Fatal(err)
	}
	spokeActor := sourceFounderFixture(t, spokeGrant, anchor, roots, &objects, protocol, reader, "ocid1.instance.oc1.us-sanjose-1.founder")
	spokeSource, err := ResolveColdStartMaterial(t.Context(), spokeGrant, spokeActor, &objects, &management, &bundles, filepath.Join(t.TempDir(), "spoke-source"), now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ResolveLinkSource(t.Context(), spokeSource, replacement, nil, &objects, &management, &bundles, filepath.Join(t.TempDir(), "unproven-spoke-link"), now); err == nil {
		t.Fatal("spoke minted Link without recovered home signer")
	}
	spokeLink, err := ResolveLinkSource(t.Context(), spokeSource, replacement, recoveredLink, &objects, &management, &bundles, filepath.Join(t.TempDir(), "spoke-link"), now)
	if err != nil {
		t.Fatal(err)
	}
	recoveredSpoke, err := ResolveLinkSource(t.Context(), spokeSource, replacement, recoveredLink, &objects, &management, &bundles, filepath.Join(t.TempDir(), "recovered-spoke-link"), now)
	if err != nil {
		t.Fatal(err)
	}
	if protocol.creates != 39 || !reflect.DeepEqual(spokeLink.Record(), recoveredSpoke.Record()) || spokeLink.Record().Signer != recoveredLink.Record().Signer || spokeLink.Record().HomeLinkSHA256 != linkPublication.MaterialSHA256 {
		t.Fatalf("spoke changed home Link authority: creates=%d", protocol.creates)
	}
	for _, file := range spokeLink.Record().Files {
		if file.Purpose == "owner-only" {
			t.Fatal("spoke source contains home signer")
		}
	}
	grant.Generation = 2
	grant.Regions[0].Generation = 2
	grant.Regions[1].Generation = 2
	intent.SourceRegistration.Generation = 2
	spokeIntent.SourceRegistration.Generation = 2
	publish()
	verified, err = reader.AuthorizedBootstrapMaterial(t.Context(), "GRU")
	if err != nil {
		t.Fatal(err)
	}
	actor = sourceFounderFixture(t, verified, anchor, roots, &objects, protocol, reader, "ocid1.instance.oc1.sa-saopaulo-1.founder")
	restarted, err := ResolveColdStartMaterial(t.Context(), verified, actor, &objects, &management, &bundles, replacement.directory, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ResolveLinkSource(t.Context(), spokeSource, restarted, recoveredLink, &objects, &management, &bundles, filepath.Join(t.TempDir(), "mixed-generation-link"), now); err == nil {
		t.Fatal("Link mixed grant generations")
	}
	if !reflect.DeepEqual(restarted.Record(), replacement.Record()) {
		t.Fatal("grant renewal rotated immutable source")
	}
	if _, err := restarted.Provision(t.Context(), target, &management, &bundles, verified.ExpiresAt()); err == nil {
		t.Fatal("expired grant published material")
	}
	grant.Generation = 3
	intent.Config.ValidityHours = 72
	wire, _ = json.Marshal(intent.Config, json.Deterministic(true))
	intent.PlanSHA256 = digestWire(wire)
	intent.SourceRegistration.PlanSHA256 = intent.PlanSHA256
	publish()
	changed, err := reader.AuthorizedBootstrapMaterial(t.Context(), "GRU")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ResolveColdStartMaterial(t.Context(), changed, actor, &objects, &management, &bundles, filepath.Join(t.TempDir(), "changed"), now); err == nil {
		t.Fatal("same installation changed its signing source")
	}
	grant.Generation = 4
	intent.Config = cfg
	wire, _ = json.Marshal(cfg, json.Deterministic(true))
	intent.PlanSHA256, intent.SourceRegistration = digestWire(wire), nil
	publish()
	wrongPin, err := reader.AuthorizedBootstrapMaterial(t.Context(), "GRU")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ResolveColdStartMaterial(t.Context(), wrongPin, actor, &objects, &management, &bundles, filepath.Join(t.TempDir(), "wrong-pin"), now); err == nil || protocol.creates != 39 {
		t.Fatal("source escrow overrode pinned ledger key")
	}
	grant.Generation = 5
	pinnedLedgerWire = sourcePinnedLedger(t, private, replacement.Record(), now)
	pinnedSlots = []string{"controller-a", "controller-b", "controller-c"}
	publish()
	matchingPin, err := reader.AuthorizedBootstrapMaterial(t.Context(), "GRU")
	if err != nil {
		t.Fatal(err)
	}
	actor = sourceFounderFixture(t, matchingPin, anchor, roots, &objects, protocol, reader, "ocid1.instance.oc1.sa-saopaulo-1.founder")
	pinnedRecovery, err := ResolveColdStartMaterial(t.Context(), matchingPin, actor, &objects, &management, &bundles, filepath.Join(t.TempDir(), "matching-pin"), now)
	if err != nil || !reflect.DeepEqual(pinnedRecovery.Record(), replacement.Record()) || protocol.creates != 39 {
		t.Fatalf("matching pinned source recovery: %v", err)
	}
}
