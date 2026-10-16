//go:build fixturetest

package materialsource

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json/v2"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapmaterial"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/region"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/nats-io/jwt/v2"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"
	ocisecrets "github.com/oracle/oci-go-sdk/v65/secrets"
	ocivault "github.com/oracle/oci-go-sdk/v65/vault"
)

// This public-proof fixture assumes the protected source-CAS origin invariant.
// Actual OCI installer/founder provenance is exercised by the source actor suite.
func TestPublicLinkDeliveryRestoresOnlyRegionalLeaves(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second).Add(-2 * time.Second)
	anchor, _, roots, root, _ := materialSourceAnchor(t)
	target := bootstrapmaterial.VaultTarget{CompartmentOCID: "ocid1.compartment.oc1..control", VaultOCID: "ocid1.vault.oc1.sa-saopaulo-1.vault", KMSKeyOCID: "ocid1.key.oc1.sa-saopaulo-1.head"}
	homeProtocol := &materialProtocol{directory: t.TempDir(), target: target}
	objects, homeManagement, homeBundles := publicLinkSDK(t, homeProtocol, "sa-saopaulo-1")
	spokeTarget := bootstrapmaterial.VaultTarget{CompartmentOCID: "ocid1.compartment.oc1..sfocontrol", VaultOCID: "ocid1.vault.oc1.us-sanjose-1.vault", KMSKeyOCID: "ocid1.key.oc1.us-sanjose-1.key"}
	spokeProtocol := &materialProtocol{directory: t.TempDir(), target: spokeTarget}
	_, spokeManagement, spokeBundles := publicLinkSDK(t, spokeProtocol, "us-sanjose-1")
	cfg := bootstrapmaterial.Config{Environment: "production", Region: "sa-saopaulo-1", Cell: "gru", DeploymentID: anchor.Anchor().DeploymentID, ClusterID: anchor.Anchor().ClusterID, SubnetCIDR: "10.251.0.0/24", ValidityHours: 48, Slots: []bootstrapmaterial.Slot{{Name: "controller-a", PrivateIP: "10.251.0.11"}, {Name: "controller-b", PrivateIP: "10.251.0.12"}, {Name: "controller-c", PrivateIP: "10.251.0.13"}}}
	configs := []bootstrapmaterial.Config{cfg, cfg}
	configs[1].Cell, configs[1].Region, configs[1].ClusterID = "sfo", "us-sanjose-1", "0000000000F9PR1WNVDTEXS31Z"
	intentWire, err := trust.EncodePayload(oci.RegionIntent{SchemaVersion: 1, Generation: 4, BootstrapRegion: oci.RegionGRU, Regions: []oci.RegionMapping{{Cell: oci.RegionGRU, OCIRegion: "sa-saopaulo-1"}, {Cell: oci.RegionSFO, OCIRegion: "us-sanjose-1"}}})
	if err != nil {
		t.Fatal(err)
	}
	grant := region.FoundationGrant{InstallationID: "0000000000YTR4D9RJ6W8NG1HC", SchemaVersion: 1, Generation: 1, TenancyID: "ocid1.tenancy.oc1..test", ParentCompartmentID: "ocid1.compartment.oc1..parent", SharedCompartmentID: "ocid1.compartment.oc1..shared", Currency: "USD", MonthlyLimitMinor: 10000, CleanupOwner: "integration"}
	for index, config := range configs {
		wire, _ := json.Marshal(config, json.Deterministic(true))
		vault := target
		if index == 1 {
			vault = spokeTarget
		}
		ids := map[string]any{"control_compartment": vault.CompartmentOCID, "vault": vault.VaultOCID, "key": vault.KMSKeyOCID, "subnet": "ocid1.subnet.oc1." + config.Region + ".test", "network_security_group": "ocid1.networksecuritygroup.oc1." + config.Region + ".test"}
		startup, _ := sourceImageRecipe(t, root, roots, now, config, ids, intentWire)
		registration := bootstrap.InitialSourceRegistration{InstallationID: grant.InstallationID, DeploymentID: config.DeploymentID, Environment: config.Environment, ClusterID: config.ClusterID, Cell: oci.Region(strings.ToUpper(config.Cell)), Generation: 1, PlanSHA256: digestWire(wire), SeedSlot: startup.SeedSlot, ControllerSlots: []string{"controller-a", "controller-b", "controller-c"}, StorageDomain: anchor.StorageDomain(), LedgerRecordDomains: bootstrap.BootstrapLedgerCapabilityDomains()}
		material := &region.BootstrapMaterialIntent{InstallationID: grant.InstallationID, PlanSHA256: digestWire(wire), Config: config, SourceVaultTarget: target, Startup: &startup, SourceRegistration: &registration}
		grant.Regions = append(grant.Regions, region.FoundationIntent{Generation: 1, Plan: map[string]any{"cell": strings.ToUpper(config.Cell), "region": config.Region, "tenancy_id": grant.TenancyID, "parent_compartment_id": grant.ParentCompartmentID, "shared_compartment_id": grant.SharedCompartmentID, "resource_ids": ids}, BootstrapMaterial: material})
	}
	payload, err := trust.EncodePayload(grant)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := trust.Sign(payload, trust.Scope{Domain: "terrascale.foundation.scope", DeploymentID: cfg.DeploymentID, Cell: "GRU", Environment: cfg.Environment, Role: "foundation", Slot: cfg.ClusterID}, now.Add(-time.Minute), now.Add(30*time.Minute), root)
	if err != nil {
		t.Fatal(err)
	}
	grantWire, err := trust.EncodeEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}
	value := anchor.Anchor()
	value.InitialSourceRegistration = grant.Regions[0].BootstrapMaterial.SourceRegistration
	value.LedgerDelegationWire = nil
	value.ControllerSlots = slices.Clone(value.InitialSourceRegistration.ControllerSlots)
	value.InitialRegionIntentWire = bytes.Clone(intentWire)
	value.InitialRegionIntentSHA256 = digestWire(intentWire)
	value.FoundationScope = &bootstrap.FoundationScope{InstallationID: grant.InstallationID, DeploymentID: cfg.DeploymentID, ClusterID: cfg.ClusterID, TenancyID: grant.TenancyID, OCIRegion: cfg.Region, StorageDomain: anchor.StorageDomain(), GrantGeneration: 1, GrantSHA256: digestWire(grantWire)}
	signed, err := bootstrap.SignBootstrapAnchor(value, now.Add(-time.Minute), now.Add(time.Hour), root)
	if err != nil {
		t.Fatal(err)
	}
	anchor, err = bootstrap.VerifyBootstrapAnchor(signed, roots, bootstrap.BootstrapAnchorExpectation{DeploymentID: cfg.DeploymentID, Environment: cfg.Environment, Cell: oci.RegionGRU}, now, bootstrap.BootstrapAnchorTrustPolicy())
	if err != nil {
		t.Fatal(err)
	}
	templates := make([]bootstrap.VerifiedStartupTemplate, 2)
	sourceDirs := []string{filepath.Join(t.TempDir(), "home-source"), filepath.Join(t.TempDir(), "spoke-source")}
	inventories := make([]bootstrap.VerifiedRegionalSource, 2)
	states := make([]materialSourceState, 2)
	for i, config := range configs {
		templates[i], err = bootstrap.VerifyRegionalStartupTemplate(grantWire, roots, anchor, oci.Region(strings.ToUpper(config.Cell)), now)
		if err != nil {
			t.Fatal(err)
		}
		record, err := bootstrapmaterial.Generate(sourceDirs[i], config, now)
		if err != nil {
			t.Fatal(err)
		}
		metadata, err := os.ReadFile(filepath.Join(sourceDirs[i], "material.json"))
		if err != nil {
			t.Fatal(err)
		}
		actor := bootstrap.SourceInventoryActor{InstanceID: "ocid1.instance.oc1." + config.Region + ".founder", GrantDigest: templates[i].GrantDigest(), TemplateDigest: templates[i].TemplateDigest()}
		inventory := bootstrap.RegionalSourceInventory{SchemaVersion: 1, Actor: actor, GrantSHA256: templates[i].GrantDigest(), PlanSHA256: templates[i].PlanDigest(), SourceSHA256: digestWire([]byte(config.Cell + "-archive")), MaterialRecord: metadata}
		inventoryPayload, err := trust.EncodePayload(inventory)
		if err != nil {
			t.Fatal(err)
		}
		key, err := os.ReadFile(filepath.Join(sourceDirs[i], "founder-ledger.key"))
		if err != nil {
			t.Fatal(err)
		}
		signed, err := trust.Sign(inventoryPayload, bootstrap.RegionalSourceInventoryScope(templates[i]), record.IssuedAt, templates[i].ExpiresAt(), ed25519.PrivateKey(key))
		clear(key)
		if err != nil {
			t.Fatal(err)
		}
		wire, err := trust.EncodeEnvelope(signed)
		if err != nil {
			t.Fatal(err)
		}
		states[i] = materialSourceState{SchemaVersion: 1, Actor: materialSourceActor{InstanceID: actor.InstanceID, GrantDigest: actor.GrantDigest, TemplateDigest: actor.TemplateDigest}, InstallationID: grant.InstallationID, Cell: config.Cell, Generation: 1, PlanSHA256: templates[i].PlanDigest(), Target: target, Reference: materialSourceReference{SecretOCID: "ocid1.vaultsecret.oc1.sa-saopaulo-1.source" + config.Cell, SHA256: inventory.SourceSHA256, MaxBytes: 100}, Inventory: wire}
		publicSourceState(t, homeProtocol, config.Cell, grant.InstallationID, states[i])
		inventories[i], err = bootstrap.LoadRegionalSource(t.Context(), templates[i], objects, now)
		if err != nil {
			t.Fatal(err)
		}
	}
	recipient, err := bootstrap.VerifyLinkRecipient(t.Context(), inventories[1], inventories[0], now)
	if err != nil {
		t.Fatal(err)
	}
	homeLinkDir := filepath.Join(t.TempDir(), "home-link")
	homeClaimWire, err := os.ReadFile(filepath.Join(sourceDirs[0], "cell.jwt"))
	if err != nil {
		t.Fatal(err)
	}
	homeClaim, err := jwt.DecodeAccountClaims(strings.TrimSpace(string(homeClaimWire)))
	if err != nil {
		t.Fatal(err)
	}
	if delay := time.Until(time.Unix(homeClaim.IssuedAt+1, 0)); delay > 0 {
		if delay > 1200*time.Millisecond {
			t.Fatal("home cell claim issuance exceeds the fixture clock")
		}
		timer := time.NewTimer(delay)
		defer timer.Stop()
		select {
		case <-t.Context().Done():
			t.Fatal(t.Context().Err())
		case <-timer.C:
		}
	}
	if _, err := bootstrapmaterial.GenerateLink(sourceDirs[0], sourceDirs[0], homeLinkDir, homeLinkDir, now); err != nil {
		t.Fatal(err)
	}
	homePublication, err := bootstrapmaterial.ProvisionLink(t.Context(), homeLinkDir, target, homeManagement, homeBundles, now)
	if err != nil {
		t.Fatal(err)
	}
	homeMetadata, _ := os.ReadFile(filepath.Join(homeLinkDir, "material.json"))
	homeJournal, _ := os.ReadFile(filepath.Join(homeLinkDir, "publication.json"))
	homeBindingWire, _ := json.Marshal([]string{"link", digestWire(inventories[0].MaterialRecord()), digestWire(inventories[0].MaterialRecord()), ""}, json.Deterministic(true))
	homeBinding := digestWire(homeBindingWire)
	homeKey := "private/bootstrap/bootstrap/v2/material-source/link-" + digestWire([]byte(grant.InstallationID+"\x00gru\x00link\x00"+homeBinding)) + ".json"
	homeState := materialSourceState{SchemaVersion: 1, Actor: states[0].Actor, Kind: "link", BindingSHA256: homeBinding, InstallationID: grant.InstallationID, Cell: "gru", Generation: 1, PlanSHA256: templates[0].PlanDigest(), Target: target, Reference: materialSourceReference{SecretOCID: "ocid1.vaultsecret.oc1.sa-saopaulo-1.homelink", SHA256: digestWire([]byte("home-link-archive")), MaxBytes: 100}, Journal: homeJournal}
	publicLinkState(t, homeProtocol, homeKey, homeState)
	homeEvidence := bootstrap.RegionalLinkEvidence{Actor: inventories[0].OriginalActor(), SourceObjectKey: homeKey, SourceSHA256: homeState.Reference.SHA256, MaterialRecord: homeMetadata, Journal: homeJournal, References: homePublication.LinkGenerationReferences()}
	if _, err := bootstrap.VerifyStartupLink(t.Context(), templates[0], objects, homeEvidence, now); err != nil {
		t.Fatal("home public proof:", err)
	}
	spokeLinkDir := filepath.Join(t.TempDir(), "issued-spoke-link")
	spokeRecord, err := bootstrapmaterial.Load(sourceDirs[1])
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bootstrapmaterial.GenerateSpokeLink(sourceDirs[0], homeLinkDir, spokeRecord, recipient.SourceSHA256(), spokeLinkDir, now); err != nil {
		t.Fatal(err)
	}
	publication, err := bootstrapmaterial.ProvisionLink(t.Context(), spokeLinkDir, spokeTarget, spokeManagement, spokeBundles, now)
	if err != nil {
		t.Fatal(err)
	}
	metadata, _ := os.ReadFile(filepath.Join(spokeLinkDir, "material.json"))
	journal, _ := os.ReadFile(filepath.Join(spokeLinkDir, "publication.json"))
	state := materialSourceState{SchemaVersion: 1, Actor: states[0].Actor, Kind: "spoke-link-v1", BindingSHA256: recipient.BindingSHA256(), InstallationID: grant.InstallationID, Cell: "sfo", Generation: 1, PlanSHA256: templates[1].PlanDigest(), Target: target, Reference: materialSourceReference{SecretOCID: "ocid1.vaultsecret.oc1.sa-saopaulo-1.spokelink", SHA256: digestWire([]byte("spoke-link-archive")), MaxBytes: 100}, Journal: journal}
	evidence := bootstrap.RegionalLinkEvidence{Actor: inventories[0].OriginalActor(), SourceObjectKey: recipient.LinkObjectKey(), SourceSHA256: state.Reference.SHA256, MaterialRecord: metadata, Journal: journal, References: publication.LinkGenerationReferences()}
	deliveryPayload, _ := bootstrap.LinkDeliveryPayload(evidence)
	key, _ := os.ReadFile(filepath.Join(sourceDirs[0], "founder-ledger.key"))
	state.Delivery, err = bootstrap.SignLinkDelivery(recipient, deliveryPayload, ed25519.PrivateKey(key), now, recipient.ExpiresAt())
	clear(key)
	if err != nil {
		t.Fatal(err)
	}
	evidence.Delivery = bytes.Clone(state.Delivery)
	publicLinkState(t, homeProtocol, recipient.LinkObjectKey(), state)
	proof, err := bootstrap.VerifyStartupLink(t.Context(), templates[1], objects, evidence, now)
	if err != nil {
		t.Fatal("spoke public proof:", err)
	}
	for _, directory := range append(sourceDirs, homeLinkDir, spokeLinkDir) {
		if err := os.RemoveAll(directory); err != nil {
			t.Fatal(err)
		}
	}
	var record bootstrapmaterial.LinkRecord
	if err := json.Unmarshal(metadata, &record); err != nil {
		t.Fatal(err)
	}
	recovered := filepath.Join(t.TempDir(), "recovered")
	if err := restoreRegionalLink(t.Context(), proof, publication, spokeBundles, recovered, now); err != nil {
		t.Fatal(err)
	}
	if err := restoreRegionalLink(t.Context(), proof, publication, spokeBundles, recovered, now); err != nil {
		t.Fatal("exact retry:", err)
	}
	if _, err := bootstrapmaterial.LoadLink(recovered, now); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"issuer-link.seed", "issuer-ca.key", "founder-ledger.key"} {
		if _, err := os.Stat(filepath.Join(recovered, name)); !os.IsNotExist(err) {
			t.Fatal("private home material reached recipient:", name)
		}
	}
	tampered := proof.Evidence()
	tampered.References[0].SecretOCID = "ocid1.vaultsecret.oc1.us-sanjose-1.other"
	if _, err := bootstrap.VerifyStartupLink(t.Context(), templates[1], objects, tampered, now); err == nil {
		t.Fatal("tampered delivery references accepted")
	}
	for _, mutation := range []struct {
		name   string
		change func(*materialSourceState)
	}{
		{"missing original actor", func(state *materialSourceState) { state.Actor = materialSourceActor{} }},
		{"substituted original actor", func(state *materialSourceState) { state.Actor.InstanceID = "ocid1.instance.oc1.us-sanjose-1.other" }},
		{"substituted archive", func(state *materialSourceState) { state.Reference.SHA256 = digestWire([]byte("other archive")) }},
		{"wrong escrow", func(state *materialSourceState) { state.Target = spokeTarget }},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			changed := states[1]
			mutation.change(&changed)
			publicSourceState(t, homeProtocol, "sfo", grant.InstallationID, changed)
			defer publicSourceState(t, homeProtocol, "sfo", grant.InstallationID, states[1])
			if _, err := bootstrap.LoadRegionalSource(t.Context(), templates[1], objects, now); err == nil {
				t.Fatal("altered source identity admitted")
			}
		})
	}
	states[1].Inventory[0] ^= 1
	publicSourceState(t, homeProtocol, "sfo", grant.InstallationID, states[1])
	if err := proof.VerifyCurrent(t.Context(), now); err == nil {
		t.Fatal("revoked recipient inventory remained current")
	}
	if err := restoreRegionalLink(t.Context(), proof, publication, spokeBundles, filepath.Join(t.TempDir(), "revoked"), now); err == nil {
		t.Fatal("revoked recipient inventory restored files")
	}
}

func publicSourceState(t *testing.T, protocol *materialProtocol, cell, installation string, state materialSourceState) {
	t.Helper()
	key := "private/bootstrap/bootstrap/v2/material-source/" + digestWire([]byte(installation+"\x00"+cell)) + ".json"
	publicLinkState(t, protocol, key, state)
}
func publicLinkState(t *testing.T, protocol *materialProtocol, key string, state materialSourceState) {
	t.Helper()
	wire, err := json.Marshal(state, json.Deterministic(true))
	if err != nil {
		t.Fatal(err)
	}
	protocol.mu.Lock()
	defer protocol.mu.Unlock()
	if err := protocol.put("/n/namespace-a/b/gru-1-head/o/"+key, wire); err != nil {
		t.Fatal(err)
	}
}

func publicLinkSDK(t *testing.T, protocol *materialProtocol, ociRegion string) (*objectstorage.ObjectStorageClient, *ocivault.VaultsClient, *ocisecrets.SecretsClient) {
	t.Helper()
	endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		request := r.Clone(r.Context())
		request.URL = r.URL.Clone()
		request.URL.Path = strings.ReplaceAll(request.URL.Path, "ocid1.vaultsecret.oc1."+ociRegion+".", "ocid1.vaultsecret.oc1.sa-saopaulo-1.")
		recorder := httptest.NewRecorder()
		protocol.ServeHTTP(recorder, request)
		for name, values := range recorder.Header() {
			w.Header()[name] = slices.Clone(values)
		}
		w.WriteHeader(recorder.Code)
		w.Write(bytes.ReplaceAll(recorder.Body.Bytes(), []byte("ocid1.vaultsecret.oc1.sa-saopaulo-1."), []byte("ocid1.vaultsecret.oc1."+ociRegion+".")))
	}))
	t.Cleanup(endpoint.Close)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	provider := common.NewRawConfigurationProvider("ocid1.tenancy.oc1..test", "ocid1.user.oc1..test", ociRegion, "test", string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})), nil)
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
	return &objects, &management, &bundles
}
