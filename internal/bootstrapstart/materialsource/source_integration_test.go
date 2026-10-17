//go:build fixturetest

package materialsource

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json/v2"
	"encoding/pem"
	"fmt"
	"maps"
	"net"
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
	"github.com/oracle/oci-go-sdk/v65/objectstorage"
	ocisecrets "github.com/oracle/oci-go-sdk/v65/secrets"
	ocivault "github.com/oracle/oci-go-sdk/v65/vault"
)

func TestColdMaterialHTTPConcurrentBootAndHostLossRecovery(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	now := time.Now().UTC().Truncate(time.Second).Add(-2 * time.Second)
	anchor, _, roots, private, _ := materialSourceAnchor(t)
	target := bootstrapmaterial.VaultTarget{CompartmentOCID: "ocid1.compartment.oc1..control", VaultOCID: "ocid1.vault.oc1.sa-saopaulo-1.vault", KMSKeyOCID: "ocid1.key.oc1.sa-saopaulo-1.head"}
	protocol := &materialProtocol{directory: t.TempDir(), target: target, loseCreate: true, loseSourceCreate: true}
	endpoint := httptest.NewTLSServer(protocol)
	defer endpoint.Close()
	transport := endpoint.Client().Transport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.DialContext = func(context.Context, string, string) (net.Conn, error) {
		return nil, fmt.Errorf("source SDK fixture refuses plaintext transport")
	}
	transport.DialTLSContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil || network != "tcp" || port != "443" || !strings.HasSuffix(host, ".oraclecloud.com") {
			return nil, fmt.Errorf("unexpected SDK TLS endpoint %s", address)
		}
		return (&tls.Dialer{Config: transport.TLSClientConfig}).DialContext(ctx, network, endpoint.Listener.Addr().String())
	}
	originalTransport := http.DefaultTransport
	http.DefaultTransport = transport
	t.Cleanup(func() { http.DefaultTransport = originalTransport; transport.CloseIdleConnections() })
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
		for index := range grant.Regions {
			grant.Regions[index].Generation = grant.Generation
			if material := grant.Regions[index].BootstrapMaterial; material != nil && material.SourceRegistration != nil {
				material.SourceRegistration.Generation = grant.Generation
			}
		}
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
		if err := protocol.put("/n/namespace-a/b/gru-1-head/o/orchestrator/foundation/v1/anchor.json", rootWire); err != nil {
			t.Fatal(err)
		}
		if err := protocol.put("/n/namespace-a/b/gru-1-head/o/orchestrator/foundation/v1/root-chain.json", chainWire); err != nil {
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
	grant.Regions[0].BootstrapMaterial = intent
	grant.Regions[1].BootstrapMaterial = spokeIntent
	for index, material := range []*region.BootstrapMaterialIntent{intent, spokeIntent} {
		ids := grant.Regions[index].Plan["resource_ids"].(map[string]any)
		ids["subnet"], ids["network_security_group"] = "ocid1.subnet.oc1."+material.Config.Region+".test", "ocid1.networksecuritygroup.oc1."+material.Config.Region+".test"
		startup, _ := sourceImageRecipe(t, private, roots, now, material.Config, ids, anchor.Anchor().InitialRegionIntentWire)
		material.Startup = &startup
	}
	publish()
	pinnedOnly, err := reader.AuthorizedBootstrapMaterial(t.Context(), "GRU")
	if err != nil {
		t.Fatal(err)
	}
	pinnedActor := sourceFounderFixture(t, pinnedOnly, anchor, roots, &objects, protocol, reader, "ocid1.instance.oc1.sa-saopaulo-1.founder")
	if _, err := ResolveColdStartMaterial(t.Context(), region.VerifiedBootstrapMaterial{}, pinnedActor, &objects, &management, &bundles, filepath.Join(t.TempDir(), "source"), now); err == nil {
		t.Fatal("empty grant minted source")
	}
	if _, err := ResolveColdStartMaterial(t.Context(), pinnedOnly, pinnedActor, &objects, &management, &bundles, filepath.Join(t.TempDir(), "missing-pinned-source"), now); err == nil || protocol.creates != 0 {
		t.Fatal("existing pinned identity minted replacement source")
	}
	for _, material := range []*region.BootstrapMaterialIntent{intent, spokeIntent} {
		startup := *material.Startup
		material.SourceRegistration = &bootstrap.InitialSourceRegistration{InstallationID: material.InstallationID, DeploymentID: material.Config.DeploymentID, Environment: material.Config.Environment, ClusterID: material.Config.ClusterID, Cell: oci.Region(strings.ToUpper(material.Config.Cell)), Generation: 1, PlanSHA256: material.PlanSHA256, SeedSlot: startup.SeedSlot, ControllerSlots: []string{"controller-a", "controller-b", "controller-c"}, StorageDomain: anchor.StorageDomain(), LedgerRecordDomains: bootstrap.BootstrapLedgerCapabilityDomains()}
		if material.Config.Cell == "sfo" {
			material.SourceRegistration.StorageDomain = bootstrap.StorageDomain{Namespace: "namespace-sfo", LedgerBucket: "sfo-ledger", HeadBucket: "sfo-1-head", LedgerKMSKeyOCID: "ocid1.key.oc1.us-sanjose-1.ledger", HeadKMSKeyOCID: "ocid1.key.oc1.us-sanjose-1.head", Prefix: "regional/sfo"}
		}
	}
	// The genuine pinned founder already adopted the original generation.
	grant.Generation = 2
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
	spokeAnchor := assertHomeStartupPublicProof(t, replacement, projection, anchor, roots, private, protocol, now)
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
	homeTemplate, err := bootstrap.VerifyStartupTemplate(projection.Grant().FoundationGrantWire(), roots, anchor, now)
	if err != nil {
		t.Fatal(err)
	}
	homePublic, err := bootstrap.LoadRegionalSource(t.Context(), homeTemplate, &objects, now)
	if err != nil {
		t.Fatal(err)
	}
	homeLinkProof, err := recoveredLink.StartupLink(t.Context(), homeTemplate, now)
	if err != nil {
		t.Fatal(err)
	}
	linkDeadline := linkRecord.ExpiresAt
	for _, deadline := range []time.Time{homeTemplate.ExpiresAt(), homePublic.ExpiresAt()} {
		if deadline.Before(linkDeadline) {
			linkDeadline = deadline
		}
	}
	if !homeLinkProof.ExpiresAt().Equal(linkDeadline) {
		t.Fatal("public Link proof did not retain its original shortest lifetime")
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
	// Regional ledger storage deliberately differs from the foundation source
	// bucket; the public proof must read home while preserving SFO ledger pins.
	protocol.target = bootstrapmaterial.VaultTarget{CompartmentOCID: "ocid1.compartment.oc1..sfocontrol", VaultOCID: "ocid1.vault.oc1.us-sanjose-1.vault", KMSKeyOCID: "ocid1.key.oc1.us-sanjose-1.key"}
	if _, err := spokeSource.Provision(t.Context(), protocol.target, &management, &bundles, now); err != nil {
		t.Fatal(err)
	}
	spokeMaterial, err := spokeSource.InstallMaterial(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	spokeTemplate, err := bootstrap.VerifyStartupTemplate(spokeGrant.FoundationGrantWire(), roots, spokeAnchor, now)
	if err != nil {
		t.Fatal(err)
	}
	startup, err := NewStartupProjection(spokeTemplate, spokeMaterial, "controller-a")
	if err != nil {
		t.Fatal(err)
	}
	configs := map[string][]byte{}
	for _, slot := range spokeAnchor.Anchor().ControllerSlots {
		configs[slot], err = json.Marshal(map[string]any{"nats": map[string]any{}, "controller": map[string]string{"cell": "sfo", "slot": slot}})
		if err != nil {
			t.Fatal(err)
		}
	}
	bound, err := startup.BindConfigs(t.Context(), configs)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := bootstrap.LoadDerivedStartupAuthority(t.Context(), spokeTemplate, &objects, "controller-a", now)
	if err != nil || loaded.Digest() != bound.Digest() || loaded.StorageDomain() != spokeAnchor.StorageDomain() || !strings.HasPrefix(spokeSource.key, "private/bootstrap/") || strings.HasPrefix(spokeSource.key, "regional/sfo/") {
		t.Fatalf("independent home source and regional ledger domains: %v", err)
	}
	grant.Generation = 3
	grant.Regions[0].Generation = 3
	grant.Regions[1].Generation = 3
	intent.SourceRegistration.Generation = 3
	spokeIntent.SourceRegistration.Generation = 3
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
	grant.Generation = 4
	intent.Config.ValidityHours = 72
	wire, _ = json.Marshal(intent.Config, json.Deterministic(true))
	intent.PlanSHA256 = digestWire(wire)
	intent.SourceRegistration.PlanSHA256 = intent.PlanSHA256
	publish()
	changed, err := reader.AuthorizedBootstrapMaterial(t.Context(), "GRU")
	if err != nil {
		t.Fatal(err)
	}
	actor = sourceFounderFixture(t, changed, anchor, roots, &objects, protocol, reader, "ocid1.instance.oc1.sa-saopaulo-1.founder")
	if _, err := ResolveColdStartMaterial(t.Context(), changed, actor, &objects, &management, &bundles, filepath.Join(t.TempDir(), "changed"), now); err == nil {
		t.Fatal("same installation changed its signing source")
	}
	grant.Generation = 5
	intent.Config = cfg
	wire, _ = json.Marshal(cfg, json.Deterministic(true))
	intent.PlanSHA256, intent.SourceRegistration = digestWire(wire), nil
	publish()
	wrongPin, err := reader.AuthorizedBootstrapMaterial(t.Context(), "GRU")
	if err != nil {
		t.Fatal(err)
	}
	actor = sourceFounderFixture(t, wrongPin, anchor, roots, &objects, protocol, reader, "ocid1.instance.oc1.sa-saopaulo-1.founder")
	if _, err := ResolveColdStartMaterial(t.Context(), wrongPin, actor, &objects, &management, &bundles, filepath.Join(t.TempDir(), "wrong-pin"), now); err == nil || protocol.creates != 39 {
		t.Fatal("source escrow overrode pinned ledger key")
	}
	grant.Generation = 6
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
