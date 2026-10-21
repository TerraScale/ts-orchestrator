package region

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/v2"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapmaterial"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/releasechannel"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/oracle/oci-go-sdk/v65/common"
)

type foundationProvisionFixture struct {
	approval   FoundationPreparationInput
	prepared   FoundationPreparation
	bundle     RetainedFoundation
	roots      trust.Keyring
	root       ed25519.PrivateKey
	now        time.Time
	images     map[string]releasechannel.CurrentImage
	cloud      *provisionCloud
	provider   *provisionProvider
	factoryFor func() *ociclient.Factory
}

func newFoundationProvisionFixture(t *testing.T) foundationProvisionFixture {
	t.Helper()
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv(common.UsingExpectHeaderEnvVar, "false")
	now := time.Now().UTC().Truncate(time.Second)
	rootPublic, root, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	roots, err := trust.ParseKeyring(rootPublic)
	if err != nil {
		t.Fatal(err)
	}
	leafPublic, leaf, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	host := FoundationHostApproval{OCPUs: 1, MemoryGB: 6, BootGB: 50, MonthlyLimitMinor: 1000}
	signers, err := protocol.EncodeJSON([]map[string]any{{"actor": "scenario", "public_key": base64.StdEncoding.EncodeToString(leafPublic), "roles": []string{"terrabase"}, "environments": []string{"production"}}})
	if err != nil {
		t.Fatal(err)
	}
	approval := FoundationPreparationInput{TenancyID: "ocid1.tenancy.oc1..test", ParentCompartmentID: "ocid1.compartment.oc1..parent", SharedCompartmentID: "ocid1.compartment.oc1..shared", Currency: "USD", MonthlyLimitMinor: 12000, InfrastructureMonthlyLimitMinor: 10000, BootstrapReservedMinor: 4000, CleanupOwner: "scenario",
		HomeStorageDomain: bootstrap.StorageDomain{Namespace: "ns", HeadBucket: foundationDiscoveryBucket, LedgerBucket: "gru-1-ledger", HeadKMSKeyOCID: "ocid1.key.oc1.sa-saopaulo-1.head", LedgerKMSKeyOCID: "ocid1.key.oc1.sa-saopaulo-1.ledger", Prefix: "bootstrap"},
		SourceVaultTarget: bootstrapmaterial.VaultTarget{CompartmentOCID: "ocid1.compartment.oc1..control", VaultOCID: "ocid1.vault.oc1.sa-saopaulo-1.home", KMSKeyOCID: "ocid1.key.oc1.sa-saopaulo-1.head"}, TrustedSigners: signers, GRUController: host, SFOController: host, FRAController: host, NetBirdManager: host}
	approval.ReleaseAuthorities = provisionReleaseAuthorities(t, root, leafPublic, approval.HomeStorageDomain, now)
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rawProvider := common.NewRawConfigurationProvider(approval.TenancyID, "ocid1.user.oc1..test", foundationHomeRegion, "test", string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rsaKey)})), nil)
	provider := &provisionProvider{ConfigurationProvider: rawProvider}
	historicalAuthorities := approval.ReleaseAuthorities
	approval.ReleaseAuthorities = slices.Clone(historicalAuthorities)
	for index := range approval.ReleaseAuthorities {
		approval.ReleaseAuthorities[index].SequenceMigrationWire = nil
	}
	cloud := &provisionCloud{test: t, directory: t.TempDir(), rows: map[string]map[string]any{}, collections: map[string]string{}, tokens: map[string]string{}, rules: map[string][]any{}, retention: map[string][]any{}, launches: map[string]string{}, tariff: 0.0001, lostLaunch: true, lostPolicy: true, lostMaterialIndex: -1, materialRoot: bytes.Repeat([]byte{'Q'}, 64)}
	images := map[string]releasechannel.CurrentImage{}
	for _, role := range []string{"GRU", "SFO", "FRA", "netbird-manager"} {
		cell := role
		if role == "netbird-manager" {
			cell = "GRU"
		}
		wire, delegation, evidence := provisionImage(t, root, leaf, roots, cell, role, now)
		for digest, body := range evidence {
			cloud.writeObject("gru-1-head/"+releasechannel.ImageProductionEvidenceObject(digest), body)
		}
		expected := release.ImageExpectation{Environment: "production", LogicalRegion: cell, Architecture: "arm64", OCIImageOCID: "ocid1.image.oc1." + catalog.OCIRegion(cell) + ".qualified"}
		var image release.VerifiedImage
		if role == "netbird-manager" {
			image, err = release.VerifyNetBirdImageCurrent(wire, delegation, roots, expected, now)
		} else {
			image, err = release.VerifyImageCurrent(wire, delegation, roots, expected, now)
		}
		if err != nil {
			t.Fatal(err)
		}
		current := releasechannel.CurrentImage{Image: image, ExpiresAt: image.ExpiresAt(), ReceiptWire: wire, DelegationWire: delegation}
		if role == "netbird-manager" {
			proof := image.Receipt().HostProduction[role]
			current.QualificationWire, current.QualificationDelegationWire = proof.Qualification, proof.Delegation
		}
		images[role] = current
		imageID := image.Receipt().OCIImageOCID
		cloud.rows[imageID] = map[string]any{"id": imageID, "compartmentId": "ocid1.compartment.oc1..sharedimages" + strings.ToLower(cell), "lifecycleState": "AVAILABLE"}
		cloud.collections[imageID] = "images"
	}
	server := httptest.NewTLSServer(http.HandlerFunc(cloud.serveHTTP))
	t.Cleanup(server.Close)
	listener, ok := server.Listener.Addr().(*net.TCPAddr)
	if !ok || !listener.IP.IsLoopback() || listener.Port == 0 {
		t.Fatal("provision fixture requires literal loopback listener")
	}
	original := http.DefaultTransport
	transport := original.(*http.Transport).Clone()
	transport.Proxy = func(request *http.Request) (*url.URL, error) {
		if request.URL == nil || request.URL.Scheme != "https" || request.URL.User != nil || request.URL.Opaque != "" || request.Response != nil || request.Method == http.MethodConnect {
			return nil, fmt.Errorf("fixture refuses noninitial HTTPS request")
		}
		return nil, nil
	}
	transport.DialContext = func(context.Context, string, string) (net.Conn, error) {
		return nil, fmt.Errorf("fixture refuses plaintext dialing")
	}
	transport.DialTLSContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		if network != "tcp" && network != "tcp4" && network != "tcp6" {
			return nil, fmt.Errorf("fixture refuses network %q", network)
		}
		return (&tls.Dialer{Config: server.Client().Transport.(*http.Transport).TLSClientConfig}).DialContext(ctx, "tcp", listener.String())
	}
	http.DefaultTransport = transport
	t.Cleanup(func() { http.DefaultTransport = original; transport.CloseIdleConnections() })
	factoryFor := func() *ociclient.Factory {
		limits := map[ociclient.Service]ociclient.Limit{}
		for service := range ociclient.DefaultLimits {
			limits[service] = ociclient.Limit{PerSecond: 100000, Burst: 100000}
		}
		factory, err := ociclient.New(provider, ociclient.Options{Region: foundationHomeRegion, Limits: limits, Retry: ociclient.RetryOptions{MaxAttempts: 1}})
		if err != nil {
			t.Fatal(err)
		}
		return factory
	}
	componentObjects, err := factoryFor().ObjectStorage()
	if err != nil {
		t.Fatal(err)
	}
	components := netBirdComponentFixtures(t, root, roots, approval.HomeStorageDomain, &componentObjects, now,
		func(value any, scope trust.Scope, signer ed25519.PrivateKey) []byte {
			t.Helper()
			payload, err := trust.EncodePayload(value)
			if err != nil {
				t.Fatal(err)
			}
			envelope, err := trust.Sign(payload, scope, now.Add(-time.Minute), now.Add(30*24*time.Hour), signer)
			if err != nil {
				t.Fatal(err)
			}
			return provisionEnvelope(t, envelope)
		}, func(name string, wire []byte) { cloud.writeObject("gru-1-head/"+name, wire) })
	for index, component := range components {
		approval.NetBirdComponents[index] = component.authority
	}
	cloud.seedPrerequisites(approval)
	preparationRequests := cloud.requests
	prepared, err := PrepareFoundationGrant(t.Context(), approval, images, func(_ context.Context, _ string, region string) (Live, error) {
		entry, _ := catalog.CellForOCIRegion(region)
		serviceID := "ocid1.service.oc1." + region + ".services"
		serviceCIDR := "all-" + strings.ToLower(entry.OCIRegionKey) + "-services-in-oracle-services-network"
		cloud.rows[serviceID] = map[string]any{"id": serviceID, "name": "All " + entry.OCIRegionKey + " Services In Oracle Services Network", "cidrBlock": serviceCIDR}
		cloud.collections[serviceID] = "services"
		return Live{AvailabilityDomain: "scenario:AD-1", ServiceID: serviceID, ServiceCIDR: serviceCIDR}, nil
	}, factoryFor())
	if err != nil {
		t.Fatal(err)
	}
	if cloud.requests-preparationRequests != 5 || len(cloud.imageReads) != 3 || cloud.creates != 0 || cloud.launchPosts != 0 || cloud.materialPosts != 0 || cloud.hasAnchor() {
		t.Fatal("preparation did not remain three image reads and two locked retention reads without effects or anchor discovery")
	}
	for index, regional := range prepared.Grant.Regions {
		cell := regional.Plan["cell"].(string)
		image := images[cell]
		imageID := image.Image.Receipt().OCIImageOCID
		expectedRead := "iaas." + catalog.OCIRegion(cell) + ".oraclecloud.com /20160918/images/" + imageID
		startup := regional.BootstrapMaterial.Startup
		control, err := preparationResource(regional.Plan, cell, "control_compartment")
		compartment := cloud.rows[imageID]["compartmentId"].(string)
		if err != nil || cloud.imageReads[index] != expectedRead || compartment == control || startup.ImageOCID != imageID ||
			!bytes.Equal(startup.ReleaseImageReceiptWire, image.ReceiptWire) || !bytes.Equal(startup.ReleaseDelegationWire, image.DelegationWire) || len(startup.FounderResources.Slots) != 3 {
			t.Fatalf("%s preparation lost exact regional image observation or independent qualification", cell)
		}
		for slot, resource := range startup.FounderResources.Slots {
			if resource.ImageCompartmentOCID != compartment || startup.Profiles[slot].CompartmentOCID != control {
				t.Fatalf("%s image compartment was substituted with its launch control compartment", cell)
			}
		}
		var fleet oci.RegionConfig
		if err := json.Unmarshal(startup.ControllerFiles[1].Bytes, &fleet); err != nil || fleet.ImageID != imageID || fleet.ImageCompartmentID != compartment || fleet.CompartmentID != control {
			t.Fatalf("%s generated fleet lost actual image compartment: %v", cell, err)
		}
		for _, file := range startup.ControllerFiles {
			if preparationDigest(file.Bytes) != file.SHA256 {
				t.Fatalf("%s image observation followed controller file hashing", cell)
			}
		}
		recipe, err := ControllerBootstrapRecipeDigest(*startup)
		if err != nil || prepared.Grant.InfrastructureSpend.Bootstrap.Slots[index].RecipeSHA256 != recipe {
			t.Fatalf("%s image observation followed bootstrap recipe hashing: %v", cell, err)
		}
	}
	// The preparation helper leaves worker policy to its caller; the SDK
	// producer normally fills this same finite policy before offline signing.
	for _, region := range prepared.Grant.Regions {
		cell, _ := region.Plan["cell"].(string)
		bucket, err := releasechannel.BucketName(cell)
		if err != nil {
			t.Fatal(err)
		}
		ref := func(key string) string {
			value, err := FoundationResourceReference(cell, key)
			if err != nil {
				t.Fatal(err)
			}
			return value
		}
		for _, role := range []string{"container", "wasm"} {
			for _, architecture := range []string{"arm64", "amd64"} {
				shape := "VM.Standard.A1.Flex"
				if architecture == "amd64" {
					shape = "VM.Standard.E4.Flex"
				}
				prepared.Grant.WorkerProfiles = append(prepared.Grant.WorkerProfiles, WorkerProfile{Cell: cell, Environment: "production", Role: role, Architecture: architecture, Shape: shape, OCPUs: 2, MemoryGB: 12, BootGB: 50, AvailabilityDomains: []string{"scenario:AD-1"}, CompartmentRef: ref("workload_compartment"), SubnetRef: ref("subnet"), NSGRef: ref("workload_network_security_group"), Runtime: release.ProductionRuntime,
					ImageSource: WorkerImageSource{OCIRegion: catalog.OCIRegion(cell), Namespace: approval.HomeStorageDomain.Namespace, Bucket: bucket, CurrentObject: releasechannel.CurrentImageObject(role, architecture, "production"), ImageDomain: release.ImageDomain, QualificationDomain: release.ProductionQualificationDomain}, Bootstrap: WorkerBootstrapTemplate{Derivation: WorkerBootstrapDerivationV1, MaterialPlanSHA256: region.BootstrapMaterial.PlanSHA256, VaultRef: ref("vault"), KMSKeyRef: ref("key"), RecipientPermission: "SECRET_BUNDLE_READ"}})
			}
		}
	}
	chain, err := trust.EncodeRootChain(trust.RootChain{Version: 1})
	if err != nil {
		t.Fatal(err)
	}
	originPreparation := prepared
	// Preserve the original signed migration scenario as historical schema2.
	prepared.Grant.SchemaVersion = 2
	prepared.Grant.OriginalActorAdmissionReads = nil
	prepared.Grant.OriginalPublication = nil
	prepared.Grant.OriginalMaterialPublicationIAM = nil
	prepared.Grant.WorkloadGenesis = nil
	prepared.Grant.ReleaseAuthorities = historicalAuthorities
	prepared.Grant.Regions = slices.Clone(prepared.Grant.Regions)
	for index := range prepared.Grant.Regions {
		material := *prepared.Grant.Regions[index].BootstrapMaterial
		material.AdmissionAttestor = nil
		material.OriginalSourceProducer = nil
		material.OriginalStartupAdmission = nil
		prepared.Grant.Regions[index].BootstrapMaterial = &material
		if manager := prepared.Grant.Regions[index].NetBirdManager; manager != nil {
			legacy := *manager
			legacy.Material = nil
			legacy.Components = nil
			legacy.Account = nil
			legacy.Backup = nil
			prepared.Grant.Regions[index].NetBirdManager = &legacy
		}
	}
	spend := *prepared.Grant.InfrastructureSpend
	allocation := *spend.Bootstrap
	allocation.Slots = slices.Clone(allocation.Slots)
	spend.Bootstrap = &allocation
	prepared.Grant.InfrastructureSpend = &spend
	for index := range allocation.Slots {
		if allocation.Slots[index].Role == NetBirdManagerRole {
			manager := prepared.Grant.Regions[0].NetBirdManager
			allocation.Slots[index].RecipeSHA256, err = NetBirdManagerRecipeDigest(*manager, images["netbird-manager"].Image.Receipt().ImageSHA256)
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	bundle := signProvisionFoundation(t, prepared, chain, root, now)
	if err := VerifyFoundationProvisionBundle(t.Context(), roots, bundle); err != nil {
		t.Fatal(err)
	}
	cloud.bundle = bundle.clone()
	return foundationProvisionFixture{approval: approval, prepared: originPreparation, bundle: bundle, roots: roots, root: root, now: now, images: images, cloud: cloud, provider: provider, factoryFor: factoryFor}
}

func signProvisionFoundation(t *testing.T, prepared FoundationPreparation, chain []byte, root ed25519.PrivateKey, now time.Time) RetainedFoundation {
	t.Helper()
	home := *prepared.Anchor.FoundationScope
	prepared.Anchor.FoundationScope = &home
	grantPayload, err := trust.EncodePayload(prepared.Grant)
	if err != nil {
		t.Fatal(err)
	}
	scope := trust.Scope{Domain: foundationGrantDomain, DeploymentID: prepared.Anchor.DeploymentID, Cell: string(prepared.Anchor.Cell), Environment: prepared.Anchor.Environment, Role: "foundation", Slot: prepared.Anchor.ClusterID}
	grantEnvelope, err := trust.Sign(grantPayload, scope, now.Add(-time.Second), now.Add(2*time.Hour), root)
	if err != nil {
		t.Fatal(err)
	}
	grantWire, err := trust.EncodeEnvelope(grantEnvelope)
	if err != nil {
		t.Fatal(err)
	}
	grantDigest := sha256.Sum256(grantWire)
	prepared.Anchor.FoundationScope.GrantSHA256 = hex.EncodeToString(grantDigest[:])
	anchorEnvelope, err := bootstrap.SignBootstrapAnchor(prepared.Anchor, now.Add(-time.Second), now.Add(2*time.Hour), root)
	if err != nil {
		t.Fatal(err)
	}
	anchorWire, err := trust.EncodeEnvelope(anchorEnvelope)
	if err != nil {
		t.Fatal(err)
	}
	bundle := RetainedFoundation{TenancyID: prepared.Grant.TenancyID, Namespace: prepared.Anchor.StorageDomain.Namespace, RootChainWire: chain, AnchorWire: anchorWire, GrantWire: grantWire}
	return bundle
}

// This extends the existing signed SDK/disk journal scenario through the actual
// operator entrypoint. Only remote OCI resources and offline keys are fixtures.
func foundationProvisionSDKScenario(t *testing.T) {
	fixture := newFoundationProvisionFixture(t)
	approval, bundle, roots := fixture.approval, fixture.bundle, fixture.roots
	cloud, provider, factoryFor := fixture.cloud, fixture.provider, fixture.factoryFor
	factory := factoryFor()
	t.Run("qualified image observation refusals", func(t *testing.T) {
		prepare := func(selected map[string]releasechannel.CurrentImage) (FoundationPreparation, error) {
			return PrepareFoundationGrant(t.Context(), approval, selected, func(_ context.Context, _ string, region string) (Live, error) {
				entry, _ := catalog.CellForOCIRegion(region)
				return Live{AvailabilityDomain: "scenario:AD-1", ServiceID: "ocid1.service.oc1." + region + ".services", ServiceCIDR: "all-" + strings.ToLower(entry.OCIRegionKey) + "-services-in-oracle-services-network"}, nil
			}, factoryFor())
		}
		imageID := fixture.images["GRU"].Image.Receipt().OCIImageOCID
		original := cloud.rows[imageID]
		for name, mutate := range map[string]func(map[string]any) map[string]any{
			"missing image": func(map[string]any) map[string]any { return nil },
			"missing image ID": func(row map[string]any) map[string]any {
				delete(row, "id")
				return row
			},
			"different image": func(row map[string]any) map[string]any {
				row["id"] = "ocid1.image.oc1.sa-saopaulo-1.foreign"
				return row
			},
			"wrong image region": func(row map[string]any) map[string]any {
				row["id"] = "ocid1.image.oc1.us-sanjose-1.qualified"
				return row
			},
			"missing compartment": func(row map[string]any) map[string]any {
				delete(row, "compartmentId")
				return row
			},
			"empty compartment": func(row map[string]any) map[string]any {
				row["compartmentId"] = ""
				return row
			},
			"malformed compartment": func(row map[string]any) map[string]any {
				row["compartmentId"] = "ocid1.compartment.oc1..bad/id"
				return row
			},
			"oversized compartment": func(row map[string]any) map[string]any {
				row["compartmentId"] = "ocid1.compartment.oc1.." + strings.Repeat("a", 256)
				return row
			},
			"unavailable image": func(row map[string]any) map[string]any {
				row["lifecycleState"] = "IMPORTING"
				return row
			},
			"SDK error": func(row map[string]any) map[string]any {
				cloud.imageFault = true
				return row
			},
		} {
			t.Run(name, func(t *testing.T) {
				cloud.rows[imageID] = mutate(maps.Clone(original))
				defer func() { cloud.rows[imageID], cloud.imageFault = original, false }()
				requests, reads := cloud.requests, len(cloud.imageReads)
				result, err := prepare(fixture.images)
				// Two locked retention reads precede the single image GET.
				if err == nil || result.Grant.InstallationID != "" || cloud.requests != requests+3 || len(cloud.imageReads) != reads+1 || cloud.creates != 0 || cloud.launchPosts != 0 || cloud.materialPosts != 0 || cloud.hasAnchor() {
					t.Fatalf("invalid image observation prepared authority or performed effects: %v", err)
				}
			})
		}
		for name, mutate := range map[string]func(*releasechannel.CurrentImage){
			"unqualified base image":   func(image *releasechannel.CurrentImage) { *image = releasechannel.CurrentImage{} },
			"expired qualification":    func(image *releasechannel.CurrentImage) { image.ExpiresAt = time.Now().Add(-time.Second) },
			"different signed receipt": func(image *releasechannel.CurrentImage) { image.ReceiptWire = fixture.images["SFO"].ReceiptWire },
		} {
			t.Run(name, func(t *testing.T) {
				selected := maps.Clone(fixture.images)
				image := selected["GRU"]
				mutate(&image)
				selected["GRU"] = image
				requests, reads := cloud.requests, len(cloud.imageReads)
				result, err := prepare(selected)
				// Only the two locked retention reads precede the qualification refusal.
				if err == nil || result.Grant.InstallationID != "" || cloud.requests != requests+2 || len(cloud.imageReads) != reads || cloud.creates != 0 || cloud.launchPosts != 0 || cloud.materialPosts != 0 || cloud.hasAnchor() {
					t.Fatalf("invalid independent qualification reached image GET or effects: %v", err)
				}
			})
		}
		for _, cell := range []string{"GRU", "SFO", "FRA"} {
			if _, err := os.Stat(cloud.objectPath("gru-1-head/" + foundationObjectPrefix + cell + ".json")); !os.IsNotExist(err) {
				t.Fatalf("image preparation created a %s foundation/writer journal: %v", cell, err)
			}
		}
	})
	invalid := bundle.clone()
	invalid.GrantWire = []byte("invalid signed authority")
	before := provider.reads.Load()
	requests := cloud.requests
	if err := ProvisionFoundationBundle(t.Context(), factory, roots, invalid); err == nil || provider.reads.Load() != before || cloud.requests != requests {
		t.Fatalf("invalid authority touched provider/cloud: reads=%d requests=%d err=%v", provider.reads.Load()-before, cloud.requests, err)
	}
	// First remote acceptance loses its original SDK LaunchInstance response.
	if err := ProvisionFoundationBundle(t.Context(), factory, roots, bundle); err == nil || cloud.lostLaunch {
		t.Fatalf("expected accepted launch response loss: %v", err)
	}
	if cloud.hasAnchor() {
		t.Fatal("public anchor preceded original launch/policy completion")
	}
	firstToken, firstID := cloud.original("GRU")
	if firstToken == "" || firstID == "" {
		t.Fatal("missing accepted original GRU launch")
	}
	first := cloud.journal("GRU").FoundationWriter
	if first == nil || first.OriginalQuote == nil || first.OriginalQuote.Validate() != nil {
		t.Fatal("original SDK launch preceded its durable authentic tariff quote")
	}
	firstQuote := first.OriginalQuote.Clone()
	objects, err := factoryFor().ObjectStorage()
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewObjectFoundationStore(&objects, "ns", "gru-1-head")
	if err != nil {
		t.Fatal(err)
	}
	for fault, mutate := range map[string]func(*FoundationRecord){
		"remove writer": func(r *FoundationRecord) { r.FoundationWriter = nil },
		"remove quote":  func(r *FoundationRecord) { r.FoundationWriter.OriginalQuote = nil },
		"replace quote identity": func(r *FoundationRecord) {
			r.FoundationWriter.OriginalQuote.IssuedAt = r.FoundationWriter.OriginalQuote.IssuedAt.Add(time.Nanosecond)
		},
		"reorder original tariffs":   func(r *FoundationRecord) { slices.Reverse(r.FoundationWriter.OriginalQuote.Prices) },
		"transplant launch identity": func(r *FoundationRecord) { r.FoundationWriter.GrantSHA256 = strings.Repeat("f", 64) },
	} {
		current, etag, err := store.Load(t.Context(), "GRU")
		if err != nil {
			t.Fatal(err)
		}
		mutate(&current)
		if _, err := store.CompareAndSwap(t.Context(), current, etag); err == nil {
			t.Fatalf("original quote custody accepted %s", fault)
		}
		reopened, actual, err := store.Load(t.Context(), "GRU")
		if err != nil || actual != etag || !sameCapacityValue(reopened.FoundationWriter.OriginalQuote, &firstQuote) {
			t.Fatalf("refused %s changed protected quote: %v", fault, err)
		}
	}
	cloud.mu.Lock()
	cloud.tariff = 0.0002
	beforeRetry := cloud.launchPosts
	cloud.mu.Unlock()
	if err := ProvisionFoundationBundle(t.Context(), factoryFor(), roots, bundle); err == nil || !strings.Contains(err.Error(), "original quoted financial terms") {
		t.Fatalf("changed current tariff did not refuse original launch replay: %v", err)
	}
	if cloud.launchPosts != beforeRetry || !sameCapacityValue(cloud.journal("GRU").FoundationWriter.OriginalQuote, &firstQuote) {
		t.Fatal("changed-tariff replay dispatched or replaced original financial evidence")
	}
	cloud.mu.Lock()
	cloud.tariff = 0.0001
	cloud.mu.Unlock()
	// New operator/factory resumes that exact token and checkpoints the same ID;
	// the first exact writer policy then loses its create response.
	if err := ProvisionFoundationBundle(t.Context(), factoryFor(), roots, bundle); err == nil || cloud.lostPolicy {
		t.Fatalf("expected accepted policy response loss: %v", err)
	}
	if token, id := cloud.original("GRU"); token != firstToken || id != firstID {
		t.Fatal("lost response purchased a second original")
	}
	if !sameCapacityValue(cloud.journal("GRU").FoundationWriter.OriginalQuote, &firstQuote) {
		t.Fatal("fresh equal-price recovery replaced original quote identity or validity")
	}
	if cloud.hasAnchor() {
		t.Fatal("public anchor preceded exact policy readback")
	}
	if err := ProvisionFoundationBundle(t.Context(), factoryFor(), roots, bundle); err != nil {
		t.Fatalf("restart full provisioning: %v", err)
	}
	for _, cell := range []string{"GRU", "SFO", "FRA"} {
		saved := cloud.journal(cell)
		if cell == "GRU" {
			for _, role := range []string{"control_compartment", "vault", "key"} {
				if _, exists := saved.ResourceProvenance[role]; exists {
					t.Fatalf("preexisting exact GRU pin acquired invented birth provenance: %s", role)
				}
			}
		}
		for _, key := range []string{"instances", "boot_volumes", "data_volumes"} {
			if _, exists := saved.ResourceIDs[key]; exists {
				t.Fatalf("%s host slot map entered scalar foundation journal: %s", cell, key)
			}
		}
		if saved.FoundationWriter == nil || saved.FoundationWriter.InstanceID == "" || saved.FoundationWriter.Policy == nil || saved.FoundationWriter.Policy.PolicyID == "" || saved.FoundationWriter.Policy.VerifiedAt.IsZero() {
			t.Fatalf("%s lacks original birth and policy readback", cell)
		}
		_, id := cloud.original(cell)
		if saved.FoundationWriter.InstanceID != id {
			t.Fatalf("%s adopted another instance", cell)
		}
		if saved.FoundationWriter.OriginalQuote == nil || saved.FoundationWriter.OriginalQuote.Validate() != nil {
			t.Fatalf("%s lost original payable tariff evidence after reopen", cell)
		}
	}
	if !cloud.hasAnchor() || len(cloud.launches) != 4 {
		t.Fatalf("complete footprint anchor=%v unique hosts=%d", cloud.hasAnchor(), len(cloud.launches))
	}
	anchor, err := verifyDiscoveryAnchor(bundle.AnchorWire, roots, approval.TenancyID, approval.HomeStorageDomain.Namespace)
	if err != nil {
		t.Fatal(err)
	}
	startup, err := bootstrap.VerifyBoundStartupTemplate(t.Context(), factoryFor(), bundle.GrantWire, roots, anchor, time.Now())
	if err != nil {
		t.Fatalf("independent pinned GRU startup: %v", err)
	}
	founder := startup.Template().FounderResources
	if founder == nil || founder.LaunchDeadline.After(startup.ExpiresAt()) || !founder.LaunchDeadline.Before(anchor.ExpiresAt()) {
		t.Fatal("verified founder deadline exceeds its enclosing signing authority")
	}
	if startup.VaultTarget().VaultOCID != approval.SourceVaultTarget.VaultOCID || !bytes.Equal(startup.GrantWire(), bundle.GrantWire) {
		t.Fatal("pinned startup lost original target or signed bytes")
	}
	for _, cell := range []oci.Region{oci.RegionSFO, oci.RegionFRA} {
		sibling, err := startup.ForCell(t.Context(), cell, time.Now())
		if err != nil {
			t.Fatalf("independent %s startup from original GRU anchor: %v", cell, err)
		}
		if err := sibling.VerifyCurrentContext(t.Context(), time.Now()); err != nil {
			t.Fatalf("revalidate %s startup: %v", cell, err)
		}
		if sibling.ExpiresAt().After(startup.ExpiresAt()) || !bytes.Equal(sibling.GrantWire(), bundle.GrantWire) {
			t.Fatalf("%s startup extended original scope", cell)
		}
	}
	objects, err = factoryFor().ObjectStorage()
	if err != nil {
		t.Fatal(err)
	}
	reader, err := NewSignedFootprint(&objects, anchor, roots, approval.TenancyID)
	if err != nil {
		t.Fatal(err)
	}
	reader.factory = factoryFor()
	if _, err := reader.resourceBindings(t.Context(), "GRU", bundle.GrantWire); err == nil || !strings.Contains(err.Error(), "persisted create provenance") {
		t.Fatalf("full worker binding promoted preexisting GRU pins: %v", err)
	}
	posts, creates := cloud.launchPosts, cloud.creates
	if err := ProvisionFoundationBundle(t.Context(), factoryFor(), roots, bundle); err != nil {
		t.Fatalf("idempotent operator restart: %v", err)
	}
	if cloud.launchPosts != posts || cloud.creates != creates {
		t.Fatalf("completed restart mutated resources: launchposts %d->%d creates %d->%d", posts, cloud.launchPosts, creates, cloud.creates)
	}
	// Historical records have no original quote to recover from today's prices.
	legacy := cloud.journal("GRU")
	legacy.FoundationWriter.OriginalQuote = nil
	legacyWire, err := json.Marshal(legacy, json.Deterministic(true))
	if err != nil {
		t.Fatalf("absent historical quote changed legacy wire schema: %v", err)
	}
	var legacyFields struct {
		FoundationWriter map[string]any        `json:"foundationWriter"`
		NetBirdManager   *NetBirdManagerLaunch `json:"netBirdManager"`
	}
	if err := json.Unmarshal(legacyWire, &legacyFields); err != nil || legacyFields.FoundationWriter == nil {
		t.Fatalf("historical writer missing from legacy wire: %v", err)
	}
	if _, present := legacyFields.FoundationWriter["originalQuote"]; present {
		t.Fatal("absent historical writer quote entered legacy wire")
	}
	if legacyFields.NetBirdManager == nil || legacyFields.NetBirdManager.OriginalQuote == nil || !sameCapacityValue(legacyFields.NetBirdManager.OriginalQuote, legacy.NetBirdManager.OriginalQuote) {
		t.Fatal("legacy writer encoding changed the independent original manager quote")
	}
	cloud.writeObject("gru-1-head/"+foundationObjectPrefix+"GRU.json", legacyWire)
	legacy, legacyETag, err := store.Load(t.Context(), "GRU")
	if err != nil {
		t.Fatal(err)
	}
	removed := legacy
	removed.FoundationWriter = nil
	if _, err := store.CompareAndSwap(t.Context(), removed, legacyETag); err == nil {
		t.Fatal("historical writer could be erased before reconstructing quote evidence")
	}
	legacy.FoundationWriter.OriginalQuote = new(firstQuote.Clone())
	if _, err := store.CompareAndSwap(t.Context(), legacy, legacyETag); err == nil {
		t.Fatal("historical writer acquired reconstructed original tariff evidence")
	}
	if err := ProvisionFoundationBundle(t.Context(), factoryFor(), roots, bundle); err != nil {
		t.Fatalf("legacy completed writer could not reopen: %v", err)
	}
	if cloud.journal("GRU").FoundationWriter.OriginalQuote != nil || cloud.launchPosts != posts || cloud.creates != creates {
		t.Fatal("legacy reopen invented original evidence or purchased another resource")
	}
	t.Run("prospective workload genesis", foundationWorkloadGenesisSDKScenario)
}

func foundationWorkloadGenesisSDKScenario(t *testing.T) {
	fixture := newFoundationProvisionFixture(t)
	// This independent prospective operator does not inherit the legacy client's floor.
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	prepared := fixture.prepared
	if prepared.Grant.SchemaVersion != 3 || len(prepared.Grant.WorkloadGenesis) != 9 {
		t.Fatal("new founding preparation did not derive the complete prospective lineage")
	}
	for _, regional := range prepared.Grant.Regions {
		expected, err := foundationAdmissionAttestor(prepared.Grant, fixture.approval.HomeStorageDomain, regional)
		if err != nil || regional.BootstrapMaterial.AdmissionAttestor == nil || *regional.BootstrapMaterial.AdmissionAttestor != expected {
			t.Fatalf("prepared region lacks exact dedicated attestor authorization: %v", err)
		}
	}
	user, err := fixture.provider.UserOCID()
	tenancy, tenancyErr := fixture.provider.TenancyOCID()
	if err != nil || tenancyErr != nil || tenancy != prepared.Grant.TenancyID {
		t.Fatal("producer preparation lost the genuine original provider user/tenancy")
	}
	for _, regional := range prepared.Grant.Regions {
		purpose := regional.BootstrapMaterial.OriginalSourceProducer
		if purpose == nil || purpose.OriginalUserID != user || purpose.TenancyID != tenancy || purpose.OriginalUserID != prepared.Grant.Regions[0].NetBirdManager.Material.Context.ProducerUserID {
			t.Fatal("producer purpose did not bind the same authenticated original NetBird user")
		}
	}
	t.Run("producer digest graph", func(t *testing.T) {
		for _, regional := range prepared.Grant.Regions {
			withPurpose, err := FoundationIntentDigest(regional)
			if err != nil {
				t.Fatal(err)
			}
			material := *regional.BootstrapMaterial
			withoutPurpose := regional
			withoutPurpose.BootstrapMaterial = &material
			material.OriginalSourceProducer = nil
			upstream := func(intent FoundationIntent) []byte {
				m := intent.BootstrapMaterial
				wire, err := json.Marshal(map[string]any{
					"C": m.Config, "P": m.Startup.Profiles, "R": m.Startup,
					"B": prepared.Grant.InfrastructureSpend.Bootstrap, "L": m.SourceRegistration,
					"G": prepared.Grant.WorkloadGenesis, "A": m.AdmissionAttestor,
				}, json.Deterministic(true))
				if err != nil {
					t.Fatal(err)
				}
				return wire
			}
			without, err := FoundationIntentDigest(withoutPurpose)
			if err != nil || without == withPurpose || !bytes.Equal(upstream(withoutPurpose), upstream(regional)) {
				t.Fatal("attaching sibling Q changed an upstream C/P/R/B/L/G/A byte or failed to change the parent")
			}
			recomputed, err := originalSourceProducerIntent(prepared.Grant, fixture.approval.HomeStorageDomain, withoutPurpose)
			if err != nil || !sameOriginalSourceValue(recomputed, regional.BootstrapMaterial.OriginalSourceProducer) {
				t.Fatalf("Q derivation consumed its own parent or sibling purpose: %v", err)
			}
			p, err := ControllerBootstrapProfileDigest(recomputed.Profile)
			r, recipeErr := ControllerBootstrapRecipeDigest(*material.Startup)
			config, configErr := json.Marshal(material.Config, json.Deterministic(true))
			registration, registrationErr := json.Marshal(material.SourceRegistration, json.Deterministic(true))
			attestor, attestorErr := json.Marshal(material.AdmissionAttestor, json.Deterministic(true))
			if err != nil || recipeErr != nil || configErr != nil || registrationErr != nil || attestorErr != nil || p != recomputed.Allocation.ProfileSHA256 || r != recomputed.Allocation.RecipeSHA256 || preparationDigest(config) != recomputed.PlanSHA256 || preparationDigest(registration) != recomputed.SourceRegistrationSHA256 || preparationDigest(attestor) != recomputed.AdmissionAuthorizationSHA256 {
				t.Fatal("Q did not preserve the actual typed upstream projection digests")
			}
			wire, err := json.Marshal(regional.BootstrapMaterial.OriginalSourceProducer, json.Deterministic(true))
			if err != nil {
				t.Fatal(err)
			}
			for _, field := range []string{"bootstrapMaterialSha256", "foundationIntentSha256", "foundationGrantSha256", "retainedBundleSha256"} {
				var object map[string]any
				if err := json.Unmarshal(wire, &object); err != nil {
					t.Fatal(err)
				}
				object[field] = withPurpose
				backedge, err := json.Marshal(object, json.Deterministic(true))
				if err != nil {
					t.Fatal(err)
				}
				var actual OriginalSourceProducerIntent
				if json.Unmarshal(backedge, &actual, json.RejectUnknownMembers(true)) == nil {
					t.Fatalf("actual typed producer parser accepted forbidden parent backedge %s", field)
				}
			}
		}
	})
	bundle := signProvisionFoundation(t, prepared, fixture.bundle.RootChainWire, fixture.root, fixture.now)
	if err := VerifyFoundationProvisionBundle(t.Context(), fixture.roots, bundle); err != nil {
		t.Fatalf("original root-signed prospective founding grant: %v", err)
	}
	t.Run("signed document without prospective purpose", func(t *testing.T) {
		t.Setenv("XDG_CONFIG_HOME", t.TempDir())
		var old FoundationPreparation
		wire, err := json.Marshal(prepared)
		if err != nil || json.Unmarshal(wire, &old) != nil {
			t.Fatal("clone original document")
		}
		for index := range old.Grant.Regions {
			old.Grant.Regions[index].BootstrapMaterial.OriginalSourceProducer = nil
		}
		previous := signProvisionFoundation(t, old, bundle.RootChainWire, fixture.root, fixture.now)
		resolver, err := verifyRetainedFoundation(t.Context(), previous, fixture.roots)
		if err != nil {
			t.Fatalf("historical schema3 document validation changed: %v", err)
		}
		for _, cell := range []string{"GRU", "SFO", "FRA"} {
			proof, err := resolver.Footprint.(*SignedFootprint).OriginalSourceProducer(t.Context(), cell)
			if err == nil || proof.IsVerified() {
				t.Fatal("already signed schema3 gained retrofitted producer purpose")
			}
		}
	})
	_, foreignRoot, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	foreign := signProvisionFoundation(t, prepared, bundle.RootChainWire, foreignRoot, fixture.now)
	factory := fixture.factoryFor()
	reads, requests := fixture.provider.reads.Load(), fixture.cloud.requests
	if err := ProvisionFoundationBundle(t.Context(), factory, fixture.roots, foreign); err == nil || fixture.provider.reads.Load() != reads || fixture.cloud.requests != requests {
		t.Fatalf("untrusted origin signer reached the operator/cloud boundary: %v", err)
	}
	t.Run("startup authority before provider access", func(t *testing.T) {
		for _, test := range []struct {
			name   string
			cell   string
			mutate func(*BootstrapStartupIntent)
			want   string
		}{
			{"invalid GRU image signature", "GRU", func(startup *BootstrapStartupIntent) {
				envelope, err := trust.DecodeEnvelope(startup.ReleaseImageReceiptWire)
				if err != nil {
					t.Fatal(err)
				}
				envelope.Signature = base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
				startup.ReleaseImageReceiptWire = provisionEnvelope(t, envelope)
			}, "verify signed GRU startup image before provisioning"},
			{"different SFO image architecture", "SFO", func(startup *BootstrapStartupIntent) {
				startup.ImageArchitecture = "linux-amd64"
			}, "verify signed SFO startup image before provisioning"},
			{"FRA deadline exceeds current image", "FRA", func(startup *BootstrapStartupIntent) {
				startup.FounderResources.LaunchDeadline = fixture.now.Add(90 * time.Minute)
			}, "verify signed FRA startup deadline before provisioning"},
			{"different GRU initial intent bytes", "GRU", func(startup *BootstrapStartupIntent) {
				file := &startup.ControllerFiles[0]
				file.Bytes = append(bytes.Clone(file.Bytes), '\n')
				file.SHA256 = preparationDigest(file.Bytes)
			}, "prepared GRU startup differs from its root-anchored scope"},
		} {
			t.Run(test.name, func(t *testing.T) {
				t.Setenv("XDG_CONFIG_HOME", t.TempDir())
				candidate := prepared
				candidate.Grant = FoundationGrant{}
				wire, err := json.Marshal(prepared.Grant)
				if err != nil || json.Unmarshal(wire, &candidate.Grant) != nil {
					t.Fatal("clone prepared startup authority")
				}
				for index := range candidate.Grant.Regions {
					regional := &candidate.Grant.Regions[index]
					if regional.Plan["cell"] != test.cell {
						continue
					}
					test.mutate(regional.BootstrapMaterial.Startup)
					recipe, err := ControllerBootstrapRecipeDigest(*regional.BootstrapMaterial.Startup)
					if err != nil {
						t.Fatal(err)
					}
					for slot := range candidate.Grant.InfrastructureSpend.Bootstrap.Slots {
						allocation := &candidate.Grant.InfrastructureSpend.Bootstrap.Slots[slot]
						if allocation.Cell == test.cell && allocation.Role == "controller" {
							allocation.RecipeSHA256 = recipe
						}
					}
					purpose, err := originalSourceProducerIntent(candidate.Grant, fixture.approval.HomeStorageDomain, *regional)
					if err != nil {
						t.Fatal(err)
					}
					regional.BootstrapMaterial.OriginalSourceProducer = new(purpose)
					startupPurpose, err := originalStartupAdmission(purpose, regional.BootstrapMaterial.OriginalStartupAdmission.LedgerRetentionRuleID)
					if err != nil {
						t.Fatal(err)
					}
					regional.BootstrapMaterial.OriginalStartupAdmission = new(startupPurpose)
				}
				if err := ValidatePreparedFoundation(candidate.Grant); err != nil {
					t.Fatalf("startup refusal fixture did not pass structural preparation: %v", err)
				}
				invalid := signProvisionFoundation(t, candidate, bundle.RootChainWire, fixture.root, fixture.now)
				reads, requests := fixture.provider.reads.Load(), fixture.cloud.requests
				if err := ProvisionFoundationBundle(t.Context(), fixture.factoryFor(), fixture.roots, invalid); err == nil || !strings.Contains(err.Error(), test.want) || fixture.provider.reads.Load() != reads || fixture.cloud.requests != requests {
					t.Fatalf("startup authority reached the provider/cloud or failed at another gate: %v", err)
				}
			})
		}
	})
	for name, mutate := range map[string]func(*FoundationGrant){
		"historical schema with genesis": func(grant *FoundationGrant) { grant.SchemaVersion = 2 },
		"missing original scope":         func(grant *FoundationGrant) { grant.WorkloadGenesis = grant.WorkloadGenesis[:8] },
		"different original deployment": func(grant *FoundationGrant) {
			grant.WorkloadGenesis[0].DeploymentID = grant.WorkloadGenesis[1].DeploymentID
		},
		"different home store": func(grant *FoundationGrant) { grant.WorkloadGenesis[0].Namespace = "other" },
		"mixed historical migration": func(grant *FoundationGrant) {
			grant.ReleaseAuthorities[0].SequenceMigrationWire = []byte("test-only conflicting migration input")
		},
		"signed schema3 without producer purpose": func(grant *FoundationGrant) {
			for index := range grant.Regions {
				grant.Regions[index].BootstrapMaterial.OriginalSourceProducer = nil
			}
		},
		"producer digest in config": func(grant *FoundationGrant) {
			wire, err := json.Marshal(grant.Regions[0].BootstrapMaterial.OriginalSourceProducer, json.Deterministic(true))
			if err != nil {
				t.Fatal(err)
			}
			grant.Regions[0].BootstrapMaterial.PlanSHA256 = preparationDigest(wire)
		},
		"producer digest in source registration": func(grant *FoundationGrant) {
			wire, err := json.Marshal(grant.Regions[0].BootstrapMaterial.OriginalSourceProducer, json.Deterministic(true))
			if err != nil {
				t.Fatal(err)
			}
			grant.Regions[0].BootstrapMaterial.SourceRegistration.PlanSHA256 = preparationDigest(wire)
		},
		"producer digest in attestor": func(grant *FoundationGrant) {
			wire, err := json.Marshal(grant.Regions[0].BootstrapMaterial.OriginalSourceProducer, json.Deterministic(true))
			if err != nil {
				t.Fatal(err)
			}
			grant.Regions[0].BootstrapMaterial.AdmissionAttestor.SourceRegistrationSHA256 = preparationDigest(wire)
		},
		"missing producer purpose": func(grant *FoundationGrant) { grant.Regions[0].BootstrapMaterial.OriginalSourceProducer = nil },
		"foreign producer user": func(grant *FoundationGrant) {
			grant.Regions[0].BootstrapMaterial.OriginalSourceProducer.OriginalUserID = "ocid1.user.oc1..foreign"
		},
		"foreign producer selection": func(grant *FoundationGrant) {
			grant.Regions[0].BootstrapMaterial.OriginalSourceProducer.Profile.SubnetOCID = "ocid1.subnet.oc1.sa-saopaulo-1.unproven"
		},
		"foreign producer source": func(grant *FoundationGrant) {
			grant.Regions[0].BootstrapMaterial.OriginalSourceProducer.SourceObject += ".foreign"
		},
		"parent recipe backedge": func(grant *FoundationGrant) {
			parent, err := FoundationIntentDigest(grant.Regions[0])
			if err != nil {
				t.Fatal(err)
			}
			grant.Regions[0].BootstrapMaterial.OriginalSourceProducer.Allocation.RecipeSHA256 = parent
		},
		"missing material purpose": func(grant *FoundationGrant) { grant.Regions[0].NetBirdManager.Material = nil },
		"foreign material producer": func(grant *FoundationGrant) {
			grant.Regions[0].NetBirdManager.Material.Context.ProducerUserID = "ocid1.user.oc1..foreign"
		},
		"foreign material target": func(grant *FoundationGrant) {
			grant.Regions[0].NetBirdManager.Material.Context.Target.KMSKeyOCID = "ocid1.key.oc1.sa-saopaulo-1.foreign"
		},
		"foreign material lineage": func(grant *FoundationGrant) {
			grant.Regions[0].NetBirdManager.Material.LineageSHA256 = strings.Repeat("a", 64)
		},
		"ordinary material name":         func(grant *FoundationGrant) { grant.Regions[0].NetBirdManager.Material.Names[0] = "gru-1-netbird-root" },
		"restored material":              func(grant *FoundationGrant) { grant.Regions[0].NetBirdManager.StoreOrigin = "restore" },
		"later material grant":           func(grant *FoundationGrant) { grant.Generation = 2 },
		"missing attestor authorization": func(grant *FoundationGrant) { grant.Regions[0].BootstrapMaterial.AdmissionAttestor = nil },
		"duplicate attestor authorization": func(grant *FoundationGrant) {
			grant.Regions[0].BootstrapMaterial.AdmissionAttestor = new(*grant.Regions[1].BootstrapMaterial.AdmissionAttestor)
		},
		"foreign attestor scope": func(grant *FoundationGrant) {
			grant.Regions[0].BootstrapMaterial.AdmissionAttestor.InstallationID = "0000000000YTR4D9RJ6W8NG1HC"
		},
		"foreign attestor source store": func(grant *FoundationGrant) {
			grant.Regions[0].BootstrapMaterial.AdmissionAttestor.SourceNamespace = "foreign"
		},
		"foreign attestor source object": func(grant *FoundationGrant) {
			grant.Regions[0].BootstrapMaterial.AdmissionAttestor.SourceObject += ".other"
		},
		"foreign attestor plan": func(grant *FoundationGrant) {
			grant.Regions[0].BootstrapMaterial.AdmissionAttestor.PlanSHA256 = strings.Repeat("a", 64)
		},
		"foreign attestor registration": func(grant *FoundationGrant) {
			grant.Regions[0].BootstrapMaterial.AdmissionAttestor.SourceRegistrationSHA256 = strings.Repeat("a", 64)
		},
		"foreign attestor genesis": func(grant *FoundationGrant) {
			grant.Regions[0].BootstrapMaterial.AdmissionAttestor.WorkloadGenesisSHA256 = strings.Repeat("a", 64)
		},
		"foreign attestor domain": func(grant *FoundationGrant) {
			grant.Regions[0].BootstrapMaterial.AdmissionAttestor.Domain = "bootstrap-intent"
		},
		"foreign attestor action": func(grant *FoundationGrant) { grant.Regions[0].BootstrapMaterial.AdmissionAttestor.Action = "sign" },
		"foreign attestor binding": func(grant *FoundationGrant) {
			grant.Regions[0].BootstrapMaterial.AdmissionAttestor.SourceBinding = "latest-source"
		},
		"schema1 with attestor": func(grant *FoundationGrant) { grant.SchemaVersion = 1; grant.WorkloadGenesis = nil },
		"schema2 with attestor": func(grant *FoundationGrant) { grant.SchemaVersion = 2; grant.WorkloadGenesis = nil },
	} {
		candidate := prepared
		candidate.Grant = FoundationGrant{}
		grantWire, err := json.Marshal(prepared.Grant)
		if err != nil || json.Unmarshal(grantWire, &candidate.Grant) != nil {
			t.Fatalf("clone prospective root document: %v", err)
		}
		mutate(&candidate.Grant)
		invalid := signProvisionFoundation(t, candidate, bundle.RootChainWire, fixture.root, fixture.now)
		factory := fixture.factoryFor()
		reads, requests := fixture.provider.reads.Load(), fixture.cloud.requests
		if err := ProvisionFoundationBundle(t.Context(), factory, fixture.roots, invalid); err == nil || fixture.provider.reads.Load() != reads || fixture.cloud.requests != requests {
			t.Fatalf("%s reached the operator/cloud boundary: %v", name, err)
		}
	}
	fixture.cloud.bundle = bundle.clone()
	fixture.cloud.lostOrigin = true
	before := fixture.cloud.creates
	assertMissingCurrentGrant := func(err error) {
		t.Helper()
		var service common.ServiceError
		if !errors.As(err, &service) || service.GetHTTPStatusCode() != http.StatusNotFound || !strings.Contains(err.Error(), "read current protected foundation grant") {
			t.Fatalf("prospective startup bypassed the missing protected current grant: %v", err)
		}
		if _, err := os.Stat(fixture.cloud.objectPath("gru-1-head/bootstrap/" + foundationGrantObject)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("unpublished current grant unexpectedly exists: %v", err)
		}
	}
	fixture.provisionMaterial(t, bundle)
	if fixture.cloud.lostOrigin || fixture.cloud.creates != before || fixture.cloud.launchPosts != 0 || fixture.cloud.hasAnchor() {
		t.Fatal("prospective publication failed uncertain-write recovery or preceded paid effects/startup")
	}
	expected, err := json.Marshal(bundle, json.Deterministic(true))
	if err != nil {
		t.Fatal(err)
	}
	for _, origin := range prepared.Grant.WorkloadGenesis {
		name, err := release.WorkloadGenesisObject(origin.TenancyID, origin.Cell, origin.Environment, origin.Role)
		if err != nil {
			t.Fatal(err)
		}
		wire, err := os.ReadFile(fixture.cloud.objectPath("gru-1-head/" + name))
		if err != nil || !bytes.Equal(wire, expected) {
			t.Fatalf("origin did not retain original grant/anchor/root lineage at %s: %v", name, err)
		}
	}
	fixture.provisionMaterial(t, bundle)
	if fixture.cloud.creates != before || fixture.cloud.launchPosts != 0 {
		t.Fatal("identical origin replay initialized a runtime or purchased a resource")
	}
	fixture.assertMaterial(t)
	t.Run("original producer birth retention", func(t *testing.T) {
		client, err := fixture.factoryFor().ObjectStorage()
		if err != nil {
			t.Fatal(err)
		}
		store, err := NewObjectFoundationStore(&client, fixture.approval.HomeStorageDomain.Namespace, fixture.approval.HomeStorageDomain.HeadBucket)
		if err != nil {
			t.Fatal(err)
		}
		path := fixture.cloud.objectPath("gru-1-head/" + foundationObjectPrefix + "GRU.json")
		original, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		for name, mutate := range map[string]func(*FoundationRecord){
			"remove array": func(r *FoundationRecord) { r.OriginalSourceProducers = nil },
			"remove GRU":   func(r *FoundationRecord) { r.OriginalSourceProducers[0] = OriginalSourceProducerBirth{} },
			"remove SFO":   func(r *FoundationRecord) { r.OriginalSourceProducers[1] = OriginalSourceProducerBirth{} },
			"remove FRA":   func(r *FoundationRecord) { r.OriginalSourceProducers[2] = OriginalSourceProducerBirth{} },
			"replace user": func(r *FoundationRecord) {
				r.OriginalSourceProducers[0].Intent.OriginalUserID = "ocid1.user.oc1..foreign"
			},
			"replace original grant":      func(r *FoundationRecord) { r.OriginalSourceProducers[0].OriginalGrantSHA256 = strings.Repeat("a", 64) },
			"replace original bundle":     func(r *FoundationRecord) { r.OriginalSourceProducers[0].OriginalBundleSHA256 = strings.Repeat("a", 64) },
			"replace original generation": func(r *FoundationRecord) { r.OriginalSourceProducers[0].OriginalGeneration++ },
			"replace original operation": func(r *FoundationRecord) {
				r.OriginalSourceProducers[0].OriginalOperationID = r.OriginalSourceProducers[0].Intent.OperationID
			},
			"replace original time": func(r *FoundationRecord) {
				r.OriginalSourceProducers[0].BornAt = r.OriginalSourceProducers[0].BornAt.Add(time.Second)
			},
			"replace slot": func(r *FoundationRecord) {
				r.OriginalSourceProducers[0].Intent.Allocation.SlotID = r.OriginalSourceProducers[1].Intent.Allocation.SlotID
			},
			"replace signed selection": func(r *FoundationRecord) {
				r.OriginalSourceProducers[0].Intent.Profile.SubnetOCID = "ocid1.subnet.oc1.sa-saopaulo-1.unproven"
			},
			"replace selection digest": func(r *FoundationRecord) {
				r.OriginalSourceProducers[0].Intent.ResourceSelectionsSHA256 = strings.Repeat("a", 64)
			},
			"replace finite budget":        func(r *FoundationRecord) { r.OriginalSourceProducers[0].Intent.Allocation.MonthlyLimitMinor++ },
			"replace source":               func(r *FoundationRecord) { r.OriginalSourceProducers[0].Intent.SourceObject += ".foreign" },
			"replace escrow":               func(r *FoundationRecord) { r.OriginalSourceProducers[0].Intent.Escrow.KMSKeyOCID += ".foreign" },
			"replace original head bucket": func(r *FoundationRecord) { r.OriginalSourceProducers[0].HeadBucketID += ".foreign" },
			"replace original origin":      func(r *FoundationRecord) { r.OriginalSourceProducers[0].OriginObjects[0] += ".foreign" },
			"erase both purposes": func(r *FoundationRecord) {
				r.OriginalSourceProducers = nil
				r.NetBirdMaterial = nil
				r.Stage = "blocked"
				r.BlockedReason = "foundation-unavailable"
			},
		} {
			record, etag, err := store.Load(t.Context(), "GRU")
			if err != nil {
				t.Fatal(err)
			}
			mutate(&record)
			// Rehashing a modified scope cannot replace its immutable original.
			if record.OriginalSourceProducers != nil {
				for index := range record.OriginalSourceProducers {
					wire, err := json.Marshal(record.OriginalSourceProducers[index].Intent, json.Deterministic(true))
					if err != nil {
						t.Fatal(err)
					}
					record.OriginalSourceProducers[index].IntentSHA256 = preparationDigest(wire)
				}
			}
			if _, err := store.CompareAndSwap(t.Context(), record, etag); err == nil {
				t.Fatalf("protected CAS accepted producer birth reset: %s", name)
			}
			retained, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(retained, original) {
				t.Fatal("refused producer reset changed protected bytes")
			}
		}
		for _, failure := range []string{"NetBird-only birth", "partial birth", "foreign birth", "erased birth"} {
			t.Run(failure, func(t *testing.T) {
				defer fixture.cloud.writeObject("gru-1-head/"+foundationObjectPrefix+"GRU.json", original)
				var record FoundationRecord
				if err := json.Unmarshal(original, &record); err != nil {
					t.Fatal(err)
				}
				switch failure {
				case "NetBird-only birth":
					record.OriginalSourceProducers = nil
				case "partial birth":
					record.OriginalSourceProducers[1] = OriginalSourceProducerBirth{}
				case "foreign birth":
					record.OriginalSourceProducers[0].Intent.OriginalUserID = "ocid1.user.oc1..foreign"
				}
				wire, err := json.Marshal(record, json.Deterministic(true))
				if err != nil {
					t.Fatal(err)
				}
				fixture.cloud.writeObject("gru-1-head/"+foundationObjectPrefix+"GRU.json", wire)
				if failure == "erased birth" {
					if err := os.Remove(path); err != nil {
						t.Fatal(err)
					}
				} else {
					var complete FoundationRecord
					if err := json.Unmarshal(original, &complete); err != nil {
						t.Fatal(err)
					}
					if _, err := store.CompareAndSwap(t.Context(), complete, digestSource(wire)); err == nil {
						t.Fatal("existing missing/foreign scope accepted a post-origin retrofit")
					}
				}
				posts := fixture.cloud.materialPosts
				if err := ProvisionFoundationBundle(t.Context(), fixture.factoryFor(), fixture.roots, bundle); err == nil || fixture.cloud.materialPosts != posts || fixture.cloud.creates != before || fixture.cloud.launchPosts != 0 || fixture.cloud.hasAnchor() {
					t.Fatalf("missing/partial/foreign/erased original producer birth regenerated or progressed: %v", err)
				}
				retained, readErr := os.ReadFile(path)
				if failure == "erased birth" {
					if !errors.Is(readErr, os.ErrNotExist) {
						t.Fatal("retained origins permitted recreation of erased birth")
					}
				} else if readErr != nil || !bytes.Equal(retained, wire) {
					t.Fatal("HOLD rewrote established incomplete birth")
				}
			})
		}
	})
	t.Run("uncertain original producer birth", func(t *testing.T) {
		fixture := newFoundationProvisionFixture(t)
		t.Setenv("XDG_CONFIG_HOME", t.TempDir())
		bundle := signProvisionFoundation(t, fixture.prepared, fixture.bundle.RootChainWire, fixture.root, fixture.now)
		fixture.cloud.bundle, fixture.cloud.lostProducerBirth = bundle, true
		if err := ProvisionFoundationBundle(t.Context(), fixture.factoryFor(), fixture.roots, bundle); err == nil || fixture.cloud.materialPosts != 0 || fixture.cloud.launchPosts != 0 {
			t.Fatalf("unknown original birth outcome progressed: %v", err)
		}
		original := fixture.cloud.journal("GRU").OriginalSourceProducers
		if original == nil {
			t.Fatal("accepted unknown CAS lost complete original array")
		}
		fixture.provisionMaterial(t, bundle)
		if !sameOriginalSourceValue(original, fixture.cloud.journal("GRU").OriginalSourceProducers) {
			t.Fatal("unknown original birth was recreated")
		}
		fixture.assertMaterial(t)
	})
	t.Run("original material recovery and refusal", foundationNetBirdMaterialSDKScenario)
	t.Run("independent historical operator", func(t *testing.T) {
		t.Setenv("XDG_CONFIG_HOME", t.TempDir())
		if err := ProvisionFoundationBundle(t.Context(), fixture.factoryFor(), fixture.roots, fixture.bundle); err == nil || !strings.Contains(err.Error(), "permanent founding workload origin") || fixture.cloud.creates != before || fixture.cloud.launchPosts != 0 {
			t.Fatalf("same-root historical grant bypassed the stable founding origin: %v", err)
		}
	})
	t.Run("different original installation", func(t *testing.T) {
		t.Setenv("XDG_CONFIG_HOME", t.TempDir())
		approval := fixture.approval
		approval.ParentCompartmentID = "ocid1.compartment.oc1..replacement-parent"
		replacement, err := PrepareFoundationGrant(t.Context(), approval, fixture.images, func(_ context.Context, _ string, region string) (Live, error) {
			entry, _ := catalog.CellForOCIRegion(region)
			return Live{AvailabilityDomain: "scenario:AD-1", ServiceID: "ocid1.service.oc1." + region + ".services", ServiceCIDR: "all-" + strings.ToLower(entry.OCIRegionKey) + "-services-in-oracle-services-network"}, nil
		}, fixture.factoryFor())
		if err != nil || replacement.Grant.InstallationID == prepared.Grant.InstallationID {
			t.Fatalf("replacement installation fixture: %v", err)
		}
		other := signProvisionFoundation(t, replacement, bundle.RootChainWire, fixture.root, fixture.now)
		if err := ProvisionFoundationBundle(t.Context(), fixture.factoryFor(), fixture.roots, other); err == nil || !strings.Contains(err.Error(), "permanent founding workload origin") || fixture.cloud.creates != before || fixture.cloud.launchPosts != 0 {
			t.Fatalf("new root-signed installation bypassed the original permanent scope: %v", err)
		}
	})
	resolver, err := verifyRetainedFoundation(t.Context(), bundle, fixture.roots)
	if err != nil {
		t.Fatal(err)
	}
	for _, regional := range prepared.Grant.Regions {
		cell := regional.Plan["cell"].(string)
		proof, err := resolver.Footprint.(*SignedFootprint).AdmissionAttestor(t.Context(), cell)
		if err != nil || !proof.IsVerified() || proof.Authorization() != *regional.BootstrapMaterial.AdmissionAttestor {
			t.Fatalf("original root document did not produce its exact %s authorization: %v", cell, err)
		}
		producer, err := resolver.Footprint.(*SignedFootprint).OriginalSourceProducer(t.Context(), cell)
		if err != nil || !producer.IsVerified() || !sameOriginalSourceValue(producer.Intent(), regional.BootstrapMaterial.OriginalSourceProducer) {
			t.Fatalf("original document lost exact prospective producer purpose for %s: %v", cell, err)
		}
		// Signed logical subnet references remain unresolved: document permission
		// cannot manufacture physical bindings, actors or current material.
		if !strings.HasPrefix(producer.Intent().Profile.SubnetOCID, "foundation:") {
			t.Fatal("metadata fixture unexpectedly substituted a physical subnet identity")
		}
		if selected, err := proof.OriginalBinding(t.Context(), nil); err == nil || selected.IsVerified() {
			t.Fatal("document-only proof inferred a protected original actor/source binding")
		}
	}
	if authority, err := resolver.ContainerReleaseAuthority(t.Context(), "GRU", "terrabase", "production"); err == nil || !strings.Contains(err.Error(), "only generic container roles") || authority.IsVerified() {
		t.Fatal("TerraBase original commitment minted generic container ordering authority")
	}
	if spending, err := resolver.InfrastructureSpend(t.Context()); err == nil || !strings.Contains(err.Error(), "authenticated production OCI factory") || spending.IsVerified() {
		t.Fatal("document-only origin minted resolved infrastructure spending without physical bindings")
	}
	if spending, err := resolver.Footprint.(*SignedFootprint).InfrastructureSpend(t.Context()); err == nil || !strings.Contains(err.Error(), "logical spending scope requires independently verified foundation bindings") || spending.IsVerified() {
		t.Fatal("document-only origin minted direct infrastructure spending without physical bindings")
	}
	if _, err := resolver.Footprint.(*SignedFootprint).OCIRIssuers(t.Context()); err == nil || !strings.Contains(err.Error(), "authenticated production OCI factory") {
		t.Fatalf("document-only origin exposed OCIR credentials without physical bindings: %v", err)
	}
	footprint, err := resolver.Footprint.AuthorizedRegions(t.Context())
	if err != nil || footprint.GrantSHA256 != preparationDigest(bundle.GrantWire) || footprint.TenancyID != prepared.Grant.TenancyID ||
		footprint.ParentCompartmentID != prepared.Grant.ParentCompartmentID || footprint.SharedCompartmentID != prepared.Grant.SharedCompartmentID ||
		!sameOriginalSourceValue(footprint.Regions, prepared.Grant.Regions) {
		t.Fatalf("complete prospective grant lost its exact signed read-only regional scope: %v", err)
	}
	anchor, err := verifyDiscoveryAnchor(bundle.AnchorWire, fixture.roots, bundle.TenancyID, bundle.Namespace)
	if err != nil {
		t.Fatal(err)
	}
	for _, cell := range []oci.Region{oci.RegionGRU, oci.RegionSFO, oci.RegionFRA} {
		if _, err := bootstrap.VerifyRegionalStartupTemplate(bundle.GrantWire, fixture.roots, anchor, cell, time.Now()); !errors.Is(err, bootstrap.ErrManifestInvalid) {
			t.Fatalf("unbound %s parser ignored the signed prospective schema: %v", cell, err)
		}
		_, err := bootstrap.VerifyBoundRegionalStartupTemplate(t.Context(), fixture.factoryFor(), bundle.GrantWire, fixture.roots, anchor, cell, time.Now())
		assertMissingCurrentGrant(err)
	}
	first := prepared.Grant.WorkloadGenesis[0]
	name, err := release.WorkloadGenesisObject(first.TenancyID, first.Cell, first.Environment, first.Role)
	if err != nil {
		t.Fatal(err)
	}
	conflict := []byte("test-only conflicting original retained lineage")
	fixture.cloud.writeObject("gru-1-head/"+name, conflict)
	if err := ProvisionFoundationBundle(t.Context(), fixture.factoryFor(), fixture.roots, bundle); err == nil || fixture.cloud.creates != before || fixture.cloud.launchPosts != 0 {
		t.Fatalf("conflicting permanent origin was reused or replaced: %v", err)
	}
	actual, err := os.ReadFile(fixture.cloud.objectPath("gru-1-head/" + name))
	if err != nil || !bytes.Equal(actual, conflict) {
		t.Fatal("conflicting origin bytes were overwritten")
	}
	t.Run("public first bootstrap reaches original writer", func(t *testing.T) {
		fixture := newFoundationProvisionFixture(t)
		t.Setenv("XDG_CONFIG_HOME", t.TempDir())
		bundle := signProvisionFoundation(t, fixture.prepared, fixture.bundle.RootChainWire, fixture.root, fixture.now)
		fixture.cloud.bundle = bundle
		err := ProvisionFoundationBundle(t.Context(), fixture.factoryFor(), fixture.roots, bundle)
		if err == nil || fixture.cloud.lostLaunch || fixture.cloud.hasAnchor() {
			t.Fatalf("first bootstrap did not retain the accepted original writer response loss before discovery: %v", err)
		}
		for name, expected := range map[string][]byte{fixture.approval.HomeStorageDomain.Prefix + "/" + foundationGrantObject: bundle.GrantWire, foundationRootChainObject: bundle.RootChainWire} {
			actual, err := os.ReadFile(fixture.cloud.objectPath("gru-1-head/" + name))
			if err != nil || !bytes.Equal(actual, expected) {
				t.Fatalf("first bootstrap lacks exact protected prerequisite %s: %v", name, err)
			}
		}
		anchor, err := verifyDiscoveryAnchor(bundle.AnchorWire, fixture.roots, bundle.TenancyID, bundle.Namespace)
		if err != nil {
			t.Fatal(err)
		}
		for _, cell := range []oci.Region{oci.RegionGRU, oci.RegionSFO, oci.RegionFRA} {
			record := fixture.cloud.journal(string(cell))
			if record.Stage != "reconciled" || record.CompletedAt.IsZero() || len(record.ResourceIDs) == 0 {
				t.Fatalf("first bootstrap reached writer admission before %s reconciliation", cell)
			}
			if _, err := bootstrap.VerifyBoundRegionalStartupTemplate(t.Context(), fixture.factoryFor(), bundle.GrantWire, fixture.roots, anchor, cell, time.Now()); err != nil {
				t.Fatalf("first bootstrap lacks full current %s startup binding: %v", cell, err)
			}
		}
		token, id := fixture.cloud.original("GRU")
		writer := fixture.cloud.journal("GRU").FoundationWriter
		if token == "" || id == "" || writer == nil || writer.OriginalQuote == nil || writer.OriginalQuote.Validate() != nil {
			t.Fatal("public first bootstrap did not reach the original quoted SDK writer launch")
		}
	})
}

type provisionProvider struct {
	common.ConfigurationProvider
	reads atomic.Int64
}

func (p *provisionProvider) KeyIDContext(ctx context.Context) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	return p.ConfigurationProvider.KeyID()
}

func (p *provisionProvider) PrivateRSAKeyContext(ctx context.Context) (*rsa.PrivateKey, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return p.ConfigurationProvider.PrivateRSAKey()
}

func (p *provisionProvider) TenancyOCID() (string, error) {
	p.reads.Add(1)
	return p.ConfigurationProvider.TenancyOCID()
}
func (p *provisionProvider) UserOCID() (string, error) {
	p.reads.Add(1)
	return p.ConfigurationProvider.UserOCID()
}

type provisionCloud struct {
	imageReads                     []string
	imageFault                     bool
	materialRoot                   []byte
	materialPosts                  int
	lostMaterialIndex              int
	materialFault                  string
	test                           *testing.T
	mu                             sync.Mutex
	directory                      string
	bundle                         RetainedFoundation
	rows                           map[string]map[string]any
	collections                    map[string]string
	tokens                         map[string]string
	rules                          map[string][]any
	retention                      map[string][]any
	retentionPages                 map[string][]any
	retentionNextPages             map[string]string
	retentionDetails               map[string]map[string]any
	launches                       map[string]string
	tariff                         float64
	lostLaunch, lostPolicy         bool
	lostProducerBirth              bool
	lostOrigin                     bool
	requests, creates, launchPosts int
}

func (c *provisionCloud) objectPath(key string) string {
	sum := sha256.Sum256([]byte(key))
	return filepath.Join(c.directory, hex.EncodeToString(sum[:]))
}
func (c *provisionCloud) writeObject(key string, body []byte) {
	if err := os.WriteFile(c.objectPath(key), body, 0600); err != nil {
		c.test.Fatal(err)
	}
}
func (c *provisionCloud) journal(cell string) FoundationRecord {
	body, err := os.ReadFile(c.objectPath("gru-1-head/" + foundationObjectPrefix + cell + ".json"))
	if err != nil {
		c.test.Error(err)
		return FoundationRecord{}
	}
	var record FoundationRecord
	if err := json.Unmarshal(body, &record); err != nil {
		c.test.Error(err)
	}
	return record
}
func (c *provisionCloud) hasAnchor() bool {
	_, err := os.Stat(c.objectPath("gru-1-head/" + foundationDiscoveryObject))
	return err == nil
}
func (c *provisionCloud) original(cell string) (string, string) {
	for token, id := range c.launches {
		if c.rows[id]["displayName"] == strings.ToLower(cell)+"-1-controller-a" {
			return token, id
		}
	}
	return "", ""
}
func (c *provisionCloud) seedPrerequisites(input FoundationPreparationInput) {
	c.retention[input.HomeStorageDomain.LedgerBucket] = []any{map[string]any{"id": "ledger-indefinite-locked", "displayName": "ledger-indefinite-locked", "etag": "ledger-rule-etag", "timeCreated": "2026-01-01T00:00:00Z", "timeModified": "2026-01-01T00:00:00Z", "timeRuleLocked": "2026-01-02T00:00:00Z"}}
	c.rows[input.SourceVaultTarget.CompartmentOCID] = map[string]any{"id": input.SourceVaultTarget.CompartmentOCID, "name": "gru-1-control", "compartmentId": input.ParentCompartmentID, "lifecycleState": "ACTIVE"}
	c.collections[input.SourceVaultTarget.CompartmentOCID] = "compartments"
	c.rows[input.ParentCompartmentID] = map[string]any{"id": input.ParentCompartmentID, "name": "parent", "compartmentId": input.TenancyID, "lifecycleState": "ACTIVE"}
	c.collections[input.ParentCompartmentID] = "compartments"
	c.rows[input.SharedCompartmentID] = map[string]any{"id": input.SharedCompartmentID, "name": "shared", "compartmentId": input.TenancyID, "lifecycleState": "ACTIVE"}
	c.collections[input.SharedCompartmentID] = "compartments"
	endpoint := "https://prerequisite-management.kms.sa-saopaulo-1.oraclecloud.com"
	c.rows[input.SourceVaultTarget.VaultOCID] = map[string]any{"id": input.SourceVaultTarget.VaultOCID, "displayName": "gru-1-vault", "compartmentId": input.SourceVaultTarget.CompartmentOCID, "vaultType": "DEFAULT", "lifecycleState": "ACTIVE", "managementEndpoint": endpoint}
	c.collections[input.SourceVaultTarget.VaultOCID] = "vaults"
	c.rows[input.SourceVaultTarget.KMSKeyOCID] = map[string]any{"id": input.SourceVaultTarget.KMSKeyOCID, "displayName": "gru-1-key", "compartmentId": input.SourceVaultTarget.CompartmentOCID, "vaultId": input.SourceVaultTarget.VaultOCID, "protectionMode": "HSM", "keyShape": map[string]any{"algorithm": "AES", "length": 32}, "lifecycleState": "ENABLED"}
	c.collections[input.SourceVaultTarget.KMSKeyOCID] = "keys"
	c.rows[input.HomeStorageDomain.LedgerKMSKeyOCID] = map[string]any{"id": input.HomeStorageDomain.LedgerKMSKeyOCID, "displayName": "gru-1-ledger-key", "compartmentId": input.SourceVaultTarget.CompartmentOCID, "vaultId": input.SourceVaultTarget.VaultOCID, "protectionMode": "HSM", "keyShape": map[string]any{"algorithm": "AES", "length": 32}, "lifecycleState": "ENABLED"}
	c.collections[input.HomeStorageDomain.LedgerKMSKeyOCID] = "keys"
	for _, role := range []string{"head", "ledger"} {
		name, key, versioning := "gru-1-head", input.HomeStorageDomain.HeadKMSKeyOCID, "Enabled"
		if role == "ledger" {
			name, key, versioning = "gru-1-ledger", input.HomeStorageDomain.LedgerKMSKeyOCID, "Disabled"
		}
		id := "ocid1.bucket.oc1.sa-saopaulo-1." + role
		c.rows[id] = map[string]any{"id": id, "name": name, "namespace": "ns", "compartmentId": input.SourceVaultTarget.CompartmentOCID, "kmsKeyId": key, "versioning": versioning, "publicAccessType": "NoPublicAccess", "storageTier": "Standard"}
		c.collections[id] = "buckets"
	}
}

func (fixture foundationProvisionFixture) provisionMaterial(t *testing.T, bundle RetainedFoundation) {
	t.Helper()
	stage, err := provisionFoundationMaterial(t.Context(), fixture.factoryFor(), fixture.roots, bundle)
	if err != nil {
		t.Fatalf("material-only preparation failed: %v", err)
	}
	stage.cancel()
}

func (fixture foundationProvisionFixture) assertMaterial(t *testing.T) {
	t.Helper()
	record := fixture.cloud.journal("GRU")
	j := record.NetBirdMaterial
	if j == nil || !j.Complete || record.Stage != "material" || !record.CompletedAt.IsZero() || len(record.ResourceIDs) != 0 || record.FoundationWriter != nil || record.NetBirdManager != nil || fixture.cloud.materialPosts < 4 || fixture.cloud.creates != 0 || fixture.cloud.launchPosts != 0 || fixture.cloud.hasAnchor() {
		t.Fatal("material-only entrypoint fabricated foundation, launch or serving completion")
	}
	wire, err := os.ReadFile(fixture.cloud.objectPath("gru-1-head/" + foundationObjectPrefix + "GRU.json"))
	if err != nil {
		t.Fatal(err)
	}
	for index, create := range j.Creates {
		actual, err := os.ReadFile(fixture.cloud.objectPath("material-value/" + create.SecretID))
		if err != nil || create.Version != 1 || create.ContentSHA256 != netBirdMaterialSHA(actual) || create.FirstDispatchedAt.IsZero() {
			t.Fatalf("material ref lacks immutable content/version provenance: %v", err)
		}
		if bytes.Contains(wire, actual) || bytes.Contains(wire, []byte(base64.StdEncoding.EncodeToString(actual))) {
			t.Fatal("material plaintext leaked into protected journal")
		}
		if index == 0 {
			if !bytes.Equal(actual, fixture.cloud.materialRoot) {
				t.Fatal("Vault transport was decoded more than once")
			}
			continue
		}
		// Independently expand RFC5869 against the actual remote Vault wire value.
		extract := hmac.New(sha256.New, []byte(j.Authority.LineageSHA256))
		extract.Write(fixture.cloud.materialRoot)
		expand := hmac.New(sha256.New, extract.Sum(nil))
		purpose := [3]string{"NETBIRD_RELAY_AUTH_SECRET", "NETBIRD_SESSION_COOKIE_ENCRYPTION_KEY", "NETBIRD_DATASTORE_ENCRYPTION_KEY"}[index-1]
		expand.Write([]byte("netbird-manager-config-hkdf-sha256-v1:" + purpose))
		expand.Write([]byte{1})
		expected := base64.StdEncoding.EncodeToString(expand.Sum(nil))
		if string(actual) != expected || len(actual) != 44 || bytes.Contains(wire, []byte(base64.StdEncoding.EncodeToString(actual))) {
			t.Fatal("actual SDK child value differs from independent derivation or leaked encoded content")
		}
	}
}

func foundationNetBirdMaterialSDKScenario(t *testing.T) {
	for _, mismatch := range []string{"authenticated original user changed", "existing source key disabled"} {
		t.Run(mismatch, func(t *testing.T) {
			fixture := newFoundationProvisionFixture(t)
			t.Setenv("XDG_CONFIG_HOME", t.TempDir())
			bundle := signProvisionFoundation(t, fixture.prepared, fixture.bundle.RootChainWire, fixture.root, fixture.now)
			fixture.cloud.bundle = bundle
			if mismatch == "authenticated original user changed" {
				key, err := fixture.provider.PrivateRSAKey()
				if err != nil {
					t.Fatal(err)
				}
				fixture.provider.ConfigurationProvider = common.NewRawConfigurationProvider(fixture.approval.TenancyID, "ocid1.user.oc1..different", foundationHomeRegion, "test", string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})), nil)
			} else {
				fixture.cloud.rows[fixture.approval.SourceVaultTarget.KMSKeyOCID]["lifecycleState"] = "DISABLED"
			}
			if err := ProvisionFoundationBundle(t.Context(), fixture.factoryFor(), fixture.roots, bundle); err == nil || fixture.cloud.materialPosts != 0 || fixture.cloud.creates != 0 || fixture.cloud.launchPosts != 0 {
				t.Fatalf("foreign producer or disabled exact escrow key reached material effects: %v", err)
			}
			if _, err := os.Stat(fixture.cloud.objectPath("gru-1-head/" + foundationObjectPrefix + "GRU.json")); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("invalid original producer or key created a material birth")
			}
		})
	}
	t.Run("maximum opaque root", func(t *testing.T) {
		fixture := newFoundationProvisionFixture(t)
		t.Setenv("XDG_CONFIG_HOME", t.TempDir())
		bundle := signProvisionFoundation(t, fixture.prepared, fixture.bundle.RootChainWire, fixture.root, fixture.now)
		fixture.cloud.bundle, fixture.cloud.materialRoot = bundle, bytes.Repeat([]byte{'Q'}, 1024)
		fixture.provisionMaterial(t, bundle)
		fixture.assertMaterial(t)
	})
	for _, lost := range []int{0, 2} {
		t.Run(fmt.Sprintf("lost original response %d", lost), func(t *testing.T) {
			fixture := newFoundationProvisionFixture(t)
			t.Setenv("XDG_CONFIG_HOME", t.TempDir())
			bundle := signProvisionFoundation(t, fixture.prepared, fixture.bundle.RootChainWire, fixture.root, fixture.now)
			fixture.cloud.bundle, fixture.cloud.lostMaterialIndex = bundle, lost
			if err := ProvisionFoundationBundle(t.Context(), fixture.factoryFor(), fixture.roots, bundle); err == nil || errors.Is(err, bootstrap.ErrManifestInvalid) {
				t.Fatalf("accepted Vault response loss did not retain uncertain original operation: %v", err)
			}
			before := fixture.cloud.journal("GRU").NetBirdMaterial.Creates[lost]
			if before.SecretID != "" || before.FirstDispatchedAt.IsZero() || before.RequestSHA256 == "" || before.RetryToken == "" {
				t.Fatal("lost material response lacked protected original dispatch")
			}
			fixture.provisionMaterial(t, bundle)
			after := fixture.cloud.journal("GRU").NetBirdMaterial.Creates[lost]
			if before.RequestSHA256 != after.RequestSHA256 || before.RetryToken != after.RetryToken || !before.FirstDispatchedAt.Equal(after.FirstDispatchedAt) || fixture.cloud.materialPosts != 5 {
				t.Fatal("material recovery reset request/token/time or created replacement")
			}
			fixture.assertMaterial(t)
		})
	}
	for _, fault := range []string{"malformed encoding", "short root", "oversized root", "foreign version", "not CURRENT", "foreign target", "wrong generation", "automatic generation missing", "template added", "rotation added", "foreign same name", "token invalidated"} {
		t.Run(fault, func(t *testing.T) {
			fixture := newFoundationProvisionFixture(t)
			t.Setenv("XDG_CONFIG_HOME", t.TempDir())
			bundle := signProvisionFoundation(t, fixture.prepared, fixture.bundle.RootChainWire, fixture.root, fixture.now)
			fixture.cloud.bundle, fixture.cloud.materialFault = bundle, fault
			if fault == "short root" {
				fixture.cloud.materialRoot = bytes.Repeat([]byte{'Q'}, 63)
			}
			if fault == "oversized root" {
				fixture.cloud.materialRoot = bytes.Repeat([]byte{'Q'}, 1025)
			}
			if err := ProvisionFoundationBundle(t.Context(), fixture.factoryFor(), fixture.roots, bundle); err == nil || errors.Is(err, bootstrap.ErrManifestInvalid) {
				t.Fatalf("invalid Vault custody reached startup boundary: %v", err)
			}
			journal := fixture.cloud.journal("GRU")
			if fixture.cloud.materialPosts != 1 || fixture.cloud.creates != 0 || fixture.cloud.launchPosts != 0 || journal.NetBirdMaterial.Complete || journal.NetBirdMaterial.Creates[1].RequestSHA256 != "" {
				t.Fatal("invalid root material reached derivation, infrastructure or replacement")
			}
			if fault == "foreign same name" || fault == "token invalidated" {
				before := journal.NetBirdMaterial.Creates[0]
				posts := fixture.cloud.materialPosts
				if err := ProvisionFoundationBundle(t.Context(), fixture.factoryFor(), fixture.roots, bundle); err == nil {
					t.Fatal("conflicting same-name material was adopted")
				}
				after := fixture.cloud.journal("GRU").NetBirdMaterial.Creates[0]
				if before != after || after.SecretID != "" || after.HoldReason != "create-refused" || fixture.cloud.materialPosts != posts {
					t.Fatal("conflict/invalidation reset original unknown material")
				}
			}
		})
	}
	t.Run("expired unknown original request", func(t *testing.T) {
		fixture := newFoundationProvisionFixture(t)
		t.Setenv("XDG_CONFIG_HOME", t.TempDir())
		bundle := signProvisionFoundation(t, fixture.prepared, fixture.bundle.RootChainWire, fixture.root, fixture.now)
		fixture.cloud.bundle, fixture.cloud.lostMaterialIndex = bundle, 0
		if err := ProvisionFoundationBundle(t.Context(), fixture.factoryFor(), fixture.roots, bundle); err == nil {
			t.Fatal("lost original create did not remain unresolved")
		}
		record := fixture.cloud.journal("GRU")
		record.StartedAt = time.Now().Add(-25 * time.Hour).UTC()
		record.NetBirdMaterial.BornAt = record.StartedAt
		for index := range record.OriginalSourceProducers {
			record.OriginalSourceProducers[index].BornAt = record.StartedAt
		}
		record.NetBirdMaterial.Creates[0].FirstDispatchedAt = time.Now().Add(-24 * time.Hour).UTC()
		wire, err := json.Marshal(record, json.Deterministic(true))
		if err != nil {
			t.Fatal(err)
		}
		fixture.cloud.writeObject("gru-1-head/"+foundationObjectPrefix+"GRU.json", wire)
		posts := fixture.cloud.materialPosts
		if err := ProvisionFoundationBundle(t.Context(), fixture.factoryFor(), fixture.roots, bundle); err == nil || fixture.cloud.materialPosts != posts {
			t.Fatalf("expired unknown operation replayed or minted another token: %v", err)
		}
		if fixture.cloud.journal("GRU").NetBirdMaterial.Creates[0].HoldReason != "retry-expired" {
			t.Fatal("expired original create did not retain permanent HOLD")
		}
	})
	t.Run("pinned material outlives retry tokens", func(t *testing.T) {
		fixture := newFoundationProvisionFixture(t)
		t.Setenv("XDG_CONFIG_HOME", t.TempDir())
		bundle := signProvisionFoundation(t, fixture.prepared, fixture.bundle.RootChainWire, fixture.root, fixture.now)
		fixture.cloud.bundle = bundle
		fixture.provisionMaterial(t, bundle)
		record := fixture.cloud.journal("GRU")
		record.StartedAt = time.Now().Add(-25 * time.Hour).UTC()
		record.NetBirdMaterial.BornAt = record.StartedAt
		for index := range record.OriginalSourceProducers {
			record.OriginalSourceProducers[index].BornAt = record.StartedAt
		}
		for index := range record.NetBirdMaterial.Creates {
			record.NetBirdMaterial.Creates[index].FirstDispatchedAt = time.Now().Add(-24 * time.Hour).UTC()
		}
		wire, err := json.Marshal(record, json.Deterministic(true))
		if err != nil {
			t.Fatal(err)
		}
		fixture.cloud.writeObject("gru-1-head/"+foundationObjectPrefix+"GRU.json", wire)
		posts := fixture.cloud.materialPosts
		fixture.provisionMaterial(t, bundle)
		if fixture.cloud.materialPosts != posts {
			t.Fatal("pinned exact material was replaced after retry-token lifetime")
		}
		fixture.assertMaterial(t)
	})
	for _, failure := range []string{"missing journal and secrets", "retained origins without birth", "replaced CURRENT", "changed root content", "deleted child", "unknown original manager reservation", "original manager instance reservation"} {
		t.Run(failure, func(t *testing.T) {
			fixture := newFoundationProvisionFixture(t)
			t.Setenv("XDG_CONFIG_HOME", t.TempDir())
			bundle := signProvisionFoundation(t, fixture.prepared, fixture.bundle.RootChainWire, fixture.root, fixture.now)
			fixture.cloud.bundle = bundle
			fixture.provisionMaterial(t, bundle)
			record := fixture.cloud.journal("GRU")
			switch failure {
			case "missing journal and secrets", "retained origins without birth":
				if err := os.Remove(fixture.cloud.objectPath("gru-1-head/" + foundationObjectPrefix + "GRU.json")); err != nil {
					t.Fatal(err)
				}
				if failure == "missing journal and secrets" {
					for _, create := range record.NetBirdMaterial.Creates {
						delete(fixture.cloud.rows, create.SecretID)
						if err := os.Remove(fixture.cloud.objectPath("material-value/" + create.SecretID)); err != nil {
							t.Fatal(err)
						}
					}
				}
			case "replaced CURRENT":
				fixture.cloud.rows[record.NetBirdMaterial.Creates[0].SecretID]["currentVersionNumber"] = int64(2)
			case "changed root content":
				fixture.cloud.writeObject("material-value/"+record.NetBirdMaterial.Creates[0].SecretID, bytes.Repeat([]byte{'R'}, 64))
			case "deleted child":
				delete(fixture.cloud.rows, record.NetBirdMaterial.Creates[1].SecretID)
			default:
				// Corrupt an actual retained journal; this is refusal input, never actor evidence.
				record.NetBirdManager = &NetBirdManagerLaunch{}
				if failure == "original manager instance reservation" {
					record.NetBirdManager.InstanceID = "ocid1.instance.oc1.sa-saopaulo-1.original"
				}
				wire, err := json.Marshal(record)
				if err != nil {
					t.Fatal(err)
				}
				fixture.cloud.writeObject("gru-1-head/"+foundationObjectPrefix+"GRU.json", wire)
			}
			posts := fixture.cloud.materialPosts
			if err := ProvisionFoundationBundle(t.Context(), fixture.factoryFor(), fixture.roots, bundle); err == nil || errors.Is(err, bootstrap.ErrManifestInvalid) || fixture.cloud.materialPosts != posts || fixture.cloud.creates != 0 || fixture.cloud.launchPosts != 0 {
				t.Fatalf("lost/replaced original custody regenerated material or progressed: %v", err)
			}
		})
	}
	t.Run("protected CAS never resets material", func(t *testing.T) {
		fixture := newFoundationProvisionFixture(t)
		t.Setenv("XDG_CONFIG_HOME", t.TempDir())
		bundle := signProvisionFoundation(t, fixture.prepared, fixture.bundle.RootChainWire, fixture.root, fixture.now)
		fixture.cloud.bundle = bundle
		fixture.provisionMaterial(t, bundle)
		client, err := fixture.factoryFor().ObjectStorage()
		if err != nil {
			t.Fatal(err)
		}
		store, err := NewObjectFoundationStore(&client, fixture.approval.HomeStorageDomain.Namespace, fixture.approval.HomeStorageDomain.HeadBucket)
		if err != nil {
			t.Fatal(err)
		}
		original, err := os.ReadFile(fixture.cloud.objectPath("gru-1-head/" + foundationObjectPrefix + "GRU.json"))
		if err != nil {
			t.Fatal(err)
		}
		for _, mutate := range []func(*FoundationRecord){
			func(r *FoundationRecord) { r.NetBirdMaterial.Creates[0].RetryToken = strings.Repeat("a", 64) },
			func(r *FoundationRecord) {
				r.NetBirdMaterial.Creates[0].FirstDispatchedAt = r.NetBirdMaterial.Creates[0].FirstDispatchedAt.Add(time.Second)
			},
			func(r *FoundationRecord) { r.NetBirdMaterial.Creates[0].SecretID += ".replacement" },
			func(r *FoundationRecord) { r.NetBirdMaterial.Creates[0].ContentSHA256 = strings.Repeat("a", 64) },
			func(r *FoundationRecord) { r.NetBirdMaterial.Complete = false },
			func(r *FoundationRecord) {
				r.NetBirdMaterial = nil
				r.Stage = "blocked"
				r.BlockedReason = "foundation-unavailable"
			},
			func(r *FoundationRecord) { r.AuxiliaryIDs["head_bucket"] = "ocid1.bucket.oc1.sa-saopaulo-1.foreign" },
		} {
			record, etag, err := store.Load(t.Context(), "GRU")
			if err != nil {
				t.Fatal(err)
			}
			mutate(&record)
			if _, err := store.CompareAndSwap(t.Context(), record, etag); err == nil {
				t.Fatal("actual protected ObjectStorage CAS accepted material reset")
			}
			retained, err := os.ReadFile(fixture.cloud.objectPath("gru-1-head/" + foundationObjectPrefix + "GRU.json"))
			if err != nil || !bytes.Equal(retained, original) {
				t.Fatal("refused material reset changed original protected bytes")
			}
		}
		fixture.assertMaterial(t)
	})
}

func (c *provisionCloud) serveMaterial(w http.ResponseWriter, r *http.Request, parts []string) {
	if parts[0] == "secretbundles" && r.Method == http.MethodGet && len(parts) == 2 {
		id := parts[1]
		value, err := os.ReadFile(c.objectPath("material-value/" + id))
		if err != nil {
			c.notFound(w)
			return
		}
		if r.URL.Query().Get("versionNumber") != "1" || r.URL.Query().Get("stage") != "CURRENT" {
			c.test.Error("material read did not request exact version1 CURRENT by ID")
		}
		encoded := base64.StdEncoding.EncodeToString(value)
		if c.materialFault == "malformed encoding" {
			encoded = "!invalid-base64!"
		}
		version, stages := int64(1), []string{"CURRENT"}
		if c.materialFault == "foreign version" {
			version = 2
		}
		if c.materialFault == "not CURRENT" {
			stages = []string{"PREVIOUS"}
		}
		json.MarshalWrite(w, map[string]any{"secretId": id, "versionNumber": version, "stages": stages, "secretBundleContent": map[string]any{"contentType": "BASE64", "content": encoded}})
		return
	}
	if parts[0] == "secrets" && r.Method == http.MethodGet && len(parts) == 2 {
		row := c.rows[parts[1]]
		if row == nil {
			c.notFound(w)
			return
		}
		observed := maps.Clone(row)
		switch c.materialFault {
		case "foreign target":
			observed["keyId"] = "ocid1.key.oc1.sa-saopaulo-1.foreign"
		case "wrong generation":
			observed["secretGenerationContext"] = map[string]any{"generationType": "BYTES", "generationTemplate": "BYTES_1024"}
		case "automatic generation missing":
			delete(observed, "isAutoGenerationEnabled")
		case "template added":
			observed["secretGenerationContext"] = map[string]any{"generationType": "BYTES", "generationTemplate": "BYTES_512", "secretTemplate": "%GENERATED_BYTES%"}
		case "rotation added":
			observed["rotationConfig"] = map[string]any{"isScheduledRotationEnabled": true, "rotationInterval": "P30D"}
		}
		json.MarshalWrite(w, observed)
		return
	}
	if parts[0] != "secrets" || r.Method != http.MethodPost || len(parts) != 1 {
		c.unexpected(w, r)
		return
	}
	wire, err := io.ReadAll(io.LimitReader(r.Body, 8193))
	if err != nil || len(wire) > 8192 {
		c.test.Fatal("material request exceeded wire bound")
	}
	var body map[string]any
	if err := json.Unmarshal(wire, &body); err != nil {
		c.test.Fatal(err)
	}
	record := c.journal("GRU")
	j := record.NetBirdMaterial
	if j == nil || record.Stage != "material" {
		c.test.Fatal("Vault effect preceded original protected birth")
	}
	index := slices.Index(j.Authority.Names[:], fmt.Sprint(body["secretName"]))
	if index < 0 {
		c.test.Fatal("Vault name differs from independently signed material names")
	}
	create := j.Creates[index]
	if create.RequestSHA256 != netBirdMaterialSHA(wire) || create.RetryToken != r.Header.Get("opc-retry-token") || create.FirstDispatchedAt.IsZero() || create.SecretID != "" ||
		index > 0 && (j.Creates[0].Version != 1 || j.Creates[0].ContentSHA256 == "") {
		c.test.Fatal("Vault effect preceded exact body/token/time reservation or pinned root")
	}
	grant, err := decodeOriginalMaterialGrant(c.bundle)
	if err != nil || len(grant.WorkloadGenesis) != 9 {
		c.test.Fatal("material fixture lacks actual signed original lineage")
	}
	expected, err := json.Marshal(c.bundle, json.Deterministic(true))
	if err != nil {
		c.test.Fatal(err)
	}
	for _, origin := range grant.WorkloadGenesis {
		name, err := release.WorkloadGenesisObject(origin.TenancyID, origin.Cell, origin.Environment, origin.Role)
		if err != nil {
			c.test.Fatal(err)
		}
		retained, err := os.ReadFile(c.objectPath("gru-1-head/" + name))
		if err != nil || !bytes.Equal(retained, expected) {
			c.test.Fatal("Vault generation preceded all nine exact immutable origin readbacks")
		}
	}
	c.materialPosts++
	if c.materialFault == "foreign same name" || c.materialFault == "token invalidated" {
		w.WriteHeader(http.StatusConflict)
		io.WriteString(w, `{"code":"Conflict","message":"original material unresolved"}`)
		return
	}
	if id := c.tokens[create.RetryToken]; id != "" {
		request, err := os.ReadFile(c.objectPath("material-request/" + id))
		if err != nil || !bytes.Equal(request, wire) {
			c.test.Fatal("material retry changed exact original serialized SDK request")
		}
		json.MarshalWrite(w, c.rows[id])
		return
	}
	value := c.materialRoot
	if index == 0 {
		generation, ok := body["secretGenerationContext"].(map[string]any)
		if !ok || generation["generationType"] != "BYTES" || generation["generationTemplate"] != "BYTES_512" || generation["secretTemplate"] != nil || body["secretContent"] != nil || body["enableAutoGeneration"] != true || body["rotationConfig"] != nil || body["replicationConfig"] != nil {
			c.test.Fatal("root request changed fixed provider-generated material template")
		}
	} else {
		content, ok := body["secretContent"].(map[string]any)
		if !ok || content["contentType"] != "BASE64" || content["stage"] != "CURRENT" || body["secretGenerationContext"] != nil || body["enableAutoGeneration"] != nil {
			c.test.Fatal("child request changed fixed derived material format")
		}
		value, err = base64.StdEncoding.DecodeString(fmt.Sprint(content["content"]))
		if err != nil || len(value) != 44 {
			c.test.Fatal("child SDK payload is not padded32byte base64 material")
		}
	}
	id := fmt.Sprintf("ocid1.vaultsecret.oc1.sa-saopaulo-1.material%d", index)
	row := maps.Clone(body)
	delete(row, "secretContent")
	delete(row, "enableAutoGeneration")
	row["id"], row["lifecycleState"], row["currentVersionNumber"], row["timeCreated"] = id, "ACTIVE", int64(1), time.Now().UTC().Format(time.RFC3339)
	if index == 0 {
		row["isAutoGenerationEnabled"] = true
	}
	c.rows[id], c.collections[id], c.tokens[create.RetryToken] = row, "secrets", id
	c.writeObject("material-value/"+id, value)
	c.writeObject("material-request/"+id, wire)
	if c.lostMaterialIndex == index {
		c.lostMaterialIndex = -1
		w.WriteHeader(http.StatusServiceUnavailable)
		io.WriteString(w, `{"code":"InternalError","message":"accepted original material response lost"}`)
		return
	}
	json.MarshalWrite(w, row)
}

func (c *provisionCloud) serveHTTP(w http.ResponseWriter, r *http.Request) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.requests++
	w.Header().Set("Content-Type", "application/json")
	if r.URL.Path == "/pls/apex/cetools/api/v1/products/" {
		metric := map[string]string{"B93297": "OCPU Per Hour", "B93298": "Gigabyte Per Hour", "B91961": "Gigabyte Storage Capacity Per Month", "B91962": "Performance Units Per Gigabyte Per Month"}[r.URL.Query().Get("partNumber")]
		if metric == "" {
			c.test.Errorf("unexpected price SKU %s", r.URL.RawQuery)
		}
		fmt.Fprintf(w, `{"lastUpdated":%q,"items":[{"partNumber":%q,"metricName":%q,"currencyCodeLocalizations":[{"currencyCode":"USD","prices":[{"model":"PAY_AS_YOU_GO","value":%g}]}]}]}`, time.Now().UTC().Format(time.RFC3339), r.URL.Query().Get("partNumber"), metric, c.tariff)
		return
	}
	if !strings.HasPrefix(r.Header.Get("Authorization"), "Signature ") {
		c.test.Error("unsigned OCI effect/read")
		w.WriteHeader(401)
		return
	}
	if r.URL.Path == "/n" {
		io.WriteString(w, `"ns"`)
		return
	}
	if strings.HasPrefix(r.URL.Path, "/n/ns/b") {
		c.serveStorage(w, r)
		return
	}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/"), "/")
	if len(parts) < 2 {
		c.unexpected(w, r)
		return
	}
	parts = parts[1:]
	collection := parts[0]
	if collection == "images" {
		if r.Method != http.MethodGet || len(parts) != 2 || r.URL.Path != "/20160918/images/"+parts[1] ||
			!release.ValidOCIImageIDForRegion(parts[1], "GRU") && !release.ValidOCIImageIDForRegion(parts[1], "SFO") && !release.ValidOCIImageIDForRegion(parts[1], "FRA") ||
			r.Host != "iaas."+strings.Split(parts[1], ".")[3]+".oraclecloud.com" {
			c.unexpected(w, r)
			return
		}
		c.imageReads = append(c.imageReads, r.Host+" "+r.URL.Path)
		if c.imageFault {
			w.WriteHeader(http.StatusServiceUnavailable)
			io.WriteString(w, `{"code":"InternalError","message":"image observation unavailable"}`)
			return
		}
		row := c.rows[parts[1]]
		if row == nil || c.collections[parts[1]] != "images" {
			c.notFound(w)
			return
		}
		json.MarshalWrite(w, row)
		return
	}
	if collection == "secrets" || collection == "secretbundles" {
		c.serveMaterial(w, r, parts)
		return
	}
	if collection == "tenancies" {
		io.WriteString(w, `{"homeRegionKey":"GRU"}`)
		return
	}
	if r.Method == http.MethodGet && c.serveManagerObservation(w, r, parts) {
		return
	}
	if collection == "networkSecurityGroups" && len(parts) >= 3 {
		id := parts[1]
		if r.Method == http.MethodGet && parts[2] == "securityRules" {
			json.MarshalWrite(w, append([]any{}, c.rules[id]...))
			return
		}
		if r.Method == http.MethodPost && len(parts) == 4 && parts[3] == "addSecurityRules" {
			var body struct {
				SecurityRules []any `json:"securityRules"`
			}
			if err := json.UnmarshalRead(r.Body, &body); err != nil {
				c.test.Error(err)
			}
			for index, rule := range body.SecurityRules {
				rule.(map[string]any)["id"] = fmt.Sprintf("rule%d", index)
			}
			c.rules[id] = append(c.rules[id], body.SecurityRules...)
			json.MarshalWrite(w, map[string]any{"securityRules": c.rules[id]})
			return
		}
	}
	if r.Method == http.MethodGet && len(parts) == 2 {
		row := c.rows[parts[1]]
		if row == nil {
			c.notFound(w)
			return
		}
		w.Header().Set("etag", "resource")
		json.MarshalWrite(w, row)
		return
	}
	if r.Method == http.MethodGet && len(parts) == 1 {
		rows := []map[string]any{}
		for id, row := range c.rows {
			if c.collections[id] != collection || !c.inRegion(r, id, collection) {
				continue
			}
			matches := true
			for _, field := range []string{"compartmentId", "vcnId", "name", "displayName"} {
				if expected := r.URL.Query().Get(field); expected != "" && row[field] != expected {
					matches = false
				}
			}
			if collection == "keys" && !strings.Contains(r.Host, "prerequisite-management") {
				vault := c.rows[fmt.Sprint(row["vaultId"])]
				if vault != nil && vault["managementEndpoint"] != "https://"+r.Host {
					matches = false
				}
			}
			if matches {
				rows = append(rows, row)
			}
		}
		slices.SortFunc(rows, func(a, b map[string]any) int { return strings.Compare(fmt.Sprint(a["id"]), fmt.Sprint(b["id"])) })
		json.MarshalWrite(w, rows)
		return
	}
	if r.Method != http.MethodPost || len(parts) != 1 {
		c.unexpected(w, r)
		return
	}
	kinds := map[string]string{"compartments": "compartment", "vcns": "vcn", "serviceGateways": "servicegateway", "routeTables": "routetable", "securityLists": "securitylist", "subnets": "subnet", "networkSecurityGroups": "networksecuritygroup", "vaults": "vault", "keys": "key", "dynamicGroups": "dynamicgroup", "policies": "policy", "internetGateways": "internetgateway", "instances": "instance"}
	kind := kinds[collection]
	if kind == "" {
		c.unexpected(w, r)
		return
	}
	var body map[string]any
	if err := json.UnmarshalRead(r.Body, &body); err != nil {
		c.test.Error(err)
		w.WriteHeader(400)
		return
	}
	token := r.Header.Get("opc-retry-token")
	if collection == "instances" {
		c.launchPosts++
		c.checkLaunchReservation(r, body, token)
	}
	if kind == "policy" && strings.HasPrefix(fmt.Sprint(body["name"]), "ts-foundation-writer-") {
		c.checkPolicyReservation(body, token)
	}
	if id := c.tokens[token]; token != "" && id != "" {
		json.MarshalWrite(w, c.rows[id])
		return
	}
	region := c.region(r)
	if slices.Contains([]string{"compartment", "dynamicgroup", "policy"}, kind) {
		region = ""
	}
	id := fmt.Sprintf("ocid1.%s.oc1.%s.resource%d", kind, region, len(c.rows)+1)
	body["id"] = id
	body["lifecycleState"] = "AVAILABLE"
	if region == "" || kind == "vault" {
		body["lifecycleState"] = "ACTIVE"
	}
	switch kind {
	case "vcn":
		body["defaultDhcpOptionsId"] = strings.Replace(id, ".vcn.", ".dhcpoptions.", 1)
		if block, ok := body["cidrBlock"].(string); ok {
			body["cidrBlocks"] = []string{block}
		}
		if blocks, ok := body["cidrBlocks"].([]any); ok && len(blocks) > 0 {
			body["cidrBlock"] = blocks[0]
		}
	case "subnet":
		body["prohibitInternetIngress"] = body["prohibitPublicIpOnVnic"]
	case "vault":
		body["managementEndpoint"] = fmt.Sprintf("https://v%d-management.kms.%s.oraclecloud.com", len(c.rows)+1, region)
	case "key":
		body["lifecycleState"] = "ENABLED"
		for vaultID, vault := range c.rows {
			if c.collections[vaultID] == "vaults" && vault["managementEndpoint"] == "https://"+r.Host {
				body["vaultId"] = vaultID
			}
		}
	case "instance":
		body["lifecycleState"] = "RUNNING"
		body["imageId"] = body["sourceDetails"].(map[string]any)["imageId"]
		c.launches[token] = id
	}
	c.rows[id], c.collections[id] = body, collection
	if token != "" {
		c.tokens[token] = id
	}
	c.creates++
	if kind == "instance" && c.lostLaunch && strings.HasSuffix(fmt.Sprint(body["displayName"]), "controller-a") {
		c.lostLaunch = false
		w.WriteHeader(503)
		io.WriteString(w, `{"code":"InternalError","message":"accepted original launch response lost"}`)
		return
	}
	if kind == "policy" && c.lostPolicy && strings.HasPrefix(fmt.Sprint(body["name"]), "ts-foundation-writer-") {
		c.lostPolicy = false
		w.WriteHeader(503)
		io.WriteString(w, `{"code":"InternalError","message":"accepted original policy response lost"}`)
		return
	}
	json.MarshalWrite(w, body)
}
func (c *provisionCloud) region(r *http.Request) string {
	for _, cell := range []string{"GRU", "SFO", "FRA"} {
		region := catalog.OCIRegion(cell)
		if strings.Contains(r.Host, region) {
			return region
		}
	}
	c.test.Errorf("unexpected provider host %s", r.Host)
	return ""
}
func (c *provisionCloud) inRegion(r *http.Request, id, collection string) bool {
	if slices.Contains([]string{"compartments", "dynamicGroups", "policies"}, collection) {
		return true
	}
	return strings.Contains(id, ".oc1."+c.region(r)+".")
}
func (c *provisionCloud) notFound(w http.ResponseWriter) {
	w.WriteHeader(404)
	io.WriteString(w, `{"code":"NotAuthorizedOrNotFound","message":"fixture absent"}`)
}
func (c *provisionCloud) unexpected(w http.ResponseWriter, r *http.Request) {
	c.test.Errorf("unexpected provider operation %s %s host=%s", r.Method, r.URL, r.Host)
	w.WriteHeader(400)
	io.WriteString(w, `{"code":"Unexpected","message":"fixture unsupported"}`)
}

func provisionReleaseAuthorities(t *testing.T, root ed25519.PrivateKey, public ed25519.PublicKey, home bootstrap.StorageDomain, now time.Time) []ContainerReleaseAuthorityIntent {
	t.Helper()
	keyID, err := trust.KeyID(public)
	if err != nil {
		t.Fatal(err)
	}
	keyWire, err := trust.EncodeDelegatedPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	var authorities []ContainerReleaseAuthorityIntent
	for _, role := range []string{"terrabase", "ts-auth", "function-worker"} {
		delegation := trust.Delegation{SchemaVersion: trust.SchemaVersion, SubjectKeyID: keyID, SubjectPublicKey: keyWire}
		migration := release.SequenceMigration{Namespace: home.Namespace, Bucket: home.HeadBucket, Region: "GRU", Schema: release.SequenceMigrationSchema,
			SignerKeyID: keyID, SignerPublicKey: keyWire, Role: role, Environment: "production", SequenceFloor: 42}
		for _, cell := range []string{"GRU", "SFO", "FRA"} {
			scope := release.ContainerScope(release.ContainerTarget{Cell: cell, Role: role, Environment: "production", Architecture: "arm64"})
			delegation.Capabilities = append(delegation.Capabilities, trust.Capability{Domain: scope.Domain, DeploymentID: scope.DeploymentID, Cell: scope.Cell,
				Environment: scope.Environment, Role: scope.Role, Slots: []string{"linux-arm64", "linux-amd64"}, Actions: []string{"sign"}})
			migration.Regions = append(migration.Regions, release.SequenceFloor{Cell: cell, RunNumber: 41, IssuedAt: now.Add(-time.Hour), EvidenceSHA256: strings.Repeat("a", 64)})
		}
		delegated, err := trust.SignDelegation(delegation, now.Add(-time.Minute), now.Add(30*24*time.Hour), root)
		if err != nil {
			t.Fatal(err)
		}
		migrated, err := release.SignSequenceMigration(migration, now.Add(-time.Minute), root)
		if err != nil {
			t.Fatal(err)
		}
		authorities = append(authorities, ContainerReleaseAuthorityIntent{Role: role, Environment: "production", ImageRepository: "gru.ocir.io/ns/" + role,
			SourceRepository: "https://github.com/TerraScale/" + role, Cells: []string{"GRU", "SFO", "FRA"}, Architectures: []string{"arm64", "amd64"},
			DelegationWire: provisionEnvelope(t, delegated), SequenceMigrationWire: provisionEnvelope(t, migrated)})
	}
	return authorities
}

func provisionImage(t *testing.T, root, leaf ed25519.PrivateKey, roots trust.Keyring, cell, role string, now time.Time) ([]byte, []byte, map[string][]byte) {
	t.Helper()
	image := release.ImageReceipt{Schema: release.ImageSchema, SourceRevision: strings.Repeat("a", 40), GoVersion: release.DefaultGoVersion, Architecture: "arm64", BinaryBytes: 13,
		BinarySHA256: strings.Repeat("b", 64), QualificationSHA256: strings.Repeat("c", 64), BaseImageOCID: "ocid1.image.oc1." + catalog.OCIRegion(cell) + ".base", BaseImageRegion: cell,
		BaseImageSHA256: strings.Repeat("d", 64), KernelRelease: "6.1.0", KernelSHA256: strings.Repeat("e", 64), ImageFormat: "qcow2", ImageBytes: 1024,
		ImageSHA256: strings.Repeat("f", 64), OCIImageOCID: "ocid1.image.oc1." + catalog.OCIRegion(cell) + ".qualified", OCIRegion: cell}
	qualifiedRole, runtime := "orchestrator", release.ProductionRuntime
	gates := []string{"runtime-ha", "workload-safety"}
	lifetime := time.Hour
	delegationExpiry := now.Add(2 * time.Hour)
	if role == "netbird-manager" {
		qualifiedRole, runtime, gates = role, release.NetBirdProductionRuntime, []string{"netbird-foundation", "netbird-recovery"}
		lifetime = 30 * 24 * time.Hour
		delegationExpiry = now.Add(lifetime)
	}
	qualification := release.ProductionQualification{Schema: release.ProductionQualificationSchema, Candidate: release.ProductionExpectation{SourceRevision: image.SourceRevision, ArtifactSHA256: image.ImageSHA256,
		QualificationSHA256: image.QualificationSHA256, Cell: cell, Environment: "production", Architecture: image.Architecture, Role: qualifiedRole, Runtime: runtime}}
	evidence := map[string][]byte{}
	for _, gate := range gates {
		wire := []byte("test-only retained " + cell + " " + qualifiedRole + " " + gate)
		sum := digestSource(wire)
		evidence[sum] = wire
		qualification.Evidence = append(qualification.Evidence, release.ProductionGateEvidence{Gate: gate, SHA256: sum, Bytes: int64(len(wire)), CompletedAt: now.Add(-time.Minute)})
	}
	payload, err := trust.EncodePayload(qualification)
	if err != nil {
		t.Fatal(err)
	}
	qualified, err := trust.Sign(payload, release.ProductionQualificationScope(qualification.Candidate), now.Add(-time.Second), now.Add(lifetime), root)
	if err != nil {
		t.Fatal(err)
	}
	proof := release.ProductionProof{Qualification: provisionEnvelope(t, qualified)}
	if role == "netbird-manager" {
		image.HostProduction = map[string]release.ProductionProof{role: proof}
	} else {
		image.Production = &proof
		image.HostProduction = map[string]release.ProductionProof{release.FoundationWriterRole: provisionWriterProof(t, root, image, now, evidence)}
	}
	scope := release.ImageScope(image, "production")
	if role == "netbird-manager" {
		scope = release.NetBirdImageScope(image, "production")
	}
	public := leaf.Public().(ed25519.PublicKey)
	keyID, _ := trust.KeyID(public)
	keyWire, _ := trust.EncodeDelegatedPublicKey(public)
	delegation, err := trust.SignDelegation(trust.Delegation{SchemaVersion: trust.SchemaVersion, SubjectKeyID: keyID, SubjectPublicKey: keyWire,
		Capabilities: []trust.Capability{{Domain: scope.Domain, DeploymentID: scope.DeploymentID, Cell: scope.Cell, Environment: scope.Environment, Role: scope.Role, Slots: []string{scope.Slot}, Actions: []string{"sign"}}}}, now.Add(-time.Minute), delegationExpiry, root)
	if err != nil {
		t.Fatal(err)
	}
	var signed trust.Envelope
	if role == "netbird-manager" {
		signed, err = release.SignNetBirdImageReceipt(image, "production", delegation, roots, leaf, now, lifetime)
	} else {
		signed, err = release.SignImageReceipt(image, "production", delegation, roots, leaf, now, time.Hour)
	}
	if err != nil {
		t.Fatal(err)
	}
	return provisionEnvelope(t, signed), provisionEnvelope(t, delegation), evidence
}

func provisionEnvelope(t *testing.T, envelope trust.Envelope) []byte {
	t.Helper()
	wire, err := trust.EncodeEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

func provisionWriterProof(t *testing.T, root ed25519.PrivateKey, image release.ImageReceipt, now time.Time, objects map[string][]byte) release.ProductionProof {
	t.Helper()
	candidate := release.ProductionExpectation{ImageOCID: image.OCIImageOCID, SourceRevision: image.SourceRevision, ArtifactSHA256: image.ImageSHA256, QualificationSHA256: image.QualificationSHA256, Cell: image.OCIRegion, Environment: "production", Architecture: image.Architecture, Role: release.FoundationWriterRole, Runtime: release.ProductionRuntime}
	qualification := release.ProductionQualification{Schema: release.FoundationWriterQualificationSchema, Candidate: candidate}
	completed := now.Add(-time.Minute)
	for _, gate := range []string{"runtime-ha", "workload-safety", release.RootCredentialBoundaryGate} {
		wire := []byte("test-only simulated " + image.OCIRegion + " " + gate)
		if gate == release.RootCredentialBoundaryGate {
			boundary := release.RootCredentialBoundaryEvidence{Schema: release.RootCredentialBoundarySchema, Candidate: candidate, CompletedAt: completed}
			for index, role := range []string{"manager", "manager", "manager", "container"} {
				transcript := []byte(fmt.Sprintf("test-only simulated boundary host %d", index))
				boundary.Hosts = append(boundary.Hosts, release.RootCredentialBoundaryHost{Role: role, InstanceID: fmt.Sprintf("ocid1.instance.oc1.%s.simulated%d", catalog.OCIRegion(image.OCIRegion), index), ImageOCID: image.OCIImageOCID, SourceRevision: image.SourceRevision, NamespaceSHA256: strings.Repeat("a", 64), OrdinaryUID: 1000, RootOCIRead: "authenticated", OrdinaryUIDIMDS: "refused", OrdinaryUIDSigning: "refused", UnauthorizedIPC: "refused", Transcript: transcript, TranscriptSHA256: digestSource(transcript)})
			}
			var err error
			wire, err = protocol.EncodeJSON(boundary)
			if err != nil {
				t.Fatal(err)
			}
		}
		sum := digestSource(wire)
		objects[sum] = wire
		qualification.Evidence = append(qualification.Evidence, release.ProductionGateEvidence{Gate: gate, SHA256: sum, Bytes: int64(len(wire)), CompletedAt: completed})
	}
	payload, err := trust.EncodePayload(qualification)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := trust.Sign(payload, release.ProductionQualificationScope(candidate), now.Add(-time.Second), now.Add(time.Hour), root)
	if err != nil {
		t.Fatal(err)
	}
	return release.ProductionProof{Qualification: provisionEnvelope(t, signed)}
}

func (c *provisionCloud) serveStorage(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/n/ns/b")
	if rest == "" || rest == "/" {
		if r.Method == http.MethodGet {
			rows := []map[string]any{}
			for id, row := range c.rows {
				if c.collections[id] == "buckets" && c.inRegion(r, id, "buckets") && row["compartmentId"] == r.URL.Query().Get("compartmentId") {
					rows = append(rows, row)
				}
			}
			json.MarshalWrite(w, rows)
			return
		}
		if r.Method == http.MethodPost {
			var body map[string]any
			if err := json.UnmarshalRead(r.Body, &body); err != nil {
				c.test.Error(err)
				w.WriteHeader(400)
				return
			}
			id := fmt.Sprintf("ocid1.bucket.oc1.%s.resource%d", c.region(r), len(c.rows)+1)
			body["id"], body["namespace"] = id, "ns"
			c.rows[id], c.collections[id] = body, "buckets"
			c.creates++
			json.MarshalWrite(w, body)
			return
		}
		c.unexpected(w, r)
		return
	}
	bucket, suffix, _ := strings.Cut(strings.TrimPrefix(rest, "/"), "/")
	if strings.HasPrefix(suffix, "o/") {
		object := strings.TrimPrefix(suffix, "o/")
		path := c.objectPath(bucket + "/" + object)
		old, readErr := os.ReadFile(path)
		etag := digestSource(old)
		if r.Method == http.MethodGet {
			if readErr != nil {
				c.notFound(w)
				return
			}
			w.Header().Set("etag", etag)
			w.Write(old)
			return
		}
		if r.Method != http.MethodPut {
			c.unexpected(w, r)
			return
		}
		if r.Header.Get("If-None-Match") == "*" && readErr == nil || r.Header.Get("If-Match") != "" && (readErr != nil || r.Header.Get("If-Match") != etag) {
			w.WriteHeader(http.StatusPreconditionFailed)
			io.WriteString(w, `{"code":"PreconditionFailed","message":"conditional object changed"}`)
			return
		}
		wire, err := io.ReadAll(r.Body)
		if err != nil {
			c.test.Error(err)
			w.WriteHeader(400)
			return
		}
		if object == foundationDiscoveryObject {
			for _, cell := range []string{"GRU", "SFO", "FRA"} {
				saved := c.journal(cell).FoundationWriter
				if saved == nil || saved.InstanceID == "" || saved.Policy == nil || saved.Policy.PolicyID == "" || saved.Policy.VerifiedAt.IsZero() {
					c.test.Errorf("anchor published before %s original policy readback", cell)
					w.WriteHeader(400)
					return
				}
			}
		}
		if strings.HasPrefix(object, "orchestrator/workload-genesis/v1/") {
			birth := c.journal("GRU")
			if birth.Stage != "material" || birth.NetBirdMaterial == nil || birth.NetBirdMaterial.BornAt.IsZero() || c.materialPosts != 0 {
				c.test.Fatal("first immutable origin effect preceded protected material birth or followed Vault generation")
			}
			if birth.OriginalSourceProducers == nil || birth.validateOriginalSourceProducers() != nil {
				c.test.Fatal("first origin preceded the complete same-CAS original producer birth")
			}
			grant, err := decodeOriginalMaterialGrant(c.bundle)
			retained, marshalErr := json.Marshal(c.bundle, json.Deterministic(true))
			if err != nil || marshalErr != nil {
				c.test.Fatal("origin fixture lost exact signed original producer lineage")
			}
			for _, original := range birth.OriginalSourceProducers {
				matched := false
				for _, regional := range grant.Regions {
					if regional.Plan["cell"] == original.Intent.Cell {
						matched = sameOriginalSourceValue(original.Intent, regional.BootstrapMaterial.OriginalSourceProducer)
					}
				}
				if !matched || original.OriginalGrantSHA256 != preparationDigest(c.bundle.GrantWire) || original.OriginalBundleSHA256 != preparationDigest(retained) {
					c.test.Fatal("pre-origin producer birth differs from original signed purpose or retained bytes")
				}
			}
		}
		c.writeObject(bucket+"/"+object, wire)
		if object == foundationObjectPrefix+"GRU.json" && readErr != nil && c.lostProducerBirth {
			c.lostProducerBirth = false
			w.WriteHeader(http.StatusServiceUnavailable)
			io.WriteString(w, `{"code":"InternalError","message":"accepted original birth response lost"}`)
			return
		}
		if strings.HasPrefix(object, "orchestrator/workload-genesis/v1/") && c.lostOrigin {
			c.lostOrigin = false
			w.WriteHeader(http.StatusServiceUnavailable)
			io.WriteString(w, `{"code":"InternalError","message":"accepted origin response lost"}`)
			return
		}
		w.Header().Set("etag", digestSource(wire))
		return
	}
	var row map[string]any
	for id, item := range c.rows {
		if c.collections[id] == "buckets" && item["name"] == bucket && c.inRegion(r, id, "buckets") {
			row = item
			break
		}
	}
	if row == nil {
		c.notFound(w)
		return
	}
	if suffix == "" && r.Method == http.MethodGet {
		w.Header().Set("etag", "bucket")
		json.MarshalWrite(w, row)
		return
	}
	if suffix == "retentionRules" {
		if r.Method == http.MethodGet {
			items := c.retention[bucket]
			page := bucket + "|" + r.URL.Query().Get("page")
			if c.retentionPages != nil {
				items = c.retentionPages[page]
			}
			if next := c.retentionNextPages[page]; next != "" {
				w.Header().Set("opc-next-page", next)
			}
			json.MarshalWrite(w, map[string]any{"items": append([]any{}, items...)})
			return
		}
		if r.Method == http.MethodPost {
			var body map[string]any
			if err := json.UnmarshalRead(r.Body, &body); err != nil {
				c.test.Error(err)
				w.WriteHeader(400)
				return
			}
			body["id"] = fmt.Sprintf("retention%d", len(c.retention[bucket])+1)
			c.retention[bucket] = append(c.retention[bucket], body)
			c.creates++
			json.MarshalWrite(w, body)
			return
		}
	}
	if ruleID, ok := strings.CutPrefix(suffix, "retentionRules/"); ok && r.Method == http.MethodGet {
		for _, value := range c.retention[bucket] {
			rule, ok := value.(map[string]any)
			if ok && rule["id"] == ruleID {
				if detail := c.retentionDetails[ruleID]; detail != nil {
					rule = detail
				}
				w.Header().Set("etag", fmt.Sprint(rule["etag"]))
				json.MarshalWrite(w, rule)
				return
			}
		}
		c.notFound(w)
		return
	}
	c.unexpected(w, r)
}

func (c *provisionCloud) serveManagerObservation(w http.ResponseWriter, r *http.Request, parts []string) bool {
	collection := parts[0]
	if collection == "dhcps" && len(parts) == 2 {
		vcnID := strings.Replace(parts[1], ".dhcpoptions.", ".vcn.", 1)
		vcn := c.rows[vcnID]
		json.MarshalWrite(w, map[string]any{"id": parts[1], "vcnId": vcnID, "compartmentId": vcn["compartmentId"], "lifecycleState": "AVAILABLE", "options": []map[string]any{{"type": "DomainNameServer", "serverType": "VcnLocalPlusInternet"}}})
		return true
	}
	if !slices.Contains([]string{"vnicAttachments", "vnics", "bootVolumeAttachments", "bootVolumes"}, collection) {
		return false
	}
	var instanceID string
	if collection == "vnicAttachments" || collection == "bootVolumeAttachments" {
		instanceID = r.URL.Query().Get("instanceId")
	} else if len(parts) == 2 {
		instanceID = strings.Replace(strings.Replace(parts[1], ".vnic.", ".instance.", 1), ".bootvolume.", ".instance.", 1)
	}
	instance := c.rows[instanceID]
	if instance == nil {
		c.notFound(w)
		return true
	}
	vnicID := strings.Replace(instanceID, ".instance.", ".vnic.", 1)
	bootID := strings.Replace(instanceID, ".instance.", ".bootvolume.", 1)
	vnic := instance["createVnicDetails"].(map[string]any)
	source := instance["sourceDetails"].(map[string]any)
	switch collection {
	case "vnicAttachments":
		json.MarshalWrite(w, []map[string]any{{"instanceId": instanceID, "compartmentId": instance["compartmentId"], "vnicId": vnicID, "subnetId": vnic["subnetId"], "lifecycleState": "ATTACHED"}})
	case "vnics":
		subnet := c.rows[fmt.Sprint(vnic["subnetId"])]
		json.MarshalWrite(w, map[string]any{"id": vnicID, "compartmentId": subnet["compartmentId"], "availabilityDomain": instance["availabilityDomain"], "subnetId": vnic["subnetId"], "nsgIds": vnic["nsgIds"], "privateIp": vnic["privateIp"], "publicIp": "203.0.113.10", "isPrimary": true, "skipSourceDestCheck": false, "lifecycleState": "AVAILABLE"})
	case "bootVolumeAttachments":
		json.MarshalWrite(w, []map[string]any{{"instanceId": instanceID, "bootVolumeId": bootID, "lifecycleState": "ATTACHED"}})
	case "bootVolumes":
		json.MarshalWrite(w, map[string]any{"id": bootID, "compartmentId": instance["compartmentId"], "imageId": source["imageId"], "sizeInGBs": source["bootVolumeSizeInGBs"], "vpusPerGB": source["bootVolumeVpusPerGB"], "lifecycleState": "AVAILABLE"})
	}
	return true
}

func (c *provisionCloud) checkLaunchReservation(r *http.Request, body map[string]any, token string) {
	wire, err := json.Marshal(body, json.Deterministic(true))
	if err != nil {
		c.test.Error(err)
		return
	}
	entry, _ := catalog.CellForOCIRegion(c.region(r))
	saved := c.journal(entry.Cell)
	if c.hasAnchor() {
		c.test.Error("original launch followed public anchor")
	}
	if body["displayName"] == "gru-1-netbird-manager" {
		pending := saved.NetBirdManager
		if pending == nil || token == "" || pending.RetryToken != token || pending.RequestDigest != digestSource(wire) {
			c.test.Error("manager effect lacks exact durable reservation")
		}
		return
	}
	for _, expected := range []struct {
		name string
		wire []byte
	}{
		{foundationRootChainObject, c.bundle.RootChainWire},
		{"bootstrap/" + foundationGrantObject, c.bundle.GrantWire},
	} {
		wire, err := os.ReadFile(c.objectPath("gru-1-head/" + expected.name))
		if err != nil || !bytes.Equal(wire, expected.wire) {
			c.test.Errorf("original launch lacks exact protected prerequisite %s: %v", expected.name, err)
		}
	}
	for _, cell := range []string{"GRU", "SFO", "FRA"} {
		if c.journal(cell).Stage != "reconciled" {
			c.test.Errorf("original launch preceded %s foundation reconciliation", cell)
		}
	}
	pending := saved.FoundationWriter
	if pending == nil || pending.Cell != entry.Cell || token == "" || pending.RetryToken != token || pending.RequestDigest != digestSource(wire) || pending.InstanceID != "" {
		c.test.Error("original launch lacks exact pending durable reservation")
	}
	if pending == nil || pending.OriginalQuote == nil || pending.validate() != nil {
		c.test.Error("original launch lacks its exact durable original tariff quote")
	}
}

func (c *provisionCloud) checkPolicyReservation(body map[string]any, token string) {
	if c.hasAnchor() {
		c.test.Error("original policy followed public anchor")
	}
	for _, cell := range []string{"GRU", "SFO", "FRA"} {
		pending := c.journal(cell).FoundationWriter
		if pending == nil || pending.Policy == nil || pending.Policy.Request.Name == nil || *pending.Policy.Request.Name != body["name"] {
			continue
		}
		actual, err := json.Marshal(body, json.Deterministic(true))
		if err != nil {
			c.test.Error(err)
			return
		}
		expected, err := foundationWriterPolicyBody(pending.Policy.Request)
		if err != nil {
			c.test.Error(err)
			return
		}
		if pending.InstanceID == "" || token == "" || pending.Policy.RetryToken != token || !bytes.Equal(actual, expected) || pending.Policy.RequestDigest != digestSource(expected) {
			c.test.Error("writer policy lacks exact durable original-instance reservation")
		}
		return
	}
	c.test.Error("writer policy has no protected regional reservation")
}
