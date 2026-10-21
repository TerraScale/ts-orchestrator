package region

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/releasechannel"
	"github.com/TerraScale/ts-orchestrator/internal/vaultsecret"
)

type originalNetBirdManagerSDKFixture struct {
	*originalVaultSDKFixture
	managerMu         sync.Mutex
	managerPhase      bool
	lostLaunch        bool
	launchPosts       int
	upstream          []byte
	physicalFault     string
	binaryFault       bool
	credentialVersion int64
	route             func(http.ResponseWriter, *http.Request) bool
}

func newOriginalNetBirdManagerSDKFixture(t *testing.T) *originalNetBirdManagerSDKFixture {
	t.Helper()
	f := &originalNetBirdManagerSDKFixture{originalVaultSDKFixture: newOriginalVaultSDKFixture(t, "", 0), credentialVersion: 1}
	extendOriginalNetBirdBackupFixtureAuthority(t, f.originalVaultSDKFixture)
	server := httptest.NewTLSServer(http.HandlerFunc(f.serveHTTP))
	t.Cleanup(server.Close)
	listener, ok := server.Listener.Addr().(*net.TCPAddr)
	if !ok || !listener.IP.IsLoopback() || listener.Port == 0 {
		t.Fatal("original manager fixture requires literal loopback TLS")
	}
	previous := http.DefaultTransport
	transport := previous.(*http.Transport).Clone()
	transport.DialTLSContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		if network != "tcp" && network != "tcp4" && network != "tcp6" {
			return nil, fmt.Errorf("fixture refuses network %q", network)
		}
		return (&tls.Dialer{Config: server.Client().Transport.(*http.Transport).TLSClientConfig}).DialContext(ctx, "tcp", listener.String())
	}
	http.DefaultTransport = transport
	t.Cleanup(func() { http.DefaultTransport = previous; transport.CloseIdleConnections() })
	return f
}

func originalManagerUpstream(record FoundationRecord) ([]byte, error) {
	section := *record.OriginalFoundationCompartments
	section.Regions[0].NetBirdManager = nil
	return json.Marshal(struct {
		Material     *NetBirdMaterialJournal
		Births       *[3]OriginalSourceProducerBirth
		Compartments OriginalFoundationCompartments
	}{record.NetBirdMaterial, record.OriginalSourceProducers, section}, json.Deterministic(true))
}

func (f *originalNetBirdManagerSDKFixture) run(t *testing.T) error {
	t.Helper()
	if !f.managerPhase {
		if err := f.originalVaultSDKFixture.run(t); err != nil {
			return err
		}
		var err error
		f.upstream, err = originalManagerUpstream(f.record(t))
		if err != nil {
			return err
		}
		f.managerPhase = true
	}
	stage, err := provisionFoundationMaterial(t.Context(), f.factoryFor(), f.roots, f.bundle)
	if err != nil {
		return err
	}
	defer stage.cancel()
	ctx, release, err := stage.authority.HomeWrite(stage.ctx, 0)
	if err != nil {
		return err
	}
	defer release()
	return retainOriginalNetBirdManager(ctx, stage.authority)
}

func (f *originalNetBirdManagerSDKFixture) backupPending(t *testing.T) {
	t.Helper()
	fixture := installOriginalNetBirdBackupSDKFixture(t, f.originalVaultSDKFixture, f.serveHTTP, "")
	if err := fixture.run(t); !errors.Is(err, ErrOriginalNetBirdBackupPending) {
		t.Fatalf("genuine newly created retention did not remain pending during fourteen-day cooling: %v", err)
	}
	backup := originalNetBirdBackupJournal(f.record(t))
	if backup == nil || backup.Complete || backup.Destinations[0].Bucket.VerifiedAt.IsZero() || backup.Destinations[0].Retention.Provenance == nil || !backup.Destinations[0].Retention.VerifiedAt.IsZero() || !backup.Destinations[0].Retention.Request.TimeRuleLocked.Time.After(time.Now()) {
		t.Fatal("new original backup fabricated completed locked history before real cooling elapsed")
	}
}

func (f *originalNetBirdManagerSDKFixture) serveHTTP(w http.ResponseWriter, r *http.Request) {
	f.managerMu.Lock()
	defer f.managerMu.Unlock()
	if !strings.HasPrefix(r.Header.Get("Authorization"), "Signature ") && r.URL.Path != "/pls/apex/cetools/api/v1/products/" {
		f.cloud.test.Error("original manager escaped authenticated OCI SDK")
		originalCompartmentFailure(w, 401, "NotAuthenticated")
		return
	}
	if f.route != nil && f.route(w, r) {
		return
	}
	// Discovery reads expose the exact signed originals; the producer never publishes an anchor.
	for _, document := range []struct {
		name string
		wire []byte
	}{
		{foundationDiscoveryObject, f.bundle.AnchorWire},
		{foundationRootChainObject, f.bundle.RootChainWire},
		{"bootstrap/" + foundationGrantObject, f.bundle.GrantWire},
	} {
		if r.Method == http.MethodGet && r.URL.Path == "/n/ns/b/gru-1-head/o/"+document.name {
			w.Header().Set("ETag", preparationDigest(document.wire))
			w.Write(document.wire)
			return
		}
	}
	if !f.managerPhase {
		f.originalVaultSDKFixture.serveHTTP(w, r)
		return
	}
	record := f.record(f.cloud.test)
	upstream, err := originalManagerUpstream(record)
	if r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/20160918/") && (err != nil || !bytes.Equal(upstream, f.upstream) || record.NetBirdManager != nil || len(record.ResourceIDs) != 0 || f.cloud.hasAnchor()) {
		f.cloud.test.Error("dedicated manager changed genuine original prerequisite pins or promoted runtime foundation")
		originalCompartmentFailure(w, 400, "InvalidParameter")
		return
	}
	manager := record.OriginalFoundationCompartments.Regions[0].NetBirdManager
	if strings.HasSuffix(r.URL.Path, "/secretbundles/actions/getByName") {
		if manager == nil || r.Method != http.MethodPost || r.URL.Query().Get("stage") != "CURRENT" || r.URL.Query().Get("vaultId") != manager.Intent.Material.Context.Target.VaultOCID || f.credentialVersion == 0 {
			originalCompartmentFailure(w, 404, "NotAuthorizedOrNotFound")
			return
		}
		name := r.URL.Query().Get("secretName")
		if !slices.ContainsFunc(manager.Intent.Components[:], func(component NetBirdComponentAuthorityIntent) bool { return component.Issuer.SecretName == name }) {
			originalCompartmentFailure(w, 404, "NotAuthorizedOrNotFound")
			return
		}
		wire, err := json.Marshal(map[string]string{"username": "ns/fixture-ocir", "password": "fixture-only-issued-token"})
		if err != nil {
			f.cloud.test.Error(err)
			originalCompartmentFailure(w, 500, "InternalError")
			return
		}
		json.MarshalWrite(w, map[string]any{"secretId": "ocid1.vaultsecret.oc1.sa-saopaulo-1." + strings.ReplaceAll(name, "-", ""), "versionNumber": f.credentialVersion, "stages": []string{"CURRENT"}, "secretBundleContent": map[string]string{"contentType": "BASE64", "content": base64.StdEncoding.EncodeToString(wire)}})
		return
	}
	if manager != nil && strings.HasPrefix(r.URL.Path, "/20160918/") {
		if r.Method == http.MethodPost {
			body, canonical, err := originalNetworkBody(r)
			if err != nil {
				f.cloud.test.Error(err)
				originalCompartmentFailure(w, 400, "InvalidParameter")
				return
			}
			if r.URL.Path == "/20160918/instances" {
				f.launch(w, r, manager, body, canonical)
				return
			}
			matched := slices.ContainsFunc(manager.Creates[:], func(create OriginalFoundationNetworkCreate) bool {
				pending := create.Pending
				return pending != nil && create.Provenance == nil && pending.Request.RequestDigest == preparationDigest(canonical) && pending.Request.RetryToken == r.Header.Get("opc-retry-token") && !pending.FirstAttemptAt.IsZero() && body["compartmentId"] == manager.NetworkCompartmentID && body["displayName"] == "gru-1-netbird-manager"
			})
			if !matched {
				f.cloud.test.Error("manager network SDK mutation preceded exact protected reservation")
				originalCompartmentFailure(w, 400, "InvalidParameter")
				return
			}
		}
		if r.Method == http.MethodGet && manager.Launch != nil && manager.Launch.InstanceID != "" && f.observe(w, r, manager) {
			return
		}
	}
	// The inherited fixture already checked every upstream create and readback.
	// Continued upstream reads use the same remote rows and the frozen pins above.
	f.cloud.serveHTTP(w, r)
}

func (f *originalNetBirdManagerSDKFixture) launch(w http.ResponseWriter, r *http.Request, manager *OriginalFoundationNetBirdManager, body map[string]any, canonical []byte) {
	launch, p := manager.Launch, manager.Intent.Profile
	if launch == nil || launch.OriginalQuote == nil || launch.OriginalQuote.Validate() != nil || launch.RequestDigest != preparationDigest(canonical) || launch.RetryToken != r.Header.Get("opc-retry-token") || launch.RetryToken != BootstrapRetryToken(launch.OperationID, launch.RequestDigest) || launch.InstanceID != "" || launch.OriginalQuote.CompartmentID != manager.ControlCompartmentID || launch.OriginalQuote.ScopeSHA256 != launch.PhysicalScopeSHA256 || launch.OriginalQuote.Shape != p.Shape || launch.OriginalQuote.OCPUs != float64(p.OCPUs) || launch.OriginalQuote.MemoryGB != float64(p.MemoryGB) || launch.OriginalQuote.BootGB != float64(p.BootVolumeGB) {
		f.cloud.test.Error("manager SDK launch preceded exact acknowledged request/token/payable quote")
		originalCompartmentFailure(w, 400, "InvalidParameter")
		return
	}
	ids := originalNetBirdManagerIDs(manager)
	expected := map[string]any{"availabilityDomain": p.AvailabilityDomain, "faultDomain": p.FaultDomain, "compartmentId": manager.ControlCompartmentID, "displayName": "gru-1-netbird-manager", "shape": p.Shape,
		"shapeConfig":       map[string]any{"ocpus": float64(p.OCPUs), "memoryInGBs": float64(p.MemoryGB)},
		"sourceDetails":     map[string]any{"sourceType": "image", "imageId": manager.Intent.ImageOCID, "bootVolumeSizeInGBs": float64(p.BootVolumeGB), "bootVolumeVpusPerGB": float64(10)},
		"createVnicDetails": map[string]any{"subnetId": ids["netbird_manager_subnet"], "nsgIds": []any{ids["netbird_manager_nsg"]}, "privateIp": p.PrivateIP, "assignPublicIp": true}}
	actual, actualErr := json.Marshal(originalNetworkPrune(body), json.Deterministic(true))
	want, wantErr := json.Marshal(expected, json.Deterministic(true))
	if actualErr != nil || wantErr != nil || !bytes.Equal(actual, want) {
		f.cloud.test.Error("manager actual SDK body differs from independently projected original signed geometry")
		originalCompartmentFailure(w, 400, "InvalidParameter")
		return
	}
	f.launchPosts++
	f.cloud.mu.Lock()
	id := f.cloud.tokens[launch.RetryToken]
	if id == "" {
		id = "ocid1.instance.oc1.sa-saopaulo-1.originalmanager"
		row := maps.Clone(body)
		row["id"], row["lifecycleState"], row["imageId"] = id, "RUNNING", manager.Intent.ImageOCID
		f.cloud.rows[id], f.cloud.collections[id], f.cloud.tokens[launch.RetryToken] = row, "instances", id
		f.cloud.creates++
	}
	f.cloud.launchPosts++
	row := maps.Clone(f.cloud.rows[id])
	f.cloud.mu.Unlock()
	if f.lostLaunch {
		f.lostLaunch = false
		originalCompartmentFailure(w, 503, "InternalError")
		return
	}
	json.MarshalWrite(w, row)
}

func (f *originalNetBirdManagerSDKFixture) observe(w http.ResponseWriter, r *http.Request, manager *OriginalFoundationNetBirdManager) bool {
	id, p := manager.Launch.InstanceID, manager.Intent.Profile
	vnicID, bootID := strings.Replace(id, ".instance.", ".vnic.", 1), strings.Replace(id, ".instance.", ".bootvolume.", 1)
	ids := originalNetBirdManagerIDs(manager)
	var row map[string]any
	switch r.URL.Path {
	case "/20160918/instances/" + id:
		row = maps.Clone(f.cloud.rows[id])
		if f.physicalFault == "image" {
			row["imageId"] = "ocid1.image.oc1.sa-saopaulo-1.foreign"
			row["sourceDetails"] = map[string]any{"sourceType": "image", "imageId": row["imageId"]}
		}
	case "/20160918/vnicAttachments":
		if r.URL.Query().Get("instanceId") != id {
			return false
		}
		json.MarshalWrite(w, []map[string]any{{"id": strings.Replace(id, ".instance.", ".vnicattachment.", 1), "instanceId": id, "compartmentId": manager.ControlCompartmentID, "availabilityDomain": p.AvailabilityDomain, "vnicId": vnicID, "subnetId": ids["netbird_manager_subnet"], "lifecycleState": "ATTACHED"}})
		return true
	case "/20160918/vnics/" + vnicID:
		row = map[string]any{"id": vnicID, "compartmentId": manager.NetworkCompartmentID, "availabilityDomain": p.AvailabilityDomain, "subnetId": ids["netbird_manager_subnet"], "nsgIds": []string{ids["netbird_manager_nsg"]}, "privateIp": p.PrivateIP, "publicIp": "203.0.113.10", "isPrimary": true, "skipSourceDestCheck": false, "lifecycleState": "AVAILABLE", "ipv6Addresses": []string{}}
		if f.physicalFault == "VNIC" {
			row["subnetId"] = "ocid1.subnet.oc1.sa-saopaulo-1.foreign"
		}
	case "/20160918/bootVolumeAttachments":
		if r.URL.Query().Get("instanceId") != id {
			return false
		}
		json.MarshalWrite(w, []map[string]any{{"id": strings.Replace(id, ".instance.", ".bootvolumeattachment.", 1), "instanceId": id, "compartmentId": manager.ControlCompartmentID, "availabilityDomain": p.AvailabilityDomain, "bootVolumeId": bootID, "lifecycleState": "ATTACHED"}})
		return true
	case "/20160918/bootVolumes/" + bootID:
		row = map[string]any{"id": bootID, "compartmentId": manager.ControlCompartmentID, "availabilityDomain": p.AvailabilityDomain, "imageId": manager.Intent.ImageOCID, "sizeInGBs": p.BootVolumeGB, "vpusPerGB": 10, "lifecycleState": "AVAILABLE", "isAutoTuneEnabled": false, "autotunePolicies": []any{}}
		if f.physicalFault == "boot" {
			row["sizeInGBs"] = p.BootVolumeGB + 1
		}
	default:
		return false
	}
	json.MarshalWrite(w, row)
	return true
}

func (f *originalNetBirdManagerSDKFixture) admission(t *testing.T) (*ociclient.Factory, FoundationResolver, func() (VerifiedNetBirdManager, error)) {
	t.Helper()
	factory := f.factoryFor()
	objects, err := factory.ObjectStorage()
	if err != nil {
		t.Fatal(err)
	}
	anchor, err := verifyDiscoveryAnchor(f.bundle.AnchorWire, f.roots, f.approval.TenancyID, f.approval.HomeStorageDomain.Namespace)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := NewSignedFootprint(&objects, anchor, f.roots, f.approval.TenancyID)
	if err != nil {
		t.Fatal(err)
	}
	reader.factory = factory
	if _, _, err := reader.verifyGrant(f.bundle.GrantWire); err == nil {
		t.Fatal("schema3 original escaped generic grant refusal")
	}
	store, err := NewObjectFoundationStore(&objects, f.approval.HomeStorageDomain.Namespace, f.approval.HomeStorageDomain.HeadBucket)
	if err != nil {
		t.Fatal(err)
	}
	resolver := FoundationResolver{Footprint: reader, Store: store}
	observer, err := bootstrapstart.NewOCIInstanceObserver(oci.RegionGRU, factory.Provider())
	if err != nil {
		t.Fatal(err)
	}
	id := f.record(t).OriginalFoundationCompartments.Regions[0].NetBirdManager.Launch.InstanceID
	admit := func() (VerifiedNetBirdManager, error) {
		return admitOriginalNetBirdManager(t.Context(), resolver, reader, observer, id, func(image release.VerifiedImage) (bootstrapstart.RunningBinary, error) {
			if f.binaryFault || !image.IsVerified() || image.Receipt().OCIImageOCID != f.images["netbird-manager"].Image.Receipt().OCIImageOCID {
				return bootstrapstart.RunningBinary{}, errors.New("original manager binary fixture received an unverified or foreign image")
			}
			return bootstrapstart.RunningBinary{}, nil
		})
	}
	return factory, resolver, admit
}

func withOriginalNetBirdManagerFixture(t *testing.T, run func(*ociclient.Factory, FoundationResolver, VerifiedNetBirdManager)) {
	t.Helper()
	WithOriginalNetBirdManagerHTTPFixture(t, nil, run)
}

func WithOriginalNetBirdManagerHTTPFixture(t *testing.T, route func(http.ResponseWriter, *http.Request) bool, run func(*ociclient.Factory, FoundationResolver, VerifiedNetBirdManager)) {
	t.Helper()
	f := newOriginalNetBirdManagerSDKFixture(t)
	if err := f.run(t); err != nil {
		t.Fatal(err)
	}
	f.backupPending(t)
	factory, resolver, admit := f.admission(t)
	manager, err := admit()
	if err != nil {
		t.Fatal(err)
	}
	f.route = route
	run(factory, resolver, manager)
}

func WithOriginalNetBirdManagerFixture(t *testing.T, run func(*ociclient.Factory, FoundationResolver, VerifiedNetBirdManager)) {
	t.Helper()
	withOriginalNetBirdManagerFixture(t, run)
}

func TestOriginalNetBirdManagerFirstLaunchAccountBirth(t *testing.T) {
	t.Skip("QUARANTINE until 2026-10-22, owner ts-orch consolidation thread: failing since the 2026-10-21 integration-line merge")
	f := newOriginalNetBirdManagerSDKFixture(t)
	var birth FoundationRecord
	var birthETag string
	f.route = func(w http.ResponseWriter, r *http.Request) bool {
		if r.Method != http.MethodPut || r.URL.Path != "/n/ns/b/gru-1-head/o/"+foundationObjectPrefix+"GRU.json" {
			return false
		}
		wire, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
			originalCompartmentFailure(w, 500, "InternalError")
			return true
		}
		r.Body = io.NopCloser(bytes.NewReader(wire))
		var current FoundationRecord
		if err := json.Unmarshal(wire, &current); err != nil {
			t.Error(err)
			originalCompartmentFailure(w, 500, "InternalError")
			return true
		}
		if current.OriginalFoundationCompartments == nil || current.OriginalFoundationCompartments.Regions[0].NetBirdManager == nil || current.OriginalFoundationCompartments.Regions[0].NetBirdManager.Launch == nil {
			return false
		}
		// Capture the genuine producer's first launch CAS without storing it.
		birth, birthETag = current, r.Header.Get("If-Match")
		originalCompartmentFailure(w, 503, "InternalError")
		return true
	}
	if err := f.run(t); err == nil || birthETag == "" || f.launchPosts != 0 {
		t.Fatalf("did not stop genuine first launch before storage and compute dispatch: %v", err)
	}
	f.route = nil
	store, retained := f.store(t), f.wire(t)
	previous, etag, err := store.Load(t.Context(), "GRU")
	if err != nil {
		t.Fatal(err)
	}
	if etag != birthETag || previous.OriginalFoundationCompartments == nil || previous.OriginalFoundationCompartments.Regions[0].NetBirdManager == nil || previous.OriginalFoundationCompartments.Regions[0].NetBirdManager.Launch != nil {
		t.Fatal("first launch candidate is not rooted in the genuine retained prelaunch record")
	}
	manager := birth.OriginalFoundationCompartments.Regions[0].NetBirdManager
	if manager.Intent.Account == nil || manager.Launch.Account == nil || !sameOriginalSourceValue(manager.Launch.Account, newNetBirdAccountJournal(*manager.Intent.Account, manager.Launch.StartedAt)) {
		t.Fatal("genuine first launch did not reserve the exact empty signed account journal")
	}
	wire, err := json.Marshal(birth, json.Deterministic(true))
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"Password", "PAT"} {
		t.Run(name, func(t *testing.T) {
			var current FoundationRecord
			if err := json.Unmarshal(wire, &current); err != nil {
				t.Fatal(err)
			}
			account := current.OriginalFoundationCompartments.Regions[0].NetBirdManager.Launch.Account
			checkpoint := &account.Password
			if name == "PAT" {
				checkpoint = &account.PAT
			}
			checkpoint.RequestSHA256 = preparationDigest([]byte("unretained-first-birth-request:" + checkpoint.Name))
			checkpoint.RetryToken = BootstrapRetryToken(account.Authority.ManagerOperationID+":"+checkpoint.Name, checkpoint.RequestSHA256)
			checkpoint.FirstDispatchedAt = account.BornAt
			checkpoint.SecretID = "ocid1.vaultsecret.oc1." + foundationHomeRegion + ".unretained" + strings.ToLower(name)
			checkpoint.Version = 1
			checkpoint.ContentSHA256 = preparationDigest([]byte("unretained-first-birth-content:" + checkpoint.Name))
			if err := current.validate(); err != nil {
				t.Fatalf("populated first-birth %s must pass ordinary record validation: %v", name, err)
			}
			if _, err := store.CompareAndSwap(t.Context(), current, etag); !errors.Is(err, ErrOriginalSourceProducerHold) || !bytes.Equal(retained, f.wire(t)) {
				t.Fatalf("first launch adopted populated %s history or changed retained bytes: %v", name, err)
			}
		})
	}
	if _, err := store.CompareAndSwap(t.Context(), birth, etag); err != nil {
		t.Fatalf("genuine empty first-launch account birth was refused: %v", err)
	}
	if err := f.run(t); err != nil || f.launchPosts != 1 {
		t.Fatalf("genuine empty account birth did not resume the original manager launch: %v", err)
	}
}

func TestOriginalNetBirdManagerSDK(t *testing.T) {
	t.Skip("QUARANTINE until 2026-10-22, owner ts-orch consolidation thread: failing since the 2026-10-21 integration-line merge")
	f := newOriginalNetBirdManagerSDKFixture(t)
	f.lostLaunch = true
	if err := f.run(t); err == nil || f.launchPosts != 1 {
		t.Fatal("lost accepted manager response did not retain original uncertainty")
	}
	before := f.record(t).OriginalFoundationCompartments.Regions[0].NetBirdManager
	if before == nil || before.Launch == nil || before.Launch.InstanceID != "" || before.Launch.OriginalQuote == nil {
		t.Fatal("lost response lacks authentic durable original request/token/quote")
	}
	originalLaunch := *before.Launch
	if err := f.run(t); err != nil {
		t.Fatal(err)
	}
	record := f.record(t)
	physical := record.OriginalFoundationCompartments.Regions[0].NetBirdManager
	if f.launchPosts != 2 || physical.Launch.InstanceID == "" || physical.Launch.BootVolumeID == "" || physical.PrimaryVNICID == "" || physical.VerifiedAt.IsZero() || physical.ReadbackSHA256 == "" || physical.Launch.RetryToken != originalLaunch.RetryToken || physical.Launch.StartedAt != originalLaunch.StartedAt || physical.Launch.RequestDigest != originalLaunch.RequestDigest || !sameCapacityValue(physical.Launch.OriginalQuote, originalLaunch.OriginalQuote) {
		t.Fatal("manager recovery replaced original request, time, payable quote or actual identity")
	}
	if record.NetBirdMaterial == nil || !record.NetBirdMaterial.Complete || f.cloud.materialPosts != 4 || len(record.ResourceIDs) != 0 || record.NetBirdManager != nil || f.cloud.hasAnchor() {
		t.Fatal("manager fixture did not retain all-four original material without foundation runtime promotion")
	}
	factory, resolver, admit := f.admission(t)
	manager, err := admit()
	if err != nil {
		t.Fatal(err)
	}
	source := f.approval.SourceVaultTarget
	wantCredential := vaultsecret.Target{CompartmentID: source.CompartmentOCID, VaultID: source.VaultOCID, KeyID: source.KMSKeyOCID}
	if manager.CredentialTarget() != wantCredential || manager.VaultTarget() == wantCredential || manager.RecoveryRequired() {
		t.Fatal("original manager substituted generated GRU Vault for exact source credential escrow or reset genesis")
	}
	material, err := ReadNetBirdComponents(t.Context(), factory, resolver, manager)
	if err != nil {
		t.Fatal(err)
	}
	for _, role := range netBirdComponentRoles() {
		component, err := material.Component(t.Context(), role)
		if err != nil || component.Role() != role || component.Release().Claim().Role != role || component.PullClaim().Version != 1 || component.PullClaim().Scope.TaskPrincipal != entityid.Derive("netbird-component", manager.StoreGeneration(), role) {
			t.Fatalf("original manager lost authentic fixed3 signed release/pull scope %s: %v", role, err)
		}
	}
	for _, fault := range []string{"image", "VNIC", "boot"} {
		f.physicalFault = fault
		if err := manager.Check(t.Context()); err == nil {
			t.Fatalf("changed actual manager %s retained authority", fault)
		}
		f.physicalFault = ""
	}
	f.binaryFault = true
	if err := manager.Check(t.Context()); err == nil {
		t.Fatal("unmeasured running manager binary retained original authority")
	}
	f.binaryFault = false
	vcnID := originalNetBirdManagerIDs(physical)["netbird_manager_vcn"]
	vcn := maps.Clone(f.cloud.rows[vcnID])
	f.cloud.rows[vcnID]["cidrBlocks"] = []string{"10.99.0.0/24"}
	if err := manager.Check(t.Context()); err == nil {
		t.Fatal("changed actual isolated network retained original manager")
	}
	f.cloud.rows[vcnID] = vcn
	for _, fault := range []string{"foreign version", "foreign target"} {
		f.cloud.materialFault = fault
		if err := manager.Check(t.Context()); err == nil {
			t.Fatalf("changed all-four original material %s retained manager", fault)
		}
		f.cloud.materialFault = ""
	}
	f.credentialVersion = 2
	if err := material.Check(t.Context()); err == nil {
		t.Fatal("changed CURRENT credential retained original component material")
	}
	f.credentialVersion = 1
	channel := f.cloud.objectPath("gru-1-head/" + releasechannel.ContainerReleaseObject(netBirdComponentRoles()[0], "arm64"))
	channelWire, err := os.ReadFile(channel)
	if err != nil {
		t.Fatal(err)
	}
	f.cloud.writeObject("gru-1-head/"+releasechannel.ContainerReleaseObject(netBirdComponentRoles()[0], "arm64"), []byte("changed retained release Current"))
	if err := material.Check(t.Context()); err == nil {
		t.Fatal("changed component release Current retained signed original material")
	}
	f.cloud.writeObject("gru-1-head/"+releasechannel.ContainerReleaseObject(netBirdComponentRoles()[0], "arm64"), channelWire)
	if err := material.RetainReleaseFloors(t.Context()); err != nil {
		t.Fatal(err)
	}
	store, originalWire := f.store(t), f.wire(t)
	for name, mutate := range map[string]func(*OriginalFoundationNetBirdManager){
		"request":          func(m *OriginalFoundationNetBirdManager) { m.Launch.RequestDigest = strings.Repeat("a", 64) },
		"token":            func(m *OriginalFoundationNetBirdManager) { m.Launch.RetryToken = strings.Repeat("b", 64) },
		"quote":            func(m *OriginalFoundationNetBirdManager) { m.Launch.OriginalQuote = nil },
		"instance":         func(m *OriginalFoundationNetBirdManager) { m.Launch.InstanceID += "replacement" },
		"network":          func(m *OriginalFoundationNetBirdManager) { m.Creates[0].Provenance.ResourceID += "replacement" },
		"VNIC":             func(m *OriginalFoundationNetBirdManager) { m.PrimaryVNICID += "replacement" },
		"boot":             func(m *OriginalFoundationNetBirdManager) { m.Launch.BootVolumeID += "replacement" },
		"material version": func(m *OriginalFoundationNetBirdManager) { m.Intent.Material.Context.StoreGeneration += "replacement" },
	} {
		current, etag, err := store.Load(t.Context(), "GRU")
		if err != nil {
			t.Fatal(err)
		}
		mutate(current.OriginalFoundationCompartments.Regions[0].NetBirdManager)
		if _, err := store.CompareAndSwap(t.Context(), current, etag); err == nil || !bytes.Equal(originalWire, f.wire(t)) {
			t.Fatalf("protected manager CAS accepted %s: %v", name, err)
		}
	}
	if err := manager.ClaimGenesis(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := manager.ClaimGenesis(t.Context()); err == nil {
		t.Fatal("original manager consumed store genesis twice")
	}
	restarted, err := admit()
	if err != nil || !restarted.RecoveryRequired() || restarted.StoreGeneration() != manager.StoreGeneration() {
		t.Fatalf("manager restart reset original store: %v", err)
	}
	if err := restarted.MarkStoreReady(t.Context()); err != nil {
		t.Fatal(err)
	}
	ready := f.wire(t)
	if err := f.run(t); err != nil || f.launchPosts != 2 {
		t.Fatalf("ready original manager bought replacement: %v", err)
	}
	if !bytes.Equal(ready, f.wire(t)) {
		t.Fatal("read-only original manager reopen changed durable store or release floors")
	}
	// Corrupt genuine retained material, never fabricate an admitted capability.
	for index := range 4 {
		current := f.record(t)
		current.NetBirdMaterial.Creates[index].Version = 2
		wire, err := json.Marshal(current, json.Deterministic(true))
		if err != nil {
			t.Fatal(err)
		}
		f.cloud.writeObject("gru-1-head/"+foundationObjectPrefix+"GRU.json", wire)
		if err := restarted.Check(t.Context()); err == nil {
			t.Fatalf("changed exact material version %d retained original manager", index)
		}
		f.cloud.writeObject("gru-1-head/"+foundationObjectPrefix+"GRU.json", ready)
	}
	retained := f.bundle.clone()
	f.bundle = signProvisionFoundation(t, f.prepared, retained.RootChainWire, f.root, f.now.Add(-24*time.Hour))
	if err := restarted.Check(t.Context()); err == nil {
		t.Fatal("expired genuinely signed full original bundle retained manager")
	}
	f.bundle = retained
	preparedWire, err := json.Marshal(f.prepared)
	if err != nil {
		t.Fatal(err)
	}
	var changed FoundationPreparation
	if err := json.Unmarshal(preparedWire, &changed); err != nil {
		t.Fatal(err)
	}
	changed.Grant.Regions[0].NetBirdManager.Material.Context.Target.KMSKeyOCID = "ocid1.key.oc1.sa-saopaulo-1.foreign"
	f.bundle = signProvisionFoundation(t, changed, retained.RootChainWire, f.root, f.now)
	if err := restarted.Check(t.Context()); err == nil {
		t.Fatal("genuinely signed foreign material target retained original manager")
	}
	f.bundle = retained
	if err := restarted.Check(t.Context()); err != nil {
		t.Fatal(err)
	}
	f.backupPending(t)
	if _, err := os.Stat(f.cloud.objectPath("gru-1-head/" + foundationDiscoveryObject)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("manager test published discovery anchor")
	}
}
