package region

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json/v2"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/capacityinventory"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/foundation"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/core"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"
)

// The consumer independently verifies signed Object Storage bytes, protected
// creation checkpoints, live compartment ancestry and current public tariffs.
func TestLogicalSpendingBindingsRetainSignedAuthority(t *testing.T) {
	store, objects, write := foundationProtocolStore(t)
	objectURL, err := url.Parse(objects.(*objectstorage.ObjectStorageClient).Host)
	if err != nil {
		t.Fatal(err)
	}
	proxy := httputil.NewSingleHostReverseProxy(objectURL)
	const tenancy = "ocid1.tenancy.oc1..test"
	const parent = "ocid1.compartment.oc1..parent"
	const control = "ocid1.compartment.oc1..control"
	var wrongParent atomic.Bool
	var controlReads atomic.Int64
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasPrefix(r.URL.Path, "/n/"):
			proxy.ServeHTTP(w, r)
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/20160918/compartments/"):
			if r.Header.Get("Authorization") == "" {
				t.Error("unsigned compartment observation")
			}
			id := strings.TrimPrefix(r.URL.Path, "/20160918/compartments/")
			observedParent := parent
			if id == control {
				controlReads.Add(1)
				if wrongParent.Load() {
					observedParent = "ocid1.compartment.oc1..foreign"
				}
			}
			fmt.Fprintf(w, `{"id":%q,"compartmentId":%q,"lifecycleState":"ACTIVE"}`, id, observedParent)
		case r.Method == http.MethodGet && r.URL.Path == "/pls/apex/cetools/api/v1/products/":
			metric := map[string]string{"B93297": "OCPU Per Hour", "B93298": "Gigabyte Per Hour", "B91961": "Gigabyte Storage Capacity Per Month", "B91962": "Performance Units Per Gigabyte Per Month"}[r.URL.Query().Get("partNumber")]
			if metric == "" {
				t.Errorf("unexpected tariff SKU %s", r.URL.RawQuery)
			}
			fmt.Fprintf(w, `{"lastUpdated":%q,"items":[{"partNumber":%q,"metricName":%q,"currencyCodeLocalizations":[{"currencyCode":"USD","prices":[{"model":"PAY_AS_YOU_GO","value":0.001}]}]}]}`, time.Now().UTC().Format(time.RFC3339), r.URL.Query().Get("partNumber"), metric)
		default:
			t.Errorf("unexpected spending binding request %s %s", r.Method, r.URL)
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	transport := http.DefaultTransport.(*http.Transport).Clone()
	original := http.DefaultTransport
	transport.DialTLSContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&tls.Dialer{Config: server.Client().Transport.(*http.Transport).TLSClientConfig}).DialContext(ctx, network, strings.TrimPrefix(server.URL, "https://"))
	}
	http.DefaultTransport = transport
	t.Cleanup(func() { http.DefaultTransport = original; transport.CloseIdleConnections() })
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	provider := common.NewRawConfigurationProvider(tenancy, "ocid1.user.oc1..test", "sa-saopaulo-1", "test", string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})), nil)
	factory, err := ociclient.New(provider, ociclient.Options{Region: "sa-saopaulo-1", Retry: ociclient.RetryOptions{MaxAttempts: 1}})
	if err != nil {
		t.Fatal(err)
	}
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
	reader := &SignedFootprint{client: objects, factory: factory, storage: bootstrap.StorageDomain{Namespace: "ns", HeadBucket: "heads", Prefix: "bootstrap"},
		scope: scope, expires: now.Add(2 * time.Hour), roots: roots, tenancy: tenancy, home: bootstrap.FoundationScope{InstallationID: entityid.New(), GrantGeneration: 1}}
	ref, err := FoundationResourceReference("GRU", "control_compartment")
	if err != nil {
		t.Fatal(err)
	}
	slot := BootstrapSlotIntent{SlotID: BootstrapSlotID(reader.home.InstallationID, "GRU", "controller", "controller-a"), Cell: "GRU", Role: "controller", Slot: "controller-a", CompartmentID: ref,
		ProfileSHA256: strings.Repeat("a", 64), RecipeSHA256: strings.Repeat("b", 64), Shape: "VM.Standard.A1.Flex", OCPUs: 2, MemoryGB: 4, BootGB: 50, MonthlyLimitMinor: 2000}
	grant := FoundationGrant{SchemaVersion: 2, InstallationID: reader.home.InstallationID, Generation: 1, TenancyID: tenancy, ParentCompartmentID: parent, SharedCompartmentID: "ocid1.compartment.oc1..shared", Currency: "USD", MonthlyLimitMinor: 10000, CleanupOwner: "integration",
		Regions: []FoundationIntent{{Generation: 1, Plan: map[string]any{"cell": "GRU", "region": "sa-saopaulo-1", "tenancy_id": tenancy, "parent_compartment_id": parent, "shared_compartment_id": "ocid1.compartment.oc1..shared", "resource_ids": map[string]any{}}}}}
	logicalSHA, err := FoundationInfrastructureScopeDigest(grant)
	if err != nil {
		t.Fatal(err)
	}
	grant.InfrastructureSpend = &InfrastructureSpendIntent{BudgetID: entityid.New(), Currency: "USD", MonthlyLimitMinor: 9000, ScopeSHA256: logicalSHA, Bootstrap: &BootstrapSpendingIntent{ReservedMinor: 2000, Slots: []BootstrapSlotIntent{slot}}}
	payload, err := trust.EncodePayload(grant)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := trust.Sign(payload, scope, now.Add(-time.Minute), now.Add(time.Hour), private)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := trust.EncodeEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}
	grantSHA := sha256.Sum256(wire)
	reader.home.GrantSHA256 = hex.EncodeToString(grantSHA[:])
	write("bootstrap/"+foundationGrantObject, wire)
	intentWire, err := json.Marshal(grant.Regions[0], json.Deterministic(true))
	if err != nil {
		t.Fatal(err)
	}
	intentSHA := sha256.Sum256(intentWire)
	record := FoundationRecord{SchemaVersion: 1, Cell: "GRU", OCIRegion: "sa-saopaulo-1", TenancyID: tenancy, ParentCompartmentID: parent, SharedCompartmentID: grant.SharedCompartmentID, Generation: 1,
		GrantSHA256: reader.home.GrantSHA256, IntentDigest: hex.EncodeToString(intentSHA[:]), OperationID: entityid.Derive("regional-foundation", tenancy, "GRU", "1"), Epoch: 1, Stage: "foundation", LeaseID: entityid.New(), ExpiresAt: now.Add(time.Minute), StartedAt: now, UpdatedAt: now,
		ResourceIDs: map[string]string{"control_compartment": control}, ResourceProvenance: map[string]FoundationResourceProvenance{}}
	checkpoint := func(role, id string) {
		record.ResourceIDs[role] = id
		record.ResourceProvenance[role] = FoundationResourceProvenance{ResourceID: id, Generation: 1, GrantSHA256: record.GrantSHA256, Create: PendingFoundationCreate{OperationID: record.OperationID, IntentDigest: record.IntentDigest, FirstAttemptAt: now,
			Request: foundation.CreateIdentity{Key: role, Region: record.OCIRegion, RequestDigest: strings.Repeat("c", 64), RetryToken: strings.Repeat("d", 64)}}}
	}
	checkpoint("control_compartment", control)
	etag, err := store.CompareAndSwap(t.Context(), record, "")
	if err != nil {
		t.Fatal(err)
	}
	resolver := FoundationResolver{Footprint: reader, Store: store}
	if _, err := reader.BootstrapAllocation(t.Context(), slot.SlotID); err == nil {
		t.Fatal("unresolved signed logical scope became a physical launch allocation")
	}
	allocation, err := resolver.BootstrapAllocation(t.Context(), slot.SlotID)
	if err != nil {
		t.Fatal(err)
	}
	if allocation.SignedSlot() != slot || allocation.Slot().CompartmentID != control || allocation.ScopeDigest() != logicalSHA || allocation.PhysicalScopeDigest() == logicalSHA || !bootstrapSHA256.MatchString(allocation.BindingDigest()) || allocation.ReservedMinor() != 2000 || controlReads.Load() == 0 {
		t.Fatalf("resolved slot lost its original signed identity or independent physical evidence: %+v", allocation)
	}
	if _, err := resolver.InfrastructureSpend(t.Context()); err == nil {
		t.Fatal("ordinary inventory scope omitted unfinished signed compartment roles")
	}
	checkpoint("network_compartment", "ocid1.compartment.oc1..network")
	checkpoint("workload_compartment", "ocid1.compartment.oc1..workload")
	if _, err := store.CompareAndSwap(t.Context(), record, etag); err != nil {
		t.Fatal(err)
	}
	spending, err := resolver.InfrastructureSpend(t.Context())
	if err != nil || spending.ScopeDigest() != logicalSHA || spending.PhysicalScopeDigest() == logicalSHA || spending.Generation() != 1 || spending.GrantDigest() != reader.home.GrantSHA256 || len(spending.Footprint().Regions[0].CompartmentIDs) != 5 {
		t.Fatalf("full spending scope lacks its separate original authority and physical bindings: %+v err=%v", spending, err)
	}
	inventory, err := capacityinventory.New(factory)
	if err != nil {
		t.Fatal(err)
	}
	quote, err := inventory.Quote(t.Context(), allocation.Footprint(), "GRU", control, slot.Shape, slot.OCPUs, slot.MemoryGB, slot.BootGB)
	if err != nil {
		t.Fatal(err)
	}
	requestWire, err := json.Marshal(core.LaunchInstanceDetails{CompartmentId: new(control), Shape: new(slot.Shape), ShapeConfig: &core.LaunchInstanceShapeConfigDetails{Ocpus: new(float32(slot.OCPUs)), MemoryInGBs: new(float32(slot.MemoryGB))}})
	if err != nil {
		t.Fatal(err)
	}
	requestSHA := sha256.Sum256(requestWire)
	request := BootstrapLaunchRequest{SlotID: slot.SlotID, OperationID: allocation.OperationID(), Cell: "GRU", CompartmentID: control, ProfileSHA256: slot.ProfileSHA256, RecipeSHA256: slot.RecipeSHA256, Shape: slot.Shape, OCPUs: slot.OCPUs, MemoryGB: slot.MemoryGB, BootGB: slot.BootGB,
		RequestSHA256: hex.EncodeToString(requestSHA[:]), StartedAt: time.Now()}
	request.RetryToken = BootstrapRetryToken(request.OperationID, request.RequestSHA256)
	if err := allocation.Validate(request, quote, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := allocation.Revalidate(t.Context()); err != nil {
		t.Fatal(err)
	}
	request.OCPUs++
	if allocation.Validate(request, quote, time.Now()) == nil {
		t.Fatal("signed slot quote authorized different billing geometry")
	}
	wrongParent.Store(true)
	if allocation.Revalidate(t.Context()) == nil || spending.RevalidateBindings(t.Context()) == nil {
		t.Fatal("live foreign ancestry retained bootstrap or ordinary spending authorization")
	}
}
