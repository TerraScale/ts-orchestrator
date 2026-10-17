package capacityinventory_test

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
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/oracle/oci-go-sdk/v65/common"

	"github.com/TerraScale/ts-orchestrator/internal/capacityledger"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/foundationbinding"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/ocicost"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/capacityinventory"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

func TestKnownLiabilitiesUseProtectedOriginalTariffsAndExactIDsThroughSDK(t *testing.T) {
	const tenancy = "ocid1.tenancy.oc1..financial"
	const parent = "ocid1.compartment.oc1..parent"
	const shared = "ocid1.compartment.oc1..shared"
	const workload = "ocid1.compartment.oc1..workload"
	const liveInstance = "ocid1.instance.oc1.sa-saopaulo-1.replacement"
	const liveBoot = "ocid1.bootvolume.oc1.sa-saopaulo-1.replacement"
	const foreignInstance = "ocid1.instance.oc1.sa-saopaulo-1.foreign"
	const foreignBoot = "ocid1.bootvolume.oc1.sa-saopaulo-1.foreign"
	now := time.Now().UTC().Truncate(time.Second)
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	roots, err := trust.ParseKeyring(public)
	if err != nil {
		t.Fatal(err)
	}
	installation := entityid.New()
	authority := foundationbinding.Authority{Scope: trust.Scope{Domain: "terrascale.foundation.scope", DeploymentID: entityid.New(), Cell: "GRU", Environment: "production", Role: "foundation", Slot: entityid.New()},
		Roots: roots, Policy: trust.Policy{MaxLifetime: 2 * time.Hour}, Generation: 1, InstallationID: installation, TenancyID: tenancy,
		Namespace: "namespace", Bucket: "protected", Prefix: "bootstrap", Cell: "GRU"}
	ids := map[string]string{"control_compartment": "ocid1.compartment.oc1..control", "network_compartment": "ocid1.compartment.oc1..network", "workload_compartment": workload}
	plan := map[string]any{"cell": "GRU", "region": "sa-saopaulo-1", "tenancy_id": tenancy, "parent_compartment_id": parent, "shared_compartment_id": shared, "resource_ids": map[string]any{}}
	intent := map[string]any{"generation": uint64(1), "plan": plan}
	grant := map[string]any{"schemaVersion": 2, "generation": uint64(1), "installationId": installation, "tenancyId": tenancy,
		"parentCompartmentId": parent, "sharedCompartmentId": shared, "currency": "USD", "monthlyLimitMinor": 100000, "cleanupOwner": "integration",
		"regions": []any{intent}, "infrastructureSpend": map[string]any{"budgetId": entityid.New(), "currency": "USD", "monthlyLimitMinor": 100000, "scopeSha256": strings.Repeat("b", 64)}}
	payload, err := trust.EncodePayload(grant)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := trust.Sign(payload, authority.Scope, now.Add(-10*time.Minute), now.Add(time.Hour), private)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := trust.EncodeEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}
	authority.GrantSHA256 = sumSHA256(wire)
	intentWire, err := json.Marshal(intent, json.Deterministic(true))
	if err != nil {
		t.Fatal(err)
	}
	intentSHA := sumSHA256(intentWire)
	operation := entityid.Derive("regional-foundation", tenancy, "GRU", "1")
	provenance := map[string]any{}
	for key, id := range ids {
		provenance[key] = map[string]any{"resourceId": id, "generation": uint64(1), "grantSha256": authority.GrantSHA256,
			"create": map[string]any{"operationId": operation, "intentDigest": intentSHA, "firstAttemptAt": now.Add(-9 * time.Minute),
				"request": map[string]any{"key": key, "region": "sa-saopaulo-1", "requestDigest": strings.Repeat("e", 64), "retryToken": strings.Repeat("f", 64)}}}
	}
	ledger := capacityledger.Ledger{}
	children := map[string]any{}
	var oneHost uint64
	for i := range 3 {
		at := now.Add(-5 * time.Minute).Add(time.Duration(i) * 10 * time.Second)
		q := capacityledger.Quote{ScopeSHA256: strings.Repeat("a", 64), Cell: "GRU", CompartmentID: workload, Shape: "VM.Standard.A1.Flex", Currency: "USD",
			OCPUs: 1, MemoryGB: 6, BootGB: 50, IssuedAt: at, ExpiresAt: at.Add(2 * time.Minute),
			Prices: []ocicost.Price{{SKU: "B91961", PerUnit: .0255}, {SKU: "B91962", PerUnit: .0017}, {SKU: "B93297", PerUnit: .01}, {SKU: "B93298", PerUnit: .0015}}}
		q.MonthlyCents, _ = ocicost.NodeMonthlyCents(q.Prices, q.Shape, q.OCPUs, q.MemoryGB, q.BootGB)
		oneHost = q.MonthlyCents
		r := capacityledger.Receipt{OperationID: entityid.New(), RecipeSHA256: strings.Repeat("d", 64), GrantSHA256: authority.GrantSHA256, GrantGeneration: 1,
			LogicalScopeSHA256: strings.Repeat("b", 64), ResolvedScopeSHA256: q.ScopeSHA256, BindingSHA256: strings.Repeat("c", 64), TenancyID: tenancy,
			QuoteSHA256: q.SHA256(), ReservedAt: at.Add(time.Second), Quote: q}
		if err := ledger.Reserve(r); err != nil {
			t.Fatal(err)
		}
		requestSHA := strings.Repeat(fmt.Sprint(i+1), 64)
		if err := ledger.Prepare(r.OperationID, requestSHA, at.Add(2*time.Second)); err != nil {
			t.Fatal(err)
		}
		child := map[string]any{"operationId": r.OperationID, "recipeSha256": r.RecipeSHA256,
			"launch": map[string]any{"requestSha256": requestSHA, "firstAttemptAt": at.Add(2 * time.Second)}}
		if i < 2 {
			instance, boot := liveInstance, liveBoot
			if i == 0 {
				instance, boot = "ocid1.instance.oc1.sa-saopaulo-1.original", "ocid1.bootvolume.oc1.sa-saopaulo-1.original"
			}
			born := at.Add(3 * time.Second)
			if err := ledger.BindBirth(r.OperationID, requestSHA, instance, boot, born); err != nil {
				t.Fatal(err)
			}
			child["instanceId"], child["bootVolumeId"], child["bornAt"] = instance, boot, born
			if i == 0 {
				retired := at.Add(4 * time.Second)
				if err := ledger.RetireResource(r.OperationID, instance, retired); err != nil {
					t.Fatal(err)
				}
				if err := ledger.RetireResource(r.OperationID, boot, retired); err != nil {
					t.Fatal(err)
				}
				child["instanceRetiredAt"], child["bootRetiredAt"] = retired, retired
			}
		}
		children[r.OperationID] = child
	}
	record := map[string]any{"schemaVersion": 1, "cell": "GRU", "ociRegion": "sa-saopaulo-1", "tenancyId": tenancy,
		"parentCompartmentId": parent, "sharedCompartmentId": shared, "generation": uint64(1), "grantSha256": authority.GrantSHA256,
		"operationId": operation, "intentDigest": intentSHA, "epoch": uint64(1), "stage": "reconciled", "startedAt": now.Add(-10 * time.Minute), "updatedAt": now,
		"completedAt": now, "resourceIds": ids, "resourceProvenance": provenance, "capacityLedger": ledger, "poolChildren": children}
	recordFile := filepath.Join(t.TempDir(), "protected-foundation.json")
	recordWire, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(recordFile, recordWire, 0600); err != nil {
		t.Fatal(err)
	}
	var drift atomic.Bool
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet || !strings.HasPrefix(request.Header.Get("Authorization"), "Signature ") {
			t.Errorf("financial read attempted unsigned or mutating request: %s %s", request.Method, request.URL)
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		path := request.URL.Path
		switch {
		case path == "/n/namespace/b/protected/o/bootstrap/foundation-scope-v1.json":
			w.Write(wire)
		case path == "/n/namespace/b/protected/o/orchestrator/regions/v1/GRU.json":
			w.Header().Set("ETag", "record-1")
			body, err := os.ReadFile(recordFile)
			if err != nil {
				t.Error(err)
			}
			w.Write(body)
		case strings.HasPrefix(path, "/20160918/compartments/"):
			id := strings.TrimPrefix(path, "/20160918/compartments/")
			fmt.Fprintf(w, `{"id":%q,"compartmentId":%q,"lifecycleState":"ACTIVE"}`, id, parent)
		case path == "/20160918/instances":
			if request.URL.Query().Get("compartmentId") == workload {
				fmt.Fprintf(w, `[{"id":%q,"compartmentId":%q},{"id":%q,"compartmentId":%q}]`, liveInstance, workload, foreignInstance, workload)
			} else {
				fmt.Fprint(w, `[]`)
			}
		case path == "/20160918/bootVolumes":
			if request.URL.Query().Get("compartmentId") == workload {
				fmt.Fprintf(w, `[{"id":%q,"compartmentId":%q},{"id":%q,"compartmentId":%q}]`, liveBoot, workload, foreignBoot, workload)
			} else {
				fmt.Fprint(w, `[]`)
			}
		case path == "/20160918/volumes":
			fmt.Fprint(w, `[]`)
		case strings.HasPrefix(path, "/20160918/instances/"):
			id := strings.TrimPrefix(path, "/20160918/instances/")
			ocpus := 1
			if drift.Load() && id == liveInstance {
				ocpus = 2
			}
			fmt.Fprintf(w, `{"id":%q,"compartmentId":%q,"shape":"VM.Standard.A1.Flex","shapeConfig":{"ocpus":%d,"memoryInGBs":6},"lifecycleState":"RUNNING","freeformTags":{"ts-operation-id":%q,"ts-recipe-sha256":%q}}`, id, workload, ocpus, ledger.Hosts[0].Receipt.OperationID, ledger.Hosts[0].Receipt.RecipeSHA256)
		case strings.HasPrefix(path, "/20160918/bootVolumes/"):
			id := strings.TrimPrefix(path, "/20160918/bootVolumes/")
			fmt.Fprintf(w, `{"id":%q,"compartmentId":%q,"sizeInGBs":50,"vpusPerGB":10,"lifecycleState":"AVAILABLE"}`, id, workload)
		default:
			t.Errorf("unexpected SDK/pricing request: %s", request.URL)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)
	transport := http.DefaultTransport.(*http.Transport).Clone()
	originalTransport := http.DefaultTransport
	transport.DialTLSContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&tls.Dialer{Config: server.Client().Transport.(*http.Transport).TLSClientConfig}).DialContext(ctx, network, strings.TrimPrefix(server.URL, "https://"))
	}
	http.DefaultTransport = transport
	t.Cleanup(func() { http.DefaultTransport = originalTransport; transport.CloseIdleConnections() })
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	provider := common.NewRawConfigurationProvider(tenancy, "ocid1.user.oc1..financial", "sa-saopaulo-1", "test", string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})), nil)
	factory, err := ociclient.New(provider, ociclient.Options{Region: "sa-saopaulo-1", Retry: ociclient.RetryOptions{MaxAttempts: 1}})
	if err != nil {
		t.Fatal(err)
	}
	bindings, err := foundationbinding.Verify(t.Context(), factory, authority, wire)
	if err != nil {
		t.Fatal(err)
	}
	history, err := bindings.CapacityLedger(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	reader, err := capacityinventory.New(factory)
	if err != nil {
		t.Fatal(err)
	}
	scope := capacityinventory.Scope{TenancyID: tenancy, SHA256: strings.Repeat("a", 64), Currency: "USD", ExpiresAt: now.Add(time.Hour),
		Regions: []capacityinventory.RegionScope{{Cell: "GRU", OCIRegion: "sa-saopaulo-1", CompartmentIDs: []string{parent, shared, ids["control_compartment"], ids["network_compartment"], workload}}}}
	view, err := reader.ReadKnownLiabilities(t.Context(), scope, history)
	if err != nil {
		t.Fatal(err)
	}
	want, err := ledger.Monthly(view.ObservedAt)
	if err != nil {
		t.Fatal(err)
	}
	if want < 2*oneHost || view.MonthlyCents != want || len(view.Commitments) != 3 || len(view.UnknownOperations) != 1 || len(view.Resources) != 6 || len(view.Pending) != 0 {
		t.Fatalf("retired original, live replacement or unknown full ceiling lost/double-counted: %+v", view)
	}
	if !slices.Equal(view.UnboundResources, []string{foreignBoot, foreignInstance}) || len(view.UnboundedCompartments) != 5 {
		t.Fatalf("tags adopted a foreign resource or protected child history certified full accounting: %+v", view)
	}
	for _, resource := range view.Resources {
		if resource.ID == liveInstance && (resource.MonthlyCents != oneHost || resource.OperationID != ledger.Hosts[1].Receipt.OperationID) ||
			resource.ID == liveBoot && resource.MonthlyCents != 0 ||
			slices.Contains(view.UnboundResources, resource.ID) && (resource.OperationID != "" || resource.RecipeSHA256 != "" || resource.MonthlyCents != 0) {
			t.Fatalf("original bundle was duplicated or tags changed its exact binding: %+v", resource)
		}
	}
	if _, err := reader.ReadKnownLiabilities(t.Context(), scope, history, history); err == nil {
		t.Fatal("repeated protected history counted the same original obligations twice")
	}
	if _, err := reader.ReadKnownLiabilities(t.Context(), scope, foundationbinding.VerifiedCapacityLedger{}); err == nil {
		t.Fatal("caller-created history became a financial subtotal")
	}
	drift.Store(true)
	view, err = reader.ReadKnownLiabilities(t.Context(), scope, history)
	want, monthlyErr := ledger.Monthly(view.ObservedAt)
	if err != nil || monthlyErr != nil || view.MonthlyCents != want || !slices.ContainsFunc(view.Pending, func(reason string) bool {
		return strings.Contains(reason, liveInstance) && strings.Contains(reason, "dimensions")
	}) {
		t.Fatalf("changed dimensions were silently repriced or original ceiling lost: %+v err=%v", view, err)
	}
}

func sumSHA256(wire []byte) string {
	sum := sha256.Sum256(wire)
	return hex.EncodeToString(sum[:])
}
