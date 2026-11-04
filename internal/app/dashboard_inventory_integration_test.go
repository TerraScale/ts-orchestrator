package app

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/dashboard"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/capacityinventory"
	"github.com/TerraScale/ts-orchestrator/internal/rootoci"
)

// Retained resource observations reach the dashboard through its HTTP handler.
func TestRootInventoryProjectionThroughDashboardHTTP(t *testing.T) {
	now := time.Now().UTC()
	retained := &rootInventoryViews{}
	retained.record(rootoci.InventoryObservation{
		ScopeSHA256: strings.Repeat("a", 64), Currency: "USD", ObservedAt: now,
		ExpiresAt: now.Add(time.Minute), MonthlyCents: 5000,
		CoveredCompartments: []string{"ocid1.compartment.covered"},
		Resources: []capacityinventory.Resource{{ID: "ocid1.instance.oc1.fixture", Cell: "GRU",
			CompartmentID: "ocid1.compartment.covered", LifecycleState: "RUNNING", OperationID: "live-operation"}},
	}, nil)
	server := httptest.NewServer(dashboard.New(dashboard.Options{Now: func() time.Time { return now },
		Journal: &dashboard.Journal{Inventory: dashboardInventory{source: retained}}}).Handler())
	t.Cleanup(server.Close)
	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL+"/oci", nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil || response.StatusCode != http.StatusOK {
		t.Fatalf("GET /oci status=%d read=%v", response.StatusCode, err)
	}
	if !strings.Contains(string(body), "ocid1.instance.oc1.fixture") || !strings.Contains(string(body), "50.00 USD") {
		t.Fatal("GET /oci omitted the retained resource and its observed cost")
	}
}
