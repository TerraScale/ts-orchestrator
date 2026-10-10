package dashboard

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/observability"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/regionview"
)

type failedDashboardInventory struct{}

func (failedDashboardInventory) Inventory(context.Context) ([]InventoryItem, error) {
	return nil, errors.New("inventory unavailable")
}

func (failedDashboardInventory) Qualifications(context.Context) ([]Qualification, error) {
	return nil, errors.New("qualification unavailable")
}

func TestDashboardProviderFailuresDoNotClaimEmptyInventories(t *testing.T) {
	handler := newTestDashboard(Options{Journal: &Journal{
		Inventory: failedDashboardInventory{}, Qualification: failedDashboardInventory{},
	}}).Handler()
	for _, test := range []struct{ path, want, forbidden string }{
		{"/oci", "owned resources and drift are unknown", "No OCI resource is owned"},
		{"/ci", "latest runs are unknown", "No qualification run has been reported"},
	} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, test.path, nil))
		body := response.Body.String()
		if response.Code != http.StatusOK || !strings.Contains(body, test.want) || strings.Contains(body, test.forbidden) {
			t.Errorf("%s misrepresents a provider failure: status %d, want %q without %q", test.path, response.Code, test.want, test.forbidden)
		}
	}
}

func TestPartialJetStreamInventoryRemainsVisible(t *testing.T) {
	member := memberSnapshot()
	member.NATS.Truncated = true
	current := view{Local: &member}
	body := renderHTML(t, natsBody(current))
	if !strings.Contains(body, "omitted resources have unknown health") {
		t.Fatal("NATS page hides partial inventory")
	}
}

func TestStaticTerraBaseServicesRemainVisibleWithoutManagedPlacement(t *testing.T) {
	current := topologyFixture("")
	current.Page = page{slug: "terrabase"}
	current.Now = testNow
	current.Local.Placement.Databases = nil
	for index := range current.Cluster.Members {
		current.Cluster.Members[index].Placement.Databases = nil
	}
	handler := newTestDashboard(Options{Snapshots: fixedSnapshots{snapshot: *current.Local},
		Journal: &Journal{Local: func(context.Context) regionview.Summary { return *current.LocalSummary }}}).Handler()
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/terrabase", nil))
	body := response.Body.String()
	for _, want := range []string{"TerraBase services on host nodes", "ts-gru-1", "ts-gru-2", "ts-gru-3", "running", "sha256:7da6542c9f0e1b2a3c"} {
		if !strings.Contains(body, want) {
			t.Errorf("static TerraBase service missing %q", want)
		}
	}
}

func TestDashboardActiveCountsExcludeTerminalPartitions(t *testing.T) {
	member := memberSnapshot()
	member.Placement = &observability.PlacementView{Databases: []observability.DatabaseView{
		{DatabaseID: "active", DesiredSeats: 3, Serving: 2},
		{DatabaseID: "removed", Terminal: true, DesiredSeats: 3, Serving: 3,
			Rollout: &observability.RolloutView{Seats: 3}},
	}}
	current := view{Local: &member}
	for _, tile := range current.regionKPIs() {
		if tile.Label == "Managed TerraBase partitions" && tile.Value != "1" {
			t.Fatalf("partition tile includes terminal state: %+v", tile)
		}
	}
}
