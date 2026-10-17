package app

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/capacityledger"
	"github.com/TerraScale/ts-orchestrator/internal/dashboard"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/capacityinventory"
	"github.com/TerraScale/ts-orchestrator/internal/rootoci"
)

// Retained source results drive the production supplier, projection and HTTP view.
func TestRootInventoryProjectionThroughDashboardHTTP(t *testing.T) {
	for _, scenario := range []string{"pending", "expired", "empty", "partial_error", "unavailable"} {
		t.Run(scenario, func(t *testing.T) {
			now := time.Now().UTC()
			observed := now.Add(-time.Second).Truncate(time.Microsecond)
			expires := observed.Add(time.Minute)
			observation := rootoci.InventoryObservation{
				ScopeSHA256: strings.Repeat("a", 64), Currency: "USD", ObservedAt: observed,
				ExpiresAt: expires, MonthlyCents: 5000, CoveredCompartments: []string{"ocid1.compartment.covered"},
				Pending: []string{"live scope remains incomplete", "<script>source pending</script>"},
				Resources: []capacityinventory.Resource{{ID: "ocid1.instance.oc1.fixture", Cell: "GRU",
					CompartmentID: "ocid1.compartment.covered", LifecycleState: "RUNNING", OperationID: "live-operation"}},
				KnownLiabilities: capacityinventory.KnownLiabilities{
					ScopeSHA256: strings.Repeat("b", 64), Currency: "USD", ObservedAt: observed.Add(-time.Second),
					ExpiresAt: expires, MonthlyCents: 9200,
					Commitments: []capacityledger.Receipt{{OperationID: "original-operation", ReservedAt: observed.Add(-time.Hour),
						QuoteSHA256: strings.Repeat("c", 64), Quote: capacityledger.Quote{MonthlyCents: 2200, Currency: "USD"}}},
					UnknownOperations: []string{"unresolved-operation"}, UnboundResources: []string{"unbound-resource"},
					UnboundedCompartments: []string{"GRU/financially-unbounded"}, Pending: []string{"original history pending"},
				},
			}
			var sourceErr error
			wants := []string{"50.00 USD", "92.00 USD", "22.00 USD", "never add these amounts",
				strings.Repeat("a", 64), strings.Repeat("b", 64), observed.Format(time.RFC3339Nano), expires.Format(time.RFC3339Nano),
				"ocid1.compartment.covered", "live scope remains incomplete", "original-operation", "unresolved-operation",
				"unbound-resource", "GRU/financially-unbounded", "original history pending", "&lt;script&gt;source pending&lt;/script&gt;"}
			switch scenario {
			case "expired":
				observation.ExpiresAt = now.Add(-time.Second)
				observation.KnownLiabilities.ExpiresAt = observation.ExpiresAt
				wants = append(wants, "inventory observation has expired", "liability observations have expired", observation.ExpiresAt.Format(time.RFC3339Nano))
				wants = slices.DeleteFunc(wants, func(want string) bool { return want == expires.Format(time.RFC3339Nano) })
			case "empty":
				observation.Resources = nil
				wants = append(wants, "this does not establish that the region owns none")
			case "partial_error":
				sourceErr = errors.New("root inventory read incomplete")
				wants = append(wants, "could not be read completely", "ocid1.instance.oc1.fixture", "live-operation", ">unknown<")
			case "unavailable":
				observation = rootoci.InventoryObservation{}
				sourceErr = errors.New("root reader unavailable")
				wants = []string{"could not be read completely", "Inventory scope and observation time are unavailable", "Original liability observations are unavailable"}
			default:
				wants = append(wants, "ocid1.instance.oc1.fixture", "live-operation", ">unknown<")
			}
			retained := &rootInventoryViews{}
			retained.record(observation, nil)
			if sourceErr != nil {
				retained.record(rootoci.InventoryObservation{}, sourceErr)
			}
			copy, _ := retained.Inventory(t.Context())
			if len(copy.Resources) != 0 {
				copy.Resources[0].ID = "mutated-consumer-view"
			}
			source := dashboardInventory{source: retained}
			server := httptest.NewServer(dashboard.New(dashboard.Options{Now: func() time.Time { return now },
				Journal: &dashboard.Journal{Inventory: source}}).Handler())
			defer server.Close()
			client := server.Client()
			client.Timeout = 5 * time.Second
			request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL+"/oci", nil)
			if err != nil {
				t.Fatal(err)
			}
			response, err := client.Do(request)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			body, err := io.ReadAll(response.Body)
			if err != nil || response.StatusCode != http.StatusOK {
				t.Fatalf("GET /oci status=%d read=%v", response.StatusCode, err)
			}
			for _, want := range wants {
				if !strings.Contains(string(body), want) {
					t.Errorf("GET /oci lacks %q", want)
				}
			}
			for _, forbidden := range []string{"142.00 USD", ">in_sync<", "No OCI resource is owned", "<script>source pending</script>"} {
				if strings.Contains(string(body), forbidden) {
					t.Errorf("GET /oci contains misleading or unescaped %q", forbidden)
				}
			}
		})
	}
}
