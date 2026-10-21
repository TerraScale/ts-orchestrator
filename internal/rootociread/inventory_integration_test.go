package rootociread

import (
	"context"
	"encoding/json/v2"
	"io"
	"net/http"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/capacityledger"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/ocicost"
	"github.com/TerraScale/ts-orchestrator/internal/region"
	"github.com/TerraScale/ts-orchestrator/internal/rootoci"
)

func TestRootInventoryIncludesProtectedOriginalLiabilities(t *testing.T) {
	for _, outcome := range []string{"original liability", "missing history", "grant changes", "canceled"} {
		t.Run(outcome, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
			defer cancel()
			f := newReadScenario(t)
			receipt := f.financialInventory()
			var invalidated atomic.Bool
			if outcome == "missing history" {
				var record map[string]any
				if err := json.Unmarshal(f.objects["orchestrator/regions/v1/GRU.json"], &record); err != nil {
					t.Fatal(err)
				}
				delete(record, "capacityLedger")
				f.objects["orchestrator/regions/v1/GRU.json"] = inventoryJSON(t, record)
			}
			if outcome == "grant changes" || outcome == "canceled" {
				assertRequest := f.afterRead
				f.afterRead = func(request *http.Request) {
					assertRequest(request)
					if request.Method != http.MethodPost {
						return
					}
					invalidated.Store(true)
					if outcome == "grant changes" {
						f.publish(2)
					} else {
						cancel()
					}
				}
			}
			call, err := rootoci.RootCall(ctx)
			if err != nil {
				t.Fatal(err)
			}
			observed, err := f.backend.Inventory(ctx, call)
			f.mu.Lock()
			requests := f.requests
			f.mu.Unlock()
			if requests == 0 || requests > 256 {
				t.Fatalf("root inventory exceeded its finite signed SDK boundary: %d requests", requests)
			}
			if outcome == "grant changes" || outcome == "canceled" {
				if !invalidated.Load() || err == nil || len(observed.KnownLiabilities.Commitments) != 0 {
					t.Fatalf("invalidated inventory escaped its root read: %+v, %v", observed, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			known := observed.KnownLiabilities
			if len(observed.Pending) == 0 || len(known.UnboundedCompartments) != 5 || known.ScopeSHA256 != observed.ScopeSHA256 || known.Currency != "USD" {
				t.Fatalf("known liabilities erased full-scope uncertainty: %+v", observed)
			}
			if outcome == "missing history" {
				if known.MonthlyCents != 0 || len(known.Commitments) != 0 || !slices.Contains(known.Pending, "protected financial history absent: GRU") {
					t.Fatalf("missing protected history became a known zero obligation: %+v", known)
				}
				return
			}
			if known.MonthlyCents != receipt.Quote.MonthlyCents || len(known.Commitments) != 1 ||
				known.Commitments[0].QuoteSHA256 != receipt.QuoteSHA256 || !slices.Equal(known.UnknownOperations, []string{receipt.OperationID}) || observed.MonthlyCents != 0 {
				t.Fatalf("original charged operation lost its protected tariff or identity: %+v", observed)
			}
		})
	}
}

func (f *readScenario) financialInventory() capacityledger.Receipt {
	f.test.Helper()
	f.grant.SchemaVersion = 2
	logical, err := region.FoundationInfrastructureScopeDigest(f.grant)
	if err != nil {
		f.test.Fatal(err)
	}
	f.grant.InfrastructureSpend = &region.InfrastructureSpendIntent{BudgetID: entityid.New(), Currency: "USD", MonthlyLimitMinor: 9000, ScopeSHA256: logical}
	f.publish(1)
	intent, err := region.FoundationIntentDigest(f.grant.Regions[0])
	if err != nil {
		f.test.Fatal(err)
	}
	at := time.Now().UTC().Add(-time.Minute)
	op := entityid.Derive("regional-foundation", readScenarioTenancy, "GRU", "1")
	ids, provenance := map[string]string{}, map[string]any{}
	for _, role := range []string{"control", "network", "workload"} {
		key, id := role+"_compartment", "ocid1.compartment.oc1.."+role
		ids[key] = id
		provenance[key] = map[string]any{"resourceId": id, "generation": 1, "grantSha256": f.anchor.FoundationScope.GrantSHA256,
			"create": map[string]any{"operationId": op, "intentDigest": intent, "firstAttemptAt": at.Add(time.Second),
				"request": map[string]any{"key": key, "region": readScenarioRegion, "requestDigest": strings.Repeat("a", 64), "retryToken": strings.Repeat("b", 64)}}}
		f.responses["GET identity."+readScenarioRegion+".oci.oraclecloud.com/20160918/compartments/"+id] = inventoryJSON(f.test,
			map[string]any{"id": id, "compartmentId": f.grant.ParentCompartmentID, "lifecycleState": "ACTIVE"})
	}
	quote := capacityledger.Quote{ScopeSHA256: logical, Cell: "GRU", CompartmentID: ids["workload_compartment"], Shape: "VM.Standard.A1.Flex", Currency: "USD",
		OCPUs: 1, MemoryGB: 6, BootGB: 50, IssuedAt: at, ExpiresAt: at.Add(3 * time.Minute),
		Prices: []ocicost.Price{{SKU: "B91961", PerUnit: .0255}, {SKU: "B91962", PerUnit: .0017}, {SKU: "B93297", PerUnit: .01}, {SKU: "B93298", PerUnit: .0015}}}
	quote.MonthlyCents, err = ocicost.NodeMonthlyCents(quote.Prices, quote.Shape, quote.OCPUs, quote.MemoryGB, quote.BootGB)
	if err != nil {
		f.test.Fatal(err)
	}
	receipt := capacityledger.Receipt{OperationID: entityid.New(), RecipeSHA256: strings.Repeat("c", 64), GrantSHA256: f.anchor.FoundationScope.GrantSHA256,
		GrantGeneration: 1, LogicalScopeSHA256: logical, ResolvedScopeSHA256: logical, TenancyID: readScenarioTenancy,
		ReservedAt: at.Add(time.Second), QuoteSHA256: quote.SHA256(), Quote: quote}
	ledger := &capacityledger.Ledger{}
	if err := ledger.Reserve(receipt); err != nil {
		f.test.Fatal(err)
	}
	record := map[string]any{"schemaVersion": 1, "cell": "GRU", "ociRegion": readScenarioRegion, "tenancyId": readScenarioTenancy,
		"parentCompartmentId": f.grant.ParentCompartmentID, "sharedCompartmentId": f.grant.SharedCompartmentID,
		"generation": 1, "intentDigest": intent, "grantSha256": f.anchor.FoundationScope.GrantSHA256, "operationId": op,
		"epoch": 1, "stage": "reconciled", "startedAt": at, "updatedAt": at.Add(5 * time.Second), "completedAt": at.Add(5 * time.Second),
		"resourceIds": ids, "resourceProvenance": provenance, "capacityLedger": ledger}
	f.objects["orchestrator/regions/v1/GRU.json"] = inventoryJSON(f.test, record)
	for _, family := range []string{"instances", "volumes", "bootVolumes"} {
		f.responses["GET iaas."+readScenarioRegion+".oraclecloud.com/20160918/"+family] = []byte(`[]`)
	}
	f.responses["POST query."+readScenarioRegion+".oci.oraclecloud.com/20180409/resources"] = []byte(`{"items":[]}`)
	compartments := []string{f.grant.ParentCompartmentID, f.grant.SharedCompartmentID, ids["control_compartment"], ids["network_compartment"], ids["workload_compartment"]}
	f.afterRead = func(request *http.Request) {
		if request.Method == http.MethodPost {
			wire, err := io.ReadAll(request.Body)
			var query struct{ Query string }
			if err != nil || json.Unmarshal(wire, &query) != nil || !slices.ContainsFunc(compartments, func(id string) bool {
				return query.Query == "query all resources where compartmentId = '"+id+"'"
			}) {
				f.test.Errorf("root inventory search escaped its exact signed compartments: %s, %v", wire, err)
			}
		} else if request.Host == "iaas."+readScenarioRegion+".oraclecloud.com" && !slices.Contains(compartments, request.URL.Query().Get("compartmentId")) {
			f.test.Errorf("root inventory family list escaped its exact signed compartments: %s", request.URL)
		}
	}
	return receipt
}

func inventoryJSON(t *testing.T, value any) []byte {
	t.Helper()
	wire, err := json.Marshal(value, json.Deterministic(true))
	if err != nil {
		t.Fatal(err)
	}
	return wire
}
