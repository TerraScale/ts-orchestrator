package capacityinventory

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json/v2"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/oracle/oci-go-sdk/v65/common"
)

func TestRegionalInventoryAndCurrentTariffsThroughRealProtocols(t *testing.T) {
	for _, scenario := range []string{"observed", "missing currency", "unknown shape", "region unavailable", "autotuned disk"} {
		t.Run(scenario, func(t *testing.T) {
			var mu sync.Mutex
			var compartments []string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch {
				case r.URL.Path == "/prices":
					metric, price := "", 0.0
					switch r.URL.Query().Get("partNumber") {
					case "B93297":
						metric, price = "OCPU Per Hour", .01
					case "B93298":
						metric, price = "Gigabyte Per Hour", .0015
					case "B97384":
						metric, price = "OCPU Per Hour", .03
					case "B97385":
						metric, price = "Gigabyte Per Hour", .002
					case "B91961":
						metric, price = "Gigabyte Storage Capacity Per Month", .0255
					case "B91962":
						metric, price = "Performance Units Per Gigabyte Per Month", .0017
					default:
						t.Errorf("unexpected SKU %s", r.URL.RawQuery)
					}
					currency := "USD"
					if scenario == "missing currency" {
						currency = "EUR"
					}
					fmt.Fprintf(w, `{"lastUpdated":%q,"items":[{"partNumber":%q,"metricName":%q,"currencyCodeLocalizations":[{"currencyCode":%q,"prices":[{"model":"PAY_AS_YOU_GO","value":0},{"model":"PAY_AS_YOU_GO","value":%v}]}]}]}`, time.Now().UTC().Format(time.RFC3339), r.URL.Query().Get("partNumber"), metric, currency, price)
				case r.Method == http.MethodPost && r.URL.Path == "/20180409/resources":
					if r.Header.Get("Authorization") == "" {
						t.Error("unsigned inventory request")
					}
					var body struct {
						Query string `json:"query"`
					}
					if err := json.UnmarshalRead(r.Body, &body); err != nil {
						t.Error(err)
					}
					compartment := "ocid1.compartment.oc1..gru"
					if strings.Contains(body.Query, "sfo") {
						compartment = "ocid1.compartment.oc1..sfo"
					}
					mu.Lock()
					compartments = append(compartments, compartment)
					mu.Unlock()
					if scenario == "region unavailable" && strings.HasSuffix(compartment, "sfo") {
						http.Error(w, `{"code":"NotAuthorizedOrNotFound","message":"unavailable"}`, http.StatusNotFound)
						return
					}
					fmt.Fprintf(w, `{"items":[{"identifier":%q,"compartmentId":%q,"resourceType":"Instance","lifecycleState":"RUNNING"},{"identifier":%q,"compartmentId":%q,"resourceType":"Volume","lifecycleState":"AVAILABLE"}]}`, "instance-"+compartment, compartment, "volume-"+compartment, compartment)
				case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/instances/"):
					id := strings.TrimPrefix(r.URL.Path, "/20160918/instances/")
					compartment := strings.TrimPrefix(id, "instance-")
					shape := "VM.Standard.A1.Flex"
					if strings.HasSuffix(compartment, "sfo") {
						shape = "VM.Standard.E5.Flex"
					}
					if scenario == "unknown shape" {
						shape = "VM.Unknown.Flex"
					}
					fmt.Fprintf(w, `{"id":%q,"compartmentId":%q,"shape":%q,"lifecycleState":"RUNNING","shapeConfig":{"ocpus":2,"memoryInGBs":4},"freeformTags":{"ts-operation-id":"operation-1","ts-recipe-sha256":%q}}`, id, compartment, shape, strings.Repeat("a", 64))
				case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/volumes/"):
					id := strings.TrimPrefix(r.URL.Path, "/20160918/volumes/")
					compartment := strings.TrimPrefix(id, "volume-")
					fmt.Fprintf(w, `{"id":%q,"compartmentId":%q,"lifecycleState":"AVAILABLE","sizeInGBs":50,"vpusPerGB":10,"isAutoTuneEnabled":%t}`, id, compartment, scenario == "autotuned disk")
				default:
					t.Errorf("unexpected request %s %s", r.Method, r.URL)
					http.NotFound(w, r)
				}
			}))
			defer server.Close()
			key, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				t.Fatal(err)
			}
			provider := common.NewRawConfigurationProvider("ocid1.tenancy.oc1..test", "ocid1.user.oc1..test", "sa-saopaulo-1", "test", string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})), nil)
			factory, err := ociclient.New(provider, ociclient.Options{Region: "sa-saopaulo-1"})
			if err != nil {
				t.Fatal(err)
			}
			reader, err := New(factory)
			if err != nil {
				t.Fatal(err)
			}
			reader.endpoint, reader.pricesEndpoint = server.URL, server.URL+"/prices"
			scope := Scope{TenancyID: "ocid1.tenancy.oc1..test", SHA256: strings.Repeat("a", 64), Currency: "USD", ExpiresAt: time.Now().Add(time.Hour), Regions: []RegionScope{{Cell: "GRU", OCIRegion: "sa-saopaulo-1", CompartmentIDs: []string{"ocid1.compartment.oc1..gru"}}, {Cell: "SFO", OCIRegion: "us-sanjose-1", CompartmentIDs: []string{"ocid1.compartment.oc1..sfo"}}}}
			result, err := reader.Read(t.Context(), scope)
			if err != nil {
				t.Fatal(err)
			}
			mu.Lock()
			count := len(compartments)
			mu.Unlock()
			if count != 2 {
				t.Fatalf("queried %d approved compartments", count)
			}
			if scenario == "observed" {
				prices, err := reader.Prices(t.Context(), scope, []string{"VM.Standard.A1.Flex", "VM.Standard.E5.Flex", "VM.Unknown.Flex"})
				if err != nil || len(prices) != 6 {
					t.Fatalf("mixed family tariffs=%v err=%v", prices, err)
				}
				quote, err := reader.Quote(t.Context(), scope, "GRU", "ocid1.compartment.oc1..gru", "VM.Standard.A1.Flex", 2, 4, 50)
				if err != nil || quote.MonthlyCents() != 2147 || quote.Currency() != "USD" {
					t.Fatalf("candidate quote=%+v err=%v", quote, err)
				}
				if err := quote.Validate(scope, "GRU", "ocid1.compartment.oc1..gru", "VM.Standard.A1.Flex", 2, 4, 50, time.Now()); err != nil {
					t.Fatal(err)
				}
				if quote.Validate(scope, "GRU", "ocid1.compartment.oc1..gru", "VM.Standard.A1.Flex", 20, 40, 500, time.Now()) == nil {
					t.Fatal("cheap quote admitted a larger candidate")
				}
				if len(result.Resources) != 4 || len(result.CoveredCompartments) != 2 || result.MonthlyCents != 7421 {
					t.Fatalf("snapshot=%+v", result)
				}
				if !slices.ContainsFunc(result.Resources, func(r Resource) bool {
					return r.OperationID == "operation-1" && r.RecipeSHA256 == strings.Repeat("a", 64)
				}) {
					t.Fatal("provider operation evidence lost")
				}
			}
			if scenario != "observed" && len(result.Pending) <= 2 {
				t.Fatalf("source failure lost: %+v", result)
			}
			if scenario == "region unavailable" && len(result.CoveredCompartments) != 1 {
				t.Fatalf("failed region incorrectly covered: %+v", result)
			}
			if len(result.Pending) < 2 || result.Validate(scope, time.Now()) == nil {
				t.Fatalf("incomplete accounting became spending authority: %+v", result)
			}
			result.Pending = nil
			if result.Validate(scope, time.Now()) == nil {
				t.Fatal("clearing pending reasons forged producer completeness")
			}
		})
	}
}
