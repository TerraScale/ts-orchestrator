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
	for _, scenario := range []string{"observed", "missing currency", "unknown shape", "region unavailable", "autotuned disk", "stale tariff", "search misses node", "terminal resources", "repeated page", "boot ancestry", "ambiguous boot ancestry"} {
		t.Run(scenario, func(t *testing.T) {
			var mu sync.Mutex
			var compartments []string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch {
				case r.URL.Path == "/prices":
					if scenario == "stale tariff" {
						w.Header().Set("Date", time.Now().Add(-time.Hour).UTC().Format(http.TimeFormat))
					}
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
				case r.Method == http.MethodGet && (r.URL.Path == "/20160918/instances" || r.URL.Path == "/20160918/volumes" || r.URL.Path == "/20160918/bootVolumes"):
					if r.Header.Get("Authorization") == "" {
						t.Error("unsigned direct inventory request")
					}
					compartment := r.URL.Query().Get("compartmentId")
					if scenario == "region unavailable" && strings.HasSuffix(compartment, "sfo") {
						http.Error(w, `{"code":"NotAuthorizedOrNotFound","message":"unavailable"}`, http.StatusNotFound)
						return
					}
					kind, state := "instance-", "RUNNING"
					if strings.HasSuffix(r.URL.Path, "/volumes") {
						kind, state = "volume-", "AVAILABLE"
					}
					if strings.HasSuffix(r.URL.Path, "/bootVolumes") {
						if strings.Contains(scenario, "boot ancestry") {
							fmt.Fprintf(w, `[{"id":%q,"compartmentId":%q,"lifecycleState":"AVAILABLE"}]`, "boot-"+compartment, compartment)
						} else {
							fmt.Fprint(w, `[]`)
						}
						return
					}
					if scenario == "repeated page" && kind == "instance-" {
						w.Header().Set("opc-next-page", "same")
					}
					fmt.Fprintf(w, `[{"id":%q,"compartmentId":%q,"lifecycleState":%q}]`, kind+compartment, compartment, state)
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
					if scenario == "search misses node" {
						fmt.Fprint(w, `{"items":[]}`)
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
					state := "RUNNING"
					if scenario == "terminal resources" {
						state = "TERMINATED"
					}
					fmt.Fprintf(w, `{"id":%q,"compartmentId":%q,"availabilityDomain":"AD-1","shape":%q,"lifecycleState":%q,"shapeConfig":{"ocpus":2,"memoryInGBs":4},"freeformTags":{"ts-operation-id":"operation-1","ts-recipe-sha256":%q}}`, id, compartment, shape, state, strings.Repeat("a", 64))
				case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/bootVolumes/"):
					id := strings.TrimPrefix(r.URL.Path, "/20160918/bootVolumes/")
					compartment := strings.TrimPrefix(id, "boot-")
					fmt.Fprintf(w, `{"id":%q,"compartmentId":%q,"availabilityDomain":"AD-1","lifecycleState":"AVAILABLE","sizeInGBs":50,"vpusPerGB":10}`, id, compartment)
				case r.Method == http.MethodGet && r.URL.Path == "/20160918/bootVolumeAttachments":
					compartment := r.URL.Query().Get("compartmentId")
					if r.URL.Query().Get("availabilityDomain") != "AD-1" || r.URL.Query().Get("bootVolumeId") != "boot-"+compartment {
						t.Error("boot ancestry omitted exact AD and volume filter")
					}
					fmt.Fprintf(w, `[{"id":"attachment-1","compartmentId":%q,"availabilityDomain":"AD-1","bootVolumeId":%q,"instanceId":%q,"lifecycleState":"ATTACHED"}`, compartment, "boot-"+compartment, "instance-"+compartment)
					if scenario == "ambiguous boot ancestry" {
						fmt.Fprintf(w, `,{"id":"attachment-2","compartmentId":%q,"availabilityDomain":"AD-1","bootVolumeId":%q,"instanceId":"another-instance","lifecycleState":"ATTACHED"}`, compartment, "boot-"+compartment)
					}
					fmt.Fprint(w, `]`)
				case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/volumes/"):
					id := strings.TrimPrefix(r.URL.Path, "/20160918/volumes/")
					compartment := strings.TrimPrefix(id, "volume-")
					state := "AVAILABLE"
					if scenario == "terminal resources" {
						state = "TERMINATED"
					}
					fmt.Fprintf(w, `{"id":%q,"compartmentId":%q,"lifecycleState":%q,"sizeInGBs":50,"vpusPerGB":10,"isAutoTuneEnabled":%t}`, id, compartment, state, scenario == "autotuned disk")
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
				digest := quote.SHA256()
				if len(digest) != 64 || (Quote{}).SHA256() != "" {
					t.Fatalf("quote identity is absent or unminted identity exists: %q", digest)
				}
				if quote.Validate(scope, "GRU", "ocid1.compartment.oc1..gru", "VM.Standard.A1.Flex", 2, 4, 50, quote.ExpiresAt()) == nil || quote.SHA256() != digest {
					t.Fatal("expiry renewed or erased the original sealed quote identity")
				}
				refreshed, err := reader.Quote(t.Context(), scope, "GRU", "ocid1.compartment.oc1..gru", "VM.Standard.A1.Flex", 2, 4, 50)
				if err != nil || refreshed.MonthlyCents() != quote.MonthlyCents() || refreshed.SHA256() == digest {
					t.Fatalf("fresh equal-cost quote reused original identity: %+v err=%v", refreshed, err)
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
			if scenario == "search misses node" && (len(result.Resources) != 4 || result.MonthlyCents != 7421) {
				t.Fatalf("direct lists lost resources omitted by search: %+v", result)
			}
			if strings.Contains(scenario, "boot ancestry") && (len(result.Resources) != 6 || result.MonthlyCents != 7847) {
				t.Fatalf("boot charges lost during ancestry reconciliation: %+v", result)
			}
			if scenario == "boot ancestry" && !slices.ContainsFunc(result.Resources, func(r Resource) bool {
				return strings.HasPrefix(r.ID, "boot-") && r.OperationID == "operation-1" && r.RecipeSHA256 == strings.Repeat("a", 64)
			}) {
				t.Fatal("actual boot attachment ancestry lost operation attribution")
			}
			if scenario == "terminal resources" && (len(result.Resources) != 4 || result.MonthlyCents != 0 || !slices.ContainsFunc(result.Resources, func(r Resource) bool { return r.LifecycleState == "TERMINATED" })) {
				t.Fatalf("positive terminal observations lost: %+v", result)
			}
			if scenario != "observed" && scenario != "search misses node" && scenario != "terminal resources" && scenario != "boot ancestry" && len(result.Pending) <= 2 {
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
