package nodescale

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json/v2"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/ocicost"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/core"
	"github.com/oracle/oci-go-sdk/v65/limits"
)

// TestCapacityDiscoveryOCIProtocol uses real SDK clients against OCI-shaped
// HTTP responses; it never allocates a VM or replaces an existing pool.
func TestCapacityDiscoveryOCIProtocol(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	provider := common.NewRawConfigurationProvider("tenancy", "user", "sa-saopaulo-1", "fingerprint",
		string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})), nil)
	for _, scenario := range []struct {
		name, wantShape, pending string
		architecture             string
		a1Exhausted              bool
		quotaExhausted           bool
		unknownPrice             bool
		insufficientSpend        bool
		unknownSpend             bool
		unsupportedReport        bool
		wrongReportConfig        bool
		missingQualification     bool
		invalidResources         bool
		expiredFacts             bool
		cycleEndpoint            string
		twoTokenCycle            bool
	}{
		{name: "A1 preferred over cheaper qualified A2", wantShape: PreferredShape},
		{name: "exhausted A1 selects qualified A2", wantShape: "VM.Standard.A2.Flex", a1Exhausted: true},
		{name: "x86 demand selects AMD not ARM", architecture: "amd64", wantShape: "VM.Standard.E5.Flex"},
		{name: "quota exhaustion is pending", quotaExhausted: true, pending: "effective limit/quota"},
		{name: "expired authority is pending", expiredFacts: true, pending: "expired or have unknown validity"},
		{name: "unknown price is pending", unknownPrice: true, pending: "price is unknown"},
		{name: "spending ceiling is enforced", insufficientSpend: true, pending: "exceeds authorized headroom"},
		{name: "unknown spending authority is pending", unknownSpend: true, pending: "spending headroom is unknown"},
		{name: "unsupported report is pending", unsupportedReport: true, pending: "capacity report unavailable"},
		{name: "capacity for another configuration is pending", wrongReportConfig: true, pending: "no current host capacity"},
		{name: "unqualified runtime is pending", missingQualification: true, pending: "runtime/architecture qualification"},
		{name: "invalid shape resource bounds are pending", invalidResources: true, pending: "OCPU/memory"},
		{name: "shape page self-cycle is pending", cycleEndpoint: "/shapes", pending: "pagination repeated"},
		{name: "shape two-token cycle is pending", cycleEndpoint: "/shapes", twoTokenCycle: true, pending: "pagination repeated"},
		{name: "limit page self-cycle is refused", cycleEndpoint: "/limitDefinitions"},
		{name: "limit two-token cycle is refused", cycleEndpoint: "/limitDefinitions", twoTokenCycle: true},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			architecture := scenario.architecture
			if architecture == "" {
				architecture = "arm64"
			}
			var cycleRequests, capacityReports atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if scenario.cycleEndpoint != "" && strings.HasSuffix(r.URL.Path, scenario.cycleEndpoint) {
					if cycleRequests.Add(1) > 3 {
						w.WriteHeader(http.StatusBadRequest)
						return
					}
					next := "page-a"
					if scenario.twoTokenCycle && r.URL.Query().Get("page") == "page-a" {
						next = "page-b"
					}
					w.Header().Set("opc-next-page", next)
				}
				write := func(value any) {
					if err := json.MarshalWrite(w, value); err != nil {
						t.Errorf("OCI response: %v", err)
					}
				}
				switch {
				case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/shapes"):
					if r.URL.Query().Get("imageId") != "image-"+architecture || r.URL.Query().Get("availabilityDomain") != "AD-1" || r.URL.Query().Get("compartmentId") != "compartment" {
						t.Errorf("image/AD/compartment discovery lost: %s", r.URL)
					}
					shape := func(name, processor string) core.Shape {
						minimum := float32(1)
						if scenario.invalidResources {
							minimum = 32
						}
						return core.Shape{Shape: new(name), ProcessorDescription: new(processor), IsFlexible: new(true),
							OcpuOptions:   &core.ShapeOcpuOptions{Min: new(minimum), Max: new(float32(64))},
							MemoryOptions: &core.ShapeMemoryOptions{MinInGBs: new(float32(1)), MaxInGBs: new(float32(1024)), MinPerOcpuInGBs: new(float32(1)), MaxPerOcpuInGBs: new(float32(64))},
							QuotaNames:    []string{"standard-core-count", "standard-memory-count"}}
					}
					if r.URL.Query().Get("page") == "" {
						if scenario.cycleEndpoint != "/shapes" {
							w.Header().Set("opc-next-page", "page-2")
						}
						write([]core.Shape{shape(PreferredShape, "Ampere Altra")})
					} else {
						write([]core.Shape{shape("VM.Standard.E5.Flex", "AMD EPYC"), shape("VM.Standard.A2.Flex", "AmpereOne"), shape("VM.New.Flex", "unknown CPU")})
					}
				case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/limitDefinitions"):
					if r.URL.Query().Get("serviceName") != "compute" || r.URL.Query().Get("compartmentId") != "tenancy" {
						t.Errorf("wrong limit scope: %s", r.URL)
					}
					write([]limits.LimitDefinitionSummary{
						{Name: new("standard-core-count"), ServiceName: new("compute"), ScopeType: limits.LimitDefinitionSummaryScopeTypeAd, IsResourceAvailabilitySupported: new(true)},
						{Name: new("standard-memory-count"), ServiceName: new("compute"), ScopeType: limits.LimitDefinitionSummaryScopeTypeRegion, IsResourceAvailabilitySupported: new(true)},
					})
				case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/resourceAvailability"):
					if r.URL.Query().Get("compartmentId") != "compartment" {
						t.Errorf("quota not scoped to launch compartment: %s", r.URL)
					}
					wantDomain := ""
					if strings.Contains(r.URL.Path, "/standard-core-count/") {
						wantDomain = "AD-1"
					}
					if r.URL.Query().Get("availabilityDomain") != wantDomain {
						t.Errorf("limit scope lost: %s", r.URL)
					}
					available := float32(100)
					if scenario.quotaExhausted {
						available = 0
					}
					write(limits.ResourceAvailability{FractionalAvailability: new(available)})
				case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/computeCapacityReports"):
					capacityReports.Add(1)
					if scenario.unsupportedReport {
						w.WriteHeader(http.StatusBadRequest)
						write(map[string]string{"code": "InvalidParameter", "message": "capacity report unsupported"})
						return
					}
					var request core.CreateComputeCapacityReportDetails
					if err := json.UnmarshalRead(r.Body, &request); err != nil {
						t.Errorf("capacity report request: %v", err)
						w.WriteHeader(http.StatusBadRequest)
						return
					}
					if deref(request.CompartmentId) != "tenancy" || deref(request.AvailabilityDomain) != "AD-1" || len(request.ShapeAvailabilities) != 1 {
						t.Errorf("wrong capacity report scope: %+v", request)
						w.WriteHeader(http.StatusBadRequest)
						return
					}
					shape := request.ShapeAvailabilities[0]
					status := core.CapacityReportShapeAvailabilityAvailabilityStatusAvailable
					count := int64(1)
					if scenario.a1Exhausted && deref(shape.InstanceShape) == PreferredShape {
						status, count = core.CapacityReportShapeAvailabilityAvailabilityStatusOutOfHostCapacity, 0
					}
					if scenario.wrongReportConfig {
						shape.InstanceShapeConfig.MemoryInGBs = new(float32(2))
					}
					write(core.ComputeCapacityReport{CompartmentId: request.CompartmentId, AvailabilityDomain: request.AvailabilityDomain,
						ShapeAvailabilities: []core.CapacityReportShapeAvailability{{InstanceShape: shape.InstanceShape, InstanceShapeConfig: shape.InstanceShapeConfig, AvailableCount: new(count), AvailabilityStatus: status}}})
				default:
					t.Errorf("unexpected OCI mutation/request: %s %s", r.Method, r.URL)
					w.WriteHeader(http.StatusNotFound)
				}
			}))
			t.Cleanup(server.Close)
			compute, err := core.NewComputeClientWithConfigurationProvider(provider)
			if err != nil {
				t.Fatal(err)
			}
			compute.Host = server.URL
			quotaClient, err := limits.NewLimitsClientWithConfigurationProvider(provider)
			if err != nil {
				t.Fatal(err)
			}
			quotaClient.Host = server.URL
			request := CapacityRequest{TenancyID: "tenancy", CompartmentID: "compartment", AvailabilityDomains: []string{"AD-1"}, Role: RoleContainer,
				Architectures: []string{architecture}, OCPUs: 2, MemoryGB: 12, BootGB: 50, MonthlyHeadroomCents: new(uint64(1_000_000)), FactsExpireAt: time.Now().Add(time.Hour),
				Images: []QualifiedImage{{ID: "image-" + architecture, Architecture: architecture, Role: RoleContainer, RuntimeManifestDigest: strings.Repeat("a", 64)}},
				Prices: []ocicost.Price{{SKU: "B93297", PerUnit: 0.02}, {SKU: "B93298", PerUnit: 0.002}, {SKU: "B109529", PerUnit: 0.01}, {SKU: "B109530", PerUnit: 0.001},
					{SKU: "B97384", PerUnit: 0.01}, {SKU: "B97385", PerUnit: 0.001}, {SKU: "B91961", PerUnit: 0.025}, {SKU: "B91962", PerUnit: 0.0015}}}
			if scenario.expiredFacts {
				request.FactsExpireAt = time.Now().Add(-time.Second)
			}
			if scenario.insufficientSpend {
				request.MonthlyHeadroomCents = new(uint64(1))
			}
			if scenario.unknownSpend {
				request.MonthlyHeadroomCents = nil
			}
			if scenario.unknownPrice {
				request.Prices = nil
			}
			if scenario.missingQualification {
				request.Images[0].RuntimeManifestDigest = ""
			}
			selection, err := DiscoverCapacity(t.Context(), compute, quotaClient, request)
			if scenario.cycleEndpoint != "" {
				wantRequests := int32(2)
				if scenario.twoTokenCycle {
					wantRequests = 3
				}
				if cycleRequests.Load() != wantRequests || capacityReports.Load() != 0 || len(selection.Candidates) != 0 {
					t.Fatalf("cyclic listing made %d requests and %d capacity reports, selection=%+v; want %d requests, no reports or candidates", cycleRequests.Load(), capacityReports.Load(), selection, wantRequests)
				}
			}
			if scenario.cycleEndpoint == "/limitDefinitions" {
				if err == nil || !strings.Contains(err.Error(), "pagination repeated") {
					t.Fatalf("cyclic compute limit listing error=%v, want pagination refusal", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if scenario.wantShape != "" {
				if len(selection.Candidates) == 0 || selection.Candidates[0].Shape != scenario.wantShape || selection.Candidates[0].Architecture != architecture {
					t.Fatalf("selection=%+v, want first %s/%s", selection, scenario.wantShape, architecture)
				}
				if selection.Candidates[0].MonthlyCents == 0 {
					t.Fatal("nonzero actual usage rates lost")
				}
			} else if len(selection.Candidates) != 0 || !slices.ContainsFunc(selection.Pending, func(reason string) bool { return strings.Contains(reason, scenario.pending) }) {
				t.Fatalf("selection=%+v, want pending %q", selection, scenario.pending)
			}
		})
	}
}
