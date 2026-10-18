package region

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json/v2"
	"net/http"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapmaterial"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/releasechannel"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

// The actual OCI SDK reads the signed root object from a persistent protocol
// server. An authentic grant still cannot manufacture current worker evidence.
func TestWorkerProfileAuthorityRequiresIndependentCurrentSources(t *testing.T) {
	_, client, publish := foundationProtocolStore(t)
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
	reader := &SignedFootprint{client: client, storage: bootstrap.StorageDomain{Namespace: "ns", HeadBucket: "heads", Prefix: "bootstrap"}, scope: scope, expires: now.Add(2 * time.Hour), roots: roots, tenancy: "ocid1.tenancy.oc1..test", home: bootstrap.FoundationScope{InstallationID: entityid.New(), GrantGeneration: 1}}
	grant := FoundationGrant{InstallationID: reader.home.InstallationID, SchemaVersion: 1, Generation: 1, TenancyID: reader.tenancy, ParentCompartmentID: "ocid1.compartment.oc1..parent", SharedCompartmentID: "ocid1.compartment.oc1..shared", Currency: "USD", MonthlyLimitMinor: 10000, CleanupOwner: "scenario",
		InfrastructureSpend: &InfrastructureSpendIntent{MonthlyLimitMinor: 9000}, Regions: []FoundationIntent{{Generation: 1, Plan: map[string]any{"cell": "GRU", "region": "sa-saopaulo-1", "tenancy_id": reader.tenancy, "parent_compartment_id": "ocid1.compartment.oc1..parent", "shared_compartment_id": "ocid1.compartment.oc1..shared", "resource_ids": map[string]any{}}, BootstrapMaterial: &BootstrapMaterialIntent{PlanSHA256: strings.Repeat("a", 64), Config: bootstrapmaterial.Config{Environment: "production"}, SourceRegistration: &bootstrap.InitialSourceRegistration{StorageDomain: bootstrap.StorageDomain{Namespace: "ns"}}}}}}
	ref := func(key string) string {
		value, err := FoundationResourceReference("GRU", key)
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	bucket, err := releasechannel.BucketName("GRU")
	if err != nil {
		t.Fatal(err)
	}
	for _, role := range []string{"container", "wasm"} {
		for _, arch := range []string{"arm64", "amd64"} {
			grant.WorkerProfiles = append(grant.WorkerProfiles, WorkerProfile{Cell: "GRU", Environment: "production", Role: role, Architecture: arch, Shape: "VM.Standard.A1.Flex", OCPUs: 2, MemoryGB: 12, BootGB: 50, AvailabilityDomains: []string{"test:AD-1"}, CompartmentRef: ref("workload_compartment"), SubnetRef: ref("subnet"), NSGRef: ref("workload_network_security_group"), Runtime: release.ProductionRuntime,
				PoolMembership:  WorkerPoolMembership{Purpose: PoolMembershipQuarantineV1, Provenance: PoolMembershipProvenanceV1},
				CapacityJournal: WorkerCapacityJournal{Purpose: CapacityJournalPurposeV1, Principal: CapacityJournalPrincipalV1, Delta: CapacityJournalDeltaV1},
				ImageSource:     WorkerImageSource{OCIRegion: "sa-saopaulo-1", Namespace: "ns", Bucket: bucket, CurrentObject: releasechannel.CurrentImageObject(role, arch, "production"), ImageDomain: release.ImageDomain, QualificationDomain: release.ProductionQualificationDomain}, Bootstrap: WorkerBootstrapTemplate{Derivation: WorkerBootstrapDerivationV1, MaterialPlanSHA256: strings.Repeat("a", 64), VaultRef: ref("vault"), KMSKeyRef: ref("key"), RecipientPermission: "SECRET_BUNDLE_READ"}})
		}
	}
	if err := ValidateWorkerProfiles(grant, grant.WorkerProfiles, roots, now); err != nil {
		t.Fatal(err)
	}
	write := func() {
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
		reader.home.GrantSHA256 = workerSHA256(wire)
		publish("bootstrap/"+foundationGrantObject, wire)
	}
	write()
	if _, err := reader.AuthorizedRegions(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := reader.WorkerProfiles(t.Context(), "GRU", "container"); err == nil || !strings.Contains(err.Error(), "independently authenticated OCI source") {
		t.Fatalf("root profile manufactured current worker proof: %v", err)
	}
	spending := grant.InfrastructureSpend
	grant.InfrastructureSpend = nil
	write()
	if _, err := reader.WorkerProfiles(t.Context(), "GRU", "container"); err == nil || !strings.Contains(err.Error(), "bounded fleet spending") {
		t.Fatalf("worker profile bypassed numerical fleet authority: %v", err)
	}
	grant.InfrastructureSpend = spending
	original, _ := json.Marshal(grant.WorkerProfiles, json.Deterministic(true))
	for _, permission := range []WorkerCapacityJournal{
		{},
		{Purpose: "general-foundation-write", Principal: CapacityJournalPrincipalV1, Delta: CapacityJournalDeltaV1},
		{Purpose: CapacityJournalPurposeV1, Principal: "current-regional-writer", Delta: CapacityJournalDeltaV1},
		{Purpose: CapacityJournalPurposeV1, Principal: CapacityJournalPrincipalV1, Delta: "replace-record"},
	} {
		if err := json.Unmarshal(original, &grant.WorkerProfiles); err != nil {
			t.Fatal(err)
		}
		grant.WorkerProfiles[0].CapacityJournal = permission
		write()
		if _, err := reader.WorkerProfiles(t.Context(), "GRU", "container"); err == nil || strings.Contains(err.Error(), "independently authenticated OCI source") {
			t.Fatalf("signed worker profile without exact HOME capacity purpose reached runtime source: %v", err)
		}
	}
	for _, alter := range []func(){func() { grant.WorkerProfiles[0].NSGRef = ref("network_security_group") }, func() { grant.WorkerProfiles[0].ImageSource.CurrentObject = "caller-selected" }, func() { grant.WorkerProfiles[0].Bootstrap.RecipientPermission = "MANAGE_SECRETS" }, func() { grant.WorkerProfiles[0].OCPUs = 4 }, func() { grant.WorkerProfiles[0].Bootstrap.MaterialPlanSHA256 = strings.Repeat("b", 64) }, func() { grant.WorkerProfiles[0].AvailabilityDomains = []string{"test:AD-1", "test:AD-1"} }} {
		if err := json.Unmarshal(original, &grant.WorkerProfiles); err != nil {
			t.Fatal(err)
		}
		alter()
		write()
		if _, err := reader.WorkerProfiles(t.Context(), "GRU", "container"); err == nil || strings.Contains(err.Error(), "independently authenticated OCI source") {
			t.Fatalf("invalid root worker policy reached runtime source: %v", err)
		}
	}
	if err := json.Unmarshal(original, &grant.WorkerProfiles); err != nil {
		t.Fatal(err)
	}
	write()
	reader.home.GrantSHA256 = strings.Repeat("0", 64)
	if _, err := reader.WorkerProfiles(t.Context(), "GRU", "container"); err == nil {
		t.Fatal("worker reader accepted a different root-pinned grant")
	}
}

func TestWorkerProfilePreparationSDKPagination(t *testing.T) {
	for _, scenario := range []struct {
		name, cycle   string
		emptyTerminal bool
	}{
		{name: "finite pages reuse tokens across roles architectures and domains"},
		{name: "empty terminal page", emptyTerminal: true},
		{name: "self cycle discards earlier profiles", cycle: "self"},
		{name: "two token cycle discards earlier profiles", cycle: "two"},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			var requests, listings, pageRequests, images atomic.Int32
			bucket, err := releasechannel.BucketName("GRU")
			if err != nil {
				t.Fatal(err)
			}
			factory := paginationSDKFactory(t, func(w http.ResponseWriter, r *http.Request) {
				switch {
				case r.URL.Path == "/20160918/availabilityDomains":
					if r.URL.Query().Get("compartmentId") != "ocid1.tenancy.oc1..test" {
						t.Error("availability domains escaped tenancy")
					}
					if err := json.MarshalWrite(w, []map[string]string{{"name": "test:AD-2"}, {"name": "test:AD-1"}, {"name": "test:AD-1"}}); err != nil {
						t.Error(err)
					}
				case strings.HasPrefix(r.URL.Path, "/n/ns/b/"+bucket+"/o/"):
					object := strings.TrimPrefix(r.URL.Path, "/n/ns/b/"+bucket+"/o/")
					if !slices.Contains([]string{releasechannel.CurrentImageObject("container", "arm64", "production"), releasechannel.CurrentImageObject("container", "amd64", "production"), releasechannel.CurrentImageObject("wasm", "arm64", "production"), releasechannel.CurrentImageObject("wasm", "amd64", "production")}, object) {
						t.Error("image lookup escaped current worker channels")
					}
					images.Add(1)
					w.WriteHeader(http.StatusNotFound)
					w.Write([]byte(`{"code":"ObjectNotFound","message":"no current qualified image"}`))
				case r.URL.Path == "/20160918/shapes":
					requests.Add(1)
					if r.URL.Query().Get("compartmentId") != "ocid1.compartment.oc1..parent" || !slices.Contains([]string{"test:AD-1", "test:AD-2"}, r.URL.Query().Get("availabilityDomain")) {
						t.Error("shape listing escaped compartment or availability domain")
					}
					page := r.URL.Query().Get("page")
					if page == "" {
						listings.Add(1)
						pageRequests.Store(0)
					}
					if pageRequests.Add(1) > 3 {
						w.WriteHeader(http.StatusBadRequest)
						return
					}
					cycle := scenario.cycle != "" && listings.Load() == 5
					items := []map[string]any{}
					shape, processor := "VM.Standard.A1.Flex", "Ampere Altra"
					switch page {
					case "":
						w.Header().Set("opc-next-page", "page-a")
					case "page-a":
						shape, processor = "VM.Standard.E5.Flex", "AMD EPYC"
						next := "page-b"
						if cycle && scenario.cycle == "self" {
							next = "page-a"
						}
						w.Header().Set("opc-next-page", next)
					case "page-b":
						if cycle {
							w.Header().Set("opc-next-page", "page-a")
						} else if scenario.emptyTerminal {
							w.Header().Set("opc-next-page", "")
						}
					default:
						t.Errorf("unexpected shape page: %s", r.URL)
						w.WriteHeader(http.StatusBadRequest)
						return
					}
					if page != "page-b" {
						items = append(items, map[string]any{"shape": shape, "processorDescription": processor, "isFlexible": true, "ocpuOptions": map[string]any{"min": 1, "max": 8}, "memoryOptions": map[string]any{"minInGBs": 1, "maxInGBs": 128, "minPerOcpuInGBs": 1, "maxPerOcpuInGBs": 64}})
					}
					if err := json.MarshalWrite(w, items); err != nil {
						t.Error(err)
					}
				default:
					t.Errorf("worker preparation escaped SDK fixture: %s", r.URL)
					w.WriteHeader(http.StatusBadRequest)
				}
			})
			public, _, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			roots, err := trust.ParseKeyring(public)
			if err != nil {
				t.Fatal(err)
			}
			grant := FoundationGrant{TenancyID: "ocid1.tenancy.oc1..test", ParentCompartmentID: "ocid1.compartment.oc1..parent", InfrastructureSpend: &InfrastructureSpendIntent{MonthlyLimitMinor: 9000}, Regions: []FoundationIntent{{Plan: map[string]any{"cell": "GRU", "region": foundationHomeRegion}, BootstrapMaterial: &BootstrapMaterialIntent{PlanSHA256: strings.Repeat("a", 64), Config: bootstrapmaterial.Config{Environment: "production"}, SourceRegistration: &bootstrap.InitialSourceRegistration{StorageDomain: bootstrap.StorageDomain{Namespace: "ns"}}}}}}
			profiles, err := PrepareWorkerProfilesSDK(t.Context(), factory, "ns", roots, grant, time.Now())
			if scenario.cycle != "" {
				want := int32(15)
				if scenario.cycle == "self" {
					want = 14
				}
				if err == nil || !strings.Contains(err.Error(), "repeated a page") || profiles != nil || requests.Load() != want || listings.Load() != 5 || images.Load() != 3 {
					t.Fatalf("cyclic shapes profiles=%+v error=%v requests=%d listings=%d images=%d", profiles, err, requests.Load(), listings.Load(), images.Load())
				}
				return
			}
			if err != nil || len(profiles) != 4 || requests.Load() != 24 || listings.Load() != 8 || images.Load() != 4 {
				t.Fatalf("finite shapes profiles=%+v error=%v requests=%d listings=%d images=%d", profiles, err, requests.Load(), listings.Load(), images.Load())
			}
			for _, profile := range profiles {
				shape := "VM.Standard.A1.Flex"
				if profile.Architecture == "amd64" {
					shape = "VM.Standard.E5.Flex"
				}
				if profile.Shape != shape || !slices.Equal(profile.AvailabilityDomains, []string{"test:AD-1", "test:AD-2"}) {
					t.Fatalf("paginated worker shape or placements changed: %+v", profile)
				}
			}
		})
	}
}
