package cellscale

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/core"
	"github.com/oracle/oci-go-sdk/v65/limits"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociclient"
)

type fakeCompute struct {
	pages          map[string]core.ListInstancesResponse // keyed by page token ("" = first)
	listCalls      []core.ListInstancesRequest
	launches       []core.LaunchInstanceRequest
	updates        []core.UpdateInstanceRequest
	terminates     []core.TerminateInstanceRequest
	shapes         []core.Shape
	domainShapes   map[string][]core.Shape
	shapeCalls     []core.ListShapesRequest
	image          error // GetImage fails with it; nil serves an available image
	launchError    error
	launchID       string
	launchResponse *core.LaunchInstanceResponse
	instances      map[string]core.Instance
	getCalls       []core.GetInstanceRequest
	getError       error
	updateResponse core.UpdateInstanceResponse
	updateError    error
}

func (f *fakeCompute) ListShapes(_ context.Context, r core.ListShapesRequest) (core.ListShapesResponse, error) {
	f.shapeCalls = append(f.shapeCalls, r)
	shapes := f.shapes
	if domainShapes, found := f.domainShapes[deref(r.AvailabilityDomain)]; found {
		shapes = domainShapes
	}
	if r.Page == nil {
		return core.ListShapesResponse{Items: shapes[:min(1, len(shapes))], OpcNextPage: common.String("p2")}, nil
	}
	return core.ListShapesResponse{Items: shapes[min(1, len(shapes)):]}, nil
}

func (f *fakeCompute) GetImage(_ context.Context, r core.GetImageRequest) (core.GetImageResponse, error) {
	if f.image != nil {
		return core.GetImageResponse{}, f.image
	}
	return core.GetImageResponse{Image: core.Image{Id: r.ImageId, LifecycleState: core.ImageLifecycleStateAvailable}}, nil
}

// fakeReads serves subnets and quota availability by limit name.
type fakeReads struct {
	subnet          error
	subnetAD        *string
	subnetDNSLabel  *string
	available       map[string]float32
	domainAvailable map[string]map[string]float32
	resources       map[string]limits.ResourceAvailability
	domainResources map[string]map[string]limits.ResourceAvailability
	quotas          []limits.GetResourceAvailabilityRequest
}

func (f *fakeReads) GetSubnet(_ context.Context, r core.GetSubnetRequest) (core.GetSubnetResponse, error) {
	if f.subnet != nil {
		return core.GetSubnetResponse{}, f.subnet
	}
	return core.GetSubnetResponse{Subnet: core.Subnet{Id: r.SubnetId, LifecycleState: core.SubnetLifecycleStateAvailable,
		AvailabilityDomain: f.subnetAD, DnsLabel: f.subnetDNSLabel}}, nil
}

func (f *fakeReads) GetResourceAvailability(_ context.Context, r limits.GetResourceAvailabilityRequest) (limits.GetResourceAvailabilityResponse, error) {
	f.quotas = append(f.quotas, r)
	if resource, ok := f.domainResources[deref(r.AvailabilityDomain)][*r.LimitName]; ok {
		return limits.GetResourceAvailabilityResponse{ResourceAvailability: resource}, nil
	}
	if resource, ok := f.resources[*r.LimitName]; ok {
		return limits.GetResourceAvailabilityResponse{ResourceAvailability: resource}, nil
	}
	if available, ok := f.domainAvailable[deref(r.AvailabilityDomain)][*r.LimitName]; ok {
		return limits.GetResourceAvailabilityResponse{ResourceAvailability: limits.ResourceAvailability{
			FractionalAvailability: common.Float32(available)}}, nil
	}
	return limits.GetResourceAvailabilityResponse{ResourceAvailability: limits.ResourceAvailability{
		FractionalAvailability: common.Float32(f.available[*r.LimitName])}}, nil
}

// missing is the 404 OCI answers for an absent or invisible resource.
type missing struct{}

func (missing) Error() string           { return "NotAuthorizedOrNotFound" }
func (missing) GetHTTPStatusCode() int  { return 404 }
func (missing) GetMessage() string      { return "not found" }
func (missing) GetCode() string         { return "NotAuthorizedOrNotFound" }
func (missing) GetOpcRequestID() string { return "test" }

// a1Flex is VM.Standard.A1.Flex as OCI lists it in sa-saopaulo-1.
func a1Flex() core.Shape {
	return core.Shape{Shape: common.String("VM.Standard.A1.Flex"), IsFlexible: common.Bool(true),
		OcpuOptions: &core.ShapeOcpuOptions{Min: common.Float32(1), Max: common.Float32(80)},
		MemoryOptions: &core.ShapeMemoryOptions{MinInGBs: common.Float32(1), MaxInGBs: common.Float32(512),
			MinPerOcpuInGBs: common.Float32(1), MaxPerOcpuInGBs: common.Float32(64)},
		QuotaNames: []string{"standard-a1-memory-count", "standard-a1-memory-regional-count", "standard-a1-core-count",
			"standard-a1-core-regional-count"}}
}

func (f *fakeCompute) ListInstances(_ context.Context, r core.ListInstancesRequest) (core.ListInstancesResponse, error) {
	f.listCalls = append(f.listCalls, r)
	token := ""
	if r.Page != nil {
		token = *r.Page
	}
	page, ok := f.pages[token]
	if !ok {
		return core.ListInstancesResponse{}, errors.New("unknown page " + token)
	}
	if r.AvailabilityDomain != nil {
		var items []core.Instance
		for _, item := range page.Items {
			if item.AvailabilityDomain == nil || *item.AvailabilityDomain == *r.AvailabilityDomain {
				items = append(items, item)
			}
		}
		page.Items = items
	}
	return page, nil
}

func (f *fakeCompute) LaunchInstance(_ context.Context, r core.LaunchInstanceRequest) (core.LaunchInstanceResponse, error) {
	f.launches = append(f.launches, r)
	if f.launchResponse != nil {
		return *f.launchResponse, f.launchError
	}
	if f.launchError != nil {
		return core.LaunchInstanceResponse{}, f.launchError
	}
	d := r.LaunchInstanceDetails
	id := f.launchID
	if id == "" {
		id = "ocid1.instance.new"
	}
	instance := core.Instance{
		Id: common.String(id), DisplayName: d.DisplayName, FreeformTags: d.FreeformTags,
		Shape:              d.Shape,
		AvailabilityDomain: d.AvailabilityDomain,
		LifecycleState:     core.InstanceLifecycleStateProvisioning,
		ShapeConfig:        &core.InstanceShapeConfig{Ocpus: d.ShapeConfig.Ocpus, MemoryInGBs: d.ShapeConfig.MemoryInGBs},
	}
	if f.instances == nil {
		f.instances = map[string]core.Instance{}
	}
	f.instances[id] = instance
	return core.LaunchInstanceResponse{Instance: instance}, nil
}

func (f *fakeCompute) GetInstance(_ context.Context, r core.GetInstanceRequest) (core.GetInstanceResponse, error) {
	f.getCalls = append(f.getCalls, r)
	if f.getError != nil {
		return core.GetInstanceResponse{}, f.getError
	}
	instance, ok := f.instances[deref(r.InstanceId)]
	if !ok {
		return core.GetInstanceResponse{}, missing{}
	}
	return core.GetInstanceResponse{Instance: instance}, nil
}

func (f *fakeCompute) UpdateInstance(_ context.Context, r core.UpdateInstanceRequest) (core.UpdateInstanceResponse, error) {
	f.updates = append(f.updates, r)
	return f.updateResponse, f.updateError
}

func (f *fakeCompute) TerminateInstance(_ context.Context, r core.TerminateInstanceRequest) (core.TerminateInstanceResponse, error) {
	f.terminates = append(f.terminates, r)
	return core.TerminateInstanceResponse{}, nil
}

func testTemplate() Template {
	return Template{
		Region: "sa-saopaulo-1", CompartmentID: "ocid1.compartment.x", AvailabilityDomain: "AD-1",
		SubnetID: "ocid1.subnet.x", ImageID: "ocid1.image.x", Shape: "VM.Standard.A1.Flex",
		BootVolumeGB: 100, UserData: "Y2xvdWQtaW5pdA==",
	}
}

func instanceItem(id, name, cell, role string, state core.InstanceLifecycleStateEnum, ocpus, mem float32) core.Instance {
	item := core.Instance{
		Id: common.String(id), DisplayName: common.String(name), LifecycleState: state,
		Shape:              common.String(testTemplate().Shape),
		AvailabilityDomain: common.String("AD-1"),
		FreeformTags:       map[string]string{"ts-cell": cell, "ts-role": role},
	}
	if ocpus > 0 {
		item.ShapeConfig = &core.InstanceShapeConfig{Ocpus: common.Float32(ocpus), MemoryInGBs: common.Float32(mem)}
	}
	return item
}

func newTestCloud(t *testing.T, fake *fakeCompute) *OCICloud {
	t.Helper()
	cloud, err := newOCICloud("gru-1", testTemplate(), fake, &fakeReads{})
	if err != nil {
		t.Fatal(err)
	}
	return cloud
}

func TestOCICloudListFiltersPaginatesSorts(t *testing.T) {
	fake := &fakeCompute{pages: map[string]core.ListInstancesResponse{
		"": {OpcNextPage: common.String("p2"), Items: []core.Instance{
			instanceItem("i3", "gru-1-db-3", "gru-1", "db", core.InstanceLifecycleStateRunning, 4, 24),
			instanceItem("ix", "gru-1-db-4", "gru-1", "db", core.InstanceLifecycleStateTerminating, 1, 6),
			instanceItem("iy", "gru-1-db-5", "gru-1", "db", core.InstanceLifecycleStateTerminated, 1, 6),
			instanceItem("iz", "gru-1-db-6", "gru-2", "db", core.InstanceLifecycleStateRunning, 1, 6),
		}},
		"p2": {Items: []core.Instance{
			instanceItem("i1", "gru-1-db-1", "gru-1", "db", core.InstanceLifecycleStateRunning, 2, 12),
			instanceItem("ia", "gru-1-db-7", "gru-1", "bastion", core.InstanceLifecycleStateRunning, 1, 6),
			instanceItem("ib", "bastion", "gru-1", "db", core.InstanceLifecycleStateRunning, 1, 6),
			instanceItem("i2", "gru-1-db-2", "gru-1", "db", core.InstanceLifecycleStateStopped, 0, 0),
		}},
	}}
	got, err := newTestCloud(t, fake).List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := []Instance{
		{ID: "i1", Name: "gru-1-db-1", State: "RUNNING", Shape: Shape{OCPUs: 2, MemoryGB: 12}},
		{ID: "i2", Name: "gru-1-db-2", State: "STOPPED"},
		{ID: "i3", Name: "gru-1-db-3", State: "RUNNING", Shape: Shape{OCPUs: 4, MemoryGB: 24}},
		{ID: "ix", Name: "gru-1-db-4", State: "TERMINATING", Shape: Shape{OCPUs: 1, MemoryGB: 6}},
		// Same names without this cell's db tags, such as placement seats.
		{ID: "iz", Name: "gru-1-db-6", State: "RUNNING", Shape: Shape{OCPUs: 1, MemoryGB: 6}, Foreign: true},
		{ID: "ia", Name: "gru-1-db-7", State: "RUNNING", Shape: Shape{OCPUs: 1, MemoryGB: 6}, Foreign: true},
	}
	for i := range want {
		want[i].AvailabilityDomain = "AD-1"
		want[i].ShapeName = testTemplate().Shape
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("List = %+v, want %+v", got, want)
	}
	if len(fake.listCalls) != 2 || *fake.listCalls[1].Page != "p2" {
		t.Fatalf("pagination calls = %+v", fake.listCalls)
	}
	if first := fake.listCalls[0]; *first.CompartmentId != "ocid1.compartment.x" || first.AvailabilityDomain != nil {
		t.Fatalf("list scope = %+v", first)
	}
}

func TestOCICloudDiscoveryAcrossAvailabilityDomains(t *testing.T) {
	for _, foreign := range []bool{false, true} {
		t.Run(fmt.Sprintf("foreign=%t", foreign), func(t *testing.T) {
			item := instanceItem("i1", "gru-1-db-1", "gru-1", "db", core.InstanceLifecycleStateRunning, 2, 12)
			item.AvailabilityDomain = common.String("AD-2")
			if foreign {
				item.FreeformTags = nil
			}
			fake := &fakeCompute{pages: map[string]core.ListInstancesResponse{"": {Items: []core.Instance{item}}}, shapes: []core.Shape{a1Flex()}}
			cloud := newTestCloud(t, fake)
			reads := &fakeReads{subnetDNSLabel: common.String("database"), available: map[string]float32{}}
			for _, quota := range a1Flex().QuotaNames {
				reads.available[quota] = 512
			}
			cloud.reads = reads
			instances, err := cloud.List(t.Context())
			if err != nil || len(instances) != 1 || instances[0].ID != "i1" || instances[0].Foreign != foreign || instances[0].AvailabilityDomain != "AD-2" {
				t.Fatalf("cross-domain discovery = %+v, %v", instances, err)
			}
			instance, err := cloud.Launch(t.Context(), "gru-1-db-1", Shape{OCPUs: 2, MemoryGB: 12})
			if foreign {
				if err == nil || !strings.Contains(err.Error(), "does not own") {
					t.Fatalf("cross-domain foreign name was not reserved: %+v, %v", instance, err)
				}
			} else if err != nil || instance.ID != "i1" || instance.AvailabilityDomain != "AD-2" {
				t.Fatalf("cross-domain owned name was not reused: %+v, %v", instance, err)
			}
			report, err := cloud.Preflight(t.Context(), testPolicy())
			wantNodes := 1
			if foreign {
				wantNodes = 0
			}
			if err != nil || len(report.Problems) != 0 || report.Nodes != wantNodes ||
				report.CoresNeeded != 48-float64(wantNodes)*2 || report.MemoryGBNeeded != 288-float64(wantNodes)*12 {
				t.Fatalf("cross-domain preflight = %+v, %v", report, err)
			}
			for _, request := range fake.listCalls {
				if request.AvailabilityDomain != nil || deref(request.CompartmentId) != "ocid1.compartment.x" {
					t.Fatalf("discovery scope = %+v", request)
				}
			}
			if len(fake.launches)+len(fake.updates)+len(fake.terminates) != 0 {
				t.Fatal("cross-domain occupied name caused a mutation")
			}
		})
	}
}

func TestOCICloudRejectsDuplicateLiveNames(t *testing.T) {
	name := NodeName("gru-1", maxOrdinal)
	owned := instanceItem("owned", name, "gru-1", "db", core.InstanceLifecycleStateRunning, 2, 12)
	owned.FreeformTags[tagLaunchToken] = "pending-token"
	foreign := instanceItem("foreign", name, "gru-1", "placement", core.InstanceLifecycleStateRunning, 2, 12)
	untagged := foreign
	untagged.Id, untagged.FreeformTags = common.String("untagged"), nil
	otherOwned := instanceItem("other-owned", name, "gru-1", "db", core.InstanceLifecycleStateRunning, 2, 12)
	unsupportedOwned := instanceItem("unsupported-owned", name, "gru-1", "db", core.InstanceLifecycleStateRunning, 2, 12)
	unsupportedOwned.Shape = common.String("VM.Standard.E4.Flex")
	terminatingOwned, terminatingForeign := owned, foreign
	terminatingOwned.LifecycleState, terminatingForeign.LifecycleState = core.InstanceLifecycleStateTerminating, core.InstanceLifecycleStateTerminating
	for _, test := range []struct {
		name          string
		first, second core.Instance
	}{
		{"owned then foreign", owned, foreign},
		{"foreign then owned", foreign, owned},
		{"two foreign", foreign, untagged},
		{"two owned", owned, otherOwned},
		{"unsupported owned shape", unsupportedOwned, otherOwned},
		{"terminating owned", terminatingOwned, foreign},
		{"terminating foreign", terminatingForeign, owned},
		{"both terminating", terminatingOwned, terminatingForeign},
	} {
		for _, paged := range []bool{false, true} {
			for _, remote := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/paged=%t/remote=%t", test.name, paged, remote), func(t *testing.T) {
					first, second := test.first, test.second
					first.AvailabilityDomain, second.AvailabilityDomain = common.String("AD-1"), common.String("AD-1")
					if remote {
						second.AvailabilityDomain = common.String("AD-2")
					}
					// Earlier items must neither release an old intent nor adopt an ID
					// when a later item makes the whole inventory ambiguous.
					tombstone := instanceItem("old", "gru-1-db-2", "gru-1", "db", core.InstanceLifecycleStateTerminated, 2, 12)
					unique := instanceItem("unique", "gru-1-db-3", "gru-1", "db", core.InstanceLifecycleStateRunning, 2, 12)
					fake := &fakeCompute{pages: map[string]core.ListInstancesResponse{"": {Items: []core.Instance{tombstone, unique, first}}}}
					if paged {
						page := fake.pages[""]
						page.OpcNextPage = common.String("p2")
						fake.pages[""], fake.pages["p2"] = page, core.ListInstancesResponse{Items: []core.Instance{second}}
					} else {
						page := fake.pages[""]
						page.Items = append(page.Items, second)
						fake.pages[""] = page
					}
					cloud := newTestCloud(t, fake)
					pending := OCILaunchState{Name: name, Template: testTemplate(), Shape: Shape{OCPUs: 2, MemoryGB: 12},
						RetryToken: "pending-token", StartedAt: time.Now().Add(-time.Minute)}
					pending.Request = cloud.launchDetails(name, pending.Shape, pending.Template, pending.RetryToken)
					saves := 0
					if err := cloud.RestoreLaunchState([]OCILaunchState{pending, {Name: deref(tombstone.DisplayName), InstanceID: "old"}}, func([]OCILaunchState) error {
						saves++
						return nil
					}); err != nil {
						t.Fatal(err)
					}
					before, err := json.Marshal(cloud.launches)
					if err != nil {
						t.Fatal(err)
					}
					instances, err := cloud.List(t.Context())
					if err == nil || !strings.Contains(err.Error(), "duplicate live node name") || !strings.Contains(err.Error(), name) || instances != nil {
						t.Fatalf("ambiguous listing = %+v, %v", instances, err)
					}
					// A collision blocks launches anywhere in the cell, including a free name.
					for _, launchName := range []string{name, "gru-1-db-1"} {
						if got, err := cloud.Launch(t.Context(), launchName, pending.Shape); err == nil || !strings.Contains(err.Error(), "duplicate live node name") || got != (Instance{}) {
							t.Fatalf("Launch(%s) bypassed ambiguous listing: %+v, %v", launchName, got, err)
						}
					}
					if report, err := cloud.Preflight(t.Context(), testPolicy()); err == nil || !strings.Contains(err.Error(), "duplicate live node name") || report.Nodes != 0 {
						t.Fatalf("Preflight bypassed ambiguous listing: %+v, %v", report, err)
					}
					after, err := json.Marshal(cloud.launches)
					if err != nil || string(after) != string(before) || saves != 0 || cloud.launchPersistenceError != nil {
						t.Fatalf("failed listing changed launch state: before=%s after=%s saves=%d err=%v", before, after, saves, err)
					}
					if len(fake.launches)+len(fake.updates)+len(fake.terminates)+len(fake.getCalls)+len(fake.shapeCalls) != 0 {
						t.Fatal("ambiguous inventory caused a mutation or continued identity/template reconciliation")
					}
					for _, request := range fake.listCalls {
						if request.AvailabilityDomain != nil || deref(request.CompartmentId) != "ocid1.compartment.x" {
							t.Fatalf("discovery scope = %+v", request)
						}
					}
				})
			}
		}
	}
}

func TestOCICloudListIgnoresTerminatedAndUnrelatedDuplicates(t *testing.T) {
	for _, foreign := range []bool{false, true} {
		for _, tombstonesFirst := range []bool{false, true} {
			t.Run(fmt.Sprintf("foreign=%t/tombstonesFirst=%t", foreign, tombstonesFirst), func(t *testing.T) {
				live := instanceItem("live", "gru-1-db-1", "gru-1", "db", core.InstanceLifecycleStateRunning, 2, 12)
				if foreign {
					live.FreeformTags = nil
				}
				items := []core.Instance{
					instanceItem("old-owned", deref(live.DisplayName), "gru-1", "db", core.InstanceLifecycleStateTerminated, 2, 12),
					instanceItem("old-foreign", deref(live.DisplayName), "gru-2", "db", core.InstanceLifecycleStateTerminated, 2, 12),
					instanceItem("gone1", "gru-1-db-2", "gru-1", "db", core.InstanceLifecycleStateTerminated, 2, 12),
					instanceItem("gone2", "gru-1-db-2", "gru-1", "db", core.InstanceLifecycleStateTerminated, 2, 12),
				}
				for _, name := range []string{"bastion", "gru-2-db-1", "gru-1-db-0", "gru-1-db-65", "gru-1-db-01", "gru-1-db-1-data"} {
					for _, id := range []string{"unrelated1", "unrelated2"} {
						items = append(items, instanceItem(id, name, "gru-1", "db", core.InstanceLifecycleStateRunning, 2, 12))
					}
				}
				if tombstonesFirst {
					items = append(items, live)
				} else {
					items = append([]core.Instance{live}, items...)
				}
				fake := &fakeCompute{pages: map[string]core.ListInstancesResponse{
					"": {Items: items[:1], OpcNextPage: common.String("p2")}, "p2": {Items: items[1:]},
				}}
				got, err := newTestCloud(t, fake).List(t.Context())
				want := instanceOf(live)
				want.Foreign = foreign
				if err != nil || !reflect.DeepEqual(got, []Instance{want}) {
					t.Fatalf("tombstones or unrelated duplicates blocked discovery: %+v, %v", got, err)
				}
			})
		}
	}
}

func TestOCICloudFailedListingPreservesLaunchState(t *testing.T) {
	for _, failure := range []string{"page error", "different generation"} {
		t.Run(failure, func(t *testing.T) {
			tombstone := instanceItem("old", "gru-1-db-1", "gru-1", "db", core.InstanceLifecycleStateTerminated, 2, 12)
			observed := instanceItem("accepted", "gru-1-db-2", "gru-1", "db", core.InstanceLifecycleStateRunning, 2, 12)
			observed.FreeformTags[tagLaunchToken] = "pending-token"
			fake := &fakeCompute{pages: map[string]core.ListInstancesResponse{"": {Items: []core.Instance{tombstone, observed}, OpcNextPage: common.String("p2")}}}
			if failure == "different generation" {
				fake.pages["p2"] = core.ListInstancesResponse{Items: []core.Instance{
					instanceItem("unrelated", "gru-1-db-3", "gru-1", "db", core.InstanceLifecycleStateRunning, 2, 12),
				}}
			}
			cloud := newTestCloud(t, fake)
			pending := OCILaunchState{Name: deref(observed.DisplayName), Template: testTemplate(), Shape: Shape{OCPUs: 2, MemoryGB: 12},
				RetryToken: "pending-token", StartedAt: time.Now().Add(-time.Minute)}
			pending.Request = cloud.launchDetails(pending.Name, pending.Shape, pending.Template, pending.RetryToken)
			if err := cloud.RestoreLaunchState([]OCILaunchState{
				{Name: deref(tombstone.DisplayName), InstanceID: "old"}, pending, {Name: "gru-1-db-3", InstanceID: "original"},
			}, func([]OCILaunchState) error { t.Fatal("failed listing saved journal"); return nil }); err != nil {
				t.Fatal(err)
			}
			before, err := json.Marshal(cloud.launches)
			if err != nil {
				t.Fatal(err)
			}
			if got, err := cloud.List(t.Context()); err == nil || got != nil {
				t.Fatalf("invalid listing succeeded: %+v, %v", got, err)
			}
			after, err := json.Marshal(cloud.launches)
			if err != nil || string(after) != string(before) {
				t.Fatalf("failed listing changed launch state: before=%s after=%s err=%v", before, after, err)
			}
		})
	}
}

func TestOCICloudUnsupportedShapesPreserveLaunchState(t *testing.T) {
	for _, test := range []struct {
		name  string
		shape *string
	}{
		{"different flex", common.String("VM.Standard.E4.Flex")},
		{"non-flex", common.String("VM.Standard.E4.Standard")},
		{"missing", nil},
		{"empty", common.String("")},
	} {
		for _, paged := range []bool{false, true} {
			for _, remote := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/paged=%t/remote=%t", test.name, paged, remote), func(t *testing.T) {
					tombstone := instanceItem("old", "gru-1-db-1", "gru-1", "db", core.InstanceLifecycleStateTerminated, 2, 12)
					tombstone.Shape = nil // Terminal evidence does not require resize capabilities.
					observed := instanceItem("accepted", "gru-1-db-2", "gru-1", "db", core.InstanceLifecycleStateRunning, 2, 12)
					observed.FreeformTags[tagLaunchToken] = "pending-token"
					unsupported := instanceItem("unsupported", "gru-1-db-3", "gru-1", "db", core.InstanceLifecycleStateRunning, 4, 24)
					unsupported.Shape = test.shape
					if remote {
						unsupported.AvailabilityDomain = common.String("AD-2")
					}
					page := core.ListInstancesResponse{Items: []core.Instance{tombstone, observed}}
					fake := &fakeCompute{pages: map[string]core.ListInstancesResponse{}}
					if paged {
						page.OpcNextPage = common.String("p2")
						fake.pages["p2"] = core.ListInstancesResponse{Items: []core.Instance{unsupported}}
					} else {
						page.Items = append(page.Items, unsupported)
					}
					fake.pages[""] = page
					cloud := newTestCloud(t, fake)
					reads := &fakeReads{}
					cloud.reads = reads
					pending := OCILaunchState{Name: deref(observed.DisplayName), Template: testTemplate(), Shape: small,
						RetryToken: "pending-token", StartedAt: time.Now().Add(-time.Minute)}
					pending.Request = cloud.launchDetails(pending.Name, pending.Shape, pending.Template, pending.RetryToken)
					saves := 0
					if err := cloud.RestoreLaunchState([]OCILaunchState{{Name: deref(tombstone.DisplayName), InstanceID: "old"}, pending}, func([]OCILaunchState) error {
						saves++
						return nil
					}); err != nil {
						t.Fatal(err)
					}
					before, err := json.Marshal(cloud.launches)
					if err != nil {
						t.Fatal(err)
					}
					if got, err := cloud.List(t.Context()); err == nil || !strings.Contains(err.Error(), "instance unsupported: shape") || got != nil {
						t.Fatalf("unsupported inventory accepted: %+v, %v", got, err)
					}
					for _, name := range []string{pending.Name, "gru-1-db-4"} {
						if got, err := cloud.Launch(t.Context(), name, small); err == nil || !strings.Contains(err.Error(), "instance unsupported: shape") || got != (Instance{}) {
							t.Fatalf("Launch(%s) bypassed shape validation: %+v, %v", name, got, err)
						}
					}
					if report, err := cloud.Preflight(t.Context(), testPolicy()); err == nil || !strings.Contains(err.Error(), "instance unsupported: shape") || report.Nodes != 0 {
						t.Fatalf("Preflight bypassed shape validation: %+v, %v", report, err)
					}
					after, err := json.Marshal(cloud.launches)
					if err != nil || string(after) != string(before) || saves != 0 || cloud.launchPersistenceError != nil {
						t.Fatalf("shape rejection changed journal: before=%s after=%s saves=%d err=%v", before, after, saves, err)
					}
					if len(fake.launches)+len(fake.updates)+len(fake.terminates)+len(fake.getCalls)+len(fake.shapeCalls)+len(reads.quotas) != 0 {
						t.Fatal("shape rejection caused effects or continued instance/template/quota reconciliation")
					}
					wantCalls := 4
					if paged {
						wantCalls *= 2
					}
					if len(fake.listCalls) != wantCalls {
						t.Fatalf("list calls = %d, want %d", len(fake.listCalls), wantCalls)
					}
					for _, request := range fake.listCalls {
						if request.AvailabilityDomain != nil || deref(request.CompartmentId) != testTemplate().CompartmentID {
							t.Fatalf("discovery scope = %+v", request)
						}
					}
				})
			}
		}
	}
}

func TestOCICloudUnsupportedShapesBlockControllerLifecycle(t *testing.T) {
	for _, shape := range []*string{common.String("VM.Standard.E4.Flex"), common.String("VM.Standard.E4.Standard"), nil, common.String("")} {
		for _, kind := range []Kind{KindScaleIn, KindResize, KindScaleOut} {
			t.Run(fmt.Sprintf("%s/shape=%v", kind, shape), func(t *testing.T) {
				cell := newFakeCell(4, small, 2, 150)
				s := newSim(t, testPolicy(), cell, time.Minute)
				state, err := s.controller.observe(t.Context())
				if err != nil {
					t.Fatal(err)
				}
				var items []core.Instance
				for _, instance := range cell.instances {
					item := instanceItem(instance.ID, instance.Name, cell.cell, "db", core.InstanceLifecycleStateRunning, 2, 12)
					if instance.Name == "gru-1-db-4" {
						item.Shape, item.AvailabilityDomain = shape, common.String("AD-2")
					}
					items = append(items, item)
				}
				fake := &fakeCompute{pages: map[string]core.ListInstancesResponse{"": {Items: items}}}
				s.controller.config.Cloud = newTestCloud(t, fake)
				if _, err := s.controller.Tick(t.Context()); err == nil || !strings.Contains(err.Error(), "does not match template shape") {
					t.Fatalf("observation accepted unsupported shape: %v", err)
				}
				action := Action{Kind: kind, Node: "gru-1-db-4"}
				if kind == KindResize {
					action.From, action.To = small, Shape{OCPUs: 4, MemoryGB: 24}
				} else if kind == KindScaleOut {
					action.Node, action.To = "gru-1-db-5", small
				}
				if err := s.controller.apply(t.Context(), state, action); err == nil || !strings.Contains(err.Error(), "does not match template shape") ||
					len(cell.callLog())+len(fake.launches)+len(fake.updates)+len(fake.terminates) != 0 {
					t.Fatalf("unsupported shape authorized lifecycle effects: err=%v membership=%v", err, cell.callLog())
				}
			})
		}
	}
}

func TestOCICloudDuplicateNamesBlockControllerLifecycle(t *testing.T) {
	for _, foreignFirst := range []bool{false, true} {
		for _, kind := range []Kind{KindScaleIn, KindResize, KindScaleOut} {
			t.Run(fmt.Sprintf("%s/foreignFirst=%t", kind, foreignFirst), func(t *testing.T) {
				cell := newFakeCell(4, small, 2, 150)
				s := newSim(t, testPolicy(), cell, time.Minute)
				state, err := s.controller.observe(t.Context())
				if err != nil {
					t.Fatal(err)
				}
				var items []core.Instance
				for _, instance := range cell.instances {
					items = append(items, instanceItem(instance.ID, instance.Name, cell.cell, "db", core.InstanceLifecycleStateRunning, 2, 12))
				}
				foreign := instanceItem("foreign", "gru-1-db-4", cell.cell, "placement", core.InstanceLifecycleStateRunning, 2, 12)
				if foreignFirst {
					items = append([]core.Instance{foreign}, items...)
				} else {
					items = append(items, foreign)
				}
				fake := &fakeCompute{pages: map[string]core.ListInstancesResponse{"": {Items: items}}}
				s.controller.config.Cloud = newTestCloud(t, fake)
				if _, err := s.controller.Tick(t.Context()); err == nil || !strings.Contains(err.Error(), "duplicate live node name") {
					t.Fatalf("observation accepted ambiguous identity: %v", err)
				}
				action := Action{Kind: kind, Node: "gru-1-db-4"}
				if kind == KindResize {
					action.From, action.To = small, Shape{OCPUs: 4, MemoryGB: 24}
				} else if kind == KindScaleOut {
					action.Node, action.To = "gru-1-db-5", small
				}
				if err := s.controller.apply(t.Context(), state, action); err == nil || !strings.Contains(err.Error(), "duplicate live node name") ||
					len(cell.callLog())+len(fake.launches)+len(fake.updates)+len(fake.terminates) != 0 {
					t.Fatalf("ambiguous identity authorized lifecycle effects: err=%v membership=%v", err, cell.callLog())
				}
			})
		}
	}
}

func TestOCICloudLaunchRequestAndIdempotent(t *testing.T) {
	fake := &fakeCompute{pages: map[string]core.ListInstancesResponse{"": {}}}
	cloud := newTestCloud(t, fake)
	shape := Shape{OCPUs: 2, MemoryGB: 12}
	got, err := cloud.Launch(context.Background(), "gru-1-db-2", shape)
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != "ocid1.instance.new" || got.Name != "gru-1-db-2" || got.ShapeName != testTemplate().Shape || got.Shape != shape || got.AvailabilityDomain != "AD-1" {
		t.Fatalf("Launch = %+v", got)
	}
	if len(fake.launches) != 1 {
		t.Fatalf("LaunchInstance calls = %d", len(fake.launches))
	}
	r := fake.launches[0]
	d := r.LaunchInstanceDetails
	source, ok := d.SourceDetails.(core.InstanceSourceViaImageDetails)
	if !ok || *source.ImageId != "ocid1.image.x" || *source.BootVolumeSizeInGBs != 100 {
		t.Fatalf("source = %#v", d.SourceDetails)
	}
	if *d.DisplayName != "gru-1-db-2" || *d.CompartmentId != "ocid1.compartment.x" || *d.AvailabilityDomain != "AD-1" ||
		*d.Shape != "VM.Standard.A1.Flex" || *d.ShapeConfig.Ocpus != 2 || *d.ShapeConfig.MemoryInGBs != 12 {
		t.Fatalf("details = %+v", d)
	}
	if v := d.CreateVnicDetails; *v.SubnetId != "ocid1.subnet.x" || *v.HostnameLabel != "gru-1-db-2" || *v.AssignPublicIp {
		t.Fatalf("vnic = %+v", v)
	}
	if !reflect.DeepEqual(d.FreeformTags, map[string]string{"ts-cell": "gru-1", "ts-role": "db", tagLaunchToken: deref(r.OpcRetryToken)}) {
		t.Fatalf("tags = %v", d.FreeformTags)
	}
	if !reflect.DeepEqual(d.Metadata, map[string]string{"user_data": "Y2xvdWQtaW5pdA=="}) {
		t.Fatalf("metadata = %v", d.Metadata)
	}
	if r.OpcRetryToken == nil || *r.OpcRetryToken == "" {
		t.Fatal("launch omitted the logical attempt's retry token")
	}

	fake.pages[""] = core.ListInstancesResponse{Items: []core.Instance{
		instanceItem("ocid1.instance.new", "gru-1-db-2", "gru-1", "db", core.InstanceLifecycleStateRunning, 2, 12),
	}}
	got, err = cloud.Launch(context.Background(), "gru-1-db-2", shape)
	if err != nil || got.ID != "ocid1.instance.new" {
		t.Fatalf("existing Launch = %+v, %v", got, err)
	}
	if len(fake.launches) != 1 {
		t.Fatalf("existing node launched again: %d calls", len(fake.launches))
	}
}

func TestOCICloudLaunchOmitsOptionalFields(t *testing.T) {
	fake := &fakeCompute{pages: map[string]core.ListInstancesResponse{"": {}}}
	template := testTemplate()
	template.BootVolumeGB, template.UserData = 0, ""
	cloud, err := newOCICloud("gru-1", template, fake, &fakeReads{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cloud.Launch(context.Background(), "gru-1-db-1", Shape{OCPUs: 1, MemoryGB: 6}); err != nil {
		t.Fatal(err)
	}
	d := fake.launches[0].LaunchInstanceDetails
	if d.Metadata != nil || d.SourceDetails.(core.InstanceSourceViaImageDetails).BootVolumeSizeInGBs != nil {
		t.Fatalf("optional fields set: %+v", d)
	}
}

func TestOCICloudLaunchLostResponse(t *testing.T) {
	fake := &fakeCompute{pages: map[string]core.ListInstancesResponse{"": {}}, launchError: io.ErrUnexpectedEOF}
	cloud := newTestCloud(t, fake)
	shape := Shape{OCPUs: 2, MemoryGB: 12}
	for range 2 {
		if _, err := cloud.Launch(t.Context(), "gru-1-db-2", shape); !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Fatalf("lost launch response = %v", err)
		}
	}
	launch := cloud.launches["gru-1-db-2"]
	started := launch.StartedAt
	launch.StartedAt = time.Now().Add(-launchReplayWindow - time.Second)
	if _, err := cloud.Launch(t.Context(), "gru-1-db-2", shape); err == nil ||
		!strings.Contains(err.Error(), "replay window expired") || len(fake.launches) != 2 {
		t.Fatalf("expired token permitted another POST: err=%v calls=%d", err, len(fake.launches))
	}
	launch.StartedAt = started
	fake.launchError = nil
	if _, err := cloud.Launch(t.Context(), "gru-1-db-2", shape); err != nil {
		t.Fatal(err)
	}
	first := fake.launches[0]
	if first.OpcRetryToken == nil || *first.OpcRetryToken == "" {
		t.Fatal("launch omitted a retry token")
	}
	for _, retry := range fake.launches[1:] {
		if deref(first.OpcRetryToken) != deref(retry.OpcRetryToken) || !reflect.DeepEqual(first.LaunchInstanceDetails, retry.LaunchInstanceDetails) {
			t.Fatalf("ambiguous retry changed token or payload: first=%+v, retry=%+v", first, retry)
		}
	}
}

func TestOCICloudLaunchInitialRejection(t *testing.T) {
	for _, test := range []struct {
		name     string
		err      error
		response core.LaunchInstanceResponse
		released bool
	}{
		{"invalid parameter", resizeFailure{400, "InvalidParameter"}, core.LaunchInstanceResponse{}, true},
		{"unauthenticated", resizeFailure{401, "NotAuthenticated"}, core.LaunchInstanceResponse{}, true},
		{"throttled", resizeFailure{429, "TooManyRequests"}, core.LaunchInstanceResponse{}, true},
		{"request timeout", resizeFailure{408, "RequestTimeout"}, core.LaunchInstanceResponse{}, false},
		{"server error", resizeFailure{500, "InternalServerError"}, core.LaunchInstanceResponse{}, false},
		{"unknown rejection", resizeFailure{400, "UnknownError"}, core.LaunchInstanceResponse{}, false},
		{"lost response", io.ErrUnexpectedEOF, core.LaunchInstanceResponse{}, false},
		{"cancelled", context.Canceled, core.LaunchInstanceResponse{}, false},
		{"deadline", context.DeadlineExceeded, core.LaunchInstanceResponse{}, false},
		{"no instance ID", nil, core.LaunchInstanceResponse{RawResponse: &http.Response{StatusCode: 200}}, false},
		{"wrapped rejection", fmt.Errorf("uncertain attempt: %w", resizeFailure{400, "InvalidParameter"}), core.LaunchInstanceResponse{}, false},
		{"conflicting success", resizeFailure{400, "InvalidParameter"}, core.LaunchInstanceResponse{RawResponse: &http.Response{StatusCode: 200}}, false},
		{"conflicting status", resizeFailure{400, "InvalidParameter"}, core.LaunchInstanceResponse{RawResponse: &http.Response{StatusCode: 503}}, false},
		{"accepted ID", resizeFailure{400, "InvalidParameter"}, core.LaunchInstanceResponse{Instance: core.Instance{Id: common.String("accepted")}}, false},
	} {
		for _, restart := range []bool{false, true} {
			if restart && !test.released {
				continue
			}
			t.Run(fmt.Sprintf("%s/restart=%t", test.name, restart), func(t *testing.T) {
				fake := &fakeCompute{pages: map[string]core.ListInstancesResponse{"": {}}, launchError: test.err, launchResponse: &test.response}
				cloud := newTestCloud(t, fake)
				cloud.requireLaunchPersistence = true
				config, parent, _ := provisionTestJournal(t)
				journal, initial := testLaunchJournal(t, config, parent)
				var sizes []int
				save := func(states []OCILaunchState) error {
					sizes = append(sizes, len(states))
					if len(sizes) == 1 && len(fake.launches) != 0 || test.released && len(sizes) == 2 && len(fake.launches) != 1 {
						t.Fatalf("POST was not bracketed by intent/release saves: saves=%v POSTs=%d", sizes, len(fake.launches))
					}
					return journal.save(states)
				}
				if err := cloud.RestoreLaunchState(initial, save); err != nil {
					t.Fatal(err)
				}
				name, shape := "gru-1-db-2", Shape{OCPUs: 2, MemoryGB: 12}
				if _, err := cloud.Launch(t.Context(), name, shape); err == nil || test.err != nil && !errors.Is(err, test.err) {
					t.Fatalf("launch lost rejection cause: %v", err)
				}
				reopened, states := testLaunchJournal(t, config, parent)
				if (cloud.launches[name] == nil) != test.released || (len(states) == 0) != test.released || sizes[0] != 1 {
					t.Fatalf("released=%v memory=%+v journal=%+v saves=%v", test.released, cloud.launches[name], states, sizes)
				}
				if !test.released {
					if len(states) != 1 || states[0].InstanceID != deref(test.response.Id) || states[0].RetryToken != deref(fake.launches[0].OpcRetryToken) {
						t.Fatalf("conflicting evidence lost the durable ID/token: %+v", states)
					}
					return
				}
				if !reflect.DeepEqual(sizes, []int{1, 0}) {
					t.Fatalf("rejected generation was not durably released: %v", sizes)
				}
				if restart {
					cloud = newTestCloud(t, fake)
					cloud.requireLaunchPersistence = true
					if err := cloud.RestoreLaunchState(states, reopened.save); err != nil {
						t.Fatal(err)
					}
				}
				cloud.template.ImageID = "ocid1.image.corrected"
				fake.launchError, fake.launchResponse = nil, nil
				if got, err := cloud.Launch(t.Context(), name, Shape{OCPUs: 4, MemoryGB: 24}); err != nil || got.ID == "" {
					t.Fatalf("corrected launch = %+v, %v", got, err)
				}
				retry := fake.launches[1]
				if deref(retry.OpcRetryToken) == deref(fake.launches[0].OpcRetryToken) || *retry.ShapeConfig.Ocpus != 4 ||
					deref(retry.SourceDetails.(core.InstanceSourceViaImageDetails).ImageId) != cloud.template.ImageID {
					t.Fatal("corrected launch reused rejected token or payload")
				}
				_, states = testLaunchJournal(t, config, parent)
				if len(states) != 1 || states[0].InstanceID == "" || states[0].RetryToken != deref(retry.OpcRetryToken) {
					t.Fatalf("corrected generation was not durable: %+v", states)
				}
			})
		}
	}
}

func TestOCICloudLaunchRejectionPreservesEarlierUncertainty(t *testing.T) {
	for _, mode := range []string{"same process", "restart", "crash before POST"} {
		t.Run(mode, func(t *testing.T) {
			fake := &fakeCompute{pages: map[string]core.ListInstancesResponse{"": {}}, launchError: io.ErrUnexpectedEOF}
			cloud := newTestCloud(t, fake)
			var journal []byte
			save := func(snapshot []OCILaunchState) error {
				var err error
				journal, err = json.Marshal(snapshot)
				return err
			}
			if err := cloud.RestoreLaunchState(nil, save); err != nil {
				t.Fatal(err)
			}
			name, shape := "gru-1-db-2", Shape{OCPUs: 2, MemoryGB: 12}
			if mode == "crash before POST" {
				state := OCILaunchState{Name: name, Template: testTemplate(), Shape: shape, RetryToken: "persisted-token", StartedAt: time.Now().Add(-time.Minute)}
				state.Request = cloud.launchDetails(name, shape, state.Template, state.RetryToken)
				if err := save([]OCILaunchState{state}); err != nil {
					t.Fatal(err)
				}
			} else if _, err := cloud.Launch(t.Context(), name, shape); !errors.Is(err, io.ErrUnexpectedEOF) {
				t.Fatal(err)
			}
			before := string(journal)
			var states []OCILaunchState
			if err := json.Unmarshal(journal, &states); err != nil {
				t.Fatal(err)
			}
			if mode != "same process" {
				cloud = newTestCloud(t, fake)
				if err := cloud.RestoreLaunchState(states, save); err != nil {
					t.Fatal(err)
				}
			}
			failure := resizeFailure{400, "InvalidParameter"}
			fake.launchError = failure
			if _, err := cloud.Launch(t.Context(), name, shape); !errors.Is(err, failure) {
				t.Fatal(err)
			}
			if cloud.launches[name] == nil || string(journal) != before {
				t.Fatal("later rejection released an uncertain generation")
			}
			replay := fake.launches[len(fake.launches)-1]
			wantJSON, _ := json.Marshal(states[0].Request)
			gotJSON, _ := json.Marshal(replay.LaunchInstanceDetails)
			if deref(replay.OpcRetryToken) != states[0].RetryToken || string(wantJSON) != string(gotJSON) {
				t.Fatal("later rejection changed the exact token/payload")
			}
			posts := len(fake.launches)
			cloud.template.ImageID = "ocid1.image.corrected"
			if _, err := cloud.Launch(t.Context(), name, Shape{OCPUs: 4, MemoryGB: 24}); err == nil || !strings.Contains(err.Error(), "payload") || len(fake.launches) != posts {
				t.Fatal("later rejection permitted changing uncertain payload")
			}
		})
	}
}

func TestOCICloudLaunchRejectionPersistenceFailureLatches(t *testing.T) {
	rejected, failedSave := resizeFailure{400, "InvalidParameter"}, errors.New("journal fsync failed")
	fake := &fakeCompute{pages: map[string]core.ListInstancesResponse{"": {}}, launchError: rejected}
	cloud := newTestCloud(t, fake)
	var states []OCILaunchState
	saves := 0
	if err := cloud.RestoreLaunchState(nil, func(snapshot []OCILaunchState) error {
		saves++
		if saves == 2 {
			if len(snapshot) != 0 {
				t.Fatal("rejection save retained the rejected generation")
			}
			return failedSave
		}
		states = append([]OCILaunchState(nil), snapshot...)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	name, shape := "gru-1-db-2", Shape{OCPUs: 2, MemoryGB: 12}
	if _, err := cloud.Launch(t.Context(), name, shape); !errors.Is(err, rejected) || !errors.Is(err, failedSave) {
		t.Fatalf("release save failure lost either cause: %v", err)
	}
	if cloud.launches[name] == nil || len(states) != 1 || !reflect.DeepEqual(*cloud.launches[name], states[0]) {
		t.Fatal("failed release forgot the generation")
	}
	listed := len(fake.listCalls)
	if _, err := cloud.List(t.Context()); !errors.Is(err, failedSave) {
		t.Fatalf("List ignored failed release save: %v", err)
	}
	cloud.template.ImageID = "ocid1.image.corrected"
	if _, err := cloud.Launch(t.Context(), name, shape); !errors.Is(err, failedSave) || len(fake.launches) != 1 || saves != 2 {
		t.Fatalf("failed durable release permitted another mutation: %v", err)
	}
	if err := cloud.Resize(t.Context(), "accepted", shape); !errors.Is(err, failedSave) || errors.Is(err, ErrResizeRejected) {
		t.Fatalf("Resize ignored failed release save: %v", err)
	}
	if err := cloud.Terminate(t.Context(), "accepted"); !errors.Is(err, failedSave) {
		t.Fatalf("Terminate ignored failed release save: %v", err)
	}
	if len(fake.listCalls) != listed || len(fake.getCalls)+len(fake.updates)+len(fake.terminates) != 0 || saves != 2 {
		t.Fatal("failed release save did not latch all reconciliation/mutations")
	}
}

func TestOCICloudLaunchChangesTokenOnlyAfterTermination(t *testing.T) {
	fake := &fakeCompute{pages: map[string]core.ListInstancesResponse{"": {}}}
	cloud := newTestCloud(t, fake)
	shape := Shape{OCPUs: 2, MemoryGB: 12}
	old, err := cloud.Launch(t.Context(), "gru-1-db-2", shape)
	if err != nil {
		t.Fatal(err)
	}
	first := fake.launches[0]
	if first.OpcRetryToken == nil || *first.OpcRetryToken == "" {
		t.Fatal("launch omitted a retry token")
	}
	// Success followed by a temporarily empty listing still belongs to the
	// same logical launch; termination acceptance is not terminal evidence.
	if err := cloud.Terminate(t.Context(), old.ID); err != nil {
		t.Fatal(err)
	}
	if got, err := cloud.Launch(t.Context(), old.Name, shape); err != nil || got.ID != old.ID || len(fake.launches) != 1 {
		t.Fatalf("empty listing rotated an unresolved generation: got=%+v err=%v calls=%d", got, err, len(fake.launches))
	}
	terminal := instanceItem(old.ID, old.Name, "gru-1", "db", core.InstanceLifecycleStateTerminating, 2, 12)
	fake.pages[""] = core.ListInstancesResponse{Items: []core.Instance{terminal}}
	if _, err := cloud.Launch(t.Context(), old.Name, shape); err == nil || len(fake.launches) != 1 {
		t.Fatalf("launch over a terminating generation: err=%v calls=%d", err, len(fake.launches))
	}
	terminal.LifecycleState = core.InstanceLifecycleStateTerminated
	fake.pages[""] = core.ListInstancesResponse{Items: []core.Instance{terminal}}
	fake.instances[old.ID] = terminal
	fake.launchID = "ocid1.instance.next"
	if _, err := cloud.Launch(t.Context(), old.Name, Shape{OCPUs: 4, MemoryGB: 24}); err != nil {
		t.Fatal(err)
	}
	if len(fake.launches) != 2 {
		t.Fatalf("new generation launches = %d, want 2 total", len(fake.launches))
	}
	next := fake.launches[1]
	if next.OpcRetryToken == nil || *next.OpcRetryToken == "" || *next.OpcRetryToken == *first.OpcRetryToken || *next.ShapeConfig.Ocpus != 4 {
		t.Fatalf("terminated generation did not rotate launch identity: %+v", next)
	}
	// A retained tombstone from the old generation cannot reset the new one.
	if got, err := cloud.Launch(t.Context(), old.Name, Shape{OCPUs: 4, MemoryGB: 24}); err != nil ||
		got.ID != fake.launchID || len(fake.launches) != 2 {
		t.Fatalf("old tombstone rotated the new generation: %v", err)
	}
}

func TestOCICloudLaunchUncertainPayloadAndExpiry(t *testing.T) {
	fake := &fakeCompute{pages: map[string]core.ListInstancesResponse{"": {}}, launchError: io.ErrUnexpectedEOF}
	cloud := newTestCloud(t, fake)
	name, shape := "gru-1-db-2", Shape{OCPUs: 2, MemoryGB: 12}
	if _, err := cloud.Launch(t.Context(), name, shape); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("first launch = %v", err)
	}
	first := fake.launches[0]
	if _, err := cloud.Launch(t.Context(), name, Shape{OCPUs: 4, MemoryGB: 24}); err == nil || !strings.Contains(err.Error(), "payload") {
		t.Fatalf("uncertain shape change = %v", err)
	}
	cloud.template.ImageID = "ocid1.image.changed"
	if _, err := cloud.Launch(t.Context(), name, shape); err == nil || !strings.Contains(err.Error(), "payload") {
		t.Fatalf("uncertain template change = %v", err)
	}
	cloud.template = testTemplate()
	cloud.launches[name].StartedAt = time.Now().Add(-launchReplayWindow - time.Second)
	if _, err := cloud.Launch(t.Context(), name, shape); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expired uncertain token = %v", err)
	}
	if len(fake.launches) != 1 || !reflect.DeepEqual(fake.launches[0], first) {
		t.Fatal("an uncertain payload change or expiration posted a new generation")
	}
	// Positive observation still reconciles an expired token without a POST.
	item := instanceItem("accepted", name, "gru-1", "db", core.InstanceLifecycleStateRunning, 2, 12)
	item.FreeformTags[tagLaunchToken] = *first.OpcRetryToken
	fake.pages[""] = core.ListInstancesResponse{Items: []core.Instance{item}}
	if got, err := cloud.Launch(t.Context(), name, shape); err != nil || got.ID != "accepted" || len(fake.launches) != 1 {
		t.Fatalf("expired launch reconciliation = %+v, %v", got, err)
	}
}

func TestOCICloudLaunchConfirmsTerminationByID(t *testing.T) {
	fake := &fakeCompute{pages: map[string]core.ListInstancesResponse{"": {}}}
	cloud := newTestCloud(t, fake)
	shape := Shape{OCPUs: 2, MemoryGB: 12}
	old, err := cloud.Launch(t.Context(), "gru-1-db-2", shape)
	if err != nil {
		t.Fatal(err)
	}
	first := fake.launches[0]
	for _, failure := range []error{missing{}, io.ErrUnexpectedEOF} {
		fake.getError = failure
		if _, err := cloud.Launch(t.Context(), old.Name, shape); !errors.Is(err, failure) || len(fake.launches) != 1 {
			t.Fatalf("unconfirmed termination relaunched: %v, calls=%d", err, len(fake.launches))
		}
	}
	fake.getError = nil
	item := fake.instances[old.ID]
	item.LifecycleState = core.InstanceLifecycleStateTerminating
	fake.instances[old.ID] = item
	if _, err := cloud.Launch(t.Context(), old.Name, shape); err == nil || len(fake.launches) != 1 {
		t.Fatalf("asynchronous termination relaunched: %v", err)
	}
	item.LifecycleState = core.InstanceLifecycleStateTerminated
	item.Id = common.String("another-instance")
	fake.instances[old.ID] = item
	if _, err := cloud.Launch(t.Context(), old.Name, shape); err == nil || len(fake.launches) != 1 {
		t.Fatalf("wrong terminated ID released generation: %v", err)
	}
	item.Id = common.String(old.ID)
	fake.instances[old.ID] = item
	fake.launchID = "ocid1.instance.next"
	cloud.template.ImageID = "ocid1.image.changed"
	if got, err := cloud.Launch(t.Context(), old.Name, Shape{OCPUs: 4, MemoryGB: 24}); err != nil || got.ID != fake.launchID {
		t.Fatalf("positively terminated generation = %+v, %v", got, err)
	}
	if len(fake.launches) != 2 || deref(fake.launches[1].OpcRetryToken) == deref(first.OpcRetryToken) ||
		deref(fake.launches[1].SourceDetails.(core.InstanceSourceViaImageDetails).ImageId) != cloud.template.ImageID {
		t.Fatal("confirmed termination did not get a fresh token and payload")
	}
}

func TestOCICloudLaunchLostResponseTerminationTag(t *testing.T) {
	fake := &fakeCompute{pages: map[string]core.ListInstancesResponse{"": {}}, launchError: io.ErrUnexpectedEOF}
	cloud := newTestCloud(t, fake)
	name, shape := "gru-1-db-2", Shape{OCPUs: 2, MemoryGB: 12}
	if _, err := cloud.Launch(t.Context(), name, shape); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatal(err)
	}
	token := deref(fake.launches[0].OpcRetryToken)
	old := instanceItem("historic", name, "gru-1", "db", core.InstanceLifecycleStateTerminated, 2, 12)
	old.FreeformTags[tagLaunchToken] = "older-token"
	fake.pages[""] = core.ListInstancesResponse{Items: []core.Instance{old}}
	if _, err := cloud.Launch(t.Context(), name, shape); !errors.Is(err, io.ErrUnexpectedEOF) ||
		deref(fake.launches[1].OpcRetryToken) != token {
		t.Fatalf("unrelated tombstone rotated uncertain generation: %v", err)
	}
	old.FreeformTags[tagLaunchToken] = token
	fake.pages[""] = core.ListInstancesResponse{Items: []core.Instance{old}}
	fake.launchError = nil
	if _, err := cloud.Launch(t.Context(), name, Shape{OCPUs: 4, MemoryGB: 24}); err != nil {
		t.Fatal(err)
	}
	if len(fake.launches) != 3 || deref(fake.launches[2].OpcRetryToken) == token {
		t.Fatal("matching terminal launch token did not release the uncertain generation")
	}
}

func TestOCICloudLaunchKeepsResponseIDOnError(t *testing.T) {
	item := instanceItem("accepted", "gru-1-db-2", "gru-1", "db", core.InstanceLifecycleStateProvisioning, 2, 12)
	fake := &fakeCompute{pages: map[string]core.ListInstancesResponse{"": {}}, launchError: io.ErrUnexpectedEOF,
		launchResponse: &core.LaunchInstanceResponse{Instance: item}, instances: map[string]core.Instance{"accepted": item}}
	cloud := newTestCloud(t, fake)
	if _, err := cloud.Launch(t.Context(), "gru-1-db-2", Shape{OCPUs: 2, MemoryGB: 12}); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatal(err)
	}
	if got, err := cloud.Launch(t.Context(), "gru-1-db-2", Shape{OCPUs: 4, MemoryGB: 24}); err != nil ||
		got.ID != "accepted" || len(fake.launches) != 1 || len(fake.getCalls) != 1 {
		t.Fatalf("accepted response ID was discarded: %+v, %v", got, err)
	}
}

func TestOCICloudLaunchRejectsUnsupportedResponseShapes(t *testing.T) {
	for _, test := range []struct {
		name  string
		shape *string
	}{
		{"different flex", common.String("VM.Standard.E4.Flex")},
		{"non-flex", common.String("VM.Standard.E4.Standard")},
		{"missing", nil},
		{"empty", common.String("")},
	} {
		for _, recovery := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/recovery=%t", test.name, recovery), func(t *testing.T) {
				item := instanceItem("accepted", "gru-1-db-2", "gru-1", "db", core.InstanceLifecycleStateRunning, 2, 12)
				item.Shape = test.shape
				fake := &fakeCompute{pages: map[string]core.ListInstancesResponse{"": {}},
					launchResponse: &core.LaunchInstanceResponse{Instance: item}, instances: map[string]core.Instance{"accepted": item}}
				cloud := newTestCloud(t, fake)
				var states []OCILaunchState
				if recovery {
					states = []OCILaunchState{{Name: deref(item.DisplayName), InstanceID: "accepted"}}
				}
				saves := 0
				var saved []OCILaunchState
				if err := cloud.RestoreLaunchState(states, func(states []OCILaunchState) error {
					saves++
					saved = states
					return nil
				}); err != nil {
					t.Fatal(err)
				}
				if got, err := cloud.Launch(t.Context(), deref(item.DisplayName), small); err == nil ||
					!strings.Contains(err.Error(), "does not match template shape") || got != (Instance{}) {
					t.Fatalf("unsupported OCI response accepted: %+v, %v", got, err)
				}
				if cloud.launches[deref(item.DisplayName)].InstanceID != "accepted" {
					t.Fatal("shape rejection discarded the accepted instance ID")
				}
				if recovery {
					if saves != 0 || len(fake.launches) != 0 || len(fake.getCalls) != 1 {
						t.Fatalf("recovery rejection changed journal or launched: saves=%d launches=%d gets=%d", saves, len(fake.launches), len(fake.getCalls))
					}
				} else if saves != 2 || len(fake.launches) != 1 || len(saved) != 1 || saved[0].InstanceID != "accepted" ||
					saved[0].RetryToken != deref(fake.launches[0].OpcRetryToken) || !reflect.DeepEqual(saved[0].Request, fake.launches[0].LaunchInstanceDetails) {
					t.Fatalf("response rejection did not preserve durable generation: saves=%d launches=%d saved=%+v", saves, len(fake.launches), saved)
				}
				// Once the accepted ID is known, even a missing listing cannot
				// rotate its generation or repeat the launch POST.
				launches, priorSaves := len(fake.launches), saves
				if _, err := cloud.Launch(t.Context(), deref(item.DisplayName), small); err == nil ||
					!strings.Contains(err.Error(), "does not match template shape") || len(fake.launches) != launches || saves != priorSaves {
					t.Fatalf("unsupported response rotated the accepted generation: err=%v launches=%d saves=%d", err, len(fake.launches), saves)
				}
			})
		}
	}
}

func TestOCICloudLaunchRestoresDurableIntent(t *testing.T) {
	fake := &fakeCompute{pages: map[string]core.ListInstancesResponse{"": {}}, launchError: io.ErrUnexpectedEOF}
	cloud := newTestCloud(t, fake)
	cloud.requireLaunchPersistence = true
	var journal []byte
	save := func(states []OCILaunchState) error {
		var err error
		journal, err = json.Marshal(states)
		return err
	}
	if err := cloud.RestoreLaunchState(nil, save); err != nil {
		t.Fatal(err)
	}
	shape := Shape{OCPUs: 2, MemoryGB: 12}
	if _, err := cloud.Launch(t.Context(), "gru-1-db-2", shape); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatal(err)
	}
	var states []OCILaunchState
	if err := json.Unmarshal(journal, &states); err != nil {
		t.Fatal(err)
	}
	if len(states) != 1 || states[0].RetryToken == "" || states[0].StartedAt.IsZero() || states[0].InstanceID != "" {
		t.Fatalf("uncertain durable intent = %+v", states)
	}
	if _, ok := states[0].Request.SourceDetails.(core.InstanceSourceViaImageDetails); !ok {
		if _, ok := states[0].Request.SourceDetails.(*core.InstanceSourceViaImageDetails); !ok {
			t.Fatalf("SDK source details type lost across JSON: %T", states[0].Request.SourceDetails)
		}
	}
	restarted := newTestCloud(t, fake)
	restarted.requireLaunchPersistence = true
	if err := restarted.RestoreLaunchState(states, save); err != nil {
		t.Fatal(err)
	}
	fake.launchError = nil
	if _, err := restarted.Launch(t.Context(), "gru-1-db-2", shape); err != nil {
		t.Fatal(err)
	}
	first, replay := fake.launches[0], fake.launches[1]
	firstJSON, _ := json.Marshal(first.LaunchInstanceDetails)
	replayJSON, _ := json.Marshal(replay.LaunchInstanceDetails)
	if deref(first.OpcRetryToken) != deref(replay.OpcRetryToken) || string(firstJSON) != string(replayJSON) {
		t.Fatal("restart changed the token or frozen launch payload")
	}
	if err := json.Unmarshal(journal, &states); err != nil || states[0].InstanceID == "" {
		t.Fatalf("accepted instance ID was not saved: %+v, %v", states, err)
	}
}

func TestOCICloudLaunchPersistenceFailureLatches(t *testing.T) {
	for _, failCall := range []int{1, 2} {
		t.Run(fmt.Sprintf("save%d", failCall), func(t *testing.T) {
			fake := &fakeCompute{pages: map[string]core.ListInstancesResponse{"": {}}}
			cloud := newTestCloud(t, fake)
			cloud.requireLaunchPersistence = true
			failure := errors.New("journal fsync failed")
			saves := 0
			if err := cloud.RestoreLaunchState(nil, func(states []OCILaunchState) error {
				saves++
				if len(fake.launches) != saves-1 || len(states) != 1 || states[0].RetryToken == "" {
					t.Fatalf("POST was not bracketed by durable intent/ID saves: saves=%d POSTs=%d state=%+v", saves, len(fake.launches), states)
				}
				if saves == failCall {
					return failure
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			shape := Shape{OCPUs: 2, MemoryGB: 12}
			if _, err := cloud.Launch(t.Context(), "gru-1-db-2", shape); !errors.Is(err, failure) || len(fake.launches) != failCall-1 {
				t.Fatalf("failed persistence allowed POST: %v, calls=%d", err, len(fake.launches))
			}
			listed := len(fake.listCalls)
			if _, err := cloud.List(t.Context()); !errors.Is(err, failure) {
				t.Fatalf("List ignored persistence fence: %v", err)
			}
			if _, err := cloud.Launch(t.Context(), "gru-1-db-2", shape); !errors.Is(err, failure) {
				t.Fatalf("Launch ignored persistence fence: %v", err)
			}
			if err := cloud.Resize(t.Context(), "accepted", shape); !errors.Is(err, failure) || errors.Is(err, ErrResizeRejected) {
				t.Fatalf("Resize ignored persistence fence: %v", err)
			}
			if err := cloud.Terminate(t.Context(), "accepted"); !errors.Is(err, failure) {
				t.Fatalf("Terminate ignored persistence fence: %v", err)
			}
			if saves != failCall || len(fake.listCalls) != listed || len(fake.getCalls)+len(fake.updates)+len(fake.terminates) != 0 {
				t.Fatal("persistence failure did not latch all mutation/reconciliation")
			}
		})
	}
}

func TestOCICloudLaunchRequiresPersistence(t *testing.T) {
	fake := &fakeCompute{pages: map[string]core.ListInstancesResponse{"": {}}}
	cloud := newTestCloud(t, fake)
	cloud.requireLaunchPersistence = true
	shape := Shape{OCPUs: 2, MemoryGB: 12}
	if _, err := cloud.Launch(t.Context(), "gru-1-db-2", shape); err == nil || len(fake.launches) != 0 {
		t.Fatalf("unconfigured live cloud launched: %v", err)
	}
	if err := cloud.Resize(t.Context(), "accepted", shape); err == nil || len(fake.updates) != 0 {
		t.Fatalf("unconfigured live cloud resized: %v", err)
	}
	if err := cloud.Terminate(t.Context(), "accepted"); err == nil || len(fake.terminates) != 0 {
		t.Fatalf("unconfigured live cloud terminated: %v", err)
	}
}

func TestOCICloudLaunchRestoreRejectsInconsistentState(t *testing.T) {
	for _, corrupt := range []string{"node", "duplicate", "payload", "generation", "future"} {
		t.Run(corrupt, func(t *testing.T) {
			fake := &fakeCompute{pages: map[string]core.ListInstancesResponse{"": {}}}
			cloud := newTestCloud(t, fake)
			cloud.requireLaunchPersistence = true
			state := OCILaunchState{Name: "gru-1-db-2", Template: testTemplate(), Shape: Shape{OCPUs: 2, MemoryGB: 12},
				RetryToken: "original-token", StartedAt: time.Now().Add(-time.Minute)}
			state.Request = cloud.launchDetails(state.Name, state.Shape, state.Template, state.RetryToken)
			states := []OCILaunchState{state}
			switch corrupt {
			case "node":
				states[0].Name = "gru-2-db-2"
			case "duplicate":
				states = append(states, state)
			case "payload":
				states[0].Request.ShapeConfig.Ocpus = common.Float32(4)
			case "generation":
				states[0].RetryToken = ""
			case "future":
				states[0].StartedAt = time.Now().Add(time.Hour)
			}
			if err := cloud.RestoreLaunchState(states, func([]OCILaunchState) error { t.Fatal("invalid restore saved state"); return nil }); err == nil {
				t.Fatal("corrupt journal restored")
			}
			if _, err := cloud.Launch(t.Context(), state.Name, state.Shape); err == nil || len(fake.launches) != 0 {
				t.Fatalf("invalid restore allowed POST: %v", err)
			}
		})
	}
}

func TestOCICloudLaunchDoesNotAdoptDifferentGeneration(t *testing.T) {
	fake := &fakeCompute{pages: map[string]core.ListInstancesResponse{"": {}}, launchError: io.ErrUnexpectedEOF}
	cloud := newTestCloud(t, fake)
	name, shape := "gru-1-db-2", Shape{OCPUs: 2, MemoryGB: 12}
	if _, err := cloud.Launch(t.Context(), name, shape); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatal(err)
	}
	item := instanceItem("unrelated", name, "gru-1", "db", core.InstanceLifecycleStateRunning, 2, 12)
	item.FreeformTags[tagLaunchToken] = "another-generation"
	fake.pages[""] = core.ListInstancesResponse{Items: []core.Instance{item}}
	if _, err := cloud.Launch(t.Context(), name, shape); err == nil || len(fake.launches) != 1 {
		t.Fatalf("different generation reconciled an uncertain launch: %v", err)
	}
	if cloud.launches[name].InstanceID != "" {
		t.Fatal("different generation replaced the original intent")
	}
}

func TestOCICloudLaunchSDKRejectionAfterRetries(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	privateKey := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	provider := common.NewRawConfigurationProvider("ocid1.tenancy.test", "ocid1.user.test", "sa-saopaulo-1", "fp", string(privateKey), nil)
	for _, test := range []struct {
		name      string
		statuses  []int
		released  bool
		firstCode string
		pointer   bool
	}{
		{name: "initial validation rejection", statuses: []int{400}, released: true},
		{name: "initial auth rejection", statuses: []int{401}, released: true},
		{name: "throttle then validation rejection", statuses: []int{429, 400}, released: true},
		{name: "throttles exhausted", statuses: []int{429, 429}, released: true},
		{name: "ambiguous then validation rejection", statuses: []int{500, 400}},
		{name: "ambiguous then auth rejection", statuses: []int{503, 401}, pointer: true},
		{name: "ambiguous then throttle then rejection", statuses: []int{503, 429, 400}},
		{name: "unknown throttle then rejection", statuses: []int{429, 400}, firstCode: "UnknownError"},
	} {
		t.Run(test.name, func(t *testing.T) {
			var mu sync.Mutex
			var tokens, payloads []string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if r.Method == http.MethodGet {
					_, _ = io.WriteString(w, `[]`)
					return
				}
				if r.Method != http.MethodPost || !strings.HasSuffix(r.URL.Path, "/instances") {
					t.Errorf("unexpected SDK request: %s %s", r.Method, r.URL.Path)
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				body, err := io.ReadAll(r.Body)
				if err != nil {
					t.Error(err)
					return
				}
				mu.Lock()
				index := len(tokens)
				tokens, payloads = append(tokens, r.Header.Get("opc-retry-token")), append(payloads, string(body))
				mu.Unlock()
				if index >= len(test.statuses) {
					index = len(test.statuses) - 1
				}
				status := test.statuses[index]
				code := map[int]string{400: "InvalidParameter", 401: "NotAuthenticated", 429: "TooManyRequests", 500: "InternalServerError", 503: "ServiceUnavailable"}[status]
				if index == 0 && test.firstCode != "" {
					code = test.firstCode
				}
				w.WriteHeader(status)
				_, _ = fmt.Fprintf(w, `{"code":%q,"message":"test rejection"}`, code)
			}))
			defer server.Close()
			factory, err := ociclient.New(provider, ociclient.Options{Region: "sa-saopaulo-1",
				Retry: ociclient.RetryOptions{MaxAttempts: uint(len(test.statuses)), BaseDelay: time.Millisecond, MaxDelay: time.Millisecond}})
			if err != nil {
				t.Fatal(err)
			}
			compute, err := factory.Compute()
			if err != nil {
				t.Fatal(err)
			}
			ociclient.PinHost(&compute.BaseClient, server.URL)
			compute.HTTPClient = server.Client()
			var api computeAPI = compute
			if test.pointer {
				api = &compute
			}
			cloud, err := newOCICloud("gru-1", testTemplate(), api, &fakeReads{})
			if err != nil {
				t.Fatal(err)
			}
			var journal []byte
			save := func(snapshot []OCILaunchState) error {
				var err error
				journal, err = json.Marshal(snapshot)
				return err
			}
			if err := cloud.RestoreLaunchState(nil, save); err != nil {
				t.Fatal(err)
			}
			name, shape := "gru-1-db-2", Shape{OCPUs: 2, MemoryGB: 12}
			if _, err := cloud.Launch(t.Context(), name, shape); err == nil {
				t.Fatal("SDK error responses unexpectedly launched")
			}
			var states []OCILaunchState
			if err := json.Unmarshal(journal, &states); err != nil {
				t.Fatal(err)
			}
			if (cloud.launches[name] == nil) != test.released || (len(states) == 0) != test.released {
				t.Fatalf("released=%v memory=%+v journal=%+v", test.released, cloud.launches[name], states)
			}
			if !test.released {
				before := string(journal)
				cloud, err = newOCICloud("gru-1", testTemplate(), api, &fakeReads{})
				if err != nil {
					t.Fatal(err)
				}
				if err := cloud.RestoreLaunchState(states, save); err != nil {
					t.Fatal(err)
				}
				if _, err := cloud.Launch(t.Context(), name, shape); err == nil || string(journal) != before {
					t.Fatalf("later SDK rejection released restored uncertainty: %v", err)
				}
				cloud.template.ImageID = "ocid1.image.corrected"
				if _, err := cloud.Launch(t.Context(), name, shape); err == nil || !strings.Contains(err.Error(), "payload") {
					t.Fatalf("SDK ambiguity allowed corrected payload: %v", err)
				}
			}
			mu.Lock()
			defer mu.Unlock()
			wantPosts := len(test.statuses)
			if !test.released {
				wantPosts++ // One exact replay after restoring the uncertain journal.
			}
			if len(tokens) != wantPosts || tokens[0] == "" {
				t.Fatalf("SDK POSTs=%d want %d with explicit token", len(tokens), wantPosts)
			}
			for i := 1; i < len(tokens); i++ {
				if tokens[i] != tokens[0] || payloads[i] != payloads[0] {
					t.Fatal("SDK changed launch generation during retries")
				}
			}
		})
	}
}

func TestOCICloudLaunchSDKDeduplicatesAcrossCalls(t *testing.T) {
	var mu sync.Mutex
	var tokens, payloads []string
	accepted := map[string]bool{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet {
			_, _ = io.WriteString(w, `[]`)
			return
		}
		if r.Method != http.MethodPost || !strings.HasSuffix(r.URL.Path, "/instances") {
			t.Errorf("unexpected OCI SDK request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
			return
		}
		mu.Lock()
		token := r.Header.Get("opc-retry-token")
		tokens, payloads = append(tokens, token), append(payloads, string(body))
		accepted[token] = true
		attempt := len(tokens)
		mu.Unlock()
		if attempt == 1 {
			// OCI accepted the POST but returns a retryable server error. The
			// SDK must send the same token for its within-call retry.
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = io.WriteString(w, `{"code":"InternalServerError","message":"accepted response failed"}`)
			return
		}
		if attempt == 2 {
			connection, _, err := w.(http.Hijacker).Hijack()
			if err != nil {
				t.Error(err)
				return
			}
			_ = connection.Close()
			return
		}
		_, _ = io.WriteString(w, `{"id":"accepted","displayName":"gru-1-db-2","lifecycleState":"PROVISIONING","shape":"VM.Standard.A1.Flex"}`)
	}))
	defer server.Close()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	privateKey := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	provider := common.NewRawConfigurationProvider("ocid1.tenancy.test", "ocid1.user.test", "sa-saopaulo-1", "fp", string(privateKey), nil)
	factory, err := ociclient.New(provider, ociclient.Options{Region: "sa-saopaulo-1",
		Retry: ociclient.RetryOptions{MaxAttempts: 2, BaseDelay: time.Millisecond, MaxDelay: time.Millisecond}})
	if err != nil {
		t.Fatal(err)
	}
	compute, err := factory.Compute()
	if err != nil {
		t.Fatal(err)
	}
	ociclient.PinHost(&compute.BaseClient, server.URL)
	compute.HTTPClient = server.Client()
	cloud, err := newOCICloud("gru-1", testTemplate(), compute, &fakeReads{})
	if err != nil {
		t.Fatal(err)
	}
	shape := Shape{OCPUs: 2, MemoryGB: 12}
	if _, err := cloud.Launch(t.Context(), "gru-1-db-2", shape); err == nil {
		t.Fatal("dropped accepted response should leave the first call uncertain")
	}
	if got, err := cloud.Launch(t.Context(), "gru-1-db-2", shape); err != nil || got.ID != "accepted" || got.ShapeName != testTemplate().Shape {
		t.Fatalf("cross-call launch retry = %+v, %v", got, err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(tokens) != 3 || len(accepted) != 1 || tokens[0] == "" {
		t.Fatalf("SDK accepted %d generations from %d POSTs", len(accepted), len(tokens))
	}
	for i := 1; i < len(tokens); i++ {
		if tokens[i] != tokens[0] || payloads[i] != payloads[0] {
			t.Fatalf("SDK retry %d changed token or payload", i)
		}
	}
}

func TestOCICloudLaunchRejects(t *testing.T) {
	fake := &fakeCompute{pages: map[string]core.ListInstancesResponse{"": {}}}
	cloud := newTestCloud(t, fake)
	ok := Shape{OCPUs: 1, MemoryGB: 6}
	for name, c := range map[string]struct {
		node  string
		shape Shape
	}{
		"foreign name": {"sfo-1-db-1", ok},
		"zero shape":   {"gru-1-db-1", Shape{}},
		"zero memory":  {"gru-1-db-1", Shape{OCPUs: 1}},
	} {
		if _, err := cloud.Launch(context.Background(), c.node, c.shape); err == nil {
			t.Errorf("%s: Launch succeeded", name)
		}
	}
	if len(fake.launches) != 0 || len(fake.listCalls) != 0 {
		t.Fatalf("rejected launches reached OCI: %d launches, %d lists", len(fake.launches), len(fake.listCalls))
	}
	fake.pages[""] = core.ListInstancesResponse{Items: []core.Instance{
		instanceItem("old", "gru-1-db-1", "gru-1", "db", core.InstanceLifecycleStateTerminating, 1, 6),
		{Id: common.String("seat"), DisplayName: common.String("gru-1-db-2"), LifecycleState: core.InstanceLifecycleStateRunning},
	}}
	if _, err := cloud.Launch(context.Background(), "gru-1-db-1", ok); err == nil || len(fake.launches) != 0 {
		t.Fatalf("launch over a terminating instance: %v, %d launches", err, len(fake.launches))
	}
	if _, err := cloud.Launch(context.Background(), "gru-1-db-2", ok); err == nil || !strings.Contains(err.Error(), "does not own") {
		t.Fatalf("launch over a placement seat: %v, %d launches", err, len(fake.launches))
	}
}

func TestOCICloudResizeAndTerminate(t *testing.T) {
	fake := &fakeCompute{}
	cloud := newTestCloud(t, fake)
	if err := cloud.Resize(context.Background(), "i1", Shape{OCPUs: 4, MemoryGB: 24}); err != nil {
		t.Fatal(err)
	}
	u := fake.updates[0]
	if *u.InstanceId != "i1" || *u.ShapeConfig.Ocpus != 4 || *u.ShapeConfig.MemoryInGBs != 24 {
		t.Fatalf("update = %+v", u)
	}
	if err := cloud.Resize(context.Background(), "i1", Shape{}); !errors.Is(err, ErrResizeRejected) ||
		!strings.Contains(err.Error(), "shape must have positive") || len(fake.updates) != 1 {
		t.Fatalf("zero-shape resize: err=%v updates=%d", err, len(fake.updates))
	}
	if err := cloud.Terminate(context.Background(), "i1"); err != nil {
		t.Fatal(err)
	}
	if r := fake.terminates[0]; *r.InstanceId != "i1" || r.PreserveBootVolume == nil || *r.PreserveBootVolume {
		t.Fatalf("terminate = %+v", r)
	}
}

type resizeFailure struct {
	status int
	code   string
}

func (e resizeFailure) Error() string           { return e.code }
func (e resizeFailure) GetHTTPStatusCode() int  { return e.status }
func (e resizeFailure) GetMessage() string      { return e.code }
func (e resizeFailure) GetCode() string         { return e.code }
func (e resizeFailure) GetOpcRequestID() string { return "test" }

func TestOCICloudResizeRejection(t *testing.T) {
	for _, test := range []struct {
		name     string
		err      error
		response core.UpdateInstanceResponse
		rejected bool
	}{
		{"invalid parameter", resizeFailure{400, "InvalidParameter"}, core.UpdateInstanceResponse{}, true},
		{"missing parameter", resizeFailure{400, "MissingParameter"}, core.UpdateInstanceResponse{}, true},
		{"malformed request", resizeFailure{400, "CannotParseRequest"}, core.UpdateInstanceResponse{}, true},
		{"limit exceeded", resizeFailure{400, "LimitExceeded"}, core.UpdateInstanceResponse{}, true},
		{"quota exceeded", resizeFailure{400, "QuotaExceeded"}, core.UpdateInstanceResponse{}, true},
		{"unauthenticated", resizeFailure{401, "NotAuthenticated"}, core.UpdateInstanceResponse{}, true},
		{"unauthorized", resizeFailure{403, "NotAuthorized"}, core.UpdateInstanceResponse{}, true},
		{"absent or invisible", missing{}, core.UpdateInstanceResponse{}, true},
		{"invalid path parameter", resizeFailure{404, "InvalidParameter"}, core.UpdateInstanceResponse{}, true},
		{"incorrect state", resizeFailure{409, "IncorrectState"}, core.UpdateInstanceResponse{}, true},
		{"throttled", resizeFailure{429, "TooManyRequests"}, core.UpdateInstanceResponse{}, true},
		{"matching HTTP rejection", resizeFailure{400, "InvalidParameter"}, core.UpdateInstanceResponse{RawResponse: &http.Response{StatusCode: 400}}, true},
		{"unknown validation", resizeFailure{400, "BadErrorResponse"}, core.UpdateInstanceResponse{}, false},
		{"unknown conflict", resizeFailure{409, "Conflict"}, core.UpdateInstanceResponse{}, false},
		{"request timeout", resizeFailure{408, "RequestTimeout"}, core.UpdateInstanceResponse{}, false},
		{"server error", resizeFailure{500, "InternalServerError"}, core.UpdateInstanceResponse{}, false},
		{"service unavailable", resizeFailure{503, "ServiceUnavailable"}, core.UpdateInstanceResponse{}, false},
		{"mismatched code status", resizeFailure{500, "InvalidParameter"}, core.UpdateInstanceResponse{}, false},
		{"unknown error", errors.New("connection reset"), core.UpdateInstanceResponse{}, false},
		{"lost response", io.ErrUnexpectedEOF, core.UpdateInstanceResponse{}, false},
		{"transport timeout", &url.Error{Op: "Put", URL: "https://example.invalid", Err: context.DeadlineExceeded}, core.UpdateInstanceResponse{}, false},
		{"deadline", context.DeadlineExceeded, core.UpdateInstanceResponse{}, false},
		{"cancelled", context.Canceled, core.UpdateInstanceResponse{}, false},
		{"wrapped rejection", fmt.Errorf("uncertain attempt: %w", resizeFailure{400, "InvalidParameter"}), core.UpdateInstanceResponse{}, false},
		{"rejection with HTTP success", resizeFailure{400, "InvalidParameter"}, core.UpdateInstanceResponse{RawResponse: &http.Response{StatusCode: 200}}, false},
		{"rejection with instance", resizeFailure{400, "InvalidParameter"}, core.UpdateInstanceResponse{Instance: core.Instance{Id: common.String("i1")}}, false},
		{"conflicting HTTP status", resizeFailure{400, "InvalidParameter"}, core.UpdateInstanceResponse{RawResponse: &http.Response{StatusCode: 503}}, false},
		{"success with decoding error", io.ErrUnexpectedEOF, core.UpdateInstanceResponse{RawResponse: &http.Response{StatusCode: 200}}, false},
		{"success", nil, core.UpdateInstanceResponse{Instance: core.Instance{Id: common.String("i1")}}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			fake := &fakeCompute{updateResponse: test.response, updateError: test.err}
			err := newTestCloud(t, fake).Resize(t.Context(), "i1", Shape{OCPUs: 4, MemoryGB: 24})
			if errors.Is(err, ErrResizeRejected) != test.rejected || !errors.Is(err, test.err) || len(fake.updates) != 1 {
				t.Fatalf("Resize = %v, rejected=%v, updates=%d; want rejected=%v and original cause %v",
					err, errors.Is(err, ErrResizeRejected), len(fake.updates), test.rejected, test.err)
			}
		})
	}
}

func TestTemplateValidate(t *testing.T) {
	if err := testTemplate().Validate(); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*Template){
		"fixed shape":    func(t *Template) { t.Shape = "VM.Standard.E4.Standard" },
		"unknown region": func(t *Template) { t.Region = "mars-1" },
		"no subnet":      func(t *Template) { t.SubnetID = "" },
		"small boot":     func(t *Template) { t.BootVolumeGB = 10 },
	} {
		template := testTemplate()
		mutate(&template)
		if err := template.Validate(); err == nil {
			t.Errorf("%s: Validate succeeded", name)
		}
	}
}

func TestOCIPreflight(t *testing.T) {
	ctx := context.Background()
	other := core.Shape{Shape: common.String("VM.Standard.E4.Flex")}
	fake := &fakeCompute{pages: map[string]core.ListInstancesResponse{"": {Items: []core.Instance{
		instanceItem("i1", "gru-1-db-1", "gru-1", "db", core.InstanceLifecycleStateRunning, 2, 12),
		instanceItem("foreign", "gru-1-db-2", "gru-1", "placement", core.InstanceLifecycleStateRunning, 80, 480),
	}}}, shapes: []core.Shape{other, a1Flex()}}
	reads := &fakeReads{subnetDNSLabel: common.String("database"), available: map[string]float32{
		"standard-a1-core-count": 248, "standard-a1-memory-count": 1662,
		"standard-a1-core-regional-count": 300, "standard-a1-memory-regional-count": 6000,
	}}
	cloud, err := newOCICloud("gru-1", testTemplate(), fake, reads)
	if err != nil {
		t.Fatal(err)
	}
	report, err := cloud.Preflight(ctx, testPolicy())
	// Only the managed node offsets the 6 nodes at 8 OCPUs and 48 GB;
	// a foreign reservation contributes neither nodes nor owned capacity.
	if err != nil || len(report.Problems) != 0 || report.Nodes != 1 || report.CoresNeeded != 46 || report.MemoryGBNeeded != 276 ||
		report.CoresAvailable != 248 || report.MemoryGBAvailable != 1662 {
		t.Fatalf("Preflight = %+v, %v", report, err)
	}
	if len(fake.shapeCalls) != 2 || *fake.shapeCalls[0].ImageId != "ocid1.image.x" || len(reads.quotas) != 4 ||
		*reads.quotas[0].CompartmentId != "ocid1.compartment.x" || *reads.quotas[0].AvailabilityDomain != "AD-1" {
		t.Fatalf("shape calls %+v, quota calls %+v", fake.shapeCalls, reads.quotas)
	}
	if len(fake.launches)+len(fake.updates)+len(fake.terminates) != 0 {
		t.Fatal("preflight changed OCI")
	}

	reads.available["standard-a1-core-count"] = 10
	fake.image, reads.subnet = missing{}, missing{}
	policy := testPolicy()
	policy.Shape.MemoryGBPerOCPU = 65
	report, err = cloud.Preflight(ctx, policy)
	if err != nil || len(report.Problems) != 5 {
		t.Fatalf("broken template preflight = %+v, %v", report, err)
	}
	for index, want := range []string{"image", "subnet", "GB per OCPU", "quota standard-a1-memory-count has 1662 left",
		"quota standard-a1-core-count has 10 left"} {
		if !strings.Contains(report.Problems[index], want) {
			t.Fatalf("problem %d = %q, want %q", index, report.Problems[index], want)
		}
	}
	fake.image = errors.New("connection reset")
	if _, err := cloud.Preflight(ctx, policy); err == nil {
		t.Fatal("an OCI failure must fail the preflight, not pass as a problem")
	}
	fake.image, reads.subnet, fake.shapes = nil, nil, []core.Shape{other}
	if report, _ := cloud.Preflight(ctx, testPolicy()); len(report.Problems) != 1 || !strings.Contains(report.Problems[0], "not offered") {
		t.Fatalf("missing shape preflight = %+v", report)
	}
}

func TestOCIPreflightRequiresTemplateShapeOnOwnedInstances(t *testing.T) {
	for _, test := range []struct {
		name    string
		shape   *string
		foreign bool
		valid   bool
	}{
		{"matching shape", common.String("VM.Standard.A1.Flex"), false, true},
		{"different flex shape", common.String("VM.Standard.E4.Flex"), false, false},
		{"non-flex shape", common.String("VM.Standard.E4.Standard"), false, false},
		{"missing shape", nil, false, false},
		{"empty shape", common.String(""), false, false},
		{"foreign shape ignored", common.String("VM.Standard.E4.Standard"), true, true},
		{"foreign flex shape ignored", common.String("VM.Standard.E4.Flex"), true, true},
		{"foreign missing shape ignored", nil, true, true},
		{"foreign empty shape ignored", common.String(""), true, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			first := instanceItem("matching", "gru-1-db-1", "gru-1", "db", core.InstanceLifecycleStateRunning, 2, 12)
			second := instanceItem("second", "gru-1-db-2", "gru-1", "db", core.InstanceLifecycleStateRunning, 4, 30)
			second.Shape = test.shape
			if test.foreign {
				second.FreeformTags = nil
			}
			fake := &fakeCompute{pages: map[string]core.ListInstancesResponse{"": {Items: []core.Instance{first, second}}}, shapes: []core.Shape{a1Flex()}}
			cloud := newTestCloud(t, fake)
			reads := &fakeReads{subnetDNSLabel: common.String("database"), available: map[string]float32{}}
			for _, quota := range a1Flex().QuotaNames {
				reads.available[quota] = 512
			}
			cloud.reads = reads
			if test.valid {
				instances, err := cloud.List(t.Context())
				if err != nil || len(instances) != 2 || instances[1].ShapeName != deref(test.shape) || instances[1].Foreign != test.foreign {
					t.Fatalf("shape metadata or foreign reservation lost: %+v, %v", instances, err)
				}
			}
			report, err := cloud.Preflight(t.Context(), testPolicy())
			if test.valid {
				wantNodes, wantCores, wantMemory := 2, float64(42), float64(246)
				if test.foreign {
					wantNodes, wantCores, wantMemory = 1, 46, 276
				}
				if err != nil || len(report.Problems) != 0 || len(reads.quotas) != 4 || report.Nodes != wantNodes ||
					report.CoresNeeded != wantCores || report.MemoryGBNeeded != wantMemory {
					t.Fatalf("compatible owned shapes = %+v, %v", report, err)
				}
			} else if err == nil || !strings.Contains(err.Error(), "instance second: shape") || !strings.Contains(err.Error(), "does not match template shape") || len(reads.quotas) != 0 || len(fake.shapeCalls) != 0 {
				t.Fatalf("unsupported owned shape passed quota check: %+v, %v", report, err)
			}
			if len(fake.launches)+len(fake.updates)+len(fake.terminates) != 0 {
				t.Fatal("preflight changed OCI")
			}
		})
	}
}

func TestOCIPreflightRegionalQuotas(t *testing.T) {
	for _, quota := range []string{"standard-a1-core-regional-count", "standard-a1-memory-regional-count"} {
		t.Run(quota, func(t *testing.T) {
			fake := &fakeCompute{pages: map[string]core.ListInstancesResponse{"": {}}, shapes: []core.Shape{a1Flex()}}
			reads := &fakeReads{subnetDNSLabel: common.String("database"), available: map[string]float32{
				"standard-a1-core-count": 248, "standard-a1-memory-count": 1662,
				"standard-a1-core-regional-count": 300, "standard-a1-memory-regional-count": 6000,
			}}
			reads.available[quota] = 0
			cloud, err := newOCICloud("gru-1", testTemplate(), fake, reads)
			if err != nil {
				t.Fatal(err)
			}
			report, err := cloud.Preflight(t.Context(), testPolicy())
			if err != nil || len(report.Problems) != 1 || !strings.Contains(report.Problems[0], "quota "+quota+" has 0 left") {
				t.Fatalf("exhausted regional quota with AD headroom = %+v, %v", report, err)
			}
			if strings.Contains(quota, "-core-") && report.CoresAvailable != 0 ||
				strings.Contains(quota, "-memory-") && report.MemoryGBAvailable != 0 {
				t.Fatalf("available capacity did not reflect the limiting regional quota: %+v", report)
			}
			if len(reads.quotas) != 4 {
				t.Fatalf("quota calls = %d, want both regional and AD core/memory quotas", len(reads.quotas))
			}
			for _, request := range reads.quotas {
				if *request.ServiceName != "compute" || *request.CompartmentId != "ocid1.compartment.x" {
					t.Fatalf("quota scope = %+v", request)
				}
				if strings.Contains(*request.LimitName, "-regional-") {
					if request.AvailabilityDomain != nil {
						t.Fatalf("regional quota includes an availability domain: %+v", request)
					}
				} else if request.AvailabilityDomain == nil || *request.AvailabilityDomain != "AD-1" {
					t.Fatalf("AD quota scope = %+v", request)
				}
			}
			if len(fake.launches)+len(fake.updates)+len(fake.terminates) != 0 {
				t.Fatal("preflight changed OCI")
			}
		})
	}
}

func TestOCIPreflightRequiresQuotaCoverage(t *testing.T) {
	for _, test := range []struct {
		name   string
		quotas []string
		valid  bool
	}{
		{"missing", nil, false},
		{"empty", []string{}, false},
		{"unrecognized", []string{"standard-a1-gpu-count"}, false},
		{"only cores", []string{"standard-a1-core-count"}, false},
		{"only memory", []string{"standard-a1-memory-regional-count"}, false},
		{"both resources", []string{"standard-a1-core-count", "standard-a1-memory-count"}, true},
		{"both regional resources", []string{"standard-a1-core-regional-count", "standard-a1-memory-regional-count"}, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			shape := a1Flex()
			shape.QuotaNames = test.quotas
			fake := &fakeCompute{pages: map[string]core.ListInstancesResponse{"": {}}, shapes: []core.Shape{shape}}
			reads := &fakeReads{subnetDNSLabel: common.String("database"), available: map[string]float32{}}
			for _, quota := range test.quotas {
				reads.available[quota] = 512
			}
			cloud, err := newOCICloud("gru-1", testTemplate(), fake, reads)
			if err != nil {
				t.Fatal(err)
			}
			report, err := cloud.Preflight(t.Context(), testPolicy())
			if test.valid {
				if err != nil || len(report.Problems) != 0 || report.CoresAvailable != 512 || report.MemoryGBAvailable != 512 {
					t.Fatalf("checked quota coverage = %+v, %v", report, err)
				}
			} else if err == nil || !strings.Contains(err.Error(), "quota") || !strings.Contains(err.Error(), "unchecked") {
				t.Fatalf("unchecked quota coverage passed preflight = %+v, %v", report, err)
			}
			if len(fake.launches)+len(fake.updates)+len(fake.terminates) != 0 {
				t.Fatal("preflight changed OCI")
			}
		})
	}
}

func TestOCIPreflightCapsOversizedRemoteCapacityCredit(t *testing.T) {
	for _, test := range []struct {
		name                            string
		cores, memory                   float32
		coresAvailable, memoryAvailable float32
		coresNeeded, memoryNeeded       float64
		problems                        int
	}{
		{"cores", 64, 12, 32, 512, 40, 276, 1},
		{"memory", 2, 384, 512, 200, 46, 240, 1},
		{"both", 64, 384, 32, 200, 40, 240, 2},
	} {
		t.Run(test.name, func(t *testing.T) {
			remote := instanceItem("remote", "gru-1-db-1", "gru-1", "db", core.InstanceLifecycleStateRunning, test.cores, test.memory)
			remote.AvailabilityDomain = common.String("AD-2")
			fake := &fakeCompute{pages: map[string]core.ListInstancesResponse{"": {Items: []core.Instance{remote}}}, shapes: []core.Shape{a1Flex()}}
			reads := &fakeReads{subnetDNSLabel: common.String("database"), available: map[string]float32{
				"standard-a1-core-count": test.coresAvailable, "standard-a1-memory-count": test.memoryAvailable,
				"standard-a1-core-regional-count": 512, "standard-a1-memory-regional-count": 512,
			}}
			cloud, err := newOCICloud("gru-1", testTemplate(), fake, reads)
			if err != nil {
				t.Fatal(err)
			}
			report, err := cloud.Preflight(t.Context(), testPolicy())
			if err != nil || report.Nodes != 1 || report.CoresNeeded != test.coresNeeded || report.MemoryGBNeeded != test.memoryNeeded ||
				len(report.Problems) != test.problems {
				t.Fatalf("oversized remote quota credit = %+v, %v", report, err)
			}
			for _, problem := range report.Problems {
				if !strings.Contains(problem, "quota standard-a1-") || strings.Contains(problem, "-regional-") {
					t.Fatalf("target AD quota exhaustion was not detected: %s", problem)
				}
			}
			if len(reads.quotas) != 6 || len(fake.launches)+len(fake.updates)+len(fake.terminates) != 0 {
				t.Fatal("quota credit changed coverage or mutated OCI")
			}
		})
	}
}

func TestOCIPreflightQuotaDemandByAvailabilityDomain(t *testing.T) {
	for _, test := range []struct {
		name     string
		local    Shape
		remote   Shape
		regional Shape
		problems []string
	}{
		{"exact headroom", Shape{34, 204}, Shape{6, 36}, Shape{40, 240}, nil},
		{"remote cores exhausted", Shape{512, 512}, Shape{0, 36}, Shape{512, 512}, []string{"needs 6 (availability domain \"AD-2\")"}},
		{"remote memory exhausted", Shape{512, 512}, Shape{6, 0}, Shape{512, 512}, []string{"needs 36 (availability domain \"AD-2\")"}},
		{"remote both exhausted", Shape{512, 512}, Shape{}, Shape{512, 512}, []string{"needs 36 (availability domain \"AD-2\")", "needs 6 (availability domain \"AD-2\")"}},
		{"launch domain cores short", Shape{33, 204}, Shape{512, 512}, Shape{512, 512}, []string{"needs 34 (availability domain \"AD-1\")"}},
		{"launch domain memory short", Shape{34, 203}, Shape{512, 512}, Shape{512, 512}, []string{"needs 204 (availability domain \"AD-1\")"}},
		{"regional totals short", Shape{512, 512}, Shape{512, 512}, Shape{39, 239}, []string{"needs 240 (availability domain \"\")", "needs 40 (availability domain \"\")"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			local := instanceItem("local", "gru-1-db-1", "gru-1", "db", core.InstanceLifecycleStateRunning, 6, 36)
			remote := instanceItem("remote", "gru-1-db-2", "gru-1", "db", core.InstanceLifecycleStateRunning, 2, 12)
			remote.AvailabilityDomain = common.String("AD-2")
			foreign := instanceItem("foreign", "gru-1-db-3", "gru-1", "placement", core.InstanceLifecycleStateRunning, 80, 480)
			foreign.Shape = common.String("VM.Standard.E4.Standard")
			foreign.AvailabilityDomain = common.String("AD-3")
			shape := a1Flex()
			shape.QuotaNames = append(shape.QuotaNames, shape.QuotaNames...)
			fake := &fakeCompute{pages: map[string]core.ListInstancesResponse{"": {Items: []core.Instance{local, remote, foreign}}}, shapes: []core.Shape{shape}}
			reads := &fakeReads{subnetDNSLabel: common.String("database"), domainAvailable: map[string]map[string]float32{
				"AD-1": {"standard-a1-core-count": float32(test.local.OCPUs), "standard-a1-memory-count": float32(test.local.MemoryGB)},
				"AD-2": {"standard-a1-core-count": float32(test.remote.OCPUs), "standard-a1-memory-count": float32(test.remote.MemoryGB)},
				"":     {"standard-a1-core-regional-count": float32(test.regional.OCPUs), "standard-a1-memory-regional-count": float32(test.regional.MemoryGB)},
			}}
			cloud, err := newOCICloud("gru-1", testTemplate(), fake, reads)
			if err != nil {
				t.Fatal(err)
			}
			report, err := cloud.Preflight(t.Context(), testPolicy())
			if err != nil || report.Nodes != 2 || report.CoresNeeded != 40 || report.MemoryGBNeeded != 240 || len(report.Problems) != len(test.problems) {
				t.Fatalf("per-domain quota report = %+v, %v", report, err)
			}
			for i, want := range test.problems {
				if !strings.Contains(report.Problems[i], want) {
					t.Fatalf("problem %d = %q, want %q", i, report.Problems[i], want)
				}
			}
			if len(reads.quotas) != 6 || len(report.Quotas) != 6 || len(fake.launches)+len(fake.updates)+len(fake.terminates) != 0 {
				t.Fatalf("quota requests=%d, mutations=%d", len(reads.quotas), len(fake.launches)+len(fake.updates)+len(fake.terminates))
			}
			seen := map[string]bool{}
			for _, request := range reads.quotas {
				key := deref(request.LimitName) + "/" + deref(request.AvailabilityDomain)
				if seen[key] || strings.Contains(deref(request.LimitName), "-regional-") != (request.AvailabilityDomain == nil) {
					t.Fatalf("duplicate or mis-scoped quota request: %+v", request)
				}
				if domain := deref(request.AvailabilityDomain); domain != "" && domain != "AD-1" && domain != "AD-2" {
					t.Fatalf("foreign-only domain requested: %+v", request)
				}
				seen[key] = true
			}
			for _, quota := range report.Quotas {
				needed := map[string]Shape{"AD-1": {34, 204}, "AD-2": {6, 36}, "": {40, 240}}[quota.AvailabilityDomain]
				available := map[string]Shape{"AD-1": test.local, "AD-2": test.remote, "": test.regional}[quota.AvailabilityDomain]
				wantNeeded, wantAvailable := needed.OCPUs, available.OCPUs
				if strings.Contains(quota.Quota, "-memory-") {
					wantNeeded, wantAvailable = needed.MemoryGB, available.MemoryGB
				}
				if quota.Needed != wantNeeded || quota.Available != wantAvailable {
					t.Fatalf("scoped quota = %+v; want needed=%g available=%g", quota, wantNeeded, wantAvailable)
				}
			}
		})
	}
}

func TestOCIPreflightShapeCapabilitiesByAvailabilityDomain(t *testing.T) {
	for _, test := range []struct {
		name    string
		change  func(*core.Shape)
		problem string
	}{
		{"supported", func(*core.Shape) {}, ""},
		{"not offered", func(s *core.Shape) { s.Shape = common.String("other") }, "not offered"},
		{"not flexible", func(s *core.Shape) { s.IsFlexible = common.Bool(false) }, "not flexible"},
		{"CPU minimum", func(s *core.Shape) { s.OcpuOptions.Min = common.Float32(4) }, "OCPUs"},
		{"CPU maximum", func(s *core.Shape) { s.OcpuOptions.Max = common.Float32(4) }, "OCPUs"},
		{"memory per CPU minimum", func(s *core.Shape) { s.MemoryOptions.MinPerOcpuInGBs = common.Float32(8) }, "GB per OCPU"},
		{"memory per CPU maximum", func(s *core.Shape) { s.MemoryOptions.MaxPerOcpuInGBs = common.Float32(4) }, "GB per OCPU"},
		{"memory total minimum", func(s *core.Shape) { s.MemoryOptions.MinInGBs = common.Float32(24) }, "GB per OCPU"},
		{"memory total maximum", func(s *core.Shape) { s.MemoryOptions.MaxInGBs = common.Float32(24) }, "GB per OCPU"},
	} {
		t.Run(test.name, func(t *testing.T) {
			remote := instanceItem("remote", "gru-1-db-1", "gru-1", "db", core.InstanceLifecycleStateRunning, 2, 12)
			remote.AvailabilityDomain = common.String("AD-2")
			foreign := instanceItem("foreign", "gru-1-db-2", "gru-1", "placement", core.InstanceLifecycleStateRunning, 2, 12)
			foreign.AvailabilityDomain = common.String("AD-3")
			remoteShape := a1Flex()
			test.change(&remoteShape)
			fake := &fakeCompute{pages: map[string]core.ListInstancesResponse{"": {Items: []core.Instance{remote, foreign}}},
				shapes: []core.Shape{a1Flex()}, domainShapes: map[string][]core.Shape{"AD-2": {{Shape: common.String("other")}, remoteShape}}}
			reads := &fakeReads{subnetDNSLabel: common.String("database"), available: map[string]float32{}}
			for _, quota := range a1Flex().QuotaNames {
				reads.available[quota] = 1024
			}
			cloud, err := newOCICloud("gru-1", testTemplate(), fake, reads)
			if err != nil {
				t.Fatal(err)
			}
			report, err := cloud.Preflight(t.Context(), testPolicy())
			if err != nil {
				t.Fatal(err)
			}
			if test.problem == "" {
				if len(report.Problems) != 0 {
					t.Fatalf("supported remote resize was refused: %+v", report)
				}
			} else if len(report.Problems) != 1 || !strings.Contains(report.Problems[0], "AD-2") || !strings.Contains(report.Problems[0], test.problem) {
				t.Fatalf("remote capability passed preflight: %+v; want %q in AD-2", report, test.problem)
			}
			remotePages := 0
			for _, request := range fake.shapeCalls {
				switch deref(request.AvailabilityDomain) {
				case "AD-1":
					if deref(request.ImageId) != testTemplate().ImageID {
						t.Fatal("launch shape lost image compatibility filtering")
					}
				case "AD-2":
					remotePages++
					if request.ImageId != nil {
						t.Fatal("existing-node resize was filtered by the new launch image")
					}
				default:
					t.Fatalf("shape check included a foreign-only domain: %+v", request)
				}
			}
			if remotePages != 2 || len(fake.launches)+len(fake.updates)+len(fake.terminates) != 0 {
				t.Fatalf("remote shape pagination or effects: pages=%d mutations=%d", remotePages, len(fake.launches)+len(fake.updates)+len(fake.terminates))
			}
		})
	}
}

func TestOCIPreflightRequiresInstanceAvailabilityDomain(t *testing.T) {
	for _, domain := range []*string{nil, common.String(""), common.String(" ")} {
		for _, foreign := range []bool{false, true} {
			t.Run(fmt.Sprintf("domain=%v/foreign=%t", domain, foreign), func(t *testing.T) {
				item := instanceItem("unknown", "gru-1-db-1", "gru-1", "db", core.InstanceLifecycleStateRunning, 2, 12)
				item.AvailabilityDomain = domain
				if foreign {
					item.FreeformTags = nil
				}
				fake := &fakeCompute{pages: map[string]core.ListInstancesResponse{"": {Items: []core.Instance{item}}}, shapes: []core.Shape{a1Flex()}}
				cloud := newTestCloud(t, fake)
				reads := &fakeReads{subnetDNSLabel: common.String("database"), available: map[string]float32{}}
				for _, quota := range a1Flex().QuotaNames {
					reads.available[quota] = 512
				}
				cloud.reads = reads
				report, err := cloud.Preflight(t.Context(), testPolicy())
				if foreign {
					if err != nil || len(report.Problems) != 0 || report.Nodes != 0 || len(reads.quotas) != 4 {
						t.Fatalf("foreign instance contributed quota demand: %+v, %v", report, err)
					}
				} else if err == nil || !strings.Contains(err.Error(), "instance unknown: availability domain is missing") || len(reads.quotas) != 0 {
					t.Fatalf("unknown managed domain passed preflight: %+v, %v", report, err)
				}
				if len(fake.launches)+len(fake.updates)+len(fake.terminates) != 0 {
					t.Fatal("preflight changed OCI")
				}
			})
		}
	}
}

func TestOCIPreflightGrowthDoesNotBorrowShrinks(t *testing.T) {
	for _, test := range []struct {
		name   string
		remote []Shape
		needed Shape
	}{
		{"at node limit", []Shape{small, {64, 384}}, Shape{6, 36}},
		{"above node limit", []Shape{small, small, {64, 384}}, Shape{12, 72}},
		{"mixed dimensions", []Shape{{64, 12}, {2, 384}}, Shape{6, 36}},
	} {
		t.Run(test.name, func(t *testing.T) {
			var items []core.Instance
			for i, shape := range test.remote {
				item := instanceItem(fmt.Sprintf("remote-%d", i), NodeName("gru-1", i+1), "gru-1", "db", core.InstanceLifecycleStateRunning,
					float32(shape.OCPUs), float32(shape.MemoryGB))
				item.AvailabilityDomain = common.String("AD-2")
				items = append(items, item)
			}
			items = append(items, instanceItem("local", NodeName("gru-1", len(items)+1), "gru-1", "db", core.InstanceLifecycleStateRunning, 8, 48))
			fake := &fakeCompute{pages: map[string]core.ListInstancesResponse{"": {Items: items}}, shapes: []core.Shape{a1Flex()}}
			reads := &fakeReads{subnetDNSLabel: common.String("database"), domainAvailable: map[string]map[string]float32{
				"AD-1": {"standard-a1-core-count": 0, "standard-a1-memory-count": 0},
				"AD-2": {"standard-a1-core-count": float32(test.needed.OCPUs), "standard-a1-memory-count": float32(test.needed.MemoryGB)},
				"": {"standard-a1-core-regional-count": float32(test.needed.OCPUs - 1),
					"standard-a1-memory-regional-count": float32(test.needed.MemoryGB - 1)},
			}}
			cloud, err := newOCICloud("gru-1", testTemplate(), fake, reads)
			if err != nil {
				t.Fatal(err)
			}
			policy := testPolicy()
			policy.Nodes.Max = 3
			report, err := cloud.Preflight(t.Context(), policy)
			if err != nil || report.Nodes != len(items) || report.CoresNeeded != test.needed.OCPUs || report.MemoryGBNeeded != test.needed.MemoryGB || len(report.Problems) != 2 {
				t.Fatalf("oversized nodes offset positive growth: %+v, %v", report, err)
			}
			for _, problem := range report.Problems {
				if !strings.Contains(problem, "-regional-") {
					t.Fatalf("unexpected AD shortage: %s", problem)
				}
			}
			if len(reads.quotas) != 6 || len(fake.launches)+len(fake.updates)+len(fake.terminates) != 0 {
				t.Fatal("preflight changed quota coverage or OCI")
			}
		})
	}
}

func TestOCIPreflightRemoteQuotaAvailabilityFields(t *testing.T) {
	for _, resource := range []struct {
		quota  string
		needed float32
	}{{"standard-a1-core-count", 6}, {"standard-a1-memory-count", 36}} {
		for _, test := range []struct {
			name       string
			resource   limits.ResourceAvailability
			problems   int
			unreadable bool
		}{
			{"integer fallback", limits.ResourceAvailability{Available: common.Int64(int64(resource.needed))}, 0, false},
			{"fractional preferred", limits.ResourceAvailability{FractionalAvailability: common.Float32(resource.needed + 0.5), Available: common.Int64(1)}, 0, false},
			{"fractional zero", limits.ResourceAvailability{FractionalAvailability: common.Float32(0), Available: common.Int64(512)}, 1, false},
			{"missing availability", limits.ResourceAvailability{}, 0, true},
		} {
			t.Run(resource.quota+"/"+test.name, func(t *testing.T) {
				remote := instanceItem("remote", "gru-1-db-1", "gru-1", "db", core.InstanceLifecycleStateRunning, 2, 12)
				remote.AvailabilityDomain = common.String("AD-2")
				fake := &fakeCompute{pages: map[string]core.ListInstancesResponse{"": {Items: []core.Instance{remote}}}, shapes: []core.Shape{a1Flex()}}
				reads := &fakeReads{subnetDNSLabel: common.String("database"), available: map[string]float32{}, domainResources: map[string]map[string]limits.ResourceAvailability{
					"AD-2": {resource.quota: test.resource},
				}}
				for _, quota := range a1Flex().QuotaNames {
					reads.available[quota] = 512
				}
				cloud, err := newOCICloud("gru-1", testTemplate(), fake, reads)
				if err != nil {
					t.Fatal(err)
				}
				report, err := cloud.Preflight(t.Context(), testPolicy())
				if test.unreadable {
					if err == nil || !strings.Contains(err.Error(), resource.quota) || !strings.Contains(err.Error(), "AD-2") || !strings.Contains(err.Error(), "availability is missing") {
						t.Fatalf("missing remote quota passed: %+v, %v", report, err)
					}
				} else if err != nil || len(report.Problems) != test.problems || len(reads.quotas) != 6 {
					t.Fatalf("remote availability = %+v, %v", report, err)
				}
				if test.problems > 0 && (!strings.Contains(report.Problems[0], resource.quota) || !strings.Contains(report.Problems[0], "AD-2")) {
					t.Fatalf("wrong quota scope failed: %v", report.Problems)
				}
				if len(fake.launches)+len(fake.updates)+len(fake.terminates) != 0 {
					t.Fatal("preflight changed OCI")
				}
			})
		}
	}
}

func TestOCIPreflightSubnetDNSLabelAndDomain(t *testing.T) {
	for _, test := range []struct {
		name    string
		domain  *string
		label   *string
		problem string
	}{
		{"regional null", nil, common.String("database"), ""},
		{"regional empty", common.String(""), common.String("database"), ""},
		{"matching AD", common.String("AD-1"), common.String("database"), ""},
		{"different AD", common.String("AD-2"), common.String("database"), "AD-2, template requires AD-1"},
		{"missing DNS label", nil, nil, "DNS label"},
		{"empty DNS label", nil, common.String(""), "DNS label"},
		{"whitespace DNS label", nil, common.String(" "), "DNS label"},
		{"numeric DNS prefix", nil, common.String("1database"), "DNS label"},
		{"hyphenated DNS label", nil, common.String("data-base"), "DNS label"},
		{"underscored DNS label", nil, common.String("data_base"), "DNS label"},
		{"non-ASCII DNS label", nil, common.String("dátabase"), "DNS label"},
		{"overlong DNS label", nil, common.String(strings.Repeat("a", 16)), "DNS label"},
		{"single letter DNS label", nil, common.String("a"), ""},
		{"maximum DNS label", nil, common.String("Database1234567"), ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			shape := a1Flex()
			fake := &fakeCompute{pages: map[string]core.ListInstancesResponse{"": {}}, shapes: []core.Shape{shape}}
			reads := &fakeReads{subnetAD: test.domain, subnetDNSLabel: test.label, available: map[string]float32{}}
			for _, quota := range shape.QuotaNames {
				reads.available[quota] = 512
			}
			cloud, err := newOCICloud("gru-1", testTemplate(), fake, reads)
			if err != nil {
				t.Fatal(err)
			}
			report, err := cloud.Preflight(t.Context(), testPolicy())
			if err != nil {
				t.Fatal(err)
			}
			if test.problem != "" {
				if len(report.Problems) != 1 || !strings.Contains(report.Problems[0], "subnet ocid1.subnet.x") ||
					!strings.Contains(report.Problems[0], test.problem) {
					t.Fatalf("invalid subnet = %+v; want %q", report, test.problem)
				}
			} else if len(report.Problems) != 0 {
				t.Fatalf("compatible subnet = %+v", report)
			}
			if len(fake.launches)+len(fake.updates)+len(fake.terminates) != 0 {
				t.Fatal("preflight changed OCI")
			}
		})
	}
}

func TestOCIPreflightQuotaAvailabilityFields(t *testing.T) {
	for _, test := range []struct {
		name       string
		resource   limits.ResourceAvailability
		available  float64
		problems   int
		unreadable bool
	}{
		{"integer headroom", limits.ResourceAvailability{Available: common.Int64(512)}, 512, 0, false},
		{"fractional preferred", limits.ResourceAvailability{FractionalAvailability: common.Float32(512.5), Available: common.Int64(1)}, 512.5, 0, false},
		{"fractional zero", limits.ResourceAvailability{FractionalAvailability: common.Float32(0), Available: common.Int64(512)}, 0, 4, false},
		{"integer zero", limits.ResourceAvailability{Available: common.Int64(0)}, 0, 4, false},
		{"missing availability", limits.ResourceAvailability{}, 0, 0, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			shape := a1Flex()
			fake := &fakeCompute{pages: map[string]core.ListInstancesResponse{"": {}}, shapes: []core.Shape{shape}}
			reads := &fakeReads{subnetDNSLabel: common.String("database"), resources: map[string]limits.ResourceAvailability{}}
			for _, quota := range shape.QuotaNames {
				reads.resources[quota] = test.resource
			}
			cloud, err := newOCICloud("gru-1", testTemplate(), fake, reads)
			if err != nil {
				t.Fatal(err)
			}
			report, err := cloud.Preflight(t.Context(), testPolicy())
			if len(fake.launches)+len(fake.updates)+len(fake.terminates) != 0 {
				t.Fatal("preflight changed OCI")
			}
			if test.unreadable {
				if err == nil || !strings.Contains(err.Error(), "quota standard-a1-memory-count") || !strings.Contains(err.Error(), "availability") {
					t.Fatalf("unreadable quota = %+v, %v", report, err)
				}
				return
			}
			if err != nil || report.CoresAvailable != test.available || report.MemoryGBAvailable != test.available ||
				len(report.Problems) != test.problems || len(reads.quotas) != len(shape.QuotaNames) {
				t.Fatalf("quota availability = %+v, %v; want %g available and %d problems", report, err, test.available, test.problems)
			}
		})
	}
}
