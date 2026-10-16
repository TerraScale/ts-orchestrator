package nodescale

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"maps"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/core"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/decisionlog"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/hostload"
	"github.com/TerraScale/ts-orchestrator/internal/memberstatus"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
)

const testCompartment = "ocid1.compartment.oc1..gru"

var (
	errNotFound     = errors.New("404 not found")
	errPrecondition = errors.New("412 precondition failed")
	errInUse        = errors.New("409 configuration is referenced by an instance pool")
)

// capacityCloud backs a loopback OCI HTTP simulator. It enforces ETags, configurations in use,
// and two-item pages. It has no TerminateInstance, so the code under test cannot call one.
type capacityCloud struct {
	pools        map[string]*core.InstancePool
	configs      map[string]*core.InstanceConfiguration
	instances    map[string]*core.Instance
	members      map[string]string // instance id -> pool id
	attachments  map[string][]core.VnicAttachment
	vnics        map[string]core.Vnic
	etags        map[string]string
	tokens       map[string]string // opc-retry-token -> the id it created
	detaches     []core.DetachInstancePoolInstanceDetails
	updates      int                                       // UpdateInstancePool calls
	shrinks      int                                       // UpdateInstancePool calls that lowered a pool's size
	applying     map[string]core.UpdateInstancePoolDetails // accepted configuration and placement updates; see settle
	shapeRows    []core.Shape
	rejectGrowth bool
	staleWrite   bool
	nextID       int
}

func newCapacityCloud() *capacityCloud {
	return &capacityCloud{pools: map[string]*core.InstancePool{}, configs: map[string]*core.InstanceConfiguration{},
		instances: map[string]*core.Instance{}, members: map[string]string{},
		attachments: map[string][]core.VnicAttachment{}, vnics: map[string]core.Vnic{},
		etags: map[string]string{}, tokens: map[string]string{}, applying: map[string]core.UpdateInstancePoolDetails{}}
}

func (f *capacityCloud) id(kind string) string {
	f.nextID++
	return "ocid1." + kind + ".oc1..test" + strconv.Itoa(f.nextID)
}

// touch records a new ETag for id, as every OCI write does.
func (f *capacityCloud) touch(id string) {
	f.nextID++
	f.etags[id] = "etag-" + strconv.Itoa(f.nextID)
}

func (f *capacityCloud) fresh(id string, ifMatch *string) error {
	if ifMatch != nil && *ifMatch != f.etags[id] {
		return errPrecondition
	}
	return nil
}

// launch adds an instance with one primary VNIC at ip. A non-empty poolID makes it a member of that pool.
func (f *capacityCloud) launch(name, poolID, ip string, state core.InstanceLifecycleStateEnum, tags map[string]string) string {
	id := f.id("instance")
	vnicID := f.id("vnic")
	f.instances[id] = &core.Instance{Id: common.String(id), DisplayName: common.String(name),
		LifecycleState: state, FreeformTags: tags}
	f.vnics[vnicID] = core.Vnic{Id: common.String(vnicID), IsPrimary: common.Bool(true), PrivateIp: common.String(ip)}
	f.attachments[id] = []core.VnicAttachment{{Id: common.String(f.id("attachment")), InstanceId: common.String(id),
		VnicId: common.String(vnicID), LifecycleState: core.VnicAttachmentLifecycleStateAttached}}
	if poolID != "" {
		f.members[id] = poolID
	}
	f.touch(id)
	return id
}

// pageOf returns the two-item page that token names, so every list takes more than one page.
func pageOf[T any](items []T, token *string) ([]T, *string) {
	start := 0
	if token != nil {
		start, _ = strconv.Atoi(*token)
	}
	end := min(start+2, len(items))
	if end == len(items) {
		return items[start:end], nil
	}
	next := strconv.Itoa(end)
	return items[start:end], &next
}

// sortedByID returns the values of m in key order, so pages are stable.
func sortedByID[V any](m map[string]V) []V {
	values := make([]V, 0, len(m))
	for _, key := range slices.Sorted(maps.Keys(m)) {
		values = append(values, m[key])
	}
	return values
}

func (f *capacityCloud) ListInstancePools(_ context.Context, request core.ListInstancePoolsRequest) (core.ListInstancePoolsResponse, error) {
	var items []core.InstancePoolSummary
	for _, pool := range sortedByID(f.pools) {
		if deref(pool.CompartmentId) == deref(request.CompartmentId) &&
			(request.DisplayName == nil || deref(pool.DisplayName) == *request.DisplayName) {
			items = append(items, core.InstancePoolSummary{Id: pool.Id, DisplayName: pool.DisplayName,
				FreeformTags: pool.FreeformTags, Size: pool.Size, LifecycleState: core.InstancePoolSummaryLifecycleStateEnum(pool.LifecycleState)})
		}
	}
	page, next := pageOf(items, request.Page)
	return core.ListInstancePoolsResponse{Items: page, OpcNextPage: next}, nil
}

func (f *capacityCloud) GetInstancePool(_ context.Context, request core.GetInstancePoolRequest) (core.GetInstancePoolResponse, error) {
	id := deref(request.InstancePoolId)
	pool, ok := f.pools[id]
	if !ok {
		return core.GetInstancePoolResponse{}, errNotFound
	}
	return core.GetInstancePoolResponse{InstancePool: *pool, Etag: common.String(f.etags[id])}, nil
}

func (f *capacityCloud) CreateInstancePool(_ context.Context, request core.CreateInstancePoolRequest) (core.CreateInstancePoolResponse, error) {
	if id, ok := f.tokens[deref(request.OpcRetryToken)]; ok {
		return core.CreateInstancePoolResponse{InstancePool: *f.pools[id], Etag: common.String(f.etags[id])}, nil
	}
	details := request.CreateInstancePoolDetails
	id := f.id("instancepool")
	pool := &core.InstancePool{Id: common.String(id), CompartmentId: details.CompartmentId,
		InstanceConfigurationId: details.InstanceConfigurationId, LifecycleState: core.InstancePoolLifecycleStateRunning,
		Size: details.Size, DisplayName: details.DisplayName, FreeformTags: details.FreeformTags}
	for _, placement := range details.PlacementConfigurations {
		pool.PlacementConfigurations = append(pool.PlacementConfigurations, core.InstancePoolPlacementConfiguration{
			AvailabilityDomain: placement.AvailabilityDomain, PrimaryVnicSubnets: placement.PrimaryVnicSubnets})
	}
	f.pools[id] = pool
	f.tokens[deref(request.OpcRetryToken)] = id
	f.touch(id)
	return core.CreateInstancePoolResponse{InstancePool: *pool, Etag: common.String(f.etags[id])}, nil
}

func (f *capacityCloud) UpdateInstancePool(_ context.Context, request core.UpdateInstancePoolRequest) (core.UpdateInstancePoolResponse, error) {
	id := deref(request.InstancePoolId)
	pool, ok := f.pools[id]
	if !ok {
		return core.UpdateInstancePoolResponse{}, errNotFound
	}
	if err := f.fresh(id, request.IfMatch); err != nil {
		return core.UpdateInstancePoolResponse{}, err
	}
	f.updates++
	details := request.UpdateInstancePoolDetails
	if details.InstanceConfigurationId != nil || details.PlacementConfigurations != nil {
		// OCI applies a configuration or placement change later; the pool keeps its old ones until settle.
		f.applying[id] = details
	}
	if details.Size != nil {
		if *details.Size < deref(pool.Size) {
			f.shrinks++
		}
		pool.Size = details.Size
	}
	f.touch(id)
	return core.UpdateInstancePoolResponse{InstancePool: *pool, Etag: common.String(f.etags[id])}, nil
}

// settle applies the configuration and placement updates OCI has accepted, as OCI does once the pool is done updating.
func (f *capacityCloud) settle() {
	for id, details := range f.applying {
		pool := f.pools[id]
		if details.InstanceConfigurationId != nil {
			pool.InstanceConfigurationId = details.InstanceConfigurationId
		}
		if details.PlacementConfigurations != nil {
			pool.PlacementConfigurations = nil
			for _, placement := range details.PlacementConfigurations {
				pool.PlacementConfigurations = append(pool.PlacementConfigurations, core.InstancePoolPlacementConfiguration{
					AvailabilityDomain: placement.AvailabilityDomain, PrimaryVnicSubnets: placement.PrimaryVnicSubnets})
			}
		}
		delete(f.applying, id)
		f.touch(id)
	}
}

func (f *capacityCloud) ListInstancePoolInstances(_ context.Context, request core.ListInstancePoolInstancesRequest) (core.ListInstancePoolInstancesResponse, error) {
	var items []core.InstanceSummary
	for _, id := range slices.Sorted(maps.Keys(f.members)) {
		if f.members[id] == deref(request.InstancePoolId) {
			instance := f.instances[id]
			items = append(items, core.InstanceSummary{Id: instance.Id, DisplayName: instance.DisplayName,
				State: common.String(string(instance.LifecycleState)), TimeCreated: instance.TimeCreated})
		}
	}
	page, next := pageOf(items, request.Page)
	return core.ListInstancePoolInstancesResponse{Items: page, OpcNextPage: next}, nil
}

// DetachInstancePoolInstance applies both flags the leader sends: the pool shrinks and the instance terminates.
func (f *capacityCloud) DetachInstancePoolInstance(_ context.Context, request core.DetachInstancePoolInstanceRequest) (core.DetachInstancePoolInstanceResponse, error) {
	details := request.DetachInstancePoolInstanceDetails
	pool, ok := f.pools[deref(request.InstancePoolId)]
	if !ok || f.members[deref(details.InstanceId)] != deref(pool.Id) {
		return core.DetachInstancePoolInstanceResponse{}, errNotFound
	}
	f.detaches = append(f.detaches, details)
	if deref(details.IsDecrementSize) {
		pool.Size = common.Int(deref(pool.Size) - 1)
	}
	if deref(details.IsAutoTerminate) {
		f.instances[deref(details.InstanceId)].LifecycleState = core.InstanceLifecycleStateTerminating
	}
	f.touch(deref(pool.Id))
	return core.DetachInstancePoolInstanceResponse{}, nil
}

func (f *capacityCloud) ListInstanceConfigurations(_ context.Context, request core.ListInstanceConfigurationsRequest) (core.ListInstanceConfigurationsResponse, error) {
	var items []core.InstanceConfigurationSummary
	for _, config := range sortedByID(f.configs) {
		if deref(config.CompartmentId) == deref(request.CompartmentId) {
			items = append(items, core.InstanceConfigurationSummary{Id: config.Id, CompartmentId: config.CompartmentId,
				DisplayName: config.DisplayName, FreeformTags: config.FreeformTags})
		}
	}
	page, next := pageOf(items, request.Page)
	return core.ListInstanceConfigurationsResponse{Items: page, OpcNextPage: next}, nil
}

func (f *capacityCloud) CreateInstanceConfiguration(_ context.Context, request core.CreateInstanceConfigurationRequest) (core.CreateInstanceConfigurationResponse, error) {
	if id, ok := f.tokens[deref(request.OpcRetryToken)]; ok {
		return core.CreateInstanceConfigurationResponse{InstanceConfiguration: *f.configs[id]}, nil
	}
	details := request.CreateInstanceConfiguration.(core.CreateInstanceConfigurationDetails)
	id := f.id("instanceconfiguration")
	f.configs[id] = &core.InstanceConfiguration{Id: common.String(id), CompartmentId: details.CompartmentId,
		DisplayName: details.DisplayName, FreeformTags: details.FreeformTags, InstanceDetails: details.InstanceDetails}
	f.tokens[deref(request.OpcRetryToken)] = id
	return core.CreateInstanceConfigurationResponse{InstanceConfiguration: *f.configs[id]}, nil
}

// DeleteInstanceConfiguration refuses a configuration a pool still references, as OCI does.
func (f *capacityCloud) DeleteInstanceConfiguration(_ context.Context, request core.DeleteInstanceConfigurationRequest) (core.DeleteInstanceConfigurationResponse, error) {
	id := deref(request.InstanceConfigurationId)
	if _, ok := f.configs[id]; !ok {
		return core.DeleteInstanceConfigurationResponse{}, errNotFound
	}
	for _, pool := range f.pools {
		if deref(pool.InstanceConfigurationId) == id {
			return core.DeleteInstanceConfigurationResponse{}, errInUse
		}
	}
	delete(f.configs, id)
	return core.DeleteInstanceConfigurationResponse{}, nil
}

func (f *capacityCloud) GetInstance(_ context.Context, request core.GetInstanceRequest) (core.GetInstanceResponse, error) {
	id := deref(request.InstanceId)
	instance, ok := f.instances[id]
	if !ok {
		return core.GetInstanceResponse{}, errNotFound
	}
	return core.GetInstanceResponse{Instance: *instance, Etag: common.String(f.etags[id])}, nil
}

func (f *capacityCloud) UpdateInstance(_ context.Context, request core.UpdateInstanceRequest) (core.UpdateInstanceResponse, error) {
	id := deref(request.InstanceId)
	instance, ok := f.instances[id]
	if !ok {
		return core.UpdateInstanceResponse{}, errNotFound
	}
	if err := f.fresh(id, request.IfMatch); err != nil {
		return core.UpdateInstanceResponse{}, err
	}
	if request.DisplayName != nil {
		instance.DisplayName = request.DisplayName
	}
	if request.FreeformTags != nil {
		instance.FreeformTags = request.FreeformTags
	}
	f.touch(id)
	return core.UpdateInstanceResponse{Instance: *instance, Etag: common.String(f.etags[id])}, nil
}

func (f *capacityCloud) ListVnicAttachments(_ context.Context, request core.ListVnicAttachmentsRequest) (core.ListVnicAttachmentsResponse, error) {
	return core.ListVnicAttachmentsResponse{Items: f.attachments[deref(request.InstanceId)]}, nil
}

func (f *capacityCloud) GetVnic(_ context.Context, request core.GetVnicRequest) (core.GetVnicResponse, error) {
	vnic, ok := f.vnics[deref(request.VnicId)]
	if !ok {
		return core.GetVnicResponse{}, errNotFound
	}
	return core.GetVnicResponse{Vnic: vnic}, nil
}

// capacitySigner keeps credentials out of this loopback-only protocol simulator.
type capacitySigner struct{}

func (capacitySigner) Sign(*http.Request) error { return nil }

func (f *capacityCloud) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	path := strings.TrimPrefix(r.URL.Path, "/20160918")
	parts := strings.Split(strings.Trim(path, "/"), "/")
	id := ""
	if len(parts) > 1 {
		id = parts[1]
	}
	query := r.URL.Query()
	page := (*string)(nil)
	if query.Has("page") {
		page = new(query.Get("page"))
	}
	ctx := r.Context()
	var body any
	var err error
	decode := func(v any) bool {
		if err := json.UnmarshalRead(r.Body, v); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return false
		}
		return true
	}
	switch {
	case path == "/shapes":
		if query.Get("imageId") == "" || query.Get("availabilityDomain") == "" || query.Get("compartmentId") != testCompartment {
			http.Error(w, "missing image compatibility scope", 400)
			return
		}
		body = f.shapeRows
		if f.shapeRows == nil {
			body = []core.Shape{capacityShape("VM.Standard.A1.Flex", "Ampere Altra"), capacityShape("VM.Standard.E4.Flex", "AMD EPYC")}
		}
	case path == "/instancePools" && r.Method == "GET":
		response, callErr := f.ListInstancePools(ctx, core.ListInstancePoolsRequest{CompartmentId: new(query.Get("compartmentId")), Page: page})
		body, err = response.Items, callErr
		if response.OpcNextPage != nil {
			w.Header().Set("opc-next-page", *response.OpcNextPage)
		}
	case path == "/instancePools" && r.Method == "POST":
		var details core.CreateInstancePoolDetails
		if !decode(&details) {
			return
		}
		response, callErr := f.CreateInstancePool(ctx, core.CreateInstancePoolRequest{CreateInstancePoolDetails: details, OpcRetryToken: new(r.Header.Get("opc-retry-token"))})
		body, err = response.InstancePool, callErr
		w.Header().Set("etag", deref(response.Etag))
	case len(parts) == 2 && parts[0] == "instancePools" && r.Method == "GET":
		response, callErr := f.GetInstancePool(ctx, core.GetInstancePoolRequest{InstancePoolId: new(id)})
		body, err = response.InstancePool, callErr
		w.Header().Set("etag", deref(response.Etag))
	case len(parts) == 2 && parts[0] == "instancePools" && r.Method == "PUT":
		if f.rejectGrowth {
			w.WriteHeader(500)
			json.MarshalWrite(w, map[string]string{"code": "OutOfHostCapacity", "message": "capacity unavailable"})
			return
		}
		var details core.UpdateInstancePoolDetails
		if f.staleWrite {
			f.touch(id)
			f.staleWrite = false
		}
		if !decode(&details) {
			return
		}
		if r.Header.Get("if-match") == "" {
			http.Error(w, "missing etag", 428)
			return
		}
		response, callErr := f.UpdateInstancePool(ctx, core.UpdateInstancePoolRequest{InstancePoolId: new(id), IfMatch: new(r.Header.Get("if-match")), UpdateInstancePoolDetails: details})
		body, err = response.InstancePool, callErr
	case len(parts) == 3 && parts[0] == "instancePools" && parts[2] == "instances":
		response, callErr := f.ListInstancePoolInstances(ctx, core.ListInstancePoolInstancesRequest{InstancePoolId: new(id), Page: page})
		body, err = response.Items, callErr
		if response.OpcNextPage != nil {
			w.Header().Set("opc-next-page", *response.OpcNextPage)
		}
	case len(parts) == 4 && parts[0] == "instancePools" && parts[3] == "detachInstance":
		var details core.DetachInstancePoolInstanceDetails
		if !decode(&details) {
			return
		}
		_, err = f.DetachInstancePoolInstance(ctx, core.DetachInstancePoolInstanceRequest{InstancePoolId: new(id), DetachInstancePoolInstanceDetails: details})
		body = map[string]string{}
	case path == "/instanceConfigurations" && r.Method == "GET":
		response, callErr := f.ListInstanceConfigurations(ctx, core.ListInstanceConfigurationsRequest{CompartmentId: new(query.Get("compartmentId")), Page: page})
		body, err = response.Items, callErr
		if response.OpcNextPage != nil {
			w.Header().Set("opc-next-page", *response.OpcNextPage)
		}
	case path == "/instanceConfigurations" && r.Method == "POST":
		var details core.CreateInstanceConfigurationDetails
		if !decode(&details) {
			return
		}
		response, callErr := f.CreateInstanceConfiguration(ctx, core.CreateInstanceConfigurationRequest{CreateInstanceConfiguration: details, OpcRetryToken: new(r.Header.Get("opc-retry-token"))})
		body, err = response.InstanceConfiguration, callErr
	case parts[0] == "instanceConfigurations" && r.Method == "DELETE":
		_, err = f.DeleteInstanceConfiguration(ctx, core.DeleteInstanceConfigurationRequest{InstanceConfigurationId: new(id)})
		body = map[string]string{}
	case parts[0] == "instances" && r.Method == "GET":
		response, callErr := f.GetInstance(ctx, core.GetInstanceRequest{InstanceId: new(id)})
		body, err = response.Instance, callErr
		w.Header().Set("etag", deref(response.Etag))
	case parts[0] == "instances" && r.Method == "PUT":
		var details core.UpdateInstanceDetails
		if !decode(&details) {
			return
		}
		response, callErr := f.UpdateInstance(ctx, core.UpdateInstanceRequest{InstanceId: new(id), IfMatch: new(r.Header.Get("if-match")), UpdateInstanceDetails: details})
		body, err = response.Instance, callErr
	case path == "/vnicAttachments":
		response, callErr := f.ListVnicAttachments(ctx, core.ListVnicAttachmentsRequest{InstanceId: new(query.Get("instanceId"))})
		body, err = response.Items, callErr
	case parts[0] == "vnics":
		response, callErr := f.GetVnic(ctx, core.GetVnicRequest{VnicId: new(id)})
		body, err = response.Vnic, callErr
	default:
		http.Error(w, "unexpected OCI operation: "+r.Method+" "+path, 400)
		return
	}
	if err != nil {
		status := 409
		if errors.Is(err, errNotFound) {
			status = 404
		}
		if errors.Is(err, errPrecondition) {
			status = 412
		}
		w.WriteHeader(status)
		body = map[string]string{"code": "Conflict", "message": err.Error()}
	}
	if body == nil {
		body = []any{}
	}
	if err := json.MarshalWrite(w, body); err != nil {
		panic(err)
	}
}

func capacityRecipe() Recipe {
	return Recipe{Cell: "gru", Capacity: Capacity{Role: "container", Architecture: "arm64", Shape: "VM.Standard.A1.Flex"},
		SubnetID: "ocid1.subnet.test", NSGIDs: []string{"ocid1.nsg.a", "ocid1.nsg.b"}, AvailabilityDomains: []string{"AD-1", "AD-2"},
		ImageID: "ocid1.image.v1", OCPUs: 2, MemoryGB: 12, Metadata: map[string]string{"ts_host": "descriptor"}}
}

func protocolPool(t *testing.T, cloud *capacityCloud, capacity Capacity) *OCIPool {
	t.Helper()
	srv := httptest.NewServer(cloud)
	t.Cleanup(srv.Close)
	policy := common.NoRetryPolicy()
	base := common.BaseClient{Host: srv.URL, BasePath: "20160918", UserAgent: "capacity-integration", HTTPClient: srv.Client(), Signer: capacitySigner{},
		Configuration: common.CustomClientConfiguration{RetryPolicy: &policy}}
	ociclient.ConfigureRequestCancellation(&base)
	pool, err := newOCIPool(core.ComputeManagementClient{BaseClient: base}, core.ComputeClient{BaseClient: base}, core.VirtualNetworkClient{BaseClient: base}, "gru", testCompartment, capacity)
	if err != nil {
		t.Fatal(err)
	}
	pool.Admit = func(context.Context, Recipe) (func(), error) { return func() {}, nil }
	pool.CheckpointGrowth = func(_ context.Context, _ Recipe, request core.UpdateInstancePoolRequest) (core.UpdateInstancePoolRequest, error) {
		return request, nil
	}
	return pool
}

func capacityShape(shape, processor string) core.Shape {
	return core.Shape{Shape: new(shape), ProcessorDescription: new(processor), IsFlexible: new(true),
		OcpuOptions:   &core.ShapeOcpuOptions{Min: new(float32(1)), Max: new(float32(64))},
		MemoryOptions: &core.ShapeMemoryOptions{MinInGBs: new(float32(1)), MaxInGBs: new(float32(1024)), MinPerOcpuInGBs: new(float32(1)), MaxPerOcpuInGBs: new(float32(64))}}
}

func capacityJetStream(t *testing.T) jetstream.JetStream {
	t.Helper()
	srv, err := server.NewServer(&server.Options{Host: "127.0.0.1", Port: -1, JetStream: true, StoreDir: filepath.Join(t.TempDir(), "jetstream")})
	if err != nil {
		t.Fatal(err)
	}
	go srv.Start()
	if !srv.ReadyForConnections(5 * time.Second) {
		t.Fatal("NATS did not start")
	}
	t.Cleanup(func() { srv.Shutdown(); srv.WaitForShutdown() })
	conn, err := nats.Connect(srv.ClientURL())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(conn.Close)
	js, err := jetstream.New(conn)
	if err != nil {
		t.Fatal(err)
	}
	return js
}

func TestCapacityPoolProtocolLifecycle(t *testing.T) {
	ctx := t.Context()
	cloud := newCapacityCloud()
	recipe := capacityRecipe()
	pool := protocolPool(t, cloud, recipe.Capacity)
	first, err := pool.Ensure(ctx, recipe)
	if err != nil {
		t.Fatal(err)
	}
	again, err := pool.Ensure(ctx, recipe)
	if err != nil || first.PoolID != again.PoolID || len(cloud.pools) != 1 || len(cloud.configs) != 1 {
		t.Fatalf("ensure replay created duplicates: first=%+v again=%+v err=%v", first, again, err)
	}
	config := cloud.configs[first.ConfigurationID]
	launch := config.InstanceDetails.(core.ComputeInstanceDetails).LaunchDetails
	if deref(launch.Shape) != recipe.Capacity.Shape || deref(launch.ShapeConfig.Ocpus) != recipe.OCPUs ||
		deref(launch.ShapeConfig.MemoryInGBs) != recipe.MemoryGB || deref(launch.CreateVnicDetails.AssignPublicIp) ||
		!slices.Equal(launch.CreateVnicDetails.NsgIds, recipe.NSGIDs) {
		t.Fatalf("wrong launch contract over OCI JSON: %+v", launch)
	}
	if err := pool.Grow(ctx, 0); err != nil {
		t.Fatal(err)
	}
	updates := cloud.updates
	if err := pool.Grow(ctx, 0); err != nil || cloud.updates != updates {
		t.Fatalf("growth replay: updates=%d err=%v", cloud.updates, err)
	}
	if err := pool.Grow(ctx, 2); !errors.Is(err, ErrPoolChanged) {
		t.Fatalf("unexpected size accepted: %v", err)
	}
	ids := []string{}
	for i := range 3 {
		ids = append(ids, cloud.launch(fmt.Sprintf("instance-%d", i), first.PoolID, fmt.Sprintf("10.0.0.%d", i+4), core.InstanceLifecycleStateRunning, map[string]string{"preserve": "tag"}))
	}
	observed, err := pool.Observe(ctx)
	if err != nil || len(observed.Instances) != 3 || observed.Instances[2].PrivateIP == "" {
		t.Fatalf("paginated observation: %+v err=%v", observed, err)
	}
	if err := pool.Name(ctx, ids[0], "ts-gru-4"); err != nil {
		t.Fatal(err)
	}
	if cloud.instances[ids[0]].FreeformTags["preserve"] != "tag" {
		t.Fatal("naming discarded existing tags")
	}
	outsider := cloud.launch("outsider", "", "10.0.0.99", core.InstanceLifecycleStateRunning, nil)
	if err := pool.Remove(ctx, outsider); !errors.Is(err, ErrNotPoolInstance) {
		t.Fatalf("outsider removal: %v", err)
	}
	if err := pool.Remove(ctx, ids[0]); err != nil {
		t.Fatal(err)
	}
	if len(cloud.detaches) != 1 || !deref(cloud.detaches[0].IsAutoTerminate) || !deref(cloud.detaches[0].IsDecrementSize) || cloud.shrinks != 0 {
		t.Fatalf("unsafe pool removal: detach=%+v shrinking=%d", cloud.detaches, cloud.shrinks)
	}
	if err := pool.Remove(ctx, ids[0]); err != nil || len(cloud.detaches) != 1 {
		t.Fatalf("removal replay: %v", err)
	}
	oldConfig := first.ConfigurationID
	recipe.ImageID = "ocid1.image.v2"
	if _, err := pool.Ensure(ctx, recipe); err == nil {
		t.Fatal("asynchronous configuration change was admitted before application")
	}
	if cloud.configs[oldConfig] == nil {
		t.Fatal("deleted configuration still referenced during OCI asynchronous repoint")
	}
	cloud.settle()
	if _, err := pool.Ensure(ctx, recipe); err != nil {
		t.Fatal(err)
	}
	if cloud.configs[oldConfig] != nil {
		t.Fatal("old configuration not pruned after OCI repoint completed")
	}
}

type capacityLeader struct{ snapshot authority.Snapshot }

func (f *capacityLeader) Current() authority.Snapshot { return f.snapshot }

func (f *capacityLeader) Guard(context.Context, uint64) error { return nil }

func TestCapacityPoolProtocolIsolationAndValidation(t *testing.T) {
	ctx := t.Context()
	cloud := newCapacityCloud()
	base := capacityRecipe()
	for _, capacity := range []Capacity{base.Capacity, {Role: "wasm", Architecture: "arm64", Shape: base.Capacity.Shape}, {Role: "container", Architecture: "amd64", Shape: "VM.Standard.E4.Flex"}} {
		recipe := base
		recipe.Capacity = capacity
		pool := protocolPool(t, cloud, capacity)
		if _, err := pool.Ensure(ctx, recipe); err != nil {
			t.Fatal(err)
		}
	}
	if len(cloud.pools) != 3 || len(cloud.configs) != 3 {
		t.Fatalf("capacity identities collide: pools=%d configs=%d", len(cloud.pools), len(cloud.configs))
	}
	pool := protocolPool(t, cloud, base.Capacity)
	for name, mutate := range map[string]func(*Recipe){
		"image architecture mismatch": func(r *Recipe) { r.Capacity.Architecture = "amd64" },
		"unknown shape":               func(r *Recipe) { r.Capacity.Shape = "VM.Standard.Unknown.Flex" },
		"missing metadata":            func(r *Recipe) { r.Metadata = nil },
		"missing image":               func(r *Recipe) { r.ImageID = "" },
	} {
		recipe := base
		mutate(&recipe)
		candidate := protocolPool(t, cloud, recipe.Capacity)
		if _, err := candidate.Ensure(ctx, recipe); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
	if len(cloud.pools) != 3 || len(cloud.configs) != 3 {
		t.Fatal("invalid recipe mutated OCI resources")
	}
	cloud.shapeRows = []core.Shape{}
	if _, err := pool.Ensure(ctx, base); err == nil {
		t.Fatal("empty image-compatible shape list accepted")
	}
	cloud.shapeRows = nil
	if _, err := pool.Ensure(ctx, base); err != nil {
		t.Fatal(err)
	}
	cloud.rejectGrowth = true
	if err := pool.Grow(ctx, 0); err == nil || !strings.Contains(err.Error(), "OutOfHostCapacity") {
		t.Fatalf("capacity exhaustion not surfaced: %v", err)
	}
	cloud.rejectGrowth = false

	cloud.staleWrite = true
	if err := pool.Grow(ctx, 0); err == nil {
		t.Fatal("OCI rejected stale etag but caller accepted growth")
	}
	state, err := pool.Observe(ctx)
	if err != nil || state.Size != 0 {
		t.Fatalf("stale etag changed size: %+v %v", state, err)
	}
	if err := pool.Grow(ctx, 0); err != nil {
		t.Fatalf("capacity recovery failed: %v", err)
	}
	target, _, err := pool.pool(ctx)
	if err != nil {
		t.Fatal(err)
	}
	duplicate := *cloud.pools[deref(target.Id)]
	duplicate.Id = new("ocid1.instancepool.oc1..duplicate")
	cloud.pools[*duplicate.Id] = &duplicate
	if _, err := pool.Observe(ctx); err == nil || !strings.Contains(err.Error(), "refusing to guess") {
		t.Fatalf("ambiguous ownership accepted: %v", err)
	}

}

func TestCapacityStoreReopenAndFencedWrites(t *testing.T) {
	ctx := t.Context()
	js := capacityJetStream(t)
	store, err := OpenStore(ctx, js, 1)
	if err != nil {
		t.Fatal(err)
	}
	empty, revision, err := store.Load(ctx)
	if err != nil || revision != 0 || !reflect.DeepEqual(empty, Record{}) {
		t.Fatalf("empty record=%+v rev=%d err=%v", empty, revision, err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	original := Record{LastChange: now, From: 3, Action: &InFlight{ID: entityid.New(), Kind: Up, Step: stepEnroll, Started: now}}
	first, err := store.Save(ctx, original, 0)
	if err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenStore(ctx, js, 1)
	if err != nil {
		t.Fatal(err)
	}
	restored, revision, err := reopened.Load(ctx)
	if err != nil || revision != first || !reflect.DeepEqual(restored, original) {
		t.Fatalf("reopened=%+v rev=%d err=%v", restored, revision, err)
	}
	restored.From = 4
	if _, err := reopened.Save(ctx, restored, revision); err != nil {
		t.Fatal(err)
	}
	for _, stale := range []uint64{0, first} {
		if _, err := store.Save(ctx, original, stale); !errors.Is(err, ErrRecordChanged) {
			t.Fatalf("stale writer revision %d: %v", stale, err)
		}
	}
	kv, err := js.KeyValue(ctx, Bucket)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := kv.Put(ctx, recordKey, []byte(`{"unknown_field":true}`)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := reopened.Load(ctx); err == nil {
		t.Fatal("corrupt durable protocol record accepted")
	}
}

func TestCapacityScalerRecoveryAndSafety(t *testing.T) {
	for _, scenario := range []string{"grow and restart", "launch timeout", "database drain hold", "backend drain timeout", "drain and revoke", "missing allowance", "stale loads", "request pressure", "missing host memory", "pending admission resume", "expired allowance resume", "follower"} {
		t.Run(scenario, func(t *testing.T) {
			ctx := t.Context()
			now := time.Now().UTC().Truncate(time.Second)
			cloud := newCapacityCloud()
			recipe := capacityRecipe()
			pool := protocolPool(t, cloud, recipe.Capacity)
			state, err := pool.Ensure(ctx, recipe)
			if err != nil {
				t.Fatal(err)
			}
			store, err := OpenStore(ctx, capacityJetStream(t), 1)
			if err != nil {
				t.Fatal(err)
			}
			hosts := newSwarmHosts(t)
			hosts.live = map[string]bool{"ts-gru-1": true, "ts-gru-2": true, "ts-gru-3": true}
			leader := &capacityLeader{snapshot: authority.Snapshot{DeploymentID: entityid.New(), Leader: true, Ready: true, Epoch: 7, Revision: 3, ExpiresAt: time.Now().Add(time.Hour)}}
			backendCount := 0
			cpu := .9
			stale := false
			var revoked []string
			var entries []decisionlog.Decision
			scaler := &Scaler{Cell: "gru", Pool: pool, Store: store, Leader: leader, Control: hosts.control, CanRetire: func(context.Context, string, string) error { return nil },
				Recipe: func(context.Context) (Recipe, error) { return recipe, nil }, Now: func() time.Time { return now },
				Allowance: func(time.Time) (int, bool) { return MaxNodes, scenario != "missing allowance" },
				Loads: func() []NodeLoad {
					var loads []NodeLoad
					for node, live := range hosts.live {
						if live {
							at := now
							if stale {
								at = at.Add(-3 * time.Minute)
							}
							report := hostload.Report{SchemaVersion: hostload.SchemaVersion, Host: hostload.HostUsage{CPU: new(cpu), Memory: new(.1), Disk: new(.1), CPUCores: 2}}
							if scenario == "missing host memory" {
								report.Host.Memory = nil
							}
							if scenario == "request pressure" {
								report.Roles = []hostload.RoleUsage{{TerraBase: &memberstatus.Load{WriteQPS: 450, Connections: 900}}, {TerraBase: &memberstatus.Load{WriteQPS: 450, Connections: 900}}}
							}
							if load, ok := FromHostLoad(hostload.NodeLoad{Origin: hostload.Origin{Node: node}, At: at, Report: report}); ok {
								loads = append(loads, load)
							}
						}
					}
					return loads
				}, Backends: func(context.Context, string, string) (int, error) { return backendCount, nil },
				Revoke:  func(_ context.Context, id string) error { revoked = append(revoked, id); return nil },
				Journal: func(_ context.Context, d decisionlog.Decision) { entries = append(entries, d) },
			}
			tick := func() Record {
				t.Helper()
				observed, err := pool.Observe(ctx)
				if err != nil {
					t.Fatal(err)
				}
				for _, instance := range observed.Instances {
					hosts.instanceIDs[instance.Name] = instance.ID
				}
				hosts.sync(t)
				if err := scaler.Tick(ctx); err != nil {
					t.Fatal(err)
				}
				hosts.observe(t)
				record, _, err := store.Load(ctx)
				if err != nil {
					t.Fatal(err)
				}
				return record
			}
			if scenario == "pending admission resume" || scenario == "expired allowance resume" {
				pending := Record{Action: &InFlight{ID: entityid.New(), Kind: Up, Step: stepGrow, Started: now}, From: 0}
				if _, err := store.Save(ctx, pending, 0); err != nil {
					t.Fatal(err)
				}
				if scenario == "pending admission resume" {
					pool.Admit = nil
				} else {
					scaler.Allowance = func(time.Time) (int, bool) { return 0, false }
				}
				resumed := tick()
				if resumed.Action == nil || resumed.Action.ID != pending.Action.ID || resumed.Action.Step != stepGrow || cloud.updates != 0 || scaler.Status().Action != Hold {
					t.Fatalf("pending resume mutated capacity or lost its durable operation: %+v updates=%d", resumed, cloud.updates)
				}
				return
			}
			if strings.Contains(scenario, "drain") {
				backendCount = 1
				cpu = .1
				id := cloud.launch("ts-gru-4", state.PoolID, "10.0.0.4", core.InstanceLifecycleStateRunning, nil)
				cloud.pools[state.PoolID].Size = new(1)
				hosts.live["ts-gru-4"] = true
				if scenario == "database drain hold" {
					hosts.desired = []desiredTask{{Node: "ts-gru-4", Role: "terrabase"}}
				}
				for range int(DownWindow/Interval) + 1 {
					tick()
					now = now.Add(Interval)
				}
				record := tick()
				if scenario == "database drain hold" {
					if record.Action != nil || len(hosts.cordoned) != 0 || len(cloud.detaches) != 0 {
						t.Fatal("database holder selected for removal")
					}
					return
				}
				backendCount = 1
				for range 3 {
					record = tick()
					now = now.Add(Interval)
				}
				if record.Action == nil || record.Action.InstanceID != id || record.Action.Step != stepDrain {
					t.Fatalf("drain not persisted: %+v", record.Action)
				}
				if scenario == "drain and revoke" {
					backendCount = 0
					for range 3 {
						record = tick()
						now = now.Add(Interval)
					}
					if record.Action != nil || len(cloud.detaches) != 1 || !slices.Equal(revoked, []string{id}) {
						t.Fatalf("drain/revoke failed: action=%+v detach=%v revoked=%v", record.Action, cloud.detaches, revoked)
					}
					return
				}
				now = now.Add(DrainTimeout)
				record = tick()
				if record.Action != nil || len(hosts.unretired) != 1 || len(cloud.detaches) != 0 || !record.LastChange.Equal(now) {
					t.Fatal("drain timeout terminated a node with a backend or lost cooldown")
				}
				return
			}
			if scenario == "stale loads" {
				stale = true
			}
			if scenario == "request pressure" {
				cpu = .1
			}
			if scenario == "follower" {
				leader.snapshot.Leader = false
				tick()
				_, revision, err := store.Load(ctx)
				if err != nil || revision != 0 || cloud.updates != 0 {
					t.Fatalf("follower mutated capacity: revision=%d updates=%d err=%v", revision, cloud.updates, err)
				}
				return
			}
			for range int(UpWindow/Interval) + 1 {
				tick()
				now = now.Add(Interval)
			}
			record := tick()
			if scenario == "missing allowance" || scenario == "stale loads" || scenario == "missing host memory" {
				if record.Action != nil || cloud.updates != 0 {
					t.Fatalf("unsafe growth with %s: %+v", scenario, record)
				}
				return
			}
			if record.Action == nil || record.Action.Step != stepEnroll {
				t.Fatalf("growth not persisted: %+v", record.Action)
			}
			updates := cloud.updates
			scaler = &Scaler{Cell: scaler.Cell, Pool: scaler.Pool, Store: scaler.Store, Leader: scaler.Leader, Control: scaler.Control, CanRetire: scaler.CanRetire,
				Recipe: scaler.Recipe, Now: scaler.Now, Allowance: scaler.Allowance, Loads: scaler.Loads, Backends: scaler.Backends, Revoke: scaler.Revoke, Journal: scaler.Journal}
			id := cloud.launch("new-instance", state.PoolID, "10.0.0.4", core.InstanceLifecycleStateRunning, nil)
			cloud.instances[id].TimeCreated = &common.SDKTime{Time: now}
			// Pool summaries need their real creation timestamp for launch-expiry ownership.
			if scenario == "launch timeout" {
				now = now.Add(LaunchTimeout)
				record = tick()
				if record.Action != nil || len(cloud.detaches) != 1 {
					t.Fatalf("launch timeout did not reclaim unenrolled node: %+v", record.Action)
				}
			} else {
				tick()
				hosts.live["ts-gru-4"] = true
				record = tick()
				if record.Action != nil || cloud.updates != updates || len(revoked) != 0 {
					t.Fatal("new leader repeated growth or failed to complete enrollment")
				}
				if !slices.ContainsFunc(entries, func(d decisionlog.Decision) bool { return d.Kind == decisionlog.KindHostLaunched }) {
					t.Fatal("recovered enrollment was not journaled")
				}
			}
		})
	}
}

func TestCapacityProberUsesTCPAndKeepsLastOnCancel(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()
	var calls int
	prober := &Prober{Now: time.Now, Regions: func(context.Context) ([]string, error) { return []string{"us-ashburn-1", "invalid/region"}, nil },
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			if address != "objectstorage.us-ashburn-1.oraclecloud.com:443" {
				return nil, fmt.Errorf("unexpected endpoint %s", address)
			}
			calls++
			return (&net.Dialer{}).DialContext(ctx, network, listener.Addr().String())
		},
	}
	if err := prober.Probe(t.Context()); err != nil {
		t.Fatal(err)
	}
	before, at := prober.Latest()
	if len(before) != 1 || before["us-ashburn-1"] <= 0 || calls != RTTSamples || at.IsZero() {
		t.Fatalf("TCP probe: %+v at %s calls=%d", before, at, calls)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := prober.Probe(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled probe: %v", err)
	}
	after, afterAt := prober.Latest()
	if !reflect.DeepEqual(before, after) || !at.Equal(afterAt) {
		t.Fatal("canceled round discarded last measurement")
	}
}

func TestCapacityAdmissionAndLegacyObservationOverOCI(t *testing.T) {
	ctx := t.Context()
	cloud := newCapacityCloud()
	recipe := capacityRecipe()
	pool := protocolPool(t, cloud, recipe.Capacity)
	pool.Admit = nil
	if _, err := pool.Ensure(ctx, recipe); !errors.Is(err, ErrCapacityPending) || len(cloud.configs) != 0 || len(cloud.pools) != 0 {
		t.Fatalf("missing admission mutated OCI: configs=%d pools=%d err=%v", len(cloud.configs), len(cloud.pools), err)
	}
	if err := pool.Grow(ctx, 0); !errors.Is(err, ErrCapacityPending) {
		t.Fatalf("unadmitted growth: %v", err)
	}
	calls := 0
	pool.Admit = func(context.Context, Recipe) (func(), error) {
		calls++
		if calls > 1 {
			return nil, ErrCapacityPending
		}
		return func() {}, nil
	}
	if _, err := pool.Ensure(ctx, recipe); !errors.Is(err, ErrCapacityPending) || len(cloud.configs) != 0 {
		t.Fatalf("admission revoked before configuration write: configs=%d err=%v", len(cloud.configs), err)
	}
	legacyID := "ocid1.instancepool.oc1..legacy"
	cloud.pools[legacyID] = &core.InstancePool{Id: new(legacyID), CompartmentId: new(testCompartment), DisplayName: new("ts-gru-nodes"),
		InstanceConfigurationId: new("ocid1.instanceconfiguration.old"), Size: new(1), LifecycleState: core.InstancePoolLifecycleStateRunning,
		FreeformTags: map[string]string{tagCell: "gru", tagRole: roleNodePool}}
	instanceID := cloud.launch("ts-gru-4", legacyID, "10.0.0.4", core.InstanceLifecycleStateRunning, nil)
	pool.Admit = nil
	observed, err := pool.Observe(ctx)
	if err != nil || observed.Size != 1 || len(observed.Instances) != 1 || observed.Instances[0].ID != instanceID || !strings.Contains(observed.Pending, "legacy pool") {
		t.Fatalf("legacy capacity disappeared: %+v %v", observed, err)
	}
	other := Capacity{Role: RoleContainer, Architecture: "amd64", Shape: "VM.Standard.E4.Flex"}
	otherID := "ocid1.instancepool.oc1..other"
	cloud.pools[otherID] = &core.InstancePool{Id: new(otherID), CompartmentId: new(testCompartment), DisplayName: new(PoolName("gru", other)), Size: new(1),
		LifecycleState: core.InstancePoolLifecycleStateRunning, FreeformTags: poolTags("gru", other, roleNodePool)}
	cloud.launch("ts-gru-5", otherID, "10.0.0.5", core.InstanceLifecycleStateRunning, nil)
	observed, err = pool.Observe(ctx)
	if err != nil || observed.Size != 2 || len(observed.Instances) != 2 || observed.PoolID != "" || observed.Pending == "" {
		t.Fatalf("heterogeneous capacity was hidden or collapsed: %+v %v", observed, err)
	}
	pool.Admit = func(context.Context, Recipe) (func(), error) { return func() {}, nil }
	if _, err := pool.Ensure(ctx, recipe); err == nil || !strings.Contains(err.Error(), "legacy pool") || len(cloud.configs) != 0 || len(cloud.pools) != 2 {
		t.Fatalf("legacy migration mutated OCI: configs=%d pools=%d err=%v", len(cloud.configs), len(cloud.pools), err)
	}
}

func TestCapacityGrowthRechecksAdmissionAndPlacementOverOCI(t *testing.T) {
	ctx := t.Context()
	cloud := newCapacityCloud()
	recipe := capacityRecipe()
	pool := protocolPool(t, cloud, recipe.Capacity)
	state, err := pool.Ensure(ctx, recipe)
	if err != nil {
		t.Fatal(err)
	}
	pool.Admit = func(context.Context, Recipe) (func(), error) { return nil, ErrCapacityPending }
	if err := pool.Grow(ctx, 0); !errors.Is(err, ErrCapacityPending) || cloud.updates != 0 {
		t.Fatalf("growth reused expired admission: updates=%d err=%v", cloud.updates, err)
	}
	pool.Admit = func(context.Context, Recipe) (func(), error) { return func() {}, nil }
	cloud.pools[state.PoolID].PlacementConfigurations[0].AvailabilityDomain = new("unqualified-AD")
	if err := pool.Grow(ctx, 0); !errors.Is(err, ErrCapacityPending) || cloud.updates != 0 {
		t.Fatalf("growth reused stale placement: updates=%d err=%v", cloud.updates, err)
	}
	reopened := protocolPool(t, cloud, recipe.Capacity)
	if err := reopened.Grow(ctx, 0); !errors.Is(err, ErrCapacityPending) {
		t.Fatalf("restart reused unpersisted admission: %v", err)
	}
}

func TestCapacityPruningRechecksAdmissionOverOCI(t *testing.T) {
	ctx := t.Context()
	cloud := newCapacityCloud()
	recipe := capacityRecipe()
	pool := protocolPool(t, cloud, recipe.Capacity)
	if _, err := pool.Ensure(ctx, recipe); err != nil {
		t.Fatal(err)
	}
	staleID := "ocid1.instanceconfiguration.oc1..stale"
	cloud.configs[staleID] = &core.InstanceConfiguration{Id: new(staleID), CompartmentId: new(testCompartment),
		DisplayName: new(configPrefix("gru", recipe.Capacity) + "stale"), FreeformTags: poolTags("gru", recipe.Capacity, roleNodeConfig)}
	calls := 0
	pool.Admit = func(context.Context, Recipe) (func(), error) {
		calls++
		if calls > 1 {
			return nil, ErrCapacityPending
		}
		return func() {}, nil
	}
	if _, err := pool.Ensure(ctx, recipe); !errors.Is(err, ErrCapacityPending) || cloud.configs[staleID] == nil || calls != 2 {
		t.Fatalf("pruning reused revoked admission: calls=%d stale=%v err=%v", calls, cloud.configs[staleID] != nil, err)
	}
}
