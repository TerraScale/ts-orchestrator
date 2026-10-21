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

	"github.com/moby/swarmkit/v2/api"
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
	"github.com/TerraScale/ts-orchestrator/internal/rootoci"
)

const testCompartment = "ocid1.compartment.oc1..gru"

var errNotFound = errors.New("404 not found")

// capacityCloud serves explicitly seeded observation facts, not admitted births.
// There is no mutation endpoint; every SDK write fails the test.
type capacityCloud struct {
	pools       map[string]*core.InstancePool
	configs     map[string]*core.InstanceConfiguration
	instances   map[string]*core.Instance
	members     map[string]string
	attachments map[string][]core.VnicAttachment
	vnics       map[string]core.Vnic
	shapeRows   []core.Shape
	nextID      int
}

func newCapacityCloud() *capacityCloud {
	return &capacityCloud{pools: map[string]*core.InstancePool{}, configs: map[string]*core.InstanceConfiguration{},
		instances: map[string]*core.Instance{}, members: map[string]string{},
		attachments: map[string][]core.VnicAttachment{}, vnics: map[string]core.Vnic{}}
}

func (f *capacityCloud) id(kind string) string {
	f.nextID++
	return "ocid1." + kind + ".oc1..test" + strconv.Itoa(f.nextID)
}

func (f *capacityCloud) launch(name, poolID, ip string, state core.InstanceLifecycleStateEnum, tags map[string]string) string {
	id := f.id("instance")
	vnicID := f.id("vnic")
	f.instances[id] = &core.Instance{Id: common.String(id), DisplayName: common.String(name),
		LifecycleState: state, FreeformTags: tags, InstanceOptions: &core.InstanceOptions{AreLegacyImdsEndpointsDisabled: new(true)}}
	f.vnics[vnicID] = core.Vnic{Id: common.String(vnicID), IsPrimary: common.Bool(true), PrivateIp: common.String(ip)}
	f.attachments[id] = []core.VnicAttachment{{Id: common.String(f.id("attachment")), InstanceId: common.String(id),
		VnicId: common.String(vnicID), LifecycleState: core.VnicAttachmentLifecycleStateAttached}}
	if poolID != "" {
		f.members[id] = poolID
	}
	return id
}

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
	return core.GetInstancePoolResponse{InstancePool: *pool}, nil
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

func (f *capacityCloud) GetInstanceConfiguration(_ context.Context, request core.GetInstanceConfigurationRequest) (core.GetInstanceConfigurationResponse, error) {
	config, ok := f.configs[deref(request.InstanceConfigurationId)]
	if !ok {
		return core.GetInstanceConfigurationResponse{}, errNotFound
	}
	return core.GetInstanceConfigurationResponse{InstanceConfiguration: *config}, nil
}

func (f *capacityCloud) GetInstance(_ context.Context, request core.GetInstanceRequest) (core.GetInstanceResponse, error) {
	id := deref(request.InstanceId)
	instance, ok := f.instances[id]
	if !ok {
		return core.GetInstanceResponse{}, errNotFound
	}
	return core.GetInstanceResponse{Instance: *instance}, nil
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

// The no-op signer is confined to a read-only loopback protocol fixture.
type capacitySigner struct{}

func (capacitySigner) Sign(*http.Request) error { return nil }

func (f *capacityCloud) serveRead(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	path := strings.TrimPrefix(r.URL.Path, "/20160918")
	parts := strings.Split(strings.Trim(path, "/"), "/")
	id := ""
	if len(parts) > 1 {
		id = parts[1]
	}
	query := r.URL.Query()
	var page *string
	if query.Has("page") {
		page = new(query.Get("page"))
	}
	var body any
	var next *string
	var err error
	switch {
	case path == "/shapes":
		if query.Get("imageId") == "" || query.Get("availabilityDomain") == "" || query.Get("compartmentId") != testCompartment {
			http.Error(w, "missing image compatibility scope", http.StatusBadRequest)
			return
		}
		body = f.shapeRows
		if f.shapeRows == nil {
			body = []core.Shape{capacityShape("VM.Standard.A1.Flex", "Ampere Altra"), capacityShape("VM.Standard.E4.Flex", "AMD EPYC")}
		}
	case path == "/instancePools":
		response, callErr := f.ListInstancePools(r.Context(), core.ListInstancePoolsRequest{CompartmentId: new(query.Get("compartmentId")), Page: page})
		body, next, err = response.Items, response.OpcNextPage, callErr
	case len(parts) == 2 && parts[0] == "instancePools":
		response, callErr := f.GetInstancePool(r.Context(), core.GetInstancePoolRequest{InstancePoolId: new(id)})
		body, err = response.InstancePool, callErr
	case len(parts) == 3 && parts[0] == "instancePools" && parts[2] == "instances":
		response, callErr := f.ListInstancePoolInstances(r.Context(), core.ListInstancePoolInstancesRequest{InstancePoolId: new(id), Page: page})
		body, next, err = response.Items, response.OpcNextPage, callErr
	case path == "/instanceConfigurations":
		response, callErr := f.ListInstanceConfigurations(r.Context(), core.ListInstanceConfigurationsRequest{CompartmentId: new(query.Get("compartmentId")), Page: page})
		body, next, err = response.Items, response.OpcNextPage, callErr
	case len(parts) == 2 && parts[0] == "instanceConfigurations":
		response, callErr := f.GetInstanceConfiguration(r.Context(), core.GetInstanceConfigurationRequest{InstanceConfigurationId: new(id)})
		body, err = response.InstanceConfiguration, callErr
	case len(parts) == 2 && parts[0] == "instances":
		response, callErr := f.GetInstance(r.Context(), core.GetInstanceRequest{InstanceId: new(id)})
		body, err = response.Instance, callErr
	case path == "/vnicAttachments":
		response, callErr := f.ListVnicAttachments(r.Context(), core.ListVnicAttachmentsRequest{InstanceId: new(query.Get("instanceId"))})
		body, err = response.Items, callErr
	case len(parts) == 2 && parts[0] == "vnics":
		response, callErr := f.GetVnic(r.Context(), core.GetVnicRequest{VnicId: new(id)})
		body, err = response.Vnic, callErr
	default:
		http.Error(w, "unexpected read: "+path, http.StatusBadRequest)
		return
	}
	if next != nil {
		w.Header().Set("opc-next-page", *next)
	}
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		body = map[string]string{"code": "NotAuthorizedOrNotFound", "message": err.Error()}
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
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("read-only discovery attempted OCI mutation: %s %s", r.Method, r.URL.Path)
			http.Error(w, "read-only fixture", http.StatusMethodNotAllowed)
			return
		}
		cloud.serveRead(w, r)
	}))
	t.Cleanup(srv.Close)
	policy := common.NoRetryPolicy()
	base := common.BaseClient{Host: srv.URL, BasePath: "20160918", UserAgent: "capacity-integration", HTTPClient: srv.Client(), Signer: capacitySigner{},
		Configuration: common.CustomClientConfiguration{RetryPolicy: &policy}}
	ociclient.ConfigureRequestCancellation(&base)
	pool, err := newOCIPool(core.ComputeManagementClient{BaseClient: base}, core.ComputeClient{BaseClient: base}, core.VirtualNetworkClient{BaseClient: base}, "gru", testCompartment, capacity)
	if err != nil {
		t.Fatal(err)
	}
	return pool
}

// seedCapacityPool populates provider facts only; it records no launch admission or receipt.
func seedCapacityPool(cloud *capacityCloud, recipe Recipe, size int) PoolState {
	configurationID, poolID := cloud.id("instanceconfiguration"), cloud.id("instancepool")
	cloud.configs[configurationID] = &core.InstanceConfiguration{Id: new(configurationID), CompartmentId: new(testCompartment),
		DisplayName: new(ConfigurationName(recipe)), InstanceDetails: core.ComputeInstanceDetails{LaunchDetails: launchDetails(recipe, testCompartment, "")},
		FreeformTags: poolTags(recipe.Cell, recipe.Capacity, roleNodeConfig)}
	placements := make([]core.InstancePoolPlacementConfiguration, 0, len(recipe.AvailabilityDomains))
	for _, ad := range recipe.AvailabilityDomains {
		placements = append(placements, core.InstancePoolPlacementConfiguration{AvailabilityDomain: new(ad),
			PrimaryVnicSubnets: &core.InstancePoolPlacementPrimarySubnet{SubnetId: new(recipe.SubnetID)}})
	}
	cloud.pools[poolID] = &core.InstancePool{Id: new(poolID), CompartmentId: new(testCompartment),
		DisplayName: new(PoolName(recipe.Cell, recipe.Capacity)), InstanceConfigurationId: new(configurationID), Size: new(size),
		LifecycleState: core.InstancePoolLifecycleStateRunning, FreeformTags: poolTags(recipe.Cell, recipe.Capacity, roleNodePool), PlacementConfigurations: placements}
	return PoolState{Exists: true, PoolID: poolID, ConfigurationID: configurationID, Size: size}
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

type capacityLeader struct{ snapshot authority.Snapshot }

func (f *capacityLeader) Current() authority.Snapshot         { return f.snapshot }
func (f *capacityLeader) Guard(context.Context, uint64) error { return nil }

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

func TestCapacityPoolProtocolObservation(t *testing.T) {
	ctx := t.Context()
	cloud := newCapacityCloud()
	recipe := capacityRecipe()
	seeded := seedCapacityPool(cloud, recipe, 3)
	for i := range 3 {
		cloud.launch(fmt.Sprintf("instance-%d", i), seeded.PoolID, fmt.Sprintf("10.0.0.%d", i+4), core.InstanceLifecycleStateRunning, map[string]string{"preserve": "tag"})
	}
	cloud.launch("terminated", seeded.PoolID, "10.0.0.99", core.InstanceLifecycleStateTerminated, nil)
	pool := protocolPool(t, cloud, recipe.Capacity)
	for range 2 {
		state, err := pool.Observe(ctx)
		if err != nil || state.Size != 3 || len(state.Instances) != 3 || state.PoolID != seeded.PoolID || state.ConfigurationID != seeded.ConfigurationID {
			t.Fatalf("paginated SDK observation lost actual capacity: %+v err=%v", state, err)
		}
		for _, instance := range state.Instances {
			if instance.PrivateIP == "" || instance.Birth != nil || cloud.instances[instance.ID].FreeformTags["preserve"] != "tag" {
				t.Fatalf("observation lost private IP/tags or invented original birth: %+v", instance)
			}
		}
	}
	if size, err := pool.TargetSize(ctx, recipe); err != nil || size != 3 {
		t.Fatalf("target=%d err=%v", size, err)
	}
	if len(cloud.pools) != 1 || len(cloud.configs) != 1 {
		t.Fatal("observation changed provider facts")
	}
}

func TestCapacityPoolProtocolIsolationAndValidation(t *testing.T) {
	ctx := t.Context()
	cloud := newCapacityCloud()
	base := capacityRecipe()
	for i, capacity := range []Capacity{base.Capacity, {Role: RoleWasm, Architecture: "arm64", Shape: base.Capacity.Shape}, {Role: RoleContainer, Architecture: "amd64", Shape: "VM.Standard.E4.Flex"}} {
		recipe := base
		recipe.Capacity = capacity
		seedCapacityPool(cloud, recipe, i+1)
		pool := protocolPool(t, cloud, capacity)
		if size, err := pool.TargetSize(ctx, recipe); err != nil || size != i+1 {
			t.Fatalf("isolation collision for %+v: size=%d err=%v", capacity, size, err)
		}
	}
	pool := protocolPool(t, cloud, base.Capacity)
	if state, err := pool.Observe(ctx); err != nil || state.Size != 6 || state.PoolID != "" {
		t.Fatalf("heterogeneous capacity was collapsed: %+v %v", state, err)
	}
	if err := pool.validateImage(ctx, base); err != nil {
		t.Fatalf("positive image validation: %v", err)
	}
	for name, mutate := range map[string]func(*Recipe){
		"image architecture mismatch": func(r *Recipe) { r.Capacity.Architecture = "amd64" },
		"unknown shape":               func(r *Recipe) { r.Capacity.Shape = "VM.Standard.Unknown.Flex" },
		"missing metadata":            func(r *Recipe) { r.Metadata = nil },
		"missing image":               func(r *Recipe) { r.ImageID = "" },
	} {
		t.Run(name, func(t *testing.T) {
			recipe := base
			mutate(&recipe)
			err := recipe.Validate()
			if err == nil {
				err = pool.validateImage(ctx, recipe)
			}
			if err == nil {
				t.Fatalf("%s accepted", name)
			}
		})
	}
	cloud.shapeRows = []core.Shape{}
	if err := pool.validateImage(ctx, base); err == nil {
		t.Fatal("empty image-compatible shape list accepted")
	}
	target, _, err := pool.pool(ctx)
	if err != nil {
		t.Fatal(err)
	}
	duplicate := *target
	duplicate.Id = new("ocid1.instancepool.oc1..duplicate")
	cloud.pools[*duplicate.Id] = &duplicate
	if _, err := pool.Observe(ctx); err == nil || !strings.Contains(err.Error(), "refusing to guess") {
		t.Fatalf("ambiguous ownership accepted: %v", err)
	}
}

func TestCapacityScalerRecoveryAndSafety(t *testing.T) {
	for _, scenario := range []string{"grow preparation and restart", "launch timeout", "database drain hold", "backend drain timeout", "drain and revoke refusal", "missing allowance", "stale loads", "request pressure", "missing host memory", "pending selector resume", "expired allowance resume", "follower"} {
		t.Run(scenario, func(t *testing.T) {
			ctx := t.Context()
			now := time.Now().UTC().Truncate(time.Second)
			cloud := newCapacityCloud()
			recipe := capacityEnrollmentRecipe(t)
			seeded := seedCapacityPool(cloud, recipe, 0)
			observed := protocolPool(t, cloud, recipe.Capacity)
			js := capacityJetStream(t)
			records, err := OpenStore(ctx, js, 1)
			if err != nil {
				t.Fatal(err)
			}
			selectors := capacitySelectors
			if scenario == "pending selector resume" {
				selectors = func(context.Context, Record) (rootoci.PoolChildExpectation, error) {
					return rootoci.PoolChildExpectation{}, ErrCapacityPending
				}
			}
			pool := chosenProtocolPool(t, observed, records, selectors)
			hosts := newSwarmHosts(t)
			hosts.live = map[string]bool{"ts-gru-1": true, "ts-gru-2": true, "ts-gru-3": true}
			hosts.sync(t)
			leader := &capacityLeader{snapshot: authority.Snapshot{DeploymentID: entityid.New(), Leader: true, Ready: true, Epoch: 7, Revision: 3, ExpiresAt: time.Now().Add(time.Hour)}}
			var entries []decisionlog.Decision
			revoked := 0
			scaler := &Scaler{Cell: "gru", Pool: pool, Store: records, Leader: leader, Control: hosts.control,
				CanRetire: func(context.Context, string, string) error { return ErrCapacityPending },
				Recipe:    func(context.Context) (Recipe, error) { return recipe, nil }, Now: func() time.Time { return now },
				Allowance: func(time.Time) (int, bool) {
					return MaxNodes, scenario != "missing allowance" && scenario != "expired allowance resume"
				},
				Loads: func() []NodeLoad {
					var loads []NodeLoad
					for node := range hosts.live {
						at := now
						if scenario == "stale loads" {
							at = at.Add(-3 * time.Minute)
						}
						cpu := .9
						if scenario == "request pressure" {
							cpu = .1
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
					return loads
				},
				Backends: func(context.Context, string, string) (int, error) { return 1, nil },
				Revoke:   func(context.Context, string) error { revoked++; return nil },
				Journal:  func(_ context.Context, d decisionlog.Decision) { entries = append(entries, d) },
			}
			if scenario == "launch timeout" || strings.Contains(scenario, "drain") {
				id := cloud.launch("ts-gru-4", seeded.PoolID, "10.0.0.4", core.InstanceLifecycleStateRunning, nil)
				cloud.pools[seeded.PoolID].Size = new(1)
				hosts.live["ts-gru-4"], hosts.instanceIDs["ts-gru-4"] = true, id
				if scenario == "database drain hold" {
					hosts.desired = []desiredTask{{Node: "ts-gru-4", Role: "terrabase"}}
				}
				hosts.sync(t)
				state, err := observed.Observe(ctx)
				if err != nil {
					t.Fatal(err)
				}
				nodes, err := hosts.control.ListNodes(ctx, &api.ListNodesRequest{})
				if err != nil {
					t.Fatal(err)
				}
				pass := &tick{epoch: 7, now: now.Add(LaunchTimeout + DrainTimeout), pool: state, hosts: nodes.Nodes, loads: []NodeLoad{{Node: "ts-gru-4", CPU: .1}}}
				pass.obs = scaler.observe(state, nodes.Nodes)
				if pass.obs.counted["ts-gru-4"] || pass.obs.live["ts-gru-4"] {
					t.Fatal("membership observation was treated as original birth")
				}
				if scenario == "launch timeout" {
					record := capacityBirthRecord(recipe)
					record.Action.Step = stepEnroll
					if _, err := records.Save(ctx, record, 0); err != nil {
						t.Fatal(err)
					}
					reopened, err := OpenStore(ctx, js, 1)
					if err != nil {
						t.Fatal(err)
					}
					pass.record, _, err = reopened.Load(ctx)
					if err != nil {
						t.Fatal(err)
					}
					if err := scaler.enroll(ctx, pass); err != nil {
						t.Fatal(err)
					}
					if pass.record.Action == nil || pass.record.Action.ID != record.Action.ID || pass.record.Action.Step != stepEnroll || pass.record.Retirement != nil ||
						!strings.Contains(pass.pool.Pending, "not been positively reobserved") {
						t.Fatalf("timeout adopted or retired unproven membership: %+v", pass)
					}
				} else if scenario == "backend drain timeout" {
					// An already-draining Swarm observation exercises rollback, without a root retirement receipt.
					pass.record = Record{Action: &InFlight{ID: entityid.New(), Kind: Down, Step: stepDrain, Node: "ts-gru-4", InstanceID: id, Started: now}}
					if _, err := records.Save(ctx, pass.record, 0); err != nil {
						t.Fatal(err)
					}
					pass.record, _, err = records.Load(ctx)
					if err != nil {
						t.Fatal(err)
					}
					if err := scaler.setAvailability(ctx, "ts-gru-4", id, api.NodeAvailabilityDrain, 7); err != nil {
						t.Fatal(err)
					}
					pass.now = now.Add(DrainTimeout - Interval)
					if err := scaler.drain(ctx, pass); err != nil {
						t.Fatal(err)
					}
					if pass.record.Action == nil || pass.record.Action.Step != stepDrain {
						t.Fatal("registered backend did not hold drain")
					}
					pass.now = now.Add(DrainTimeout)
					if err := scaler.drain(ctx, pass); err != nil {
						t.Fatal(err)
					}
					node, err := hosts.control.GetNode(ctx, &api.GetNodeRequest{NodeID: "ts-gru-4"})
					if err != nil || node.Node.Spec.Availability != api.NodeAvailabilityActive || pass.record.Action != nil || !pass.record.LastChange.Equal(pass.now) || pass.record.Retirement != nil {
						t.Fatalf("drain timeout did not restore active capacity and cooldown: record=%+v err=%v", pass.record, err)
					}
				} else {
					if scenario == "database drain hold" {
						protected, err := scaler.protectedNodes(ctx)
						if err != nil || !protected["ts-gru-4"] {
							t.Fatalf("actual database task lost retirement protection: %v", err)
						}
						if safe, err := scaler.retireSafe(ctx, "ts-gru-4", id); err != nil || safe {
							t.Fatalf("actual database holder admitted to drain: safe=%v err=%v", safe, err)
						}
					}
					if _, found, err := scaler.pickDrain(ctx, pass); err != nil || found {
						t.Fatalf("unproven worker entered retirement selection: found=%v err=%v", found, err)
					}
				}
				hosts.observe(t)
				if len(hosts.cordoned) != 0 || revoked != 0 || deref(cloud.instances[id].DisplayName) != "ts-gru-4" || deref(cloud.pools[seeded.PoolID].Size) != 1 ||
					slices.ContainsFunc(entries, func(d decisionlog.Decision) bool {
						return d.Kind == decisionlog.KindHostLaunched || d.Kind == decisionlog.KindHostReclaimed
					}) {
					t.Fatal("unproven observation produced lifecycle success or provider effects")
				}
				return
			}
			tickOnce := func() Record {
				t.Helper()
				if err := scaler.Tick(ctx); err != nil {
					t.Fatal(err)
				}
				record, _, err := scaler.Store.Load(ctx)
				if err != nil {
					t.Fatal(err)
				}
				return record
			}
			if scenario == "pending selector resume" || scenario == "expired allowance resume" {
				pending := capacityBirthRecord(recipe)
				if _, err := records.Save(ctx, pending, 0); err != nil {
					t.Fatal(err)
				}
				resumed := tickOnce()
				if resumed.Action == nil || resumed.Action.ID != pending.Action.ID || resumed.Action.Step != stepGrow || resumed.Child != nil || scaler.Status().Action != Hold {
					t.Fatalf("unsafe resume lost original pending action: %+v", resumed)
				}
				return
			}
			if scenario == "follower" {
				leader.snapshot.Leader = false
				tickOnce()
				_, revision, err := records.Load(ctx)
				if err != nil || revision != 0 {
					t.Fatalf("follower persisted capacity: revision=%d err=%v", revision, err)
				}
				return
			}
			for range int(UpWindow/Interval) + 1 {
				tickOnce()
				now = now.Add(Interval)
			}
			record := tickOnce()
			if scenario == "missing allowance" || scenario == "stale loads" || scenario == "missing host memory" {
				if record.Action != nil {
					t.Fatalf("unsafe growth planned with %s: %+v", scenario, record)
				}
				return
			}
			if record.Action == nil || record.Action.Step != stepGrow || record.Child != nil || record.Reservation != nil {
				t.Fatalf("pressure did not retain preparation before unavailable home authority: %+v", record)
			}
			originalID := record.Action.ID
			reopened, err := OpenStore(ctx, js, 1)
			if err != nil {
				t.Fatal(err)
			}
			scaler.Store, scaler.Pool = reopened, chosenProtocolPool(t, observed, reopened, selectors)
			retained := tickOnce()
			if retained.Action == nil || retained.Action.ID != originalID || retained.Action.Step != stepGrow || retained.Child != nil || retained.Reservation != nil {
				t.Fatalf("restart lost pending original preparation: %+v", retained)
			}
		})
	}
}

func TestCapacityAdmissionAndLegacyObservationOverOCI(t *testing.T) {
	ctx := t.Context()
	cloud := newCapacityCloud()
	recipe := capacityRecipe()
	legacyID := "ocid1.instancepool.oc1..legacy"
	cloud.pools[legacyID] = &core.InstancePool{Id: new(legacyID), CompartmentId: new(testCompartment), DisplayName: new("ts-gru-nodes"),
		InstanceConfigurationId: new("ocid1.instanceconfiguration.old"), Size: new(1), LifecycleState: core.InstancePoolLifecycleStateRunning,
		FreeformTags: map[string]string{tagCell: "gru", tagRole: roleNodePool}}
	instanceID := cloud.launch("ts-gru-4", legacyID, "10.0.0.4", core.InstanceLifecycleStateRunning, nil)
	pool := protocolPool(t, cloud, recipe.Capacity)
	observed, err := pool.Observe(ctx)
	if err != nil || observed.Size != 1 || len(observed.Instances) != 1 || observed.Instances[0].ID != instanceID || observed.Instances[0].Birth != nil || !strings.Contains(observed.Pending, "legacy pool") {
		t.Fatalf("legacy capacity disappeared or gained birth authority: %+v %v", observed, err)
	}
	other := recipe
	other.Capacity = Capacity{Role: RoleContainer, Architecture: "amd64", Shape: "VM.Standard.E4.Flex"}
	otherPool := seedCapacityPool(cloud, other, 1)
	cloud.launch("ts-gru-5", otherPool.PoolID, "10.0.0.5", core.InstanceLifecycleStateRunning, nil)
	observed, err = pool.Observe(ctx)
	if err != nil || observed.Size != 2 || len(observed.Instances) != 2 || observed.PoolID != "" || observed.Pending == "" {
		t.Fatalf("heterogeneous legacy observation collapsed capacity: %+v %v", observed, err)
	}
	if _, err := pool.TargetSize(ctx, recipe); err == nil || !strings.Contains(err.Error(), "legacy pool") {
		t.Fatalf("legacy pool admitted as a current target: %v", err)
	}
}

func TestCapacityDiscoveryDoesNotPruneTaggedConfigurations(t *testing.T) {
	cloud := newCapacityCloud()
	recipe := capacityRecipe()
	seedCapacityPool(cloud, recipe, 0)
	staleID := "ocid1.instanceconfiguration.oc1..stale"
	cloud.configs[staleID] = &core.InstanceConfiguration{Id: new(staleID), CompartmentId: new(testCompartment),
		DisplayName: new(configPrefix("gru", recipe.Capacity) + "stale"), FreeformTags: poolTags("gru", recipe.Capacity, roleNodeConfig)}
	pool := protocolPool(t, cloud, recipe.Capacity)
	for range 2 {
		if _, err := pool.Observe(t.Context()); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.TargetSize(t.Context(), recipe); err != nil {
			t.Fatal(err)
		}
	}
	if cloud.configs[staleID] == nil || len(cloud.configs) != 2 || len(cloud.pools) != 1 {
		t.Fatal("discovery used matching tags as pruning authority")
	}
}
