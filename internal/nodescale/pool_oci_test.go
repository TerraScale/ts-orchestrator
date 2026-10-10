package nodescale

import (
	"context"
	"errors"
	"maps"
	"math"
	"slices"
	"strconv"
	"testing"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/core"
)

const testCompartment = "ocid1.compartment.oc1..gru"

var (
	errNotFound     = errors.New("404 not found")
	errPrecondition = errors.New("412 precondition failed")
	errInUse        = errors.New("409 configuration is referenced by an instance pool")
)

// fakeCloud is an in-memory OCI behind the three interfaces. It enforces ETags, configurations in use,
// and two-item pages. It has no TerminateInstance, so the code under test cannot call one.
type fakeCloud struct {
	pools       map[string]*core.InstancePool
	configs     map[string]*core.InstanceConfiguration
	instances   map[string]*core.Instance
	members     map[string]string // instance id -> pool id
	attachments map[string][]core.VnicAttachment
	vnics       map[string]core.Vnic
	etags       map[string]string
	tokens      map[string]string // opc-retry-token -> the id it created
	detaches    []core.DetachInstancePoolInstanceDetails
	shrinks     int // UpdateInstancePool calls that lowered a pool's size
	nextID      int
}

func newFakeCloud() *fakeCloud {
	return &fakeCloud{pools: map[string]*core.InstancePool{}, configs: map[string]*core.InstanceConfiguration{},
		instances: map[string]*core.Instance{}, members: map[string]string{},
		attachments: map[string][]core.VnicAttachment{}, vnics: map[string]core.Vnic{},
		etags: map[string]string{}, tokens: map[string]string{}}
}

func (f *fakeCloud) id(kind string) string {
	f.nextID++
	return "ocid1." + kind + ".oc1..test" + strconv.Itoa(f.nextID)
}

// touch records a new ETag for id, as every OCI write does.
func (f *fakeCloud) touch(id string) {
	f.nextID++
	f.etags[id] = "etag-" + strconv.Itoa(f.nextID)
}

func (f *fakeCloud) fresh(id string, ifMatch *string) error {
	if ifMatch != nil && *ifMatch != f.etags[id] {
		return errPrecondition
	}
	return nil
}

// launch adds an instance with one primary VNIC at ip. A non-empty poolID makes it a member of that pool.
func (f *fakeCloud) launch(name, poolID, ip string, state core.InstanceLifecycleStateEnum, tags map[string]string) string {
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

func (f *fakeCloud) ListInstancePools(_ context.Context, request core.ListInstancePoolsRequest) (core.ListInstancePoolsResponse, error) {
	var items []core.InstancePoolSummary
	for _, pool := range sortedByID(f.pools) {
		if deref(pool.CompartmentId) == deref(request.CompartmentId) &&
			(request.DisplayName == nil || deref(pool.DisplayName) == *request.DisplayName) {
			items = append(items, core.InstancePoolSummary{Id: pool.Id, DisplayName: pool.DisplayName,
				FreeformTags: pool.FreeformTags, LifecycleState: core.InstancePoolSummaryLifecycleStateEnum(pool.LifecycleState)})
		}
	}
	page, next := pageOf(items, request.Page)
	return core.ListInstancePoolsResponse{Items: page, OpcNextPage: next}, nil
}

func (f *fakeCloud) GetInstancePool(_ context.Context, request core.GetInstancePoolRequest) (core.GetInstancePoolResponse, error) {
	id := deref(request.InstancePoolId)
	pool, ok := f.pools[id]
	if !ok {
		return core.GetInstancePoolResponse{}, errNotFound
	}
	return core.GetInstancePoolResponse{InstancePool: *pool, Etag: common.String(f.etags[id])}, nil
}

func (f *fakeCloud) CreateInstancePool(_ context.Context, request core.CreateInstancePoolRequest) (core.CreateInstancePoolResponse, error) {
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

func (f *fakeCloud) UpdateInstancePool(_ context.Context, request core.UpdateInstancePoolRequest) (core.UpdateInstancePoolResponse, error) {
	id := deref(request.InstancePoolId)
	pool, ok := f.pools[id]
	if !ok {
		return core.UpdateInstancePoolResponse{}, errNotFound
	}
	if err := f.fresh(id, request.IfMatch); err != nil {
		return core.UpdateInstancePoolResponse{}, err
	}
	details := request.UpdateInstancePoolDetails
	if details.InstanceConfigurationId != nil {
		pool.InstanceConfigurationId = details.InstanceConfigurationId
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

func (f *fakeCloud) ListInstancePoolInstances(_ context.Context, request core.ListInstancePoolInstancesRequest) (core.ListInstancePoolInstancesResponse, error) {
	var items []core.InstanceSummary
	for _, id := range slices.Sorted(maps.Keys(f.members)) {
		if f.members[id] == deref(request.InstancePoolId) {
			instance := f.instances[id]
			items = append(items, core.InstanceSummary{Id: instance.Id, DisplayName: instance.DisplayName,
				State: common.String(string(instance.LifecycleState))})
		}
	}
	page, next := pageOf(items, request.Page)
	return core.ListInstancePoolInstancesResponse{Items: page, OpcNextPage: next}, nil
}

// DetachInstancePoolInstance applies both flags the leader sends: the pool shrinks and the instance terminates.
func (f *fakeCloud) DetachInstancePoolInstance(_ context.Context, request core.DetachInstancePoolInstanceRequest) (core.DetachInstancePoolInstanceResponse, error) {
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

func (f *fakeCloud) ListInstanceConfigurations(_ context.Context, request core.ListInstanceConfigurationsRequest) (core.ListInstanceConfigurationsResponse, error) {
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

func (f *fakeCloud) CreateInstanceConfiguration(_ context.Context, request core.CreateInstanceConfigurationRequest) (core.CreateInstanceConfigurationResponse, error) {
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
func (f *fakeCloud) DeleteInstanceConfiguration(_ context.Context, request core.DeleteInstanceConfigurationRequest) (core.DeleteInstanceConfigurationResponse, error) {
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

func (f *fakeCloud) GetInstance(_ context.Context, request core.GetInstanceRequest) (core.GetInstanceResponse, error) {
	id := deref(request.InstanceId)
	instance, ok := f.instances[id]
	if !ok {
		return core.GetInstanceResponse{}, errNotFound
	}
	return core.GetInstanceResponse{Instance: *instance, Etag: common.String(f.etags[id])}, nil
}

func (f *fakeCloud) UpdateInstance(_ context.Context, request core.UpdateInstanceRequest) (core.UpdateInstanceResponse, error) {
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

func (f *fakeCloud) ListVnicAttachments(_ context.Context, request core.ListVnicAttachmentsRequest) (core.ListVnicAttachmentsResponse, error) {
	return core.ListVnicAttachmentsResponse{Items: f.attachments[deref(request.InstanceId)]}, nil
}

func (f *fakeCloud) GetVnic(_ context.Context, request core.GetVnicRequest) (core.GetVnicResponse, error) {
	vnic, ok := f.vnics[deref(request.VnicId)]
	if !ok {
		return core.GetVnicResponse{}, errNotFound
	}
	return core.GetVnicResponse{Vnic: vnic}, nil
}

func newTestPool(t *testing.T, f *fakeCloud) *OCIPool {
	t.Helper()
	pool, err := newOCIPool(f, f, f, "gru", testCompartment)
	if err != nil {
		t.Fatal(err)
	}
	return pool
}

func testRecipe() Recipe {
	return Recipe{Cell: "gru", CompartmentID: testCompartment, SubnetID: "ocid1.subnet.test",
		NSGIDs: []string{"ocid1.nsg.a", "ocid1.nsg.b"}, AvailabilityDomains: []string{"AD-1", "AD-2"},
		ImageID: "ocid1.image.v1", OCPUs: 2, MemoryGB: 12,
		Metadata: map[string]string{"ts_host": "descriptor", "ssh_authorized_keys": "ssh-ed25519 AAAA"}}
}

// onlyPool and onlyConfig return the single pool or configuration, failing the test when there is not exactly one.
func onlyPool(t *testing.T, f *fakeCloud) *core.InstancePool {
	t.Helper()
	pools := sortedByID(f.pools)
	if len(pools) != 1 {
		t.Fatalf("%d pools, want 1", len(pools))
	}
	return pools[0]
}

func onlyConfig(t *testing.T, f *fakeCloud) *core.InstanceConfiguration {
	t.Helper()
	configs := sortedByID(f.configs)
	if len(configs) != 1 {
		t.Fatalf("%d configurations, want 1", len(configs))
	}
	return configs[0]
}

func TestRecipeValidate(t *testing.T) {
	if err := testRecipe().Validate(); err != nil {
		t.Fatalf("valid recipe refused: %v", err)
	}
	cases := map[string]func(*Recipe){
		"upper-case cell": func(r *Recipe) { r.Cell = "GRU" },
		"no image":        func(r *Recipe) { r.ImageID = "" },
		"zero OCPUs":      func(r *Recipe) { r.OCPUs = 0 },
		"NaN memory":      func(r *Recipe) { r.MemoryGB = float32(math.NaN()) },
		"no AD":           func(r *Recipe) { r.AvailabilityDomains = nil },
		"empty NSG":       func(r *Recipe) { r.NSGIDs = []string{""} },
		"no metadata":     func(r *Recipe) { r.Metadata = nil },
	}
	for name, mutate := range cases {
		recipe := testRecipe()
		mutate(&recipe)
		if err := recipe.Validate(); err == nil {
			t.Errorf("%s: recipe accepted", name)
		}
	}
}

func TestRecipeDigest(t *testing.T) {
	base := testRecipe()
	if got := base.Digest(); len(got) != 12 || got != base.Digest() {
		t.Fatalf("digest %q is not stable 12 hex characters", got)
	}
	reordered := testRecipe()
	reordered.NSGIDs = []string{"ocid1.nsg.b", "ocid1.nsg.a"}
	if reordered.Digest() != base.Digest() {
		t.Error("NSG order changed the digest")
	}
	newImage := testRecipe()
	newImage.ImageID = "ocid1.image.v2"
	if newImage.Digest() == base.Digest() {
		t.Error("a new image kept the digest")
	}
	newMetadata := testRecipe()
	newMetadata.Metadata["ssh_authorized_keys"] = "ssh-ed25519 BBBB"
	if newMetadata.Digest() == base.Digest() {
		t.Error("new metadata kept the digest")
	}
	if got, want := ConfigurationName(base), "ts-gru-node-"+base.Digest(); got != want {
		t.Errorf("configuration name %q, want %q", got, want)
	}
	if got := PoolName("gru"); got != "ts-gru-nodes" {
		t.Errorf("pool name %q", got)
	}
}

func TestEnsureCreatesConfigurationAndPool(t *testing.T) {
	f := newFakeCloud()
	pool := newTestPool(t, f)
	recipe := testRecipe()
	state, err := pool.Ensure(context.Background(), recipe)
	if err != nil {
		t.Fatal(err)
	}
	config := onlyConfig(t, f)
	if got := deref(config.DisplayName); got != ConfigurationName(recipe) {
		t.Errorf("configuration named %q", got)
	}
	if config.FreeformTags[tagCell] != "gru" || config.FreeformTags[tagRole] != roleNodeConfig {
		t.Errorf("configuration tags %v", config.FreeformTags)
	}
	launch := config.InstanceDetails.(core.ComputeInstanceDetails).LaunchDetails
	source := launch.SourceDetails.(core.InstanceConfigurationInstanceSourceViaImageDetails)
	if deref(launch.Shape) != NodeShape || deref(launch.ShapeConfig.Ocpus) != 2 || deref(launch.ShapeConfig.MemoryInGBs) != 12 {
		t.Errorf("launch shape %s %v", deref(launch.Shape), launch.ShapeConfig)
	}
	if deref(source.ImageId) != recipe.ImageID || deref(source.BootVolumeSizeInGBs) != BootVolumeGB {
		t.Errorf("launch source %v", source)
	}
	if !slices.Equal(launch.CreateVnicDetails.NsgIds, recipe.NSGIDs) || deref(launch.CreateVnicDetails.AssignPublicIp) {
		t.Errorf("launch VNIC %v", launch.CreateVnicDetails)
	}
	if !maps.Equal(launch.Metadata, recipe.Metadata) || launch.FreeformTags[tagCell] != "gru" || launch.FreeformTags[tagRole] != roleNode {
		t.Errorf("launch metadata %v tags %v", launch.Metadata, launch.FreeformTags)
	}

	created := onlyPool(t, f)
	if deref(created.InstanceConfigurationId) != deref(config.Id) || deref(created.Size) != 0 {
		t.Errorf("pool configuration %s size %d", deref(created.InstanceConfigurationId), deref(created.Size))
	}
	if len(created.PlacementConfigurations) != 2 {
		t.Fatalf("%d placements, want one per AD", len(created.PlacementConfigurations))
	}
	for i, placement := range created.PlacementConfigurations {
		if deref(placement.AvailabilityDomain) != recipe.AvailabilityDomains[i] ||
			deref(placement.PrimaryVnicSubnets.SubnetId) != recipe.SubnetID {
			t.Errorf("placement %d: AD %s subnet %s", i, deref(placement.AvailabilityDomain), deref(placement.PrimaryVnicSubnets.SubnetId))
		}
	}
	if created.FreeformTags[tagCell] != "gru" || created.FreeformTags[tagRole] != roleNodePool {
		t.Errorf("pool tags %v", created.FreeformTags)
	}
	if !state.Exists || state.PoolID != deref(created.Id) || state.Size != 0 || len(state.Instances) != 0 {
		t.Errorf("state %+v", state)
	}
}

func TestEnsureIsIdempotent(t *testing.T) {
	f := newFakeCloud()
	pool := newTestPool(t, f)
	first, err := pool.Ensure(context.Background(), testRecipe())
	if err != nil {
		t.Fatal(err)
	}
	second, err := pool.Ensure(context.Background(), testRecipe())
	if err != nil {
		t.Fatal(err)
	}
	if len(f.pools) != 1 || len(f.configs) != 1 {
		t.Fatalf("%d pools and %d configurations after a second ensure, want 1 and 1", len(f.pools), len(f.configs))
	}
	if first.PoolID != second.PoolID || first.ConfigurationID != second.ConfigurationID {
		t.Errorf("second ensure changed the pool: %+v then %+v", first, second)
	}
}

func TestEnsureSwitchesRecipeAndDeletesOldConfiguration(t *testing.T) {
	f := newFakeCloud()
	pool := newTestPool(t, f)
	ctx := context.Background()
	if _, err := pool.Ensure(ctx, testRecipe()); err != nil {
		t.Fatal(err)
	}
	if err := pool.Grow(ctx, 0); err != nil {
		t.Fatal(err)
	}
	poolID := deref(onlyPool(t, f).Id)
	node := f.launch("ts-gru-4", poolID, "10.0.0.14", core.InstanceLifecycleStateRunning, nil)

	next := testRecipe()
	next.ImageID = "ocid1.image.v2"
	state, err := pool.Ensure(ctx, next)
	if err != nil {
		t.Fatal(err)
	}
	config := onlyConfig(t, f)
	if deref(config.DisplayName) != ConfigurationName(next) {
		t.Errorf("remaining configuration %q, want the new recipe's", deref(config.DisplayName))
	}
	pooled := onlyPool(t, f)
	if deref(pooled.InstanceConfigurationId) != deref(config.Id) {
		t.Error("pool still points at the old configuration")
	}
	if deref(pooled.Size) != 1 || f.shrinks != 0 {
		t.Errorf("size %d after switch, shrinks %d: the switch must not change size", deref(pooled.Size), f.shrinks)
	}
	if f.instances[node].LifecycleState != core.InstanceLifecycleStateRunning {
		t.Errorf("running node is %s after the switch", f.instances[node].LifecycleState)
	}
	if state.ConfigurationID != deref(config.Id) || len(state.Instances) != 1 {
		t.Errorf("state %+v", state)
	}
}

func TestEnsureNeverDeletesAnotherCellsConfiguration(t *testing.T) {
	f := newFakeCloud()
	ctx := context.Background()
	bog, err := newOCIPool(f, f, f, "bog", testCompartment)
	if err != nil {
		t.Fatal(err)
	}
	bogRecipe := testRecipe()
	bogRecipe.Cell = "bog"
	if _, err := bog.Ensure(ctx, bogRecipe); err != nil {
		t.Fatal(err)
	}
	bogID := deref(onlyConfigOf(f, "bog").Id)

	// Same name prefix as gru's configurations, but another cell owns it.
	foreignID := f.id("instanceconfiguration")
	f.configs[foreignID] = &core.InstanceConfiguration{Id: common.String(foreignID), CompartmentId: common.String(testCompartment),
		DisplayName: common.String("ts-gru-node-0123456789ab"), FreeformTags: map[string]string{tagCell: "bog"}}

	gru := newTestPool(t, f)
	if _, err := gru.Ensure(ctx, testRecipe()); err != nil {
		t.Fatal(err)
	}
	next := testRecipe()
	next.ImageID = "ocid1.image.v2"
	if _, err := gru.Ensure(ctx, next); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.configs[bogID]; !ok {
		t.Error("another cell's configuration was deleted")
	}
	if _, ok := f.configs[foreignID]; !ok {
		t.Error("a configuration owned by another cell's tags was deleted")
	}
	if len(f.configs) != 3 {
		t.Errorf("%d configurations, want bog, the foreign one and gru's new one", len(f.configs))
	}
}

// onlyConfigOf returns the one configuration tagged for cell.
func onlyConfigOf(f *fakeCloud, cell string) *core.InstanceConfiguration {
	for _, config := range f.configs {
		if config.FreeformTags[tagCell] == cell {
			return config
		}
	}
	return nil
}

func TestObserveListsInstancesWithPrivateIPs(t *testing.T) {
	f := newFakeCloud()
	pool := newTestPool(t, f)
	ctx := context.Background()
	if _, err := pool.Ensure(ctx, testRecipe()); err != nil {
		t.Fatal(err)
	}
	if err := pool.Grow(ctx, 0); err != nil {
		t.Fatal(err)
	}
	if err := pool.Grow(ctx, 1); err != nil {
		t.Fatal(err)
	}
	poolID := deref(onlyPool(t, f).Id)
	second := f.launch("ts-gru-4", poolID, "10.0.0.14", core.InstanceLifecycleStateRunning, nil)
	first := f.launch("inst-b", poolID, "10.0.0.12", core.InstanceLifecycleStateRunning, nil)
	f.launch("ts-gru-5", poolID, "10.0.0.15", core.InstanceLifecycleStateTerminated, nil)

	state, err := pool.Observe(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !state.Exists || state.PoolID != poolID || state.Size != 2 {
		t.Errorf("state %+v", state)
	}
	if len(state.Instances) != 2 {
		t.Fatalf("%d instances, want the 2 live ones: %+v", len(state.Instances), state.Instances)
	}
	if got := state.Instances[0]; got.ID != first || got.Name != "inst-b" || got.PrivateIP != "10.0.0.12" {
		t.Errorf("first instance %+v", got)
	}
	if got := state.Instances[1]; got.ID != second || got.Name != "ts-gru-4" || got.PrivateIP != "10.0.0.14" {
		t.Errorf("second instance %+v", got)
	}
}

func TestObserveWithoutPoolReportsNothing(t *testing.T) {
	state, err := newTestPool(t, newFakeCloud()).Observe(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if state.Exists {
		t.Errorf("state %+v reports a pool that does not exist", state)
	}
}

func TestGrowRaisesSizeOneAtATime(t *testing.T) {
	f := newFakeCloud()
	pool := newTestPool(t, f)
	ctx := context.Background()
	if _, err := pool.Ensure(ctx, testRecipe()); err != nil {
		t.Fatal(err)
	}
	poolRec := onlyPool(t, f)
	if err := pool.Grow(ctx, 0); err != nil {
		t.Fatal(err)
	}
	if err := pool.Grow(ctx, 0); err != nil {
		t.Errorf("replayed grow: %v", err)
	}
	if deref(poolRec.Size) != 1 {
		t.Errorf("size %d after a replayed grow, want 1", deref(poolRec.Size))
	}
	if err := pool.Grow(ctx, 1); err != nil {
		t.Fatal(err)
	}
	if err := pool.Grow(ctx, 0); !errors.Is(err, ErrPoolChanged) {
		t.Errorf("grow from a stale size: %v, want ErrPoolChanged", err)
	}
	for from := 2; from < MaxPoolNodes; from++ {
		if err := pool.Grow(ctx, from); err != nil {
			t.Fatal(err)
		}
	}
	if err := pool.Grow(ctx, MaxPoolNodes); err == nil {
		t.Error("grew past MaxPoolNodes")
	}
	if deref(poolRec.Size) != MaxPoolNodes || f.shrinks != 0 {
		t.Errorf("size %d, shrinks %d after growing to the maximum", deref(poolRec.Size), f.shrinks)
	}
}

func TestNameRenamesOnlyPoolInstances(t *testing.T) {
	f := newFakeCloud()
	pool := newTestPool(t, f)
	ctx := context.Background()
	if _, err := pool.Ensure(ctx, testRecipe()); err != nil {
		t.Fatal(err)
	}
	poolID := deref(onlyPool(t, f).Id)
	tags := map[string]string{tagCell: "gru", tagRole: roleNode}
	member := f.launch("inst-x", poolID, "10.0.0.20", core.InstanceLifecycleStateRunning, tags)
	controller := f.launch("ts-gru-1", "", "10.0.0.11", core.InstanceLifecycleStateRunning, map[string]string{tagCell: "gru", tagRole: "controller"})

	if err := pool.Name(ctx, member, "ts-gru-4"); err != nil {
		t.Fatal(err)
	}
	renamed := f.instances[member]
	if deref(renamed.DisplayName) != "ts-gru-4" || renamed.FreeformTags[tagNode] != "ts-gru-4" ||
		renamed.FreeformTags[tagCell] != "gru" || renamed.FreeformTags[tagRole] != roleNode {
		t.Errorf("renamed instance %s with tags %v", deref(renamed.DisplayName), renamed.FreeformTags)
	}

	if err := pool.Name(ctx, controller, "ts-gru-9"); !errors.Is(err, ErrNotPoolInstance) {
		t.Errorf("naming a controller: %v, want ErrNotPoolInstance", err)
	}
	if got := deref(f.instances[controller].DisplayName); got != "ts-gru-1" {
		t.Errorf("controller renamed to %s", got)
	}

	etag := f.etags[member]
	if err := pool.Name(ctx, member, "ts-gru-4"); err != nil {
		t.Errorf("naming an instance twice: %v", err)
	}
	if f.etags[member] != etag {
		t.Error("an already named instance was written again")
	}
}

func TestRemoveDetachesWithDecrementAndTermination(t *testing.T) {
	f := newFakeCloud()
	pool := newTestPool(t, f)
	ctx := context.Background()
	if _, err := pool.Ensure(ctx, testRecipe()); err != nil {
		t.Fatal(err)
	}
	if err := pool.Grow(ctx, 0); err != nil {
		t.Fatal(err)
	}
	poolRec := onlyPool(t, f)
	member := f.launch("ts-gru-4", deref(poolRec.Id), "10.0.0.14", core.InstanceLifecycleStateRunning, nil)
	controller := f.launch("ts-gru-1", "", "10.0.0.11", core.InstanceLifecycleStateRunning, nil)
	gone := f.launch("ts-gru-6", "", "10.0.0.16", core.InstanceLifecycleStateTerminated, nil)

	if err := pool.Remove(ctx, member); err != nil {
		t.Fatal(err)
	}
	if len(f.detaches) != 1 {
		t.Fatalf("%d detaches, want 1", len(f.detaches))
	}
	detach := f.detaches[0]
	if deref(detach.InstanceId) != member || !deref(detach.IsDecrementSize) || !deref(detach.IsAutoTerminate) {
		t.Errorf("detach %+v, want decrement and terminate", detach)
	}
	if deref(poolRec.Size) != 0 || f.instances[member].LifecycleState != core.InstanceLifecycleStateTerminating {
		t.Errorf("size %d, instance %s after detach", deref(poolRec.Size), f.instances[member].LifecycleState)
	}

	if err := pool.Remove(ctx, member); err != nil {
		t.Errorf("removing a terminating instance: %v", err)
	}
	if err := pool.Remove(ctx, gone); err != nil {
		t.Errorf("removing a terminated instance: %v", err)
	}
	if len(f.detaches) != 1 {
		t.Errorf("%d detaches after the repeats, want 1", len(f.detaches))
	}
	if err := pool.Remove(ctx, controller); !errors.Is(err, ErrNotPoolInstance) {
		t.Errorf("removing a controller: %v, want ErrNotPoolInstance", err)
	}
	if f.instances[controller].LifecycleState != core.InstanceLifecycleStateRunning {
		t.Errorf("controller is %s", f.instances[controller].LifecycleState)
	}
	if f.shrinks != 0 {
		t.Errorf("%d size-decreasing updates; scale-down must detach, not shrink", f.shrinks)
	}
}

func TestAmbiguousPoolRefusesToGuess(t *testing.T) {
	f := newFakeCloud()
	pool := newTestPool(t, f)
	ctx := context.Background()
	ours := map[string]string{tagCell: "gru", tagRole: roleNodePool}
	pools := map[string]map[string]string{"a": ours, "b": ours, "c": {tagCell: "bog", tagRole: roleNodePool}}
	for id, tags := range pools {
		f.pools[id] = &core.InstancePool{Id: common.String(id), CompartmentId: common.String(testCompartment),
			DisplayName: common.String(PoolName("gru")), FreeformTags: tags, LifecycleState: core.InstancePoolLifecycleStateRunning,
			Size: common.Int(0)}
	}
	f.pools["d"] = &core.InstancePool{Id: common.String("d"), CompartmentId: common.String(testCompartment),
		DisplayName: common.String(PoolName("gru")), FreeformTags: ours, LifecycleState: core.InstancePoolLifecycleStateTerminated}

	if _, err := pool.Observe(ctx); err == nil {
		t.Error("observed two owned pools without an error")
	}
	if _, err := pool.Ensure(ctx, testRecipe()); err == nil {
		t.Error("ensured with two owned pools")
	}
	if len(f.pools) != 4 {
		t.Errorf("%d pools after an ambiguous ensure, want the 4 that were there", len(f.pools))
	}

	delete(f.pools, "b")
	state, err := pool.Observe(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if state.PoolID != "a" {
		t.Errorf("pool %q, want the one owned pool: other cells' and terminated pools do not count", state.PoolID)
	}
}
