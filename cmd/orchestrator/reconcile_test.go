package main

import (
	"bytes"
	"context"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"terrascale.tech/orchestrator/src/orchestrator/authorityjournal"
	"terrascale.tech/orchestrator/src/orchestrator/autoscale"
	"terrascale.tech/orchestrator/src/orchestrator/provider"
	"testing"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/cloudflare"
	"terrascale.tech/orchestrator/src/orchestrator/estate"
	"terrascale.tech/orchestrator/src/orchestrator/ocireconcile"
	"terrascale.tech/orchestrator/src/orchestrator/reconcile"
)

func TestReconcileDryRunPrintsThePlan(t *testing.T) {
	output := &bytes.Buffer{}
	if err := execute(context.Background(), []string{"reconcile", dryRunFlag}, func(string) (string, bool) { return "", false }, output); err != nil {
		t.Fatalf("reconcile --dry-run failed: %v", err)
	}
	plan := output.String()
	for _, want := range []string{
		`"estateVersion": 2`,
		`"kind": "create"`,
		`"kind": "bucket"`,
		`"kind": "dns-record"`,
		`"kind": "waf-rule"`,
	} {
		if !strings.Contains(plan, want) {
			t.Fatalf("dry-run plan is missing %s:\n%s", want, plan)
		}
	}
	// The plan is the whole declared estate observed empty: every declared
	// resource appears as a create. The floor stays loose so the estate can
	// grow (add-region, I-5) without breaking this hook.
	creates := strings.Count(plan, `"kind": "create"`)
	if creates < 30 {
		t.Fatalf("dry-run plan has %d creates, want the whole declared estate", creates)
	}
}

func TestReconcileLoopRequiresProviders(t *testing.T) {
	if err := runReconcile(context.Background(), []string{"reconcile"}, &bytes.Buffer{}); err == nil {
		t.Fatal("the running loop without production configuration must be refused")
	}
}

func TestProductionReconcileWiresNonEmptyProviders(t *testing.T) {
	spec := estate.Default()
	oci := &ociReconcileController{}
	cloud := &cloudflareReconcileController{}
	loop, err := reconcile.NewLoop(reconcile.LoopConfig{
		Spec:         spec,
		Providers:    []reconcile.Reconciler{oci, cloud},
		Interval:     time.Minute,
		AllowDeletes: true,
	})
	if err != nil {
		t.Fatalf("production provider wiring rejected: %v", err)
	}
	if loop == nil {
		t.Fatal("production provider wiring returned a nil loop")
	}
	if len(oci.Kinds()) == 0 || len(cloud.Kinds()) == 0 {
		t.Fatal("production provider wiring contains an empty resource owner")
	}
}

func TestProductionReconcileRequiresDurableProgress(t *testing.T) {
	dependencies := &productionReconcileDependencies{
		Spec:       estate.Default(),
		OCI:        &ociReconcileController{},
		Cloudflare: &cloudflareReconcileController{},
		KVWriter:   &cloudflare.KVWriter{},
		Telemetry:  &reconcileTelemetry{},
	}
	if _, err := newReconcileLoop(dependencies, &bytes.Buffer{}); err == nil {
		t.Fatal("production reconcile accepted without durable progress")
	}
	progress, err := reconcile.NewFileProgressStore(filepath.Join(t.TempDir(), "progress.json"))
	if err != nil {
		t.Fatalf("build durable progress: %v", err)
	}
	dependencies.Progress = progress
	if _, err := newReconcileLoop(dependencies, &bytes.Buffer{}); err != nil {
		t.Fatalf("production reconcile rejected configured progress: %v", err)
	}
}

func TestOCIReconcileAppliesAutoscalePlanToComputeDeclaration(t *testing.T) {
	region := estate.Default().Regions[0]
	controller := &ociReconcileController{regions: map[string]*ociRegionController{
		region.Code: {region: region},
	}}
	if err := controller.applyAutoscalePlan(region.Code, int(region.Members.Count)+1); err != nil {
		t.Fatal(err)
	}
	if got := controller.regions[region.Code].computeDeclared().Region.Members.Count; got != region.Members.Count+1 {
		t.Fatalf("autoscale target members = %d, want %d", got, region.Members.Count+1)
	}
}

func TestOCIReconcileDesiredSpecHoldsWhenDurableTargetProjectionFails(t *testing.T) {
	spec := estate.Default()
	regions := make(map[string]*ociRegionController, len(spec.Regions))
	for _, region := range spec.Regions {
		regions[region.Code] = &ociRegionController{region: region}
	}
	controller := &ociReconcileController{spec: spec, regions: regions}
	_, err := controller.desiredSpec(t.Context())
	if err == nil || !strings.Contains(err.Error(), "durable autoscale target projection is unavailable") {
		t.Fatalf("desired spec projection error = %v, want durable target failure", err)
	}
}

func TestProductionReconcileRefusesMissingConfiguration(t *testing.T) {
	lookup := func(string) (string, bool) { return "", false }
	if _, err := newProductionReconcileDependencies(lookup); err == nil {
		t.Fatal("missing production configuration was accepted")
	} else if !strings.Contains(err.Error(), "provider selection") {
		t.Fatalf("unexpected configuration error: %v", err)
	}
}

func TestReconcileProductionRuntimeOptionsUseDeploymentIdentity(t *testing.T) {
	lookup := func(name string) (string, bool) {
		values := map[string]string{
			"TS_ORCH_CELL":                    "gru",
			"TS_ORCH_INSTANCE":                "gru-1",
			"TS_ORCH_PRODUCTION_RUNTIME_FILE": "/etc/terrascale/runtime.json",
		}
		value, ok := values[name]
		return value, ok
	}
	options, err := reconcileProductionRuntimeOptions(lookup)
	if err != nil {
		t.Fatalf("reconcile runtime options rejected configured deployment identity: %v", err)
	}
	if options == nil || options.Cell != "gru" || options.Instance != "gru-1" || options.ProductionRuntimeFile != "/etc/terrascale/runtime.json" {
		t.Fatalf("reconcile runtime options = %+v", options)
	}
}

func TestOCICompositionCoversAllDeclaredRegionsAndObservedState(t *testing.T) {
	spec := estate.Default()
	regions := make(map[string]*ociRegionController, len(spec.Regions))
	for _, region := range spec.Regions {
		regions[region.Code] = &ociRegionController{region: region}
	}
	controller := &ociReconcileController{regions: regions}
	if got := sortedOCIRegionCodes(controller.regions); len(got) != 3 || got[0] != "fra" || got[1] != "gru" || got[2] != "sfo" {
		t.Fatalf("OCI composition regions = %v, want fra, gru, sfo", got)
	}
	region := spec.Regions[0]
	state := ociObservedState(region, &ociRegionObservation{
		compute: ocireconcile.ComputeObserved{Members: []ocireconcile.ObservedMember{{ID: "ocid1.instance.oc1.x", LifecycleState: "RUNNING", Shape: region.Members.PrimaryShape}}},
		network: ocireconcile.NetworkObserved{VCN: &ocireconcile.ObservedVCN{ID: "ocid1.vcn.oc1.x", CIDR: region.Network.CIDR}},
	})
	if len(state.Resources) < 2 {
		t.Fatalf("OCI observed state has %d resources, want at least compute and network", len(state.Resources))
	}
}

func TestOCIObservedStateIgnoresUnknownLifecycle(t *testing.T) {
	region := estate.Default().Regions[0]
	state := ociObservedState(region, &ociRegionObservation{compute: ocireconcile.ComputeObserved{
		Members: []ocireconcile.ObservedMember{{ID: "ocid1.instance.oc1.x", LifecycleState: "MYSTERY", Shape: region.Members.PrimaryShape}},
	}})
	for _, resource := range state.Resources {
		if resource.Ref.Kind == estate.ResourceCompute {
			t.Fatal("unknown OCI lifecycle was reported as a live compute resource")
		}
	}
}

func TestOCIProductionCallerCarriesConfiguredFallbackImage(t *testing.T) {
	r := &ociRegionController{region: estate.Default().Regions[0], imageID: "ocid1.image.oc1.arm64", fallbackImageID: "ocid1.image.oc1.amd64"}
	declared := r.computeDeclared()
	if declared.ImageID != r.imageID || declared.FallbackImageID != r.fallbackImageID {
		t.Fatalf("production compute declaration = %+v", declared)
	}
}

type unknownOCIAction struct{}

func (unknownOCIAction) Kind() ocireconcile.OCIActionKind { return "unexpected-provider-action" }
func (unknownOCIAction) Summary() string                  { return "unexpected" }

func TestFilterOCIPlanFailsClosedAtGenericOwnershipBoundary(t *testing.T) {
	plan := ocireconcile.OCIPlan{Actions: []ocireconcile.OCIAction{
		unknownOCIAction{},
		ocireconcile.CreateVCNAction{Name: "vcn", CIDR: "10.0.0.0/16"},
	}}
	withoutOwner := filterOCIPlan(plan, reconcile.Plan{}, "gru")
	if len(withoutOwner.Actions) != 0 {
		t.Fatalf("provider actions escaped the generic ownership plan: %v", withoutOwner.Kinds())
	}
	owned := reconcile.Plan{Actions: []reconcile.Action{{
		Kind: reconcile.ActionCreate,
		Ref:  estate.ResourceRef{Kind: estate.ResourceNetwork, Region: "gru", Name: "vcn"},
	}}}
	filtered := filterOCIPlan(plan, owned, "gru")
	if len(filtered.Actions) != 1 || filtered.Actions[0].Kind() != ocireconcile.OCIActionCreateVCN {
		t.Fatalf("owned provider action was not retained: %v", filtered.Kinds())
	}
}

type reconcileKVStoreFake struct{ health int }

func (s *reconcileKVStoreFake) SetWorkerHealth(context.Context, cloudflare.WorkerHealthDoc) error {
	s.health++
	return nil
}
func (s *reconcileKVStoreFake) SetWorkerPlacements(context.Context, map[string]cloudflare.WorkerPlacement) error {
	return nil
}
func (s *reconcileKVStoreFake) DeleteWorkerPlacements(context.Context, []string) error { return nil }

func TestProductionKVWriterStartsAndShutsDown(t *testing.T) {
	store := &reconcileKVStoreFake{}
	writer, err := cloudflare.NewKVWriter(cloudflare.KVWriterConfig{
		Store: store, Health: testObservedHealth{}, Placement: declaredKVPlacementSource{}, Catalog: cloudflare.PublicRegionCatalog(), HealthInterval: time.Hour,
	})
	if err != nil {
		t.Fatalf("KV writer construction failed: %v", err)
	}
	if _, err := writer.Step(context.Background()); err != nil {
		t.Fatalf("KV writer initial tick failed: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	if err := writer.Start(ctx); err != nil {
		t.Fatalf("KV writer start failed: %v", err)
	}
	cancel()
	if err := writer.Close(); err != nil {
		t.Fatalf("KV writer close failed: %v", err)
	}
	if store.health == 0 {
		t.Fatal("KV writer performed no health writes")
	}
}

func TestRequestedCommandAcceptsOnlyTheDryRunFlag(t *testing.T) {
	for _, args := range [][]string{{"reconcile"}, {"reconcile", dryRunFlag}} {
		if got, err := requestedCommand(args); err != nil || got != "reconcile" {
			t.Errorf("requestedCommand(%q) = %q, %v", args, got, err)
		}
	}
	for _, args := range [][]string{
		{"reconcile", "junk"},
		{"reconcile", dryRunFlag, "extra"},
		{"reconcile", "--dry-run", "--dry-run"},
	} {
		if got, err := requestedCommand(args); err == nil || got != "unsupported" {
			t.Errorf("requestedCommand(%q) = %q, %v; want rejection", args, got, err)
		}
	}
}

type testObservedHealth struct{}

func (testObservedHealth) ObserveRegionHealth(context.Context) (map[string]cloudflare.RegionHealth, error) {
	return map[string]cloudflare.RegionHealth{"gru": {Healthy: true}}, nil
}

type declaredKVPlacementSource struct{}

func (declaredKVPlacementSource) ObserveDBPlacement(ctx context.Context) (map[string]cloudflare.DBPlacement, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return map[string]cloudflare.DBPlacement{}, nil
}

// Exercise the real Loop.Pass -> desired declaration -> Diff -> OCI Apply ->
// filterOCIPlan -> ComputeReconciler.Apply call chain. OCI observations and
// launch are isolated at the gateway boundary; the target uses the real R3
// authority journal. Enrollment's cloud-init projection is supplied explicitly.
func TestAutoscaleDurableTargetReachesFirstLoopPassAndConverges(t *testing.T) {
	ctx := t.Context()
	cluster := newRotationStateCluster(t)
	connection := cluster.connect(t)
	leases := openRotationTestLeaseStore(t, ctx, connection, true)
	lease := rotationTestLease(1, "global-controller-gru-autoscale")
	putRotationTestLease(t, ctx, leases, lease)
	journalConfig := authorityjournal.Config{Connection: connection, CandidateID: lease.CandidateId, AuthorityEpoch: uint64(lease.Epoch), LeaseID: lease.LeaseId, StateKey: "autoscale"}
	openTargets := func() *autoscale.NATSTargetStore {
		t.Helper()
		journal, err := authorityjournal.New(journalConfig, func() map[string]autoscale.Target { return map[string]autoscale.Target{} }, func(map[string]autoscale.Target) error { return nil })
		if err != nil {
			t.Fatal(err)
		}
		targets, err := autoscale.NewNATSTargetStore(journal)
		if err != nil {
			t.Fatal(err)
		}
		return targets
	}
	targets := openTargets()
	if err := targets.CompareAndSwap(ctx, "gru", nil, autoscale.Target{Region: "gru", Members: 3}); err != nil {
		t.Fatal(err)
	}
	// Reopen the store with a fresh controller. No autoscale tick or in-memory
	// applyAutoscalePlan call supplies the desired count for this first pass.
	targets = openTargets()
	spec := estate.Default()
	region := spec.Regions[0]
	if region.Code != "gru" {
		t.Fatal("fixture needs GRU")
	}
	spec.Regions = slices.Clone(spec.Regions)
	gateway := &autoscaleLoopGateway{}
	for slot := 1; slot <= 2; slot++ {
		gateway.members = append(gateway.members, autoscaleLoopMember(region, slot))
		worker := autoscaleLoopMember(region, slot)
		worker.DisplayName = ocireconcile.WorkerDisplayName(region.Code, slot)
		worker.Role = "worker"
		worker.Shape = region.Workers.PrimaryShape
		worker.FreeformTags[provider.OCIManagedTag] = ocireconcile.ManagedWorkerTagValue
		gateway.members = append(gateway.members, worker)
	}
	artifact := "https://git.terrascale.tech/TerraScale/ts-orchestrator/releases/download/v1/ts-node"
	seed, err := ocireconcile.TSNodeCloudInit("v1", strings.Repeat("a", 64), artifact, artifact+".sig", strings.Repeat("ab", 32), []ocireconcile.BootstrapHostFile{{Path: "/etc/terrascale/ts-node.json", Content: []byte("{}")}, {Path: "/var/lib/terrascale/ts-node/manifest.json", Content: []byte("{}")}})
	if err != nil {
		t.Fatal(err)
	}
	regional := &ociRegionController{region: region, network: &ocireconcile.NetworkReconciler{}, compute: &ocireconcile.ComputeReconciler{Compute: gateway}, object: &ocireconcile.ObjectStorageReconciler{}, vault: &ocireconcile.VaultReconciler{}, block: &ocireconcile.BlockStorageReconciler{Block: autoscaleLoopBlock{}, Compute: gateway}, certs: &ocireconcile.CertReconciler{Gateway: autoscaleLoopCertificates{}}}
	regional.projection = func(ctx context.Context, region estate.Region) (ocireconcile.ComputeDeclared, error) {
		target, found, err := targets.Load(ctx, region.Code)
		if err != nil {
			return ocireconcile.ComputeDeclared{}, err
		}
		if found {
			// Durable autoscale owns both contraction and expansion. The
			// placement floor is enforced by the OCI reconciler, so a target
			// below the static declaration must reach ComputeReconciler.
			region.Members.Count = uint16(target.Members)
		}
		seeds := map[int]string{}
		bindings := map[int]ocireconcile.MemberBinding{}
		for slot := 1; slot <= int(region.Members.Count); slot++ {
			seeds[slot] = seed
			bindings[slot] = ocireconcile.MemberBinding{
				ServerIdentity: fmt.Sprintf("spiffe://terrascale.tech/production/member/%s-%d", region.Code, slot),
				Environment:    "production",
				Cluster:        "cluster",
				MemberID:       fmt.Sprintf("member-%d", slot),
				CellID:         region.Code,
				Generation:     7,
			}
		}
		return ocireconcile.ComputeDeclared{Region: region, ImageID: "ocid1.image.oc1.arm64", FallbackImageID: "ocid1.image.oc1.amd64", CloudInitByMember: seeds, CloudInitByWorker: map[int]string{1: seed, 2: seed}, MemberBindings: bindings}, nil
	}
	regional.targetProjection = func(ctx context.Context, region estate.Region) (uint16, error) {
		target, found, err := targets.Load(ctx, region.Code)
		if err != nil {
			return 0, err
		}
		if !found {
			return region.Members.Count, nil
		}
		return uint16(target.Members), nil
	}
	controller := &ociReconcileController{spec: spec, regions: map[string]*ociRegionController{"gru": regional}}
	for _, other := range spec.Regions[1:] {
		controller.regions[other.Code] = &ociRegionController{
			region: other,
			projection: func(_ context.Context, region estate.Region) (ocireconcile.ComputeDeclared, error) {
				return ocireconcile.ComputeDeclared{Region: region}, nil
			},
			targetProjection: func(_ context.Context, region estate.Region) (uint16, error) {
				return region.Members.Count, nil
			},
		}
	}

	observed := &autoscaleLoopProvider{ociReconcileController: controller, region: regional, gateway: gateway}
	progress, err := reconcile.NewFileProgressStore(filepath.Join(t.TempDir(), "progress.json"))
	if err != nil {
		t.Fatal(err)
	}
	loop, err := reconcile.NewLoop(reconcile.LoopConfig{Spec: spec, Desired: controller.desiredSpec, Providers: []reconcile.Reconciler{observed}, Interval: time.Minute, Progress: progress})
	if err != nil {
		t.Fatal(err)
	}
	plan, err := loop.Pass(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Empty() || len(gateway.launches) != 1 || gateway.launches[0].Index != 3 {
		t.Fatalf("first pass plan=%+v launches=%+v", plan, gateway.launches)
	}
	launch := gateway.launches[0]
	if launch.ServerIdentity == "" || launch.Environment != "production" || launch.Cluster != "cluster" || launch.MemberID != "member-3" || launch.CellID != "gru" || launch.Generation != 7 {
		t.Fatalf("slot 3 launch lost durable enrollment binding: %+v", launch)
	}
	if regional.scaleOutTarget != 0 || controller.spec.Regions[0].Members.Count != 2 || spec.Regions[0].Members.Count != 2 {
		t.Fatal("projection mutated static declaration or depended on autoscale tick")
	}
	if len(gateway.members) != 5 {
		t.Fatalf("gateway did not observe launched hosts: %d", len(gateway.members))
	}
	plan, err = loop.Pass(ctx)
	if err != nil || !plan.Empty() || len(gateway.launches) != 1 {
		t.Fatalf("converged pass plan=%+v launches=%d err=%v", plan, len(gateway.launches), err)
	}
}

// Limit observation ownership to compute for this caller regression. Counts
// come only from actual gateway members, never from the desired target.
type autoscaleLoopProvider struct {
	*ociReconcileController
	region  *ociRegionController
	gateway *autoscaleLoopGateway
}

func (p *autoscaleLoopProvider) Kinds() []estate.ResourceKind {
	return []estate.ResourceKind{estate.ResourceCompute}
}
func (p *autoscaleLoopProvider) Observe(ctx context.Context) (reconcile.State, error) {
	members, err := p.gateway.ListMembers(ctx)
	if err != nil {
		return reconcile.State{}, err
	}
	compute := ocireconcile.ComputeObserved{Members: members, AvailabilityDomains: []string{"AD-1"}, Subnets: []ocireconcile.ObservedSubnet{{ID: "ocid1.subnet.oc1.x", DisplayName: p.region.region.Network.Subnets[0].Name, LifecycleState: "AVAILABLE", FreeformTags: map[string]string{provider.OCIManagedTag: "subnet", provider.OCIScopeTag: "gru"}}}}
	for i, group := range p.region.region.Network.SecurityGroups {
		compute.NSGs = append(compute.NSGs, ocireconcile.ObservedNSG{ID: fmt.Sprintf("ocid1.networksecuritygroup.oc1.x%d", i), DisplayName: group.Name, LifecycleState: "AVAILABLE", FreeformTags: map[string]string{provider.OCIManagedTag: "networksecuritygroup", provider.OCIScopeTag: "gru"}})
	}
	observation := &ociRegionObservation{compute: compute}
	p.region.mu.Lock()
	p.region.observed = observation
	p.region.mu.Unlock()
	all := ociObservedState(p.region.region, observation)
	for _, other := range p.spec.Regions[1:] {
		members := make([]ocireconcile.ObservedMember, 0, other.Members.Count)
		for slot := 1; slot <= int(other.Members.Count); slot++ {
			members = append(members, autoscaleLoopMember(other, slot))
		}
		for slot := 1; slot <= int(other.Workers.Count); slot++ {
			worker := autoscaleLoopMember(other, slot)
			worker.DisplayName = ocireconcile.WorkerDisplayName(other.Code, slot)
			worker.Role = "worker"
			worker.Shape = other.Workers.PrimaryShape
			worker.FreeformTags[provider.OCIManagedTag] = ocireconcile.ManagedWorkerTagValue
			members = append(members, worker)
		}
		all.Resources = append(all.Resources, ociObservedState(other, &ociRegionObservation{compute: ocireconcile.ComputeObserved{Members: members}}).Resources...)
	}

	state := reconcile.State{}
	for _, resource := range all.Resources {
		if resource.Ref.Kind == estate.ResourceCompute {
			state.Resources = append(state.Resources, resource)
		}
	}
	return state, nil
}

type autoscaleLoopGateway struct {
	ocireconcile.ComputeGateway
	members  []ocireconcile.ObservedMember
	launches []ocireconcile.MemberLaunchSpec
}

func (g *autoscaleLoopGateway) ListMembers(context.Context) ([]ocireconcile.ObservedMember, error) {
	return slices.Clone(g.members), nil
}
func (g *autoscaleLoopGateway) LaunchMember(_ context.Context, launch ocireconcile.MemberLaunchSpec) (ocireconcile.ObservedMember, error) {
	g.launches = append(g.launches, launch)
	member := autoscaleLoopMember(estate.Default().Regions[0], launch.Index)
	if launch.Role == "worker" {
		member.DisplayName = ocireconcile.WorkerDisplayName(estate.Default().Regions[0].Code, launch.Index)
		member.Role = "worker"
		member.FreeformTags[provider.OCIManagedTag] = ocireconcile.ManagedWorkerTagValue
	}
	g.members = append(g.members, member)
	return member, nil
}
func autoscaleLoopMember(region estate.Region, slot int) ocireconcile.ObservedMember {
	return ocireconcile.ObservedMember{ID: fmt.Sprintf("ocid1.instance.oc1.x%d", slot), DisplayName: ocireconcile.MemberDisplayName(region.Code, slot), Index: slot, Shape: region.Members.PrimaryShape, LifecycleState: "RUNNING", AvailabilityDomain: "AD-1", FreeformTags: map[string]string{provider.OCIManagedTag: ocireconcile.ManagedMemberTagValue, provider.OCIScopeTag: region.Code}}
}

type autoscaleLoopBlock struct {
	ocireconcile.BlockStorageGateway
}
type autoscaleLoopCertificates struct{ ocireconcile.CertGateway }

func TestTargetProjectionsBoundRequiresEveryRegion(t *testing.T) {
	c := &ociReconcileController{regions: map[string]*ociRegionController{"gru": {}, "sfo": {}}}
	if c.targetProjectionsBound() {
		t.Fatal("unbound projections accepted")
	}
	c.bindComputeTargetProjection(func(context.Context, estate.Region) (uint16, error) { return 2, nil })
	if !c.targetProjectionsBound() {
		t.Fatal("bound projection rejected")
	}
	if (&ociReconcileController{}).targetProjectionsBound() {
		t.Fatal("empty controller reported bound")
	}
}
