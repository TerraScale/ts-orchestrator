package main

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/autoscale"
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

func TestAutoscaleTargetStorePersistsAndCASFencesTargets(t *testing.T) {
	path := filepath.Join(t.TempDir(), "autoscale-progress.json")
	store, err := reconcile.NewFileProgressStore(path)
	if err != nil {
		t.Fatal(err)
	}
	targets := &autoscaleTargetStore{store: store, cas: store}
	first := autoscale.Target{Region: "gru", Members: 2, OperationID: "autoscale-one"}
	if err := targets.CompareAndSwap(t.Context(), "gru", nil, first); err != nil {
		t.Fatal(err)
	}
	reopened, err := reconcile.NewFileProgressStore(path)
	if err != nil {
		t.Fatal(err)
	}
	reopenedTargets := &autoscaleTargetStore{store: reopened, cas: reopened}
	loaded, found, err := reopenedTargets.Load(t.Context(), "gru")
	if err != nil || !found || loaded != first {
		t.Fatalf("loaded target = %+v found=%v err=%v", loaded, found, err)
	}
	second := first
	second.Members = 3
	second.OperationID = "autoscale-two"
	if err := targets.CompareAndSwap(t.Context(), "gru", &first, second); err != nil {
		t.Fatal(err)
	}
	if err := targets.CompareAndSwap(t.Context(), "gru", &first, second); !errors.Is(err, reconcile.ErrProgressConflict) {
		t.Fatalf("stale target CAS error = %v", err)
	}
}

func TestOCIReconcileAppliesAutoscalePlanToComputeDeclaration(t *testing.T) {
	region := estate.Default().Regions[0]
	controller := &ociReconcileController{regions: map[string]*ociRegionController{
		region.Code: {region: region},
	}}
	plan := autoscale.Plan{Region: region.Code, PreviousMembers: int(region.Members.Count), DesiredMembers: int(region.Members.Count) + 1, OperationID: "autoscale-plan"}
	if err := controller.applyAutoscalePlan(plan); err != nil {
		t.Fatal(err)
	}
	if got := controller.regions[region.Code].computeDeclared().Members.Count; got != region.Members.Count+1 {
		t.Fatalf("autoscale target members = %d, want %d", got, region.Members.Count+1)
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
		Store: store, Health: testObservedHealth{}, Placement: declaredKVPlacementSource{}, HealthInterval: time.Hour,
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
