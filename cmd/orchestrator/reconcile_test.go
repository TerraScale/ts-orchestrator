package main

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/cloudflare"
	"terrascale.tech/orchestrator/src/orchestrator/estate"
	"terrascale.tech/orchestrator/src/orchestrator/provider"
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
		compute: provider.ComputeObserved{Members: []provider.ObservedMember{{ID: "ocid1.instance.oc1.x", LifecycleState: "RUNNING", Shape: region.Members.PrimaryShape}}},
		network: provider.NetworkObserved{VCN: &provider.ObservedVCN{ID: "ocid1.vcn.oc1.x", CIDR: region.Network.CIDR}},
	})
	if len(state.Resources) < 2 {
		t.Fatalf("OCI observed state has %d resources, want at least compute and network", len(state.Resources))
	}
}

type reconcileKVStoreFake struct{ health int }

func (s *reconcileKVStoreFake) SetRegionHealth(context.Context, string, cloudflare.RegionHealth) error {
	s.health++
	return nil
}
func (s *reconcileKVStoreFake) SetDBPlacement(context.Context, string, cloudflare.DBPlacement) error {
	return nil
}
func (s *reconcileKVStoreFake) DeleteRegionHealth(context.Context, string) error { return nil }
func (s *reconcileKVStoreFake) DeleteDBPlacement(context.Context, string) error  { return nil }

func TestProductionKVWriterStartsAndShutsDown(t *testing.T) {
	spec := estate.Default()
	members := cloudflare.Members{"gru": {"198.51.100.10"}, "sfo": {"198.51.100.11"}, "fra": {"198.51.100.12"}}
	store := &reconcileKVStoreFake{}
	writer, err := cloudflare.NewKVWriter(cloudflare.KVWriterConfig{
		Store: store, Health: &declaredKVHealthSource{spec: spec, members: members}, Placement: declaredKVPlacementSource{}, HealthInterval: time.Hour,
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
