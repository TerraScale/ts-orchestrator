package app

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/ociresource"
	"github.com/TerraScale/ts-orchestrator/internal/ociresource/lb"
	"github.com/TerraScale/ts-orchestrator/internal/ociresource/routetable"
	"github.com/TerraScale/ts-orchestrator/internal/rootoci"
)

type reconcileTestFencer struct{ fenced bool }

func (f reconcileTestFencer) Current() authority.Snapshot {
	return authority.Snapshot{DeploymentID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", Leader: true, Ready: true, Epoch: 1}
}

func (f reconcileTestFencer) Guard(context.Context, uint64) error {
	if f.fenced {
		return errors.New("lost leadership")
	}
	return nil
}

const reconcileTestNSG = "ocid1.networksecuritygroup.oc1.sa-saopaulo-1.members"

func desiredTestConfig(t *testing.T, wire string) OciDesiredConfig {
	t.Helper()
	var cfg ControllerConfig
	if err := json.Unmarshal([]byte(`{"oci_reconcile":{"desired":`+wire+`}}`), &cfg,
		json.RejectUnknownMembers(true)); err != nil {
		t.Fatal(err)
	}
	return *cfg.OciReconcile.Desired
}

func TestOciDesiredPassPublishesFencedAndFeedsInsights(t *testing.T) {
	region := oci.RegionConfig{Region: oci.RegionGRU, NetworkSecurityGroupIDs: []string{reconcileTestNSG}}
	desired := desiredTestConfig(t, `{"route_tables":{"private":{"spec":{"routeTableId":"ocid1.routetable.oc1..r",`+
		`"routes":[{"destination":"0.0.0.0/0","networkEntityId":"ocid1.natgateway.oc1..n"}]}}}}`)
	sets, delay, err := desiredSets(desired, "GRU", region)
	if err != nil {
		t.Fatal(err)
	}
	store := testOCIResourceStore(t)
	fenced := desiredPass("GRU", store, reconcileTestFencer{fenced: true}, sets, false, delay)
	if err := fenced.Run(t.Context(), 1); !errors.Is(err, ociresource.ErrFenced) {
		t.Fatalf("fenced pass err=%v", err)
	}
	if records, _ := store.List(t.Context(), "GRU", routetable.Kind); len(records) != 0 {
		t.Fatal("a fenced pass published")
	}
	if err := desiredPass("GRU", store, reconcileTestFencer{}, sets, false, delay).Run(t.Context(), 1); err != nil {
		t.Fatal(err)
	}
	records, _ := store.List(t.Context(), "GRU", routetable.Kind)
	if len(records) != 1 || records[0].Policy != ociresource.PolicyEnforce || records[0].Generation != 1 {
		t.Fatalf("records=%+v", records)
	}

	key := records[0].Key
	if err := store.PutStatus(t.Context(), ociresource.Status{Key: key, Policy: ociresource.PolicyEnforce, Found: true,
		Drift: []ociresource.Change{{Op: "add-route", Detail: "x"}}}); err != nil {
		t.Fatal(err)
	}
	runtime := &ociReconcileRuntime{store: store, cell: "GRU"}
	resources, err := runtime.resources().OCIResources(t.Context())
	if err != nil || len(resources) != 1 || resources[0].Key != "GRU/route-table-rules/private" ||
		resources[0].Drift[0] != "add-route x" || resources[0].Policy != "enforce" {
		t.Fatalf("resources=%+v err=%v", resources, err)
	}
	var off *ociReconcileRuntime
	if off.resources() != nil {
		t.Fatal("an unopened reconcile exposes a provider")
	}
}

func testOCIResourceStore(t *testing.T) *ociresource.KVStore {
	t.Helper()
	store, err := ociresource.OpenKVStore(t.Context(), testRolloutJetStream(t), 1)
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func TestRegionalFoundationPassRefusesAbsentRootAndStaleAuthority(t *testing.T) {
	var client *rootoci.Client
	if err := regionalReconcilePass("GRU", reconcileTestFencer{}, client).Run(t.Context(), 1); !errors.Is(err, rootoci.ErrInvalid) {
		t.Fatalf("missing root client = %v", err)
	}
	if err := regionalReconcilePass("GRU", reconcileTestFencer{fenced: true}, client).Run(t.Context(), 1); !errors.Is(err, ociresource.ErrFenced) {
		t.Fatalf("stale authority = %v", err)
	}
}

// publicLBPass publishes the TerraBase seats as the public load balancer's
// backend set, draining the seats the seat rollout holds drained. A profile
// that yields no serving seat, or seat records it cannot read, is an error,
// and the previous set stays in force.
func publicLBPass(store ociresource.Store, fencer authority.Fencer, key ociresource.Key, public OciReconcileLBConfig,
	profiles func() map[string]WorkloadProfile, drained func(context.Context) (map[string]bool, error),
) ociresource.Pass {
	return ociresource.Pass{Name: "publish-" + lb.Kind, Run: func(ctx context.Context, epoch uint64) error {
		if err := fencer.Guard(ctx, epoch); err != nil {
			return fmt.Errorf("%w: %w", ociresource.ErrFenced, err)
		}
		seats, err := drained(ctx)
		if err != nil {
			return fmt.Errorf("public load balancer: %w", err)
		}
		spec, err := public.spec(profiles(), seats)
		if err != nil {
			return err
		}
		_, err = lb.Publish(ctx, store, key, ociresource.PolicyEnforce, spec)
		return err
	}}
}
