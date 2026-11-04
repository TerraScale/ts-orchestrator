package app

import (
	"slices"
	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/cellspec"
	"github.com/TerraScale/ts-orchestrator/internal/ociresource/lb"
)

// newEdgeTest owns both sets: terrabase and ts-auth run on gru-1-ctl-1..3.
func newEdgeTest(t *testing.T) (*edgeReconciler, *nodeOps, *fenceLB, *nodeInstances) {
	t.Helper()
	ops, balancer, instances := newNodeOpsTest(t)
	spec := &cellspec.ReleaseFence{LoadBalancerID: "ocid1.loadbalancer.oc1..x", BackendSets: []cellspec.FencedSet{
		{Name: "terrabase", Port: 9465, Role: "terrabase"}, {Name: "ts-auth", Port: 8080, Role: "ts-auth"}}}
	ops.fence.spec = func() (*cellspec.ReleaseFence, map[string]string) { return spec, fenceAddresses }
	edge := newEdgeReconciler("gru", ops.fence)
	edge.ops, edge.downFor = ops, 0
	return edge, ops, balancer, instances
}

func (e *edgeReconciler) passes(t *testing.T, n int) {
	t.Helper()
	for range n {
		if err := e.pass(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
}

func backendOf(balancer *fenceLB, set, name string) (lb.Backend, bool) {
	balancer.mu.Lock()
	defer balancer.mu.Unlock()
	index := slices.IndexFunc(balancer.sets[set], func(b lb.Backend) bool { return b.Name() == name })
	if index < 0 {
		return lb.Backend{}, false
	}
	return balancer.sets[set][index], true
}
