package mesh

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
	"github.com/gogo/protobuf/proto"
	"github.com/moby/swarmkit/v2/agent/exec"
	"github.com/moby/swarmkit/v2/api"
)

// The fixture drains this node before applying specs; no containers execute.
type applierIdleExecutor struct{}

func (applierIdleExecutor) Describe(context.Context) (*api.NodeDescription, error) {
	return &api.NodeDescription{}, nil
}
func (applierIdleExecutor) Configure(context.Context, *api.Node) error         { return nil }
func (applierIdleExecutor) SetNetworkBootstrapKeys([]*api.EncryptionKey) error { return nil }
func (applierIdleExecutor) Controller(*api.Task) (exec.Controller, error) {
	return nil, errors.New("applier integration node does not execute tasks")
}

func TestSwarmApplierReconcilesSameGeneration(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	stateDir := t.TempDir()
	address := fmt.Sprintf("127.0.0.1:%d", freePorts(t, 1)[0])
	swarm, err := swarmruntime.StartSingleHost(ctx, stateDir, applierIdleExecutor{}, address, address, swarmruntime.FounderAdmission())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		stop, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := swarm.Stop(stop); err != nil {
			t.Error(err)
		}
	})
	client, conn, err := swarmruntime.DialSingleHost(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	current, err := client.GetNode(ctx, &api.GetNodeRequest{NodeID: swarm.ID()})
	if err != nil {
		t.Fatal(err)
	}
	nodeSpec := current.Node.Spec.Copy()
	nodeSpec.Availability = api.NodeAvailabilityDrain
	if _, err := client.UpdateNode(ctx, &api.UpdateNodeRequest{NodeID: swarm.ID(), NodeVersion: &current.Node.Meta.Version, Spec: nodeSpec}); err != nil {
		t.Fatal(err)
	}
	node := &Node{cfg: config{region: "gru", server: "gru-1", applier: swarmApplier{state: stateDir}},
		peers: &peers{root: t.TempDir(), region: "gru", node: "gru-1", address: func() (string, error) { return "10.200.0.1", nil }}}
	spec := swarmruntime.ServiceSpec{Name: "web", Image: "ghcr.io/terrascale/web@sha256:" + strings.Repeat("a", 64),
		Args: []string{"a"}, Port: 8080, Replicas: 1}
	floor := &Deployment{Repository: "TerraScale/terrascale", RunID: "99", Revision: strings.Repeat("b", 40), Image: spec.Image}
	state := stateFor(Entry{Generation: 11, Spec: &spec})
	state.Floor = floor
	reconcile := func(t *testing.T, state desiredState) *api.Service {
		t.Helper()
		if _, err := node.reconcile(ctx, spec.Name, state); err != nil {
			t.Fatal(err)
		}
		listed, err := client.ListServices(ctx, &api.ListServicesRequest{})
		if err != nil || len(listed.Services) != 1 {
			t.Fatalf("runtime services: %v, %v", listed, err)
		}
		entry := state.entry()
		want := *entry.Spec
		want.Generation, want.RollbackOf = entry.Generation, entry.RollbackOf
		want.Deployment, want.DeploymentFloor = entry.Deployment, state.Floor
		want.Region, want.Node = node.cfg.region, node.cfg.server
		expected, err := want.SwarmSpec()
		if err != nil {
			t.Fatal(err)
		}
		service := listed.Services[0]
		if !proto.Equal(&service.Spec, expected) {
			t.Fatalf("runtime differs from selected complete spec (generation %d, floor %s, args %v)", want.Generation, state.Floor.RunID, want.Args)
		}
		return service
	}
	initial := reconcile(t, state)

	t.Run("identical spec replay is idempotent", func(t *testing.T) {
		replayed := reconcile(t, state)
		if replayed.ID != initial.ID || !proto.Equal(replayed.SpecVersion, initial.SpecVersion) {
			t.Fatal("identical spec replay changed service identity or spec version")
		}
	})

	t.Run("operator keeps generation and advances floor", func(t *testing.T) {
		nextFloor := *floor
		nextFloor.RunID = "100"
		var err error
		state, err = mergeState(state, stateFor(Entry{Generation: 12, RollbackOf: 10, Spec: &spec, Deployment: &nextFloor}))
		if err != nil {
			t.Fatal(err)
		}
		if state.entry().Generation != 11 || state.entry().Deployment != nil || state.Floor.RunID != "100" {
			t.Fatalf("rollback displaced intervening operator: %+v", state)
		}
		updated := reconcile(t, state)
		if updated.ID != initial.ID || proto.Equal(updated.SpecVersion, initial.SpecVersion) {
			t.Fatal("floor advance did not update the existing service")
		}
	})

	t.Run("equal generation selects complete spec deterministically", func(t *testing.T) {
		winner := spec
		winner.Args = []string{"z"}
		next := stateFor(Entry{Generation: 11, Spec: &winner})
		forward, err := mergeState(state, next)
		if err != nil {
			t.Fatal(err)
		}
		reverse, err := mergeState(next, state)
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(forward.entry().Spec.Args, winner.Args) || !slices.Equal(reverse.entry().Spec.Args, winner.Args) {
			t.Fatal("equal-generation tie did not select the same complete spec in both orders")
		}
		state = forward
		updated := reconcile(t, state)
		if updated.ID != initial.ID {
			t.Fatal("equal-generation spec update replaced the service identity")
		}
	})
}
