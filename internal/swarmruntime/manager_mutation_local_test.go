//go:build linux

package swarmruntime

import (
	"context"
	"errors"
	"testing"

	"github.com/moby/swarmkit/v2/api"
	"github.com/moby/swarmkit/v2/manager/state/store"
)

// This uses the real manager transaction and Raft path, without its cached
// control connection. It does not qualify Unix socket authentication.
func testObservedNativeNodeMutation(t *testing.T, ctx context.Context, node *Node) {
	t.Helper()
	m := node.upstream.Manager()
	var expected *api.Node
	original, err := m.Observe(nil, func(tx store.ReadTx) error {
		expected = store.GetNode(tx, node.ID())
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer original.Cancel()
	if expected == nil {
		t.Fatal("manager self node missing")
	}
	check := func(store.ReadTx) error { return nil }
	request := &api.UpdateNodeRequest{NodeID: expected.ID, NodeVersion: expected.Meta.Version.Copy(), Spec: expected.Spec.Copy()}
	request.Spec.Availability = api.NodeAvailabilityPause
	// The complete captured certificate must match even with the correct version.
	wrong := expected.Copy()
	wrong.Certificate.Certificate = []byte("changed-certificate")
	if _, err := m.UpdateNodeAtObservation(ctx, original, wrong, request, check); err == nil {
		t.Fatal("native observation accepted changed certificate at the same version")
	}
	canceled, cancel := context.WithCancel(ctx)
	if _, err := m.UpdateNodeAtObservation(canceled, original, expected, request, func(store.ReadTx) error {
		cancel()
		return nil
	}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation inside locked CAS reached proposal: %v", err)
	}
	updated, err := m.UpdateNodeAtObservation(ctx, original, expected, request, check)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.UpdateNodeAtObservation(ctx, original, expected, request, check); err == nil {
		t.Fatal("native observation reused a stale original node version")
	}
	demote := &api.UpdateNodeRequest{NodeID: expected.ID, NodeVersion: updated.Node.Meta.Version.Copy(), Spec: updated.Node.Spec.Copy()}
	demote.Spec.DesiredRole = api.NodeRoleWorker
	if _, err := m.UpdateNodeAtObservation(ctx, original, updated.Node, demote, check); err == nil {
		t.Fatal("native observation bypassed last-manager demotion guard")
	}
	if _, err := m.RemoveNodeAtObservation(ctx, original, updated.Node, check); err == nil {
		t.Fatal("native observation bypassed manager/non-force removal guard")
	}
	restore := &api.UpdateNodeRequest{NodeID: expected.ID, NodeVersion: updated.Node.Meta.Version.Copy(), Spec: expected.Spec.Copy()}
	if _, err := m.UpdateNodeAtObservation(ctx, original, updated.Node, restore, check); err != nil {
		t.Fatal(err)
	}
}
