package controlapi

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/moby/swarmkit/v2/api"
	"github.com/moby/swarmkit/v2/ca"
	"google.golang.org/grpc/metadata"
)

func TestControllerNodeConstraintsRetainOriginalContext(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	constraints := ControllerNodeConstraints{Operation: ControllerNodeActivate, LeaseEpoch: 1, RaftTerm: 2, RaftLeader: 3,
		TargetSHA256: strings.Repeat("a", 64), SourceSHA256: strings.Repeat("b", 64)}
	forwarded, err := WithControllerNodeConstraints(ctx, constraints)
	if err != nil {
		t.Fatal(err)
	}
	originalDeadline, _ := ctx.Deadline()
	forwardedDeadline, _ := forwarded.Deadline()
	if !originalDeadline.Equal(forwardedDeadline) {
		t.Fatal("native forwarding changed the original deadline")
	}
	md, _ := metadata.FromOutgoingContext(forwarded)
	incoming := metadata.NewIncomingContext(forwarded, md)
	actual, err := ControllerNodeConstraintsFromContext(incoming)
	if err != nil || actual != constraints {
		t.Fatalf("finite constraints changed: %#v, %v", actual, err)
	}
	if _, err := WithControllerNodeConstraints(incoming, constraints); err == nil {
		t.Fatal("forwarded metadata can be replaced")
	}
	cancel()
	if _, err := ControllerNodeConstraintsFromContext(incoming); !errors.Is(err, context.Canceled) {
		t.Fatalf("original cancellation lost: %v", err)
	}
}

func TestControllerNodeConstraintsNeverGrantSource(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	constraints := ControllerNodeConstraints{Operation: ControllerNodeRetire, LeaseEpoch: 1, RaftTerm: 2, RaftLeader: 3,
		TargetSHA256: strings.Repeat("a", 64), SourceSHA256: strings.Repeat("b", 64)}
	forwarded, err := WithControllerNodeConstraints(ctx, constraints)
	if err != nil {
		t.Fatal(err)
	}
	md, _ := metadata.FromOutgoingContext(forwarded)
	incoming := metadata.NewIncomingContext(ctx, md)
	incoming = context.WithValue(incoming, ca.LocalRequestKey, ca.RemoteNodeInfo{NodeID: "actual-manager", Organization: "actual-cluster", Roles: []string{ca.ManagerRole}})
	server := NewServer(nil, nil, nil, nil, nil)
	if _, err := server.UpdateNode(incoming, &api.UpdateNodeRequest{NodeID: "old-node", NodeVersion: &api.Version{Index: 1},
		Spec: &api.NodeSpec{DesiredRole: api.NodeRoleWorker, Availability: api.NodeAvailabilityPause}}); err == nil {
		t.Fatal("tagged native demotion granted authority without a concrete source")
	}
	if _, err := server.RemoveNode(incoming, &api.RemoveNodeRequest{NodeID: "old-node"}); err == nil {
		t.Fatal("tagged native removal granted authority without a concrete source")
	}
	wire := md.Get(controllerNodeMetadata)[0]
	for _, malformed := range []metadata.MD{
		metadata.Pairs(controllerNodeMetadata, wire, controllerNodeMetadata, wire),
		metadata.Pairs(controllerNodeMetadata, strings.TrimSuffix(wire, "}")+`,"Unknown":true}`),
		metadata.Pairs(controllerNodeMetadata, strings.TrimSuffix(wire, "}")+`,"LeaseEpoch":99}`),
		metadata.Pairs(controllerNodeMetadata, wire+`{}`),
		metadata.Pairs(controllerNodeMetadata, strings.Replace(wire, `"retire"`, `"arbitrary"`, 1)),
	} {
		if _, err := ControllerNodeConstraintsFromContext(metadata.NewIncomingContext(ctx, malformed)); err == nil {
			t.Fatalf("malformed constraints accepted: %v", malformed)
		}
	}
	if _, err := WithControllerNodeConstraints(context.Background(), constraints); err == nil {
		t.Fatal("unbounded context accepted")
	}
}

func TestControllerNodeRawMutationBoundary(t *testing.T) {
	manager := &api.Node{Role: api.NodeRoleManager, Spec: api.NodeSpec{DesiredRole: api.NodeRoleManager, Availability: api.NodeAvailabilityActive}}
	initial := manager.Spec.Copy()
	initial.Annotations.Labels = map[string]string{"terrascale.instance-id": "current-instance", "terrascale.host-role": "manager"}
	if controllerNodeUnobservedUpdate(manager, initial) {
		t.Fatal("initial identity attachment cannot preserve native initial availability")
	}
	manager.Spec = *initial.Copy()
	if !controllerNodeUnobservedUpdate(manager, initial) {
		t.Fatal("ordinary ACTIVE no-op bypasses concrete controller source")
	}
	pause := initial.Copy()
	pause.Availability = api.NodeAvailabilityPause
	if controllerNodeUnobservedUpdate(manager, pause) {
		t.Fatal("ordinary PAUSE was denied")
	}
	spoof := pause.Copy()
	delete(spoof.Annotations.Labels, "terrascale.instance-id")
	if !controllerNodeUnobservedUpdate(manager, spoof) {
		t.Fatal("ordinary update can erase admitted identity before activation")
	}
	demote := pause.Copy()
	demote.DesiredRole = api.NodeRoleWorker
	if !controllerNodeUnobservedUpdate(manager, demote) {
		t.Fatal("ordinary demotion bypasses concrete controller source")
	}
	worker := manager.Copy()
	worker.Role, worker.Spec.DesiredRole = api.NodeRoleWorker, api.NodeRoleWorker
	worker.Spec.Annotations.Labels["terrascale.host-role"] = "container"
	if !controllerNodeUnobservedUpdate(worker, initial) {
		t.Fatal("ordinary worker promotion bypasses concrete controller source")
	}
	if controllerNodeUnobservedUpdate(worker, worker.Spec.Copy()) {
		t.Fatal("controller source intercepted independent worker membership")
	}
}
