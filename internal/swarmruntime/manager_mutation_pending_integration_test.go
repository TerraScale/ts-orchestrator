//go:build linux

package swarmruntime

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/gogo/protobuf/proto"
	"github.com/moby/swarmkit/v2/api"
	"github.com/moby/swarmkit/v2/manager"
	"github.com/moby/swarmkit/v2/manager/state/store"
)

// This submits one actual Raft proposal without a reachable quorum. The same
// managers then resume and apply that expired proposal, without a second write.
func TestObservedNativeMutationCommitsAfterOriginalDeadline(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	seedConfig := nodeFixtureConfig(t, "founder", "manager")
	seedConfig.Admission.Region = "sa-saopaulo-1"
	seedRelay := newNativeMutationRelay(t, seedConfig.ListenAddress)
	seedConfig.AdvertiseAddress = seedRelay.listener.Addr().String()
	seed := nodeFixtureStart(t, ctx, seedConfig)
	client, err := seed.ControlClient(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := AdmitNode(ctx, client, seed.ID(), seedConfig.Admission); err != nil {
		t.Fatal(err)
	}
	clusters, err := client.ListClusters(ctx, &api.ListClustersRequest{})
	if err != nil || len(clusters.Clusters) != 1 {
		t.Fatal("actual native cluster unavailable", err)
	}
	nodes := []*Node{seed}
	var relays []*nativeMutationRelay
	for _, slot := range []string{"peer-a", "peer-b"} {
		config := nodeFixtureConfig(t, slot, "manager")
		config.Admission.Region = seedConfig.Admission.Region
		config.Admission.ManagerAddress = seedConfig.AdvertiseAddress
		config.Admission.JoinToken = clusters.Clusters[0].RootCA.JoinTokens.Manager
		relay := newNativeMutationRelay(t, config.ListenAddress)
		config.AdvertiseAddress = relay.listener.Addr().String()
		node := nodeFixtureStart(t, ctx, config)
		if _, err := AdmitNode(ctx, client, node.ID(), config.Admission); err != nil {
			t.Fatal(err)
		}
		nodes, relays = append(nodes, node), append(relays, relay)
	}
	readers := make([]*manager.ControlReader, 0, len(nodes))
	for _, node := range nodes {
		reader, err := node.upstream.Manager().ReadOnlyControlClient(func(call context.Context) error { return call.Err() })
		if err != nil {
			t.Fatal(err)
		}
		readers = append(readers, reader)
	}
	waitNativeMutation(t, ctx, func() bool {
		response, err := client.ListNodes(ctx, &api.ListNodesRequest{})
		if err != nil || len(response.Nodes) != 3 {
			return false
		}
		for _, node := range response.Nodes {
			if node.ManagerStatus == nil || node.ManagerStatus.Reachability != api.RaftMemberStatus_REACHABLE || node.Status.State != api.NodeStatus_READY ||
				node.ID == seed.ID() && !node.ManagerStatus.Leader {
				return false
			}
		}
		return true
	})
	for _, relay := range relays {
		relay.block(true)
	}
	m := seed.upstream.Manager()
	var expected *api.Node
	observed, err := m.Observe(nil, func(tx store.ReadTx) error {
		expected = store.GetNode(tx, seed.ID())
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer observed.Cancel()
	request := &api.UpdateNodeRequest{NodeID: seed.ID(), NodeVersion: expected.Meta.Version.Copy(), Spec: expected.Spec.Copy()}
	request.Spec.Availability = api.NodeAvailabilityPause
	request.Spec.Annotations.Labels["test.original-proposal"] = "one-finite-admission"
	// This expires before the native election interval, while both followers
	// remain live and cannot receive the proposal through their blocked relays.
	original, expire := context.WithTimeout(ctx, 100*time.Millisecond)
	defer expire()
	if _, err := m.UpdateNodeAtObservation(original, observed, expected, request, func(store.ReadTx) error { return nil }); !errors.Is(err, manager.ErrMutationAmbiguous) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("one admitted pending proposal did not retain its expired original outcome: %v", err)
	}
	for _, reader := range readers {
		before, err := reader.GetNode(ctx, &api.GetNodeRequest{NodeID: seed.ID()})
		if err != nil || before.Node.Spec.Annotations.Labels["test.original-proposal"] != "" {
			t.Fatal("proposal applied before the blocked quorum resumed", err)
		}
	}
	for _, relay := range relays {
		relay.block(false)
	}
	waitNativeMutation(t, ctx, func() bool {
		var committed *api.Node
		for _, reader := range readers {
			response, err := reader.GetNode(ctx, &api.GetNodeRequest{NodeID: seed.ID()})
			if err != nil || response.Node.Spec.Availability != api.NodeAvailabilityPause || response.Node.Spec.Annotations.Labels["test.original-proposal"] != "one-finite-admission" {
				return false
			}
			if committed != nil && (response.Node.Meta.Version.Index != committed.Meta.Version.Index || !proto.Equal(&response.Node.Spec, &committed.Spec)) {
				return false
			}
			committed = response.Node
		}
		return true
	})
	if original.Err() != context.DeadlineExceeded {
		t.Fatal("committed outcome used a renewed original context")
	}
}

func waitNativeMutation(t *testing.T, ctx context.Context, ready func() bool) {
	t.Helper()
	bounded, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for !ready() {
		select {
		case <-bounded.Done():
			t.Fatal("actual native manager projection did not converge", bounded.Err())
		case <-ticker.C:
		}
	}
}

// The relay only drops actual TLS TCP connections; it never interprets Raft,
// substitutes acknowledgments, changes a store or fabricates native outcomes.
type nativeMutationRelay struct {
	listener net.Listener
	target   string
	mu       sync.Mutex
	blocked  bool
	open     map[net.Conn]struct{}
}

func newNativeMutationRelay(t *testing.T, target string) *nativeMutationRelay {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	relay := &nativeMutationRelay{listener: listener, target: target, open: make(map[net.Conn]struct{})}
	t.Cleanup(func() { _ = listener.Close(); relay.block(true) })
	go func() {
		for {
			incoming, err := listener.Accept()
			if err != nil {
				return
			}
			go relay.forward(incoming)
		}
	}()
	return relay
}

func (relay *nativeMutationRelay) block(blocked bool) {
	relay.mu.Lock()
	defer relay.mu.Unlock()
	relay.blocked = blocked
	if blocked {
		for connection := range relay.open {
			_ = connection.Close()
		}
	}
}

func (relay *nativeMutationRelay) forward(incoming net.Conn) {
	defer incoming.Close()
	outgoing, err := net.DialTimeout("tcp", relay.target, time.Second)
	if err != nil {
		return
	}
	defer outgoing.Close()
	relay.mu.Lock()
	if relay.blocked {
		relay.mu.Unlock()
		return
	}
	relay.open[incoming], relay.open[outgoing] = struct{}{}, struct{}{}
	relay.mu.Unlock()
	defer func() {
		relay.mu.Lock()
		delete(relay.open, incoming)
		delete(relay.open, outgoing)
		relay.mu.Unlock()
	}()
	done := make(chan struct{})
	go func() { _, _ = io.Copy(outgoing, incoming); _ = outgoing.Close(); close(done) }()
	_, _ = io.Copy(incoming, outgoing)
	_ = incoming.Close()
	<-done
}
