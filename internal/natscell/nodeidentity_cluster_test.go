package natscell

import (
	"bufio"
	"context"
	"encoding/json/v2"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/testutil/tier"
	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go/jetstream"
)

func TestPrepareNodeIdentityPreservesR3State(t *testing.T) {
	tier.Integration(t)
	ctx, cancel := context.WithTimeout(t.Context(), 120*time.Second)
	defer cancel()
	cluster := &labCluster{stores: make([]string, 3), runtimes: make([]*Runtime, 3)}
	for index := range 3 {
		cluster.stores[index] = filepath.Join(t.TempDir(), "store")
	}
	t.Cleanup(func() {
		for index := range 3 {
			cluster.stop(index)
		}
	})
	start := func(index int) {
		instance := fmt.Sprintf("controller-%c", 'a'+index)
		var routes []string
		for _, peer := range cluster.runtimes {
			if peer != nil {
				routes = append(routes, "nats-route://"+peer.server.ClusterAddr().String())
			}
		}
		if len(routes) == 0 {
			routes = []string{"nats-route://127.0.0.1:1"}
		}
		runtime, err := Start(ctx, Config{Cell: "gru", Instance: instance, Replicas: 3, Lab: true,
			Embedded: &Embedded{Host: "127.0.0.1", Port: -1, RouteHost: "127.0.0.1",
				RoutePort: -1, Routes: routes,
				StoreDir: cluster.stores[index], BrokerIDs: []string{"controller-a", "controller-b", "controller-c"}}})
		if err != nil {
			t.Fatal(err)
		}
		cluster.runtimes[index] = runtime
		waitUntil(t, ctx, "ephemeral route listener", func() bool { return runtime.server.ClusterAddr() != nil })
	}
	for index := range 3 {
		start(index)
	}
	waitUntil(t, ctx, "initial R3 metadata quorum", func() bool { return cluster.runtimes[0].FullClusterReady(3) })
	stream, err := createR3Stream(ctx, cluster.runtimes[0].JetStream())
	if err != nil {
		t.Fatal(err)
	}
	initial, err := stream.Info(ctx)
	if err != nil {
		t.Fatal(err)
	}
	consumer, err := stream.CreateConsumer(ctx, jetstream.ConsumerConfig{Durable: "IDENTITY", Replicas: 3,
		AckPolicy: jetstream.AckExplicitPolicy, AckWait: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	var payloads []string
	publish := func(index int) {
		payload := fmt.Sprintf("message-%d", len(payloads)+1)
		ack, err := cluster.runtimes[index].JetStream().Publish(ctx, "formation.identity", []byte(payload))
		if err != nil || ack.Sequence != uint64(len(payloads)+1) {
			t.Fatalf("publish %q: %+v, %v", payload, ack, err)
		}
		payloads = append(payloads, payload)
	}
	for range 3 {
		publish(0)
	}
	first, err := consumer.Next(jetstream.FetchMaxWait(5 * time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if err := first.DoubleAck(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := consumer.Next(jetstream.FetchMaxWait(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	current := func(cluster *jetstream.ClusterInfo) bool {
		if cluster == nil || cluster.Leader == "" || len(cluster.Replicas) != 2 {
			return false
		}
		for _, replica := range cluster.Replicas {
			if !replica.Current || replica.Offline || replica.Lag != 0 {
				return false
			}
		}
		return true
	}
	waitForReplicas := func() {
		waitUntil(t, ctx, "current R3 stream and consumer replicas", func() bool {
			probe, cancel := context.WithTimeout(ctx, 2*time.Second)
			defer cancel()
			js := cluster.runtimes[0].JetStream()
			retained, err := js.Stream(probe, "FORMATION")
			if err != nil || !current(retained.CachedInfo().Cluster) {
				return false
			}
			worker, err := retained.Consumer(probe, "IDENTITY")
			return err == nil && current(worker.CachedInfo().Cluster)
		})
	}
	waitForReplicas()
	var identities [3]nodeIdentity
	for index, runtime := range cluster.runtimes {
		identities[index] = readNodeIdentity(t, cluster.stores[index])
		if identities[index].NodeID != runtime.server.NodeName() {
			t.Fatal("the persisted ID differs from the actual Raft node")
		}
	}
	// Model stores from before preparation: existing WALs and name ownership,
	// with no independent identity pin yet. No NATS state is removed.
	for index := range 3 {
		cluster.stop(index)
		if err := os.Remove(filepath.Join(cluster.stores[index], nodeIdentityFile)); err != nil {
			t.Fatal(err)
		}
	}
	for _, index := range []int{0, 2} {
		start(index)
		if got := readNodeIdentity(t, cluster.stores[index]); got != identities[index] {
			t.Fatalf("preparation changed persisted identity: %+v, want %+v", got, identities[index])
		}
	}
	if err := cluster.runtimes[0].WaitForCluster(ctx, 3); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, ctx, "R3 stream quorum on two retained stores", func() bool {
		probe, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		_, err := cluster.runtimes[0].JetStream().Stream(probe, "FORMATION")
		return err == nil
	})
	publish(0)
	start(1)
	for index := range 3 {
		waitUntil(t, ctx, "full metadata quorum", func() bool { return cluster.runtimes[index].FullClusterReady(3) })
		assertAdvertisedNodeID(t, cluster.runtimes[index].server.ClusterAddr().Port, identities[index].NodeID)
	}
	waitForReplicas()
	// Each rolling restart misses a write and must catch up using the same ID.
	for index := range 3 {
		cluster.stop(index)
		publish((index + 1) % 3)
		start(index)
		waitUntil(t, ctx, "metadata recovery after rolling restart", func() bool {
			return cluster.runtimes[index].FullClusterReady(3)
		})
		if got := readNodeIdentity(t, cluster.stores[index]); got != identities[index] {
			t.Fatalf("rolling restart changed identity: %+v", got)
		}
		waitForReplicas()
	}
	for _, runtime := range cluster.runtimes {
		got, err := runtime.JetStream().Stream(ctx, "FORMATION")
		if err != nil {
			t.Fatal(err)
		}
		info, err := got.Info(ctx)
		if err != nil || !info.Created.Equal(initial.Created) || info.State.Msgs != uint64(len(payloads)) || info.Config.Replicas != 3 {
			t.Fatalf("stream identity/state changed: %+v, %v", info, err)
		}
		for index, payload := range payloads {
			message, err := got.GetMsg(ctx, uint64(index+1))
			if err != nil || string(message.Data) != payload {
				t.Fatalf("message %d changed: %+v, %v", index+1, message, err)
			}
		}
		worker, err := got.Consumer(ctx, "IDENTITY")
		if err != nil {
			t.Fatal(err)
		}
		state, err := worker.Info(ctx)
		if err != nil || state.Config.Replicas != 3 || state.AckFloor.Stream != 1 || state.NumAckPending != 1 ||
			state.NumPending != uint64(len(payloads)-2) {
			t.Fatalf("durable consumer state changed: %+v, %v", state, err)
		}
		view, err := runtime.Observe(ctx)
		if err != nil || view.RaftNodeID != runtime.server.NodeName() {
			t.Fatalf("identity readback: %+v, %v", view, err)
		}
	}
}

func assertAdvertisedNodeID(t *testing.T, port int, want string) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	var info server.Info
	if err := json.Unmarshal([]byte(strings.TrimPrefix(strings.TrimSpace(line), "INFO ")), &info); err != nil || info.RaftNodeID != want {
		t.Fatalf("route advertises %q, want immutable ID %q: %v", info.RaftNodeID, want, err)
	}
}
