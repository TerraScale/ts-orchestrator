package natscell

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/nats-io/nats.go/jetstream"
)

// labCluster uses signed JWT credentials, mutual TLS and the production seed-route
// shape: each broker lists only the other brokers' routes.
type labCluster struct {
	routes      []string
	clientPorts []int
	routePorts  []int
	stores      []string
	runtimes    []*Runtime
	region      *testRegion
	routeSecret string
}

func newLabCluster(t *testing.T, size int) *labCluster {
	t.Helper()
	ports := freeClientPorts(t, 2*size)
	cluster := &labCluster{region: productionTestRegion(t, "lab", "peer0"), routeSecret: productionRouteSecret(t), clientPorts: ports[:size], routePorts: ports[size:], stores: make([]string, size),
		runtimes: make([]*Runtime, size), routes: make([]string, size)}
	for index := range size {
		cluster.routes[index] = fmt.Sprintf("nats-route://127.0.0.1:%d", cluster.routePorts[index])
		cluster.stores[index] = filepath.Join(t.TempDir(), fmt.Sprintf("peer%d", index))
	}
	t.Cleanup(func() {
		for _, runtime := range cluster.runtimes {
			_ = runtime.Close()
		}
	})
	return cluster
}

func (cluster *labCluster) start(t *testing.T, ctx context.Context, index int) *Runtime {
	t.Helper()
	instance := fmt.Sprintf("peer%d", index)
	cfg := cluster.region.cfg
	embedded := *cfg.Embedded
	cfg.Embedded = &embedded
	cfg.Instance, cfg.Replicas = instance, len(cluster.routes)
	embedded.Port = cluster.clientPorts[index]
	embedded.RouteHost, embedded.RoutePort = "127.0.0.1", cluster.routePorts[index]
	embedded.Routes = PeerRoutes(cluster.routes, cluster.routes[index])
	embedded.StoreDir = cluster.stores[index]
	embedded.BrokerIDs = []string{"peer0", "peer1", "peer2"}[:len(cluster.routes)]
	embedded.RoutePasswordFile = cluster.routeSecret
	runtime, err := openTestBroker(t, ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	cluster.runtimes[index] = runtime
	return runtime
}

func (cluster *labCluster) stop(index int) {
	if cluster.runtimes[index] != nil {
		_ = cluster.runtimes[index].Close()
		cluster.runtimes[index] = nil
	}
}

func TestObserveStandaloneBroker(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	runtime, err := openTestBroker(t, ctx, productionTestConfig(t, "lab", "solo"))
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()
	observation, err := runtime.ObserveCluster()
	if err != nil || !observation.Running || observation.MetaLeader != "lab-solo" || observation.MetaSize != 1 {
		t.Fatalf("standalone observation = %+v, %v", observation, err)
	}
}

func TestPeerRoutesOmitsOnlySelf(t *testing.T) {
	routes := []string{"nats-route://10.0.0.1:6222", "nats-route://10.0.0.2:6222", "nats-route://10.0.0.3:6222"}
	got := PeerRoutes(routes, routes[1])
	if !slices.Equal(got, []string{routes[0], routes[2]}) {
		t.Fatalf("peer routes = %v", got)
	}
	if len(routes) != 3 || routes[1] != "nats-route://10.0.0.2:6222" {
		t.Fatal("PeerRoutes mutated its input")
	}
}

// A seed that starts alone must wait, then form the full metadata group as
// peers arrive minutes apart in production. The production route shape starts
// the metadata group at expected size two, so full readiness proves it grows.
func TestStagedFormationWithProductionRouteShape(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()
	cluster := newLabCluster(t, 3)
	seed := cluster.start(t, ctx, 0)
	short, shortCancel := context.WithTimeout(ctx, 500*time.Millisecond)
	if err := seed.WaitForCluster(short, 3); !errors.Is(err, context.DeadlineExceeded) {
		shortCancel()
		t.Fatalf("a lone seed reported quorum: %v", err)
	}
	shortCancel()
	cluster.start(t, ctx, 1)
	for _, index := range []int{0, 1} {
		if err := cluster.runtimes[index].WaitForCluster(ctx, 3); err != nil {
			t.Fatalf("peer%d did not reach 2/3 quorum: %v", index, err)
		}
	}
	cluster.start(t, ctx, 2)
	for _, runtime := range cluster.runtimes {
		waitUntil(t, ctx, "full metadata group", func() bool { return runtime.FullClusterReady(3) })
	}
	observation, err := seed.ObserveCluster()
	if err != nil {
		t.Fatal(err)
	}
	if observation.MetaSize != 3 || observation.MetaLeader == "" || len(observation.Routes) != 2 ||
		!slices.Equal(observation.ExpectedPeers, []string{"lab-peer0", "lab-peer1", "lab-peer2"}) {
		t.Fatalf("unexpected cluster observation: %+v", observation)
	}
}

// After a region-wide stop only two of three brokers return. Their persisted
// peer set lets them elect a metadata leader and serve an existing R3 stream.
func TestColdRestartWithTwoOfThreeBrokers(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	cluster := newLabCluster(t, 3)
	for index := range 3 {
		cluster.start(t, ctx, index)
	}
	for _, runtime := range cluster.runtimes {
		waitUntil(t, ctx, "full metadata group", func() bool { return runtime.FullClusterReady(3) })
	}
	if _, err := createR3Stream(ctx, cluster.runtimes[0].JetStream()); err != nil {
		t.Fatal(err)
	}
	if _, err := cluster.runtimes[0].JetStream().Publish(ctx, "formation.cold", []byte("before")); err != nil {
		t.Fatal(err)
	}
	waitForStreamState := func(runtime *Runtime, offline int) {
		t.Helper()
		var last string
		defer func() {
			if t.Failed() {
				t.Log(last)
			}
		}()
		waitUntil(t, ctx, fmt.Sprintf("%s R3 stream with %d offline replicas", runtime.serverName, offline), func() bool {
			probe, cancel := context.WithTimeout(ctx, 3*time.Second)
			defer cancel()
			states, healthErr := runtime.StreamHealth(probe)
			view, observeErr := runtime.Observe(probe)
			last = fmt.Sprintf("StreamHealth = %+v, %v; Observe = %+v, %v", states, healthErr, view, observeErr)
			if healthErr != nil || observeErr != nil || len(states) != 1 || states[0].Name != "FORMATION" ||
				len(states[0].Peers) != 3 || states[0].Lagging != (offline > 0) {
				return false
			}
			for _, stream := range view.Streams {
				if stream.Name == "FORMATION" {
					return stream.Replicas == 3 && stream.Leader != "" && stream.OfflinePeers == offline
				}
			}
			return false
		})
	}
	for _, runtime := range cluster.runtimes {
		waitForStreamState(runtime, 0)
	}
	for index := range 3 {
		cluster.stop(index)
	}
	for _, index := range []int{0, 2} {
		cluster.start(t, ctx, index)
	}
	for _, index := range []int{0, 2} {
		if err := cluster.runtimes[index].WaitForCluster(ctx, 3); err != nil {
			t.Fatalf("peer%d did not recover 2/3 quorum: %v", index, err)
		}
	}
	if cluster.runtimes[0].FullClusterReady(3) {
		t.Fatal("full cluster reported ready with one broker permanently absent")
	}
	waitUntil(t, ctx, "R3 stream readable on two brokers", func() bool {
		probe, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		existing, err := cluster.runtimes[2].JetStream().Stream(probe, "FORMATION")
		if err != nil {
			return false
		}
		info, err := existing.Info(probe)
		return err == nil && info.State.Msgs == 1
	})
	publish, publishCancel := context.WithTimeout(ctx, 10*time.Second)
	defer publishCancel()
	waitUntil(t, publish, "R3 publish with one broker absent", func() bool {
		_, err := cluster.runtimes[2].JetStream().Publish(publish, "formation.cold", []byte("after"))
		return err == nil
	})
	for _, index := range []int{0, 2} {
		waitForStreamState(cluster.runtimes[index], 1)
	}
	// Monitoring must retain the configured R3 factor when quorum and the leader disappear.
	cluster.stop(2)
	waitUntil(t, ctx, "leaderless stream retains configured R3", func() bool {
		view, err := cluster.runtimes[0].Observe(ctx)
		if err != nil {
			return false
		}
		for _, stream := range view.Streams {
			if stream.Name == "FORMATION" && stream.Leader == "" {
				if stream.Replicas != 3 {
					t.Fatalf("leaderless stream replication = %+v", stream)
				}
				return true
			}
		}
		return false
	})
	probe, probeCancel := context.WithTimeout(ctx, 3*time.Second)
	states, healthErr := cluster.runtimes[0].StreamHealth(probe)
	probeCancel()
	if healthErr == nil && (len(states) != 1 || states[0].Name != "FORMATION" || !states[0].Lagging) {
		t.Fatalf("leaderless stream reported healthy: %+v", states)
	}
	t.Logf("leaderless StreamHealth = %+v, %v", states, healthErr)
	for _, index := range []int{2, 1} {
		cluster.start(t, ctx, index)
	}
	for _, runtime := range cluster.runtimes {
		waitUntil(t, ctx, "restored full metadata group", func() bool { return runtime.FullClusterReady(3) })
		waitForStreamState(runtime, 0)
	}
	recovered, err := cluster.runtimes[1].JetStream().Stream(ctx, "FORMATION")
	if err != nil {
		t.Fatal(err)
	}
	message, err := recovered.GetMsg(ctx, 1)
	if err != nil || string(message.Data) != "before" {
		t.Fatalf("first message after recovery = %+v, %v", message, err)
	}
	// An unavailable R1 stream must hold rollout even while metadata still has quorum.
	single, err := cluster.runtimes[0].JetStream().CreateStream(ctx, jetstream.StreamConfig{
		Name: "UNAVAILABLE", Subjects: []string{"unavailable.>"}, Replicas: 1, Storage: jetstream.FileStorage})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cluster.runtimes[0].JetStream().Publish(ctx, "unavailable.probe", []byte("single-before")); err != nil {
		t.Fatal(err)
	}
	singleInfo := single.CachedInfo()
	if singleInfo.Cluster == nil || singleInfo.Cluster.Leader == "" {
		t.Fatalf("R1 stream has no assigned leader: %+v", singleInfo)
	}
	owner := singleInfo.Cluster.Leader
	ownerIndex := slices.IndexFunc(cluster.runtimes, func(runtime *Runtime) bool { return runtime.serverName == owner })
	if ownerIndex < 0 {
		t.Fatalf("R1 stream owner %q is not a lab broker", owner)
	}
	survivor := cluster.runtimes[(ownerIndex+1)%3]
	cluster.stop(ownerIndex)
	if err := survivor.WaitForCluster(ctx, 3); err != nil {
		t.Fatalf("metadata quorum did not survive the R1 owner stop: %v", err)
	}
	var lastR1Health string
	defer func() {
		if t.Failed() {
			t.Log(lastR1Health)
		}
	}()
	waitUntil(t, ctx, "unavailable R1 stream reported lagging with metadata quorum", func() bool {
		probe, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		states, err := survivor.StreamHealth(probe)
		lastR1Health = fmt.Sprintf("unavailable R1 StreamHealth = %+v, %v", states, err)
		index := slices.IndexFunc(states, func(state StreamState) bool { return state.Name == "UNAVAILABLE" })
		return err == nil && len(states) == 2 && index >= 0 && states[index].Lagging && len(states[index].Peers) == 0
	})
	t.Log(lastR1Health)
	cluster.start(t, ctx, ownerIndex)
	for _, runtime := range cluster.runtimes {
		waitUntil(t, ctx, "metadata restored after R1 owner restart", func() bool { return runtime.FullClusterReady(3) })
	}
	waitUntil(t, ctx, "R1 stream healthy on its restored owner", func() bool {
		probe, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		states, err := survivor.StreamHealth(probe)
		lastR1Health = fmt.Sprintf("restored R1 StreamHealth = %+v, %v", states, err)
		index := slices.IndexFunc(states, func(state StreamState) bool { return state.Name == "UNAVAILABLE" })
		return err == nil && len(states) == 2 && index >= 0 && !states[index].Lagging && slices.Equal(states[index].Peers, []string{owner})
	})
	single, err = survivor.JetStream().Stream(ctx, "UNAVAILABLE")
	if err != nil {
		t.Fatal(err)
	}
	message, err = single.GetMsg(ctx, 1)
	if err != nil || string(message.Data) != "single-before" {
		t.Fatalf("R1 message after owner recovery = %+v, %v", message, err)
	}
	if err := survivor.JetStream().DeleteStream(ctx, "UNAVAILABLE"); err != nil {
		t.Fatal(err)
	}
	for _, runtime := range cluster.runtimes {
		waitForStreamState(runtime, 0)
	}
}

func TestWaitForClusterFailsFastWhenEmbeddedServerStopped(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	cluster := newLabCluster(t, 3)
	runtime := cluster.start(t, ctx, 0)
	runtime.server.Shutdown()
	runtime.server.WaitForShutdown()
	started := time.Now()
	err := runtime.WaitForCluster(ctx, 3)
	if !errors.Is(err, ErrEmbeddedServerStopped) {
		t.Fatalf("WaitForCluster on a dead broker returned %v", err)
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("WaitForCluster took %s to notice a dead broker", elapsed)
	}
	observation, err := runtime.ObserveCluster()
	if err != nil || observation.Running {
		t.Fatalf("observation of a dead broker = %+v, %v", observation, err)
	}
}

// Closing a stream leader hands leadership to a current follower before the
// broker stops, so the remaining brokers keep a leader without an election gap.
func TestCloseHandsOffStreamLeadership(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()
	cluster := newLabCluster(t, 3)
	for index := range 3 {
		cluster.start(t, ctx, index)
	}
	for _, runtime := range cluster.runtimes {
		waitUntil(t, ctx, "full metadata group", func() bool { return runtime.FullClusterReady(3) })
	}
	stream, err := createR3Stream(ctx, cluster.runtimes[0].JetStream())
	if err != nil {
		t.Fatal(err)
	}
	var leader string
	waitUntil(t, ctx, "stream leader with current followers", func() bool {
		info, err := stream.Info(ctx)
		if err != nil || info.Cluster == nil || info.Cluster.Leader == "" {
			return false
		}
		for _, replica := range info.Cluster.Replicas {
			if !replica.Current {
				return false
			}
		}
		leader = info.Cluster.Leader
		return true
	})
	leaderIndex := slices.IndexFunc(cluster.runtimes, func(runtime *Runtime) bool { return runtime.serverName == leader })
	if leaderIndex < 0 {
		t.Fatalf("stream leader %q is not a lab broker", leader)
	}
	if len(cluster.runtimes[leaderIndex].ledGroups()) == 0 {
		t.Fatal("stream leader does not report its led group")
	}
	cluster.runtimes[leaderIndex].handOffLeadership(closeHandoffTimeout)
	if led := cluster.runtimes[leaderIndex].ledGroups(); len(led) != 0 {
		t.Fatalf("leader still leads %v after handoff", led)
	}
	survivor := cluster.runtimes[(leaderIndex+1)%3]
	cluster.stop(leaderIndex)
	waitUntil(t, ctx, "new stream leader", func() bool {
		probe, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		existing, err := survivor.JetStream().Stream(probe, "FORMATION")
		if err != nil {
			return false
		}
		info, err := existing.Info(probe)
		return err == nil && info.Cluster != nil && info.Cluster.Leader != "" && info.Cluster.Leader != leader
	})
}

func createR3Stream(ctx context.Context, js jetstream.JetStream) (jetstream.Stream, error) {
	var stream jetstream.Stream
	var err error
	for ctx.Err() == nil {
		attempt, cancel := context.WithTimeout(ctx, 5*time.Second)
		stream, err = js.CreateOrUpdateStream(attempt, jetstream.StreamConfig{Name: "FORMATION",
			Subjects: []string{"formation.>"}, Replicas: 3, Storage: jetstream.FileStorage})
		cancel()
		if err == nil {
			return stream, nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return nil, fmt.Errorf("create R3 stream: %w", err)
}

func waitUntil(t *testing.T, ctx context.Context, what string, ready func() bool) {
	t.Helper()
	for !ready() {
		if err := ctx.Err(); err != nil {
			t.Fatalf("%s: %v", what, err)
		}
		time.Sleep(50 * time.Millisecond)
	}
}
