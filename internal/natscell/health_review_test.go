package natscell

import (
	"context"
	"errors"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/nats-io/nats.go/jetstream"
)

// A running server whose JetStream was shut down (as a store failure does)
// must not be reported as a healthy single-member metadata group.
func TestObserveClusterReportsDisabledJetStream(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	runtime, err := Start(ctx, Config{Cell: "lab", Instance: "solo", Replicas: 1, Lab: true,
		Embedded: &Embedded{Host: "127.0.0.1", Port: -1, StoreDir: filepath.Join(t.TempDir(), "solo")}})
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()
	if err := runtime.server.ShutdownJetStream(); err != nil {
		t.Fatal(err)
	}
	observation, err := runtime.ObserveCluster()
	if !errors.Is(err, ErrJetStreamDisabled) || observation.MetaLeader != "" || observation.MetaSize != 0 {
		t.Fatalf("observation = %+v, %v", observation, err)
	}
	if _, err := runtime.Observe(ctx); !errors.Is(err, ErrJetStreamDisabled) {
		t.Fatalf("Observe error = %v", err)
	}
	if _, err := runtime.StreamHealth(ctx); !errors.Is(err, ErrJetStreamDisabled) {
		t.Fatalf("StreamHealth error = %v", err)
	}
}

// A standalone broker's streams have no replicas to lag behind; they are
// reported with this broker as their only peer.
func TestStreamHealthReportsUnreplicatedStreamsOnThisBroker(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	runtime, err := Start(ctx, Config{Cell: "lab", Instance: "solo", Replicas: 1, Lab: true,
		Embedded: &Embedded{Host: "127.0.0.1", Port: -1, StoreDir: filepath.Join(t.TempDir(), "solo")}})
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()
	if _, err := runtime.JetStream().CreateKeyValue(ctx, jetstream.KeyValueConfig{Bucket: "LAGGING_TEST"}); err != nil {
		t.Fatal(err)
	}
	states, err := runtime.StreamHealth(ctx)
	if err != nil || len(states) != 1 || states[0].Lagging || !slices.Equal(states[0].Peers, []string{runtime.server.Name()}) {
		t.Fatalf("states = %+v, %v", states, err)
	}
	var stopped *Runtime
	if _, err := stopped.StreamHealth(ctx); err == nil {
		t.Fatal("a missing runtime reported no lagging streams")
	}
}

// The leader's STREAM.INFO marks a replica whose Raft log is current but
// whose out-of-band snapshot catchup is incomplete as not current (with a
// lag); such a stream is lagging, as is one without a leader or with an
// offline replica, wherever it is led.
func TestStreamLaggingJudgesEveryReplicaAsItsLeaderReports(t *testing.T) {
	t.Parallel()

	replicated := func(peers ...*jetstream.PeerInfo) *jetstream.StreamInfo {
		return &jetstream.StreamInfo{Cluster: &jetstream.ClusterInfo{Leader: "b", Replicas: peers}}
	}
	for name, test := range map[string]struct {
		info    *jetstream.StreamInfo
		lagging bool
	}{
		"no answer":          {nil, true},
		"unreplicated":       {&jetstream.StreamInfo{}, false},
		"current replicas":   {replicated(&jetstream.PeerInfo{Name: "a", Current: true}, &jetstream.PeerInfo{Name: "c", Current: true}), false},
		"snapshot catchup":   {replicated(&jetstream.PeerInfo{Name: "a", Current: true}, &jetstream.PeerInfo{Name: "c", Lag: 42}), true},
		"offline replica":    {replicated(&jetstream.PeerInfo{Name: "a", Current: true, Offline: true}), true},
		"leaderless":         {&jetstream.StreamInfo{Cluster: &jetstream.ClusterInfo{}}, true},
		"single-replica R1":  {&jetstream.StreamInfo{Cluster: &jetstream.ClusterInfo{Leader: "a"}}, false},
		"nil replica record": {replicated(nil), true},
	} {
		if got := StreamLagging(test.info); got != test.lagging {
			t.Errorf("%s: lagging = %v, want %v", name, got, test.lagging)
		}
	}
}
