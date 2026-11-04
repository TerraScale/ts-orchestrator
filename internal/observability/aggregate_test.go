package observability

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
)

func startTestNATS(t *testing.T) *nats.Conn {
	t.Helper()
	embedded, err := server.NewServer(&server.Options{Host: "127.0.0.1", Port: -1, NoLog: true, NoSigs: true})
	if err != nil {
		t.Fatal(err)
	}
	go embedded.Start()
	if !embedded.ReadyForConnections(10 * time.Second) {
		t.Fatal("test NATS server did not start")
	}
	t.Cleanup(embedded.Shutdown)
	conn, err := nats.Connect(embedded.ClientURL())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(conn.Close)
	return conn
}

func TestAggregatorGathersMembersAndReportsMissing(t *testing.T) {
	t.Parallel()
	conn := startTestNATS(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	for _, member := range []string{"one", "two"} {
		collector, _ := testCollector(t, member, nil)
		if _, err := ServeSnapshots(ctx, conn, "gru", collector); err != nil {
			t.Fatal(err)
		}
	}
	// A reply claiming another cell, and an unknown member, are ignored.
	subject := "ts.orch.v1.gru.obs.snapshot"
	if _, err := conn.Subscribe(subject, func(message *nats.Msg) {
		for _, forged := range []MemberSnapshot{{Version: 1, Cell: "sjc", Member: "three"}, {Version: 1, Cell: "gru", Member: "rogue"}} {
			data, _ := json.Marshal(forged)
			_ = conn.Publish(message.Reply, data)
		}
	}); err != nil {
		t.Fatal(err)
	}
	if err := conn.Flush(); err != nil {
		t.Fatal(err)
	}
	aggregator, err := NewAggregator(conn, "gru", []string{"two", "one", "three"}, 500*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	cluster, err := aggregator.Cluster(t.Context(), true)
	if err != nil {
		t.Fatal(err)
	}
	if len(cluster.Members) != 2 || cluster.Members[0].Member != "one" || cluster.Members[1].Member != "two" {
		t.Fatalf("members = %+v", cluster.Members)
	}
	if len(cluster.Missing) != 1 || cluster.Missing[0] != "three" {
		t.Fatalf("missing = %v", cluster.Missing)
	}
	if cluster.Members[0].Metrics == "" {
		t.Fatal("requested metrics were not included")
	}
	if elapsed := time.Since(started); elapsed < 400*time.Millisecond {
		t.Fatalf("gather with a missing member returned before its timeout: %v", elapsed)
	}

	complete, err := NewAggregator(conn, "gru", []string{"one", "two"}, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	started = time.Now()
	cluster, err = complete.Cluster(t.Context(), false)
	if err != nil || len(cluster.Members) != 2 || len(cluster.Missing) != 0 {
		t.Fatalf("complete gather = %+v, %v", cluster, err)
	}
	if time.Since(started) > 5*time.Second {
		t.Fatal("a complete roster did not end the gather early")
	}
	if cluster.Members[0].Metrics != "" {
		t.Fatal("metrics were included without being requested")
	}
}
