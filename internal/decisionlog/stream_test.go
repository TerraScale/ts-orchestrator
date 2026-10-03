package decisionlog

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/regionlink"
)

func startJetStream(t *testing.T) *nats.Conn {
	t.Helper()
	srv, err := server.NewServer(&server.Options{Host: "127.0.0.1", Port: -1, JetStream: true,
		StoreDir: t.TempDir(), NoLog: true, NoSigs: true})
	if err != nil {
		t.Fatal(err)
	}
	go srv.Start()
	if !srv.ReadyForConnections(5 * time.Second) {
		t.Fatal("NATS did not start")
	}
	t.Cleanup(func() { srv.Shutdown(); srv.WaitForShutdown() })
	conn, err := nats.Connect(srv.ClientURL())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(conn.Close)
	return conn
}

func openTestStream(t *testing.T, conn *nats.Conn) *Stream {
	t.Helper()
	js, err := jetstream.New(conn)
	if err != nil {
		t.Fatal(err)
	}
	stream, err := OpenStream(t.Context(), js, StreamConfig{Cell: "gru", Replicas: 1})
	if err != nil {
		t.Fatal(err)
	}
	return stream
}

func TestStreamPublishTailAndScan(t *testing.T) {
	conn := startJetStream(t)
	stream := openTestStream(t, conn)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	writer := NewJournal(JournalConfig{Region: "gru", Member: "ctrl-1", Sink: stream, Archive: stream})
	go func() { _ = writer.Run(ctx) }()
	parent := writer.Record(ctx, Decision{Kind: KindReleaseAdmitted, Actor: Actor{Slice: "rollout"},
		Subject: Subject{Kind: "release", ID: "sha256:aa"}, Status: StatusInProgress})
	for index := range 5 {
		writer.Record(ctx, Decision{Kind: KindBatchPromoted, Actor: Actor{Slice: "rollout"}, ParentID: parent,
			Subject: Subject{Kind: "release", ID: "sha256:aa"}, Summary: fmt.Sprint("batch ", index)})
	}
	waitFor(t, func() bool { return writer.Stats().Published == 6 })

	// A second member with a small window warms from the stream tail and
	// then follows new decisions recorded by the first.
	reader := NewJournal(JournalConfig{Region: "gru", Member: "ctrl-2", Capacity: 3, Archive: stream})
	go func() { _ = stream.Tail(ctx, reader, 3) }()
	waitFor(t, func() bool { return reader.Stats().Indexed == 3 })
	late := writer.Record(ctx, Decision{Kind: KindRolloutCompleted, Actor: Actor{Slice: "rollout"}, ParentID: parent})
	waitFor(t, func() bool {
		result, _ := reader.Query(ctx, Query{Kinds: []Kind{KindRolloutCompleted}})
		return len(result.Decisions) == 1 && result.Decisions[0].ID == late
	})
	// Older decisions come from the archive.
	result, err := reader.Query(ctx, Query{Since: time.Now().Add(-time.Hour)})
	if err != nil || len(result.Decisions) != 7 || result.Partial {
		t.Fatalf("archive query = %d decisions partial=%v err=%v", len(result.Decisions), result.Partial, err)
	}
	chain, err := reader.Chain(ctx, late)
	if err != nil || chain.Root.ID != parent || len(chain.Decisions) != 7 || chain.Latest.ID != late {
		t.Fatalf("chain = %+v err=%v", chain, err)
	}
	// Publishing the same ID twice is deduplicated by the stream.
	again, _ := writer.Query(ctx, Query{Kinds: []Kind{KindRolloutCompleted}})
	if err := stream.Publish(ctx, again.Decisions[0]); err != nil {
		t.Fatal(err)
	}
	complete, err := stream.Scan(ctx, time.Time{}, 100, func(Decision) bool { return true })
	if err != nil || !complete {
		t.Fatalf("scan complete=%v err=%v", complete, err)
	}
	info, _ := stream.stream.Info(ctx)
	if info.State.Msgs != 7 {
		t.Fatalf("stream holds %d messages", info.State.Msgs)
	}
}

func TestStreamScanStopsAtBound(t *testing.T) {
	conn := startJetStream(t)
	stream := openTestStream(t, conn)
	for index := range 10 {
		decision := Decision{Region: "gru", Kind: KindHeld, Summary: fmt.Sprint(index)}.Normalize(time.Now())
		if err := stream.Publish(t.Context(), decision); err != nil {
			t.Fatal(err)
		}
	}
	visited := 0
	complete, err := stream.Scan(t.Context(), time.Time{}, 4, func(Decision) bool { visited++; return true })
	if err != nil || complete || visited != 4 {
		t.Fatalf("complete=%v visited=%d err=%v", complete, visited, err)
	}
	visited = 0
	complete, err = stream.Scan(t.Context(), time.Now().Add(time.Hour), 4, func(Decision) bool { visited++; return true })
	if err != nil || !complete || visited != 0 {
		t.Fatalf("future scan complete=%v visited=%d err=%v", complete, visited, err)
	}
}

func TestFederationAcrossRegions(t *testing.T) {
	conn := startJetStream(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	base := time.Now().Add(-time.Minute).UTC()
	local := NewJournal(JournalConfig{Region: "gru", Member: "gru-1"})
	remote := NewJournal(JournalConfig{Region: "sfo", Member: "sfo-1"})
	local.Record(ctx, Decision{Kind: KindHeld, Time: base, Actor: Actor{Slice: "placement"}})
	remoteID := remote.Record(ctx, Decision{Kind: KindScaleUp, Time: base.Add(time.Second),
		Actor: Actor{Slice: "autoscale"}})
	// A misbehaving responder must not answer for another region.
	remote.Ingest(Decision{ID: "forged", Region: "gru", Kind: KindRollback, Time: base}.Normalize(base))
	if _, err := ServeQueries(ctx, conn, "sfo", remote); err != nil {
		t.Fatal(err)
	}
	links, err := regionlink.New("GRU", conn, []string{"GRU", "SFO", "FRA", "MIA"}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := links.Link("sfo", conn); err != nil {
		t.Fatal(err)
	}
	if err := links.Link("mia", conn); err != nil { // linked but nobody answers
		t.Fatal(err)
	}
	federation := Federation{Local: local, Links: links}
	result, err := federation.Query(ctx, Query{})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Decisions) != 2 || result.Decisions[0].Region != "sfo" || result.Decisions[1].Region != "gru" {
		t.Fatalf("decisions = %+v", result.Decisions)
	}
	states := map[string]string{}
	for _, status := range result.Regions {
		states[status.Region] = status.State
	}
	if states["gru"] != RegionOK || states["sfo"] != RegionOK || states["fra"] != RegionNotLinked ||
		states["mia"] != RegionUnreachable {
		t.Fatalf("states = %v", states)
	}
	if !result.Partial {
		t.Fatal("an unreachable region must mark the result partial")
	}
	filtered, _ := federation.Query(ctx, Query{Regions: []string{"SFO"}, Actors: []string{"autoscale"}})
	if len(filtered.Decisions) != 1 || len(filtered.Regions) != 1 {
		t.Fatalf("filtered = %+v", filtered)
	}
	chain, err := federation.Chain(ctx, remoteID)
	if err != nil || chain.Root.ID != remoteID {
		t.Fatalf("remote chain = %+v err=%v", chain, err)
	}
	// MIA is linked but does not answer: a miss is not proof of absence.
	if _, err := federation.Chain(ctx, "missing"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("chain with an unreachable region = %v, want ErrUnavailable", err)
	}
	// A configured region that is not linked was not searched either.
	linked, _ := federation.Query(ctx, Query{Regions: []string{"gru", "fra"}})
	if !linked.Partial {
		t.Fatal("an unlinked configured region left the result complete")
	}
}

func TestEncodeReplyTrimsToLimit(t *testing.T) {
	result := Result{}
	for index := range 200 {
		result.Decisions = append(result.Decisions, Decision{ID: fmt.Sprint(index), Summary: fmt.Sprintf("%0200d", index)})
	}
	data, err := encodeReply(remoteReply{Version: wireVersion, Result: &result}, 8<<10)
	if err != nil || len(data) > 8<<10 {
		t.Fatalf("len=%d err=%v", len(data), err)
	}
}
