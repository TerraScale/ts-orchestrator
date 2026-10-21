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

	"github.com/TerraScale/ts-orchestrator/internal/regionlink"
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
		Subject: Subject{Kind: "release", ID: "0000000000HYGTY0DVBVSP34H6"}, Status: StatusInProgress})
	for index := range 5 {
		writer.Record(ctx, Decision{Kind: KindBatchPromoted, Actor: Actor{Slice: "rollout"}, ParentID: parent,
			Subject: Subject{Kind: "release", ID: "0000000000HYGTY0DVBVSP34H6"}, Summary: fmt.Sprint("batch ", index)})
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

	t.Run("retainedArchiveWindowOrder", func(t *testing.T) {
		stream := openTestStream(t, startJetStream(t))
		base := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
		journal := NewJournal(JournalConfig{Region: "gru", Capacity: 2, Archive: stream})
		for index := range 6 {
			decision := Decision{ID: fmt.Sprintf("d%d", index), Region: "gru",
				Kind: KindHeld, Time: base.Add(time.Duration(index) * time.Minute)}
			if err := stream.Publish(t.Context(), decision); err != nil {
				t.Fatal(err)
			}
			journal.Ingest(decision)
		}
		result, err := journal.Query(t.Context(), Query{Since: base})
		if err != nil || len(result.Decisions) != 6 || result.Partial {
			t.Fatalf("result = %+v, %v", result, err)
		}
		for index, decision := range result.Decisions {
			if decision.ID != fmt.Sprintf("d%d", 5-index) {
				t.Fatalf("order %d = %s", index, decision.ID)
			}
		}
	})

	t.Run("retainedArchiveChainCompleteness", func(t *testing.T) {
		stream := openTestStream(t, startJetStream(t))
		base := time.Now().Add(-time.Hour).UTC()
		root := Decision{ID: newIDAt(base), Region: "gru", Kind: KindReleaseAdmitted, Time: base}
		canary := Decision{ID: newIDAt(base.Add(time.Minute)), Region: "gru", Kind: KindUpgradeStarted,
			ParentID: root.ID, Time: base.Add(time.Minute)}
		batch := Decision{ID: newIDAt(base.Add(2 * time.Minute)), Region: "gru", Kind: KindCanaryPromoted,
			ParentID: canary.ID, Time: base.Add(2 * time.Minute)}
		done := Decision{ID: newIDAt(base.Add(3 * time.Minute)), Region: "gru", Kind: KindRolloutCompleted,
			ParentID: batch.ID, Time: base.Add(3 * time.Minute)}
		journal := NewJournal(JournalConfig{Region: "gru", Capacity: 2, Archive: stream})
		for _, decision := range []Decision{root, canary, batch, done} {
			if err := stream.Publish(t.Context(), decision); err != nil {
				t.Fatal(err)
			}
			journal.Ingest(decision)
		}
		chain, err := journal.Chain(t.Context(), done.ID)
		if err != nil {
			t.Fatal(err)
		}
		if chain.Root.ID != root.ID || len(chain.Decisions) != 4 || chain.Latest.ID != done.ID {
			t.Fatalf("chain = %+v", chain)
		}
		if _, err := journal.Chain(t.Context(), "missing"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("missing chain err = %v", err)
		}
	})

	t.Run("retainedArchiveClockSkew", func(t *testing.T) {
		stream := openTestStream(t, startJetStream(t))
		base := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
		older := Decision{ID: "00000000007M2BHZ0MP819C5RF", Region: "gru", Kind: KindHeld, Time: base.Add(time.Minute)}
		// Published first by a controller whose clock runs ahead.
		ahead := Decision{ID: "0000000000HPQQ4SQ462GH8ZMJ", Region: "gru", Kind: KindHeld, Time: base.Add(4 * time.Minute)}
		newest := []Decision{{ID: "n1", Region: "gru", Kind: KindHeld, Time: base.Add(5 * time.Minute)},
			{ID: "n2", Region: "gru", Kind: KindHeld, Time: base.Add(6 * time.Minute)}}
		for _, decision := range []Decision{ahead, older, newest[0], newest[1]} {
			if err := stream.Publish(t.Context(), decision); err != nil {
				t.Fatal(err)
			}
		}
		journal := NewJournal(JournalConfig{Region: "gru", Capacity: 3, Archive: stream})
		journal.Ingest(ahead)
		for _, decision := range newest {
			journal.Ingest(decision)
		}
		journal.MarkCoveredFrom(base.Add(2 * time.Minute))
		result, _ := journal.Query(t.Context(), Query{Since: base})
		found := map[string]bool{}
		for _, decision := range result.Decisions {
			found[decision.ID] = true
		}
		if !found["00000000007M2BHZ0MP819C5RF"] {
			t.Fatalf("an archived record behind a skewed one was skipped: %+v", result)
		}
	})

	t.Run("retainedArchiveUnavailable", func(t *testing.T) {
		conn := startJetStream(t)
		stream := openTestStream(t, conn)
		if complete, err := stream.Scan(t.Context(), time.Time{}, 1, func(Decision) bool { return true }); err != nil || !complete {
			t.Fatalf("archive before outage: complete=%v err=%v", complete, err)
		}
		journal := NewJournal(JournalConfig{Region: "gru", Capacity: 2, Archive: stream})
		missing := newIDAt(time.Now().Add(-time.Hour))
		conn.Close()
		if _, err := journal.Chain(t.Context(), missing); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("an archive outage = %v, want ErrUnavailable", err)
		}
	})

	t.Run("retainedArchiveLongChain", func(t *testing.T) {
		stream := openTestStream(t, startJetStream(t))
		base := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
		decisions := []Decision{{ID: "root", Time: base}}
		for index := range MaxQueryLimit + 10 {
			decisions = append(decisions, Decision{ID: fmt.Sprintf("c%05d", index), ParentID: "root",
				Time: base.Add(time.Duration(index+1) * time.Second)})
		}
		for _, decision := range decisions {
			if err := stream.Publish(t.Context(), decision); err != nil {
				t.Fatal(err)
			}
		}
		journal := NewJournal(JournalConfig{Region: "gru", Capacity: 1, Archive: stream})
		last := decisions[len(decisions)-1]
		chain, err := journal.Chain(t.Context(), last.ID)
		if err != nil || !chain.Truncated || chain.Latest.ID != last.ID || len(chain.Decisions) > MaxQueryLimit ||
			chain.Decisions[0].ID != "root" || chain.Decisions[len(chain.Decisions)-1].ID != last.ID {
			t.Fatalf("chain: truncated=%v latest=%s len=%d err=%v", chain.Truncated, chain.Latest.ID, len(chain.Decisions), err)
		}
		middle := decisions[5].ID
		if chain, _ := journal.Chain(t.Context(), middle); !containsID(chain.Decisions, middle) {
			t.Fatal("a truncated chain dropped the requested decision")
		}
	})

	t.Run("retainedArchiveOutOfOrder", func(t *testing.T) {
		stream := openTestStream(t, startJetStream(t))
		base := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
		t3 := Decision{ID: "t3", Region: "gru", Kind: KindHeld, Time: base.Add(3 * time.Minute)}
		t1 := Decision{ID: "t1", Region: "gru", Kind: KindHeld, Time: base.Add(time.Minute)}
		t2 := Decision{ID: "t2", Region: "gru", Kind: KindHeld, Time: base.Add(2 * time.Minute)}
		journal := NewJournal(JournalConfig{Region: "gru", Capacity: 2, Archive: stream})
		for _, decision := range []Decision{t3, t1, t2} {
			if err := stream.Publish(t.Context(), decision); err != nil {
				t.Fatal(err)
			}
			journal.Ingest(decision)
		}
		result, err := journal.Query(t.Context(), Query{Limit: 1})
		if err != nil || len(result.Decisions) != 1 || result.Decisions[0].ID != "t3" {
			t.Fatalf("newest page = %+v (%v), want the evicted t3", result.Decisions, err)
		}
	})
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
	remote.Ingest(Decision{ID: "0000000000RPYNQGXVXJSC20CX", Region: "gru", Kind: KindRollback, Time: base}.Normalize(base))
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
	data, err := encodeReply(remoteReply{Version: wireVersion, Result: &result}, "", 8<<10)
	if err != nil || len(data) > 8<<10 {
		t.Fatalf("len=%d err=%v", len(data), err)
	}
}

// A replay whose consumer broke half way resumes from the next sequence; it
// must still end once the sequence the stream held at the start is read,
// not leave every later query partial for the life of the process.
func TestResumedReplayStillEnds(t *testing.T) {
	conn := startJetStream(t)
	stream := openTestStream(t, conn)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	writer := NewJournal(JournalConfig{Region: "gru", Member: "ctrl-1", Sink: stream})
	go func() { _ = writer.Run(ctx) }()
	for index := range 4 {
		writer.Record(ctx, Decision{Kind: KindHeld, Actor: Actor{Slice: "placement"}, Summary: fmt.Sprint(index)})
	}
	waitFor(t, func() bool { return writer.Stats().Published == 4 })
	info, err := stream.stream.Info(ctx)
	if err != nil {
		t.Fatal(err)
	}
	reader := NewJournal(JournalConfig{Region: "gru", Member: "ctrl-2"})
	reader.beginReplay()
	// The first consumer read the first two messages before it broke.
	next, caughtUp := uint64(3), info.State.LastSeq
	go func() { _ = stream.tailOnce(ctx, reader, 100, &next, &caughtUp) }()
	waitFor(t, func() bool { return !reader.replaying.Load() })
}

// A local journal that cannot answer (it is still replaying) must not stop
// the federation from finding a chain held by another region, and a miss
// everywhere is unavailable rather than not found.
func TestFederatedChainSearchesPastAnUnavailableLocalJournal(t *testing.T) {
	conn := startJetStream(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	local := NewJournal(JournalConfig{Region: "gru", Member: "gru-1"})
	local.beginReplay()
	remote := NewJournal(JournalConfig{Region: "sfo", Member: "sfo-1"})
	remoteID := remote.Record(ctx, Decision{Kind: KindScaleUp, Actor: Actor{Slice: "autoscale"}})
	if _, err := ServeQueries(ctx, conn, "sfo", remote); err != nil {
		t.Fatal(err)
	}
	links, err := regionlink.New("GRU", conn, []string{"GRU", "SFO"}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := links.Link("sfo", conn); err != nil {
		t.Fatal(err)
	}
	federation := Federation{Local: local, Links: links}
	chain, err := federation.Chain(ctx, remoteID)
	if err != nil || chain.Root.ID != remoteID {
		t.Fatalf("remote chain behind a replaying local journal = %+v err=%v", chain, err)
	}
	if _, err := federation.Chain(ctx, "missing"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("miss with an unavailable local journal = %v, want ErrUnavailable", err)
	}
	if _, err := (Federation{Local: local}).Chain(ctx, "missing"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("miss without links = %v, want ErrUnavailable", err)
	}
}

// A configured region without a link was never searched: a chain miss is
// unavailable, not absent.
func TestFederatedChainMissWithUnlinkedRegionIsUnavailable(t *testing.T) {
	conn := startJetStream(t)
	local := NewJournal(JournalConfig{Region: "gru", Member: "gru-1"})
	links, err := regionlink.New("GRU", conn, []string{"GRU", "SFO"}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := (Federation{Local: local, Links: links}).Chain(t.Context(), NewID()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("miss with an unlinked region = %v, want ErrUnavailable", err)
	}
}
