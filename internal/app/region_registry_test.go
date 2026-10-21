package app

import (
	"bytes"
	"context"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/atlas"
	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/globalcontrol"
	"github.com/TerraScale/ts-orchestrator/internal/naming"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/regionlink"
	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

// TestRegionRegistryBuildsAndFollowsRoster has the home keep the roster from
// heartbeats that match their subject, and a peer region follow the roster
// into its links.
func TestRegionRegistryBuildsAndFollowsRoster(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()
	srv, err := server.NewServer(&server.Options{Host: "127.0.0.1", Port: -1, JetStream: true, StoreDir: t.TempDir()})
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
	js, err := jetstream.New(conn)
	if err != nil {
		t.Fatal(err)
	}
	global, err := authority.Start(ctx, js, authority.Config{DeploymentID: "01ARZ3NDEKTSV4RRFFQ69G5FAV",
		Scope: protocol.GlobalScope, CandidateID: entityid.Derive("test-controller", protocol.GlobalScope), Replicas: 1,
		LeaseDuration: 5 * time.Second, RenewInterval: 500 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = global.Close() })
	waitRegistry(ctx, t, "global authority leader", global.Current().CanMutate)
	writer, err := globalcontrol.OpenHome(ctx, js, "gru", nil, 1, global)
	if err != nil {
		t.Fatal(err)
	}
	home := &globalControl{authority: global, writer: writer, reader: &writer.Reader}

	keeper := newRosterKeeper(home, "gru", time.Now())
	sub, err := conn.Subscribe(protocol.AnyRegionHealthSubject(), func(message *nats.Msg) {
		keeper.record(message, time.Now())
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sub.Unsubscribe() })
	if err := sendHeartbeat(conn, "gru", "sa-saopaulo-1", time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := sendHeartbeat(conn, "sjc", "us-sanjose-1", time.Now()); err != nil {
		t.Fatal(err)
	}
	// A heartbeat claiming sjc, published on fra's subject, is dropped.
	spoofed, err := protocol.EncodeJSON(globalcontrol.Heartbeat{Version: 1, Cell: "sjc", OCIRegion: "us-sanjose-1", SentAt: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	if err := conn.Publish(protocol.RegionHealthSubject("fra"), spoofed); err != nil {
		t.Fatal(err)
	}
	if err := conn.Flush(); err != nil {
		t.Fatal(err)
	}
	heard := func() int {
		keeper.mu.Lock()
		defer keeper.mu.Unlock()
		return len(keeper.seen)
	}
	waitRegistry(ctx, t, "heartbeats of gru and sjc", func() bool { return heard() == 2 })

	if err := keeper.refresh(ctx, time.Now()); err != nil {
		t.Fatal(err)
	}
	roster, _, err := writer.Roster(ctx)
	if err != nil || roster.Generation != 1 || len(roster.Regions) != 2 || !roster.Active("sjc") || roster.Active("fra") {
		t.Fatalf("roster = %+v, %v", roster, err)
	}
	if err := keeper.refresh(ctx, time.Now()); err != nil {
		t.Fatal(err)
	}
	if again, _, err := writer.Roster(ctx); err != nil || again.Generation != 1 {
		t.Fatalf("unchanged roster = %+v, %v", again, err)
	}

	peers := &rosterPeers{}
	links, err := regionlink.New("sjc", conn, nil, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	linkRoster(links, conn, peers)
	followCtx, stopFollow := context.WithCancel(ctx)
	followed := make(chan struct{})
	go func() {
		defer close(followed)
		followRoster(followCtx, &writer.Reader, "sjc", peers.apply)
	}()
	waitRegistry(ctx, t, "gru as the only peer of sjc", func() bool {
		return slices.Equal(peers.current(), []string{"gru"}) && links.Linked("gru")
	})
	stopFollow()
	<-followed
	{
		drained := make(chan struct{})
		sub.SetClosedHandler(func(string) { close(drained) })
		if err := sub.Drain(); err != nil {
			t.Fatal(err)
		}
		select {
		case <-drained:
		case <-ctx.Done():
			t.Fatalf("original heartbeat subscription did not finish: %v", ctx.Err())
		}
		if sub.IsValid() || conn.IsClosed() {
			t.Fatal("original subscription is still valid or its connection closed")
		}
		if err := conn.FlushWithContext(ctx); err != nil {
			t.Fatal(err)
		}
		encode := func(value any) []byte {
			wire, err := protocol.EncodeJSON(value)
			if err != nil {
				t.Fatal(err)
			}
			return wire
		}
		readRoster := func() (globalcontrol.Roster, uint64, []byte) {
			reader, err := globalcontrol.OpenHomeReader(ctx, js, 1)
			if err != nil {
				t.Fatal(err)
			}
			value, sequence, err := reader.Roster(ctx)
			if err != nil {
				t.Fatal(err)
			}
			stream, err := js.Stream(ctx, globalcontrol.StreamName)
			if err != nil {
				t.Fatal(err)
			}
			stored, err := stream.GetLastMsgForSubject(ctx, protocol.GlobalState(string(globalcontrol.KindRoster), globalcontrol.RosterKey))
			if err != nil {
				t.Fatal(err)
			}
			info, err := stream.Info(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if info.Config.Storage != jetstream.FileStorage || info.Config.Replicas != 1 || stored.Sequence != sequence {
				t.Fatalf("registry storage or sequence changed: %+v, %d, %d", info.Config, stored.Sequence, sequence)
			}
			return value, sequence, encode([]any{value, sequence, stored.Subject, stored.Sequence, stored.Data, stored.Header, info.State.LastSeq, info.State.Msgs})
		}
		if err := keeper.refresh(ctx, time.Now().Add(globalcontrol.RegionSilence)); err != nil {
			t.Fatal(err)
		}
		silent, silentSequence, _ := readRoster()
		if silent.Generation != 2 || silent.HomeRegion != "gru" || len(silent.Regions) != 1 ||
			silent.Regions[0] != (globalcontrol.RosterEntry{Cell: "gru", OCIRegion: "sa-saopaulo-1", State: globalcontrol.RegionActive}) {
			t.Fatalf("silence did not persist the gru-only baseline: %+v", silent)
		}
		type delivery struct {
			subject string
			wire    []byte
		}
		completed := make(chan delivery, 1)
		observed, err := conn.Subscribe(protocol.AnyRegionHealthSubject(), func(message *nats.Msg) {
			keeper.record(message, time.Now())
			select {
			case completed <- delivery{subject: message.Subject, wire: bytes.Clone(message.Data)}:
			case <-ctx.Done():
			}
		})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = observed.Unsubscribe() })
		if err := conn.FlushWithContext(ctx); err != nil {
			t.Fatal(err)
		}
		publish := func(heartbeat globalcontrol.Heartbeat) globalcontrol.Heartbeat {
			wire := encode(heartbeat)
			if len(wire) > maxHeartbeatBytes {
				t.Fatalf("original heartbeat exceeds the production decode bound: %d", len(wire))
			}
			// Invalid cells still need a valid wire subject to reach the real validator.
			subject := protocol.SubjectRoot + "." + heartbeat.Cell + "." + protocol.VerbRegionHealth
			if err := conn.Publish(subject, wire); err != nil {
				t.Fatal(err)
			}
			if err := conn.FlushWithContext(ctx); err != nil {
				t.Fatal(err)
			}
			var got delivery
			select {
			case got = <-completed:
			case <-ctx.Done():
				t.Fatalf("heartbeat callback did not finish: %v", ctx.Err())
			}
			if got.subject != subject || !bytes.Equal(got.wire, wire) {
				t.Fatalf("delivered heartbeat changed: %s %s, want %s %s", got.subject, got.wire, subject, wire)
			}
			var decoded globalcontrol.Heartbeat
			if err := protocol.DecodeStrict(got.wire, &decoded, maxHeartbeatBytes); err != nil {
				t.Fatal(err)
			}
			if decoded.Version != heartbeat.Version || decoded.Cell != heartbeat.Cell || decoded.OCIRegion != heartbeat.OCIRegion || !decoded.SentAt.Equal(heartbeat.SentAt) {
				t.Fatalf("received heartbeat differs from original input: %+v, want %+v", decoded, heartbeat)
			}
			return decoded
		}
		valid := globalcontrol.Heartbeat{Version: 1, Cell: "sjc", OCIRegion: "us-sanjose-1", SentAt: time.Now()}
		if err := valid.Validate(); err != nil {
			t.Fatal(err)
		}
		if decoded := publish(valid); decoded.Validate() != nil {
			t.Fatalf("valid heartbeat was invalid after network delivery: %+v", decoded)
		}
		keeper.mu.Lock()
		accepted, present := keeper.seen["sjc"]
		keeper.mu.Unlock()
		if !present || accepted.Version != valid.Version || accepted.Cell != valid.Cell || accepted.OCIRegion != valid.OCIRegion || accepted.SentAt.IsZero() {
			t.Fatalf("production callback did not admit the valid heartbeat: %+v", accepted)
		}
		if err := keeper.refresh(ctx, time.Now()); err != nil {
			t.Fatal(err)
		}
		stored, sequence, _ := readRoster()
		expected := globalcontrol.Roster{Generation: 3, HomeRegion: "gru", Regions: []globalcontrol.RosterEntry{
			{Cell: "gru", OCIRegion: "sa-saopaulo-1", State: globalcontrol.RegionActive},
			{Cell: "sjc", OCIRegion: "us-sanjose-1", State: globalcontrol.RegionActive},
		}}
		if sequence <= silentSequence || stored.Validate() != nil || !stored.Active("sjc") || !bytes.Equal(encode(stored), encode(expected)) {
			t.Fatalf("valid heartbeat persisted roster = %+v, %d, want %+v after %d", stored, sequence, expected, silentSequence)
		}
		seenBytes := func() []byte {
			keeper.mu.Lock()
			defer keeper.mu.Unlock()
			return encode(keeper.seen)
		}
		for name, mutate := range map[string]func(*globalcontrol.Heartbeat){
			"version":    func(h *globalcontrol.Heartbeat) { h.Version = 2 },
			"global":     func(h *globalcontrol.Heartbeat) { h.Cell = "global" },
			"cell":       func(h *globalcontrol.Heartbeat) { h.Cell = "SJC" },
			"oci region": func(h *globalcontrol.Heartbeat) { h.OCIRegion = "" },
			"long":       func(h *globalcontrol.Heartbeat) { h.OCIRegion = string(make([]byte, 65)) },
			"charset":    func(h *globalcontrol.Heartbeat) { h.OCIRegion = "US_SANJOSE 1" },
			"short":      func(h *globalcontrol.Heartbeat) { h.OCIRegion = "us" },
			"sent":       func(h *globalcontrol.Heartbeat) { h.SentAt = time.Time{} },
		} {
			heartbeat := valid
			mutate(&heartbeat)
			if heartbeat.Validate() == nil {
				t.Errorf("%s accepted: %+v", name, heartbeat)
			}
			beforeSeen := seenBytes()
			_, _, beforeStored := readRoster()
			if decoded := publish(heartbeat); decoded.Validate() == nil {
				t.Errorf("%s accepted after network delivery: %+v", name, decoded)
			}
			if afterSeen := seenBytes(); !bytes.Equal(afterSeen, beforeSeen) {
				t.Fatalf("%s rejected heartbeat changed keeper: before %s, after %s", name, beforeSeen, afterSeen)
			}
			if err := keeper.refresh(ctx, time.Now()); err != nil {
				t.Fatal(err)
			}
			if _, _, afterStored := readRoster(); !bytes.Equal(afterStored, beforeStored) {
				t.Fatalf("%s rejected heartbeat changed persisted roster: before %s, after %s", name, beforeStored, afterStored)
			}
		}
	}

	{
		data, err := os.ReadFile("../../deploy/oci-region/atlas-gru-1.json")
		if err != nil {
			t.Fatal(err)
		}
		var gru atlas.Config
		if err := protocol.DecodeStrict(data, &gru, 64<<10); err != nil {
			t.Fatal(err)
		}
		gru.Regions = gru.Regions[:1]
		gru.Regions[0].Name = "Sao Paulo (reviewed)"
		ids := func(config atlas.Config) []string {
			var ids []string
			for _, region := range config.Regions {
				ids = append(ids, region.ID)
			}
			return ids
		}

		readerConn, err := nats.Connect(srv.ClientURL(), nats.Timeout(5*time.Second))
		if err != nil {
			t.Fatal(err)
		}
		defer readerConn.Close()
		readerJS, err := jetstream.New(readerConn)
		if err != nil {
			t.Fatal(err)
		}
		reader, err := globalcontrol.OpenHomeReader(ctx, readerJS, 1)
		if err != nil {
			t.Fatal(err)
		}
		baseline, baselineSequence, err := reader.Roster(ctx)
		wantBaseline := globalcontrol.Roster{Generation: 3, HomeRegion: "gru", Regions: []globalcontrol.RosterEntry{
			{Cell: "gru", OCIRegion: "sa-saopaulo-1", State: globalcontrol.RegionActive},
			{Cell: "sjc", OCIRegion: "us-sanjose-1", State: globalcontrol.RegionActive},
		}}
		if err != nil || baselineSequence == 0 || baseline.Generation != wantBaseline.Generation || baseline.HomeRegion != wantBaseline.HomeRegion || !slices.Equal(baseline.Regions, wantBaseline.Regions) {
			t.Fatalf("persisted baseline = %+v at %d: %v", baseline, baselineSequence, err)
		}
		stream, err := readerJS.Stream(ctx, globalcontrol.StreamName)
		if err != nil {
			t.Fatal(err)
		}
		info, err := stream.Info(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if info.Config.Storage != jetstream.FileStorage || info.Config.Replicas != 1 {
			t.Fatalf("roster storage = %+v", info.Config)
		}

		expanded := globalcontrol.Roster{Generation: 4, HomeRegion: "gru", Regions: []globalcontrol.RosterEntry{
			{Cell: "fra", OCIRegion: "eu-frankfurt-1", State: globalcontrol.RegionActive},
			{Cell: "gru", OCIRegion: "sa-saopaulo-1", State: globalcontrol.RegionActive},
			{Cell: "sjc", OCIRegion: "us-sanjose-1", State: globalcontrol.RegionActive},
		}}
		// Publish roster records only: the earlier heartbeat observer remains subscribed.
		expandedSequence, err := writer.PutRoster(ctx, global.Current().Epoch, expanded)
		if err != nil || expandedSequence <= baselineSequence {
			t.Fatalf("expanded roster publish = %d after %d: %v", expandedSequence, baselineSequence, err)
		}
		stored, sequence, err := reader.Roster(ctx)
		if err != nil || sequence != expandedSequence || stored.Generation != expanded.Generation || stored.HomeRegion != expanded.HomeRegion || !slices.Equal(stored.Regions, expanded.Regions) {
			t.Fatalf("expanded roster = %+v at %d, want %+v at %d: %v", stored, sequence, expanded, expandedSequence, err)
		}
		cells := make([]string, 0, len(stored.Regions))
		for _, region := range stored.Regions {
			cell, err := naming.RegionCell(region.Cell).Name()
			if err != nil {
				t.Fatal(err)
			}
			cells = append(cells, cell)
		}
		if !slices.Equal(cells, []string{"fra-1", "gru-1", "sjc-1"}) {
			t.Fatalf("stored Atlas cells = %v", cells)
		}
		// Reverse the observed roster to retain the original unsorted WithRegions input.
		slices.Reverse(cells)
		if !slices.Equal(cells, []string{"sjc-1", "gru-1", "fra-1"}) {
			t.Fatalf("original Atlas input changed: %v", cells)
		}
		next, err := gru.WithRegions(cells)
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(ids(next), []string{"gru-1", "sjc-1", "fra-1"}) {
			t.Fatalf("regions = %v", ids(next))
		}
		if next.Regions[0] != gru.Regions[0] {
			t.Fatalf("spec entry replaced: %+v", next.Regions[0])
		}
		if want, _ := atlas.RegionFor("sjc-1"); next.Regions[1] != want {
			t.Fatalf("derived sjc-1 = %+v", next.Regions[1])
		}
		if len(gru.Regions) != 1 {
			t.Fatal("WithRegions changed its receiver's regions")
		}
		if err := next.Validate("gru"); err != nil {
			t.Fatal(err)
		}

		shrink := globalcontrol.Roster{Generation: 5, HomeRegion: "gru", Regions: []globalcontrol.RosterEntry{
			{Cell: "gru", OCIRegion: "sa-saopaulo-1", State: globalcontrol.RegionActive},
		}}
		shrinkSequence, err := writer.PutRoster(ctx, global.Current().Epoch, shrink)
		if err != nil || shrinkSequence <= expandedSequence {
			t.Fatalf("shrunk roster publish = %d after %d: %v", shrinkSequence, expandedSequence, err)
		}
		stored, sequence, err = reader.Roster(ctx)
		if err != nil || sequence != shrinkSequence || stored.Generation != shrink.Generation || stored.HomeRegion != shrink.HomeRegion || !slices.Equal(stored.Regions, shrink.Regions) {
			t.Fatalf("shrunk roster = %+v at %d, want %+v at %d: %v", stored, sequence, shrink, shrinkSequence, err)
		}
		shrinkCells := make([]string, 0, len(stored.Regions))
		for _, region := range stored.Regions {
			cell, err := naming.RegionCell(region.Cell).Name()
			if err != nil {
				t.Fatal(err)
			}
			shrinkCells = append(shrinkCells, cell)
		}
		if !slices.Equal(shrinkCells, []string{"gru-1"}) {
			t.Fatalf("original Atlas shrink input changed: %v", shrinkCells)
		}
		if shrunk, err := next.WithRegions(shrinkCells); err != nil || !slices.Equal(ids(shrunk), []string{"gru-1"}) {
			t.Fatalf("roster without sjc-1 and fra-1 = %v %v", ids(shrunk), err)
		}
	}

}

// waitRegistry polls cond until it holds or ctx ends.
func waitRegistry(ctx context.Context, t *testing.T, what string, cond func() bool) {
	t.Helper()
	for !cond() {
		if ctx.Err() != nil {
			t.Fatalf("%s: %v", what, ctx.Err())
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// The Atlas loop lists the local cell and the live roster peers, keeps the
// spec's entry for a listed region, and falls back to the spec when the roster
// names a region the catalog cannot describe.
func TestAtlasRosterListsTheLiveRoster(t *testing.T) {
	spec := &atlas.Config{Regions: []atlas.Region{{ID: "gru-1", Name: "Sao Paulo (reviewed)",
		API: "https://gru.api.terrascale.tech", Auth: "https://gru.auth.terrascale.tech"}}}
	peers := &rosterPeers{}
	config := atlasRoster(func() *atlas.Config { return spec }, "gru", peers)
	ids := func(c *atlas.Config) []string {
		var ids []string
		for _, region := range c.Regions {
			ids = append(ids, region.ID)
		}
		return ids
	}
	if got := config(); got != spec {
		t.Fatalf("before the first roster the spec's regions must stay: %+v", got.Regions)
	}
	peers.apply(nil)
	if got := config(); !slices.Equal(ids(got), []string{"gru-1"}) || got.Regions[0].Name != "Sao Paulo (reviewed)" {
		t.Fatalf("alone: %+v", got.Regions)
	}
	peers.apply([]string{"sjc", "fra"})
	if got := config(); !slices.Equal(ids(got), []string{"gru-1", "sjc-1", "fra-1"}) || got.Regions[0].Name != "Sao Paulo (reviewed)" {
		t.Fatalf("with roster: %+v", got.Regions)
	}
	peers.apply([]string{"zzz"})
	if got := config(); got != spec {
		t.Fatalf("unlistable roster must keep the spec: %+v", got.Regions)
	}
	if got := atlasRoster(func() *atlas.Config { return nil }, "gru", peers)(); got != nil {
		t.Fatal("no spec section must publish nothing")
	}
}
