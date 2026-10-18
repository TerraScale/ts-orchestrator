package globalcontrol

import (
	"context"
	"errors"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

func testRoster(generation uint64) Roster {
	return Roster{Generation: generation, HomeRegion: "gru", Regions: []RosterEntry{
		{Cell: "fra", OCIRegion: "eu-frankfurt-1", State: RegionProvisioning},
		{Cell: "gru", OCIRegion: "sa-saopaulo-1", State: RegionActive},
		{Cell: "sfo", OCIRegion: "us-sanjose-1", State: RegionActive},
	}}
}

func TestDirectoryValidation(t *testing.T) {
	t.Parallel()

	entry := DirectoryEntry{DatabaseID: "00000000004SJMRETVW39JX054", PartitionID: "00000000003K6TBW31R91GBDRD", HomeRegion: "gru", ActiveRegions: []string{"gru", "sfo"}, Generation: 1}
	if err := entry.ValidateAgainst(testRoster(1)); err != nil {
		t.Fatal(err)
	}
	if entry.Key() != DirectoryKey(entry.DatabaseID, entry.PartitionID) || DirectoryKey("a--b", "c") == DirectoryKey("a", "b--c") {
		t.Fatalf("directory keys collide or changed: %q", entry.Key())
	}
	provisioning := entry
	provisioning.ActiveRegions = []string{"fra", "gru"}
	if err := provisioning.ValidateAgainst(testRoster(1)); err == nil {
		t.Fatal("directory placed a partition in a non-active region")
	}
	cases := map[string]func(*DirectoryEntry){
		"no generation":   func(d *DirectoryEntry) { d.Generation = 0 },
		"bad database":    func(d *DirectoryEntry) { d.DatabaseID = "DB" },
		"dotted database": func(d *DirectoryEntry) { d.DatabaseID = "db.1" },
		"home not active": func(d *DirectoryEntry) { d.HomeRegion = "fra" },
		"unsorted":        func(d *DirectoryEntry) { d.ActiveRegions = []string{"sfo", "gru"} },
		"duplicate":       func(d *DirectoryEntry) { d.ActiveRegions = []string{"gru", "gru"} },
		"empty":           func(d *DirectoryEntry) { d.ActiveRegions = nil },
		"too many":        func(d *DirectoryEntry) { d.ActiveRegions = []string{"a", "b", "c", "d", "e", "gru"} },
	}
	for name, mutate := range cases {
		candidate := entry
		candidate.ActiveRegions = append([]string(nil), entry.ActiveRegions...)
		mutate(&candidate)
		if err := candidate.Validate(); err == nil {
			t.Errorf("%s directory entry validated", name)
		}
	}
}

func TestMirrorConfigIsReadOnlyAndPinnedToHome(t *testing.T) {
	t.Parallel()

	config := MirrorStreamConfig("gru", "sfo", 3)
	if len(config.Subjects) != 0 || config.Mirror == nil ||
		config.Mirror.External.APIPrefix != "$JS.gru.API" ||
		config.Mirror.External.DeliverPrefix != "" || config.Mirror.Consumer == nil ||
		config.Mirror.Consumer.Name != "global-mirror-sfo" ||
		config.Mirror.Consumer.DeliverSubject != "ts.interregion.v1.sfo.global" {
		t.Fatalf("mirror config = %+v", config)
	}
	if err := verifyMirror(config, "gru", "sfo", 3); err != nil {
		t.Fatal(err)
	}
	if err := verifyHome(HomeStreamConfig(3), 3); err != nil {
		t.Fatal(err)
	}
	if err := verifyHome(config, 3); err == nil {
		t.Fatal("mirror verified as the writable home stream")
	}
	tampered := []func(*jetstream.StreamConfig){
		func(c *jetstream.StreamConfig) { c.Subjects = []string{protocol.GlobalStateStreamSubject()} },
		func(c *jetstream.StreamConfig) { c.Mirror.External.APIPrefix = "$JS.sfo.API" },
		func(c *jetstream.StreamConfig) { c.Mirror.External.DeliverPrefix = "ts.interregion.v1.sfo.global" },
		func(c *jetstream.StreamConfig) { c.Mirror.Consumer = nil },
		func(c *jetstream.StreamConfig) {
			c.Mirror.Consumer = &jetstream.StreamConsumerSource{Name: "global-mirror-fra", DeliverSubject: "ts.interregion.v1.sfo.global"}
		},
		func(c *jetstream.StreamConfig) {
			c.Mirror.Consumer = &jetstream.StreamConsumerSource{Name: "global-mirror-sfo", DeliverSubject: "ts.orch.v1.sfo.placement.apply"}
		},
		func(c *jetstream.StreamConfig) { c.Mirror.FilterSubject = "ts.global.v1.roster.>" },
		func(c *jetstream.StreamConfig) { c.DenyPurge = false },
		func(c *jetstream.StreamConfig) {
			c.Metadata = map[string]string{"terrascale-contract": contract, "terrascale-role": "mirror", "terrascale-home": "sfo"}
		},
	}
	for index, mutate := range tampered {
		candidate := MirrorStreamConfig("gru", "sfo", 3)
		mutate(&candidate)
		if err := verifyMirror(candidate, "gru", "sfo", 3); err == nil {
			t.Errorf("tampered mirror %d verified", index)
		}
	}
	if _, err := OpenMirror(t.Context(), nil, "gru", "gru", 1); err == nil {
		t.Fatal("home region opened a mirror of itself")
	}
}

func TestHomeWriterGuardsAndCompareAndSets(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	js := newTestJetStream(t)
	global := startAuthority(ctx, t, js, protocol.GlobalScope)
	regional := startAuthority(ctx, t, js, "gru")
	if _, err := OpenHome(ctx, js, "gru", nil, 1, regional); err == nil {
		t.Fatal("regional authority opened the global writer")
	}
	for _, peers := range [][]string{{"gru"}, {"global"}, {"S.FO"}} {
		if _, err := OpenHome(ctx, js, "gru", peers, 1, global); err == nil {
			t.Fatalf("home accepted mirror peers %v", peers)
		}
	}
	writer, err := OpenHome(ctx, js, "gru", []string{"fra", "sfo"}, 1, global)
	if err != nil {
		t.Fatal(err)
	}
	// Reopening is idempotent and keeps exactly one contract consumer per peer.
	if _, err := OpenHome(ctx, js, "gru", []string{"fra", "sfo"}, 1, global); err != nil {
		t.Fatalf("reopen home: %v", err)
	}
	assertMirrorConsumers(ctx, t, js, []string{"fra", "sfo"})
	epoch := global.Current().Epoch
	entry := DirectoryEntry{DatabaseID: "00000000004SJMRETVW39JX054", PartitionID: "00000000003K6TBW31R91GBDRD", HomeRegion: "gru", ActiveRegions: []string{"gru"}, Generation: 1}
	if _, err := writer.PutDirectory(ctx, epoch, entry); !errors.Is(err, ErrRosterRequired) {
		t.Fatalf("directory without roster = %v", err)
	}
	first, err := writer.PutRoster(ctx, epoch, testRoster(1))
	if err != nil {
		t.Fatal(err)
	}
	if again, err := writer.PutRoster(ctx, epoch, testRoster(1)); err != nil || again != first {
		t.Fatalf("idempotent roster retry = %d, %v; want %d", again, err, first)
	}
	changed := testRoster(1)
	changed.Regions = append([]RosterEntry(nil), changed.Regions...)
	changed.Regions[0].State = RegionActive
	if _, err := writer.PutRoster(ctx, epoch, changed); !errors.Is(err, ErrStaleRecord) {
		t.Fatalf("same generation with different content = %v", err)
	}
	moved := testRoster(2)
	moved.HomeRegion = "sfo"
	if _, err := writer.PutRoster(ctx, epoch, moved); !errors.Is(err, ErrNotHomeRegion) {
		t.Fatalf("home move through roster write = %v", err)
	}
	if _, err := writer.PutRoster(ctx, epoch+1, testRoster(2)); !errors.Is(err, authority.ErrFenced) {
		t.Fatalf("write with a foreign epoch = %v", err)
	}
	if _, err := writer.PutRoster(ctx, 0, testRoster(2)); !errors.Is(err, authority.ErrFenced) {
		t.Fatalf("write with zero epoch = %v", err)
	}
	if _, err := writer.PutDirectory(ctx, epoch, entry); err != nil {
		t.Fatal(err)
	}
	inactive := entry
	inactive.Generation, inactive.ActiveRegions = 2, []string{"fra", "gru"}
	if _, err := writer.PutDirectory(ctx, epoch, inactive); err == nil {
		t.Fatal("directory accepted a provisioning region")
	}
	read, sequence, err := writer.Directory(ctx, "00000000004SJMRETVW39JX054", "00000000003K6TBW31R91GBDRD")
	if err != nil || read.Generation != 1 || read.HomeRegion != "gru" || sequence == 0 {
		t.Fatalf("directory readback = %+v, %d, %v", read, sequence, err)
	}
	if _, _, err := writer.Directory(ctx, "00000000000DXJQRPPVPZTKPAZ", "00000000003K6TBW31R91GBDRD"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing directory entry = %v", err)
	}
	// A record written outside the writer cannot be read as valid state.
	if _, err := js.Publish(ctx, protocol.GlobalState(string(KindDirectory), DirectoryKey("00000000000000000000000009", "00000000003K6TBW31R91GBDRD")), []byte(`{"version":1}`)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := writer.Directory(ctx, "00000000000000000000000009", "00000000003K6TBW31R91GBDRD"); !errors.Is(err, ErrRecordCorrupt) {
		t.Fatalf("corrupt directory entry = %v", err)
	}
	roster, _, err := writer.Roster(ctx)
	if err != nil || roster.Generation != 1 {
		t.Fatalf("roster readback = %+v, %v", roster, err)
	}
	stream, err := js.Stream(ctx, StreamName)
	if err != nil {
		t.Fatal(err)
	}
	if err := stream.Purge(ctx); err == nil {
		t.Fatal("global stream allowed purge")
	}

	{
		js := newTestJetStream(t)
		global := startAuthority(ctx, t, js, protocol.GlobalScope)
		writer, err := OpenHome(ctx, js, "gru", nil, 1, global)
		if err != nil {
			t.Fatal(err)
		}
		reader, err := OpenHomeReader(ctx, js, 1)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := reader.Roster(ctx); !errors.Is(err, ErrNotFound) {
			t.Fatalf("independent roster before heartbeats = %v", err)
		}
		epoch := global.Current().Epoch
		now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
		heard := func(cell, ociRegion string, age time.Duration) Heartbeat {
			return Heartbeat{Version: 1, Cell: cell, OCIRegion: ociRegion, SentAt: now.Add(-age)}
		}
		seen := map[string]Heartbeat{
			"gru": heard("gru", "sa-saopaulo-1", 0),
			"sfo": heard("sfo", "us-sanjose-1", time.Second),
			"fra": heard("fra", "eu-frankfurt-1", RegionSilence),
		}

		first, changed := NextRoster(Roster{}, "gru", seen, now)
		if !changed || first.Generation != 1 || first.HomeRegion != "gru" || first.Validate() != nil {
			t.Fatalf("first roster = %+v, changed %v", first, changed)
		}
		if len(first.Regions) != 2 || first.Regions[0].Cell != "gru" || first.Regions[1].Cell != "sfo" ||
			!first.Active("sfo") || first.Active("fra") {
			t.Fatalf("regions = %+v", first.Regions)
		}
		sequence, err := writer.PutRoster(ctx, epoch, first)
		if err != nil || sequence == 0 {
			t.Fatalf("first roster write = %d, %v", sequence, err)
		}
		stored, gotSequence, err := reader.Roster(ctx)
		if err != nil || gotSequence != sequence || stored.Generation != first.Generation ||
			stored.HomeRegion != first.HomeRegion || !slices.Equal(stored.Regions, first.Regions) {
			t.Fatalf("stored first roster = %+v, %d, %v", stored, gotSequence, err)
		}
		if stored.Generation != 1 || stored.HomeRegion != "gru" || stored.Validate() != nil ||
			len(stored.Regions) != 2 || stored.Regions[0].Cell != "gru" || stored.Regions[1].Cell != "sfo" ||
			!stored.Active("sfo") || stored.Active("fra") {
			t.Fatalf("stored first roster changed heartbeat predicates: %+v", stored)
		}

		kept, changed := NextRoster(first, "gru", seen, now.Add(time.Minute))
		if changed || kept.Generation != 1 {
			t.Fatalf("unchanged roster = %+v, changed %v", kept, changed)
		}
		if kept.Generation != first.Generation || kept.HomeRegion != first.HomeRegion || !slices.Equal(kept.Regions, first.Regions) {
			t.Fatalf("unchanged producer changed the roster: %+v", kept)
		}
		stored, gotSequence, err = reader.Roster(ctx)
		if err != nil || gotSequence != sequence || stored.Generation != first.Generation ||
			stored.HomeRegion != first.HomeRegion || !slices.Equal(stored.Regions, first.Regions) {
			t.Fatalf("unchanged stored roster = %+v, %d, %v", stored, gotSequence, err)
		}

		seen["fra"] = heard("fra", "eu-frankfurt-1", 0)
		added, changed := NextRoster(first, "gru", seen, now)
		if !changed || added.Generation != 2 || len(added.Regions) != 3 || !added.Active("fra") {
			t.Fatalf("added roster = %+v, changed %v", added, changed)
		}
		addedSequence, err := writer.PutRoster(ctx, epoch, added)
		if err != nil || addedSequence <= sequence {
			t.Fatalf("added roster write = %d after %d, %v", addedSequence, sequence, err)
		}
		stored, gotSequence, err = reader.Roster(ctx)
		if err != nil || gotSequence != addedSequence || stored.Generation != added.Generation ||
			stored.HomeRegion != added.HomeRegion || !slices.Equal(stored.Regions, added.Regions) {
			t.Fatalf("stored added roster = %+v, %d, %v", stored, gotSequence, err)
		}
		if stored.Generation != 2 || len(stored.Regions) != 3 || !stored.Active("fra") {
			t.Fatalf("stored added roster changed heartbeat predicates: %+v", stored)
		}

		delete(seen, "gru")
		dropped, changed := NextRoster(added, "gru", seen, now.Add(RegionSilence))
		if !changed || dropped.Generation != 3 || len(dropped.Regions) != 1 || dropped.Regions[0].Cell != "gru" ||
			dropped.Regions[0].OCIRegion != "sa-saopaulo-1" || dropped.Validate() != nil {
			t.Fatalf("dropped roster = %+v, changed %v", dropped, changed)
		}
		droppedSequence, err := writer.PutRoster(ctx, epoch, dropped)
		if err != nil || droppedSequence <= addedSequence {
			t.Fatalf("dropped roster write = %d after %d, %v", droppedSequence, addedSequence, err)
		}
		stored, gotSequence, err = reader.Roster(ctx)
		if err != nil || gotSequence != droppedSequence || stored.Generation != dropped.Generation ||
			stored.HomeRegion != dropped.HomeRegion || !slices.Equal(stored.Regions, dropped.Regions) {
			t.Fatalf("stored dropped roster = %+v, %d, %v", stored, gotSequence, err)
		}
		if stored.Generation != 3 || len(stored.Regions) != 1 || stored.Regions[0].Cell != "gru" ||
			stored.Regions[0].OCIRegion != "sa-saopaulo-1" || stored.Validate() != nil {
			t.Fatalf("stored dropped roster changed heartbeat predicates: %+v", stored)
		}
	}
}

func assertMirrorConsumers(ctx context.Context, t *testing.T, js jetstream.JetStream, peers []string) {
	t.Helper()
	stream, err := js.Stream(ctx, StreamName)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	lister := stream.ConsumerNames(ctx)
	for name := range lister.Name() {
		names = append(names, name)
	}
	slices.Sort(names)
	var want []string
	for _, peer := range peers {
		want = append(want, protocol.GlobalMirrorConsumer(peer))
		consumer, err := stream.PushConsumer(ctx, protocol.GlobalMirrorConsumer(peer))
		if err != nil {
			t.Fatal(err)
		}
		config := consumer.CachedInfo().Config
		if config.DeliverSubject != protocol.InterRegionGlobalDeliverSubject(peer) ||
			config.AckPolicy != jetstream.AckFlowControlPolicy || !config.FlowControl {
			t.Fatalf("%s mirror consumer = %+v", peer, config)
		}
	}
	if !slices.Equal(names, want) {
		t.Fatalf("home consumers = %v, want %v", names, want)
	}
}

// TestHomeRefusesADriftedMirrorConsumer: a consumer that already exists under
// a peer's contract name but delivers elsewhere is never adopted.
func TestHomeRefusesADriftedMirrorConsumer(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	js := newTestJetStream(t)
	global := startAuthority(ctx, t, js, protocol.GlobalScope)
	stream, err := js.CreateStream(ctx, HomeStreamConfig(1))
	if err != nil {
		t.Fatal(err)
	}
	drifted := MirrorConsumerConfig("sfo", 1)
	drifted.DeliverSubject = protocol.PlacementApplySubject("gru")
	if _, err := stream.CreatePushConsumer(ctx, drifted); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenHome(ctx, js, "gru", []string{"sfo"}, 1, global); err == nil {
		t.Fatal("home adopted a mirror consumer delivering outside the contract")
	}
	if err := verifyMirrorConsumer(MirrorConsumerConfig("sfo", 1), "fra", 1); err == nil {
		t.Fatal("one peer's consumer verified as another's")
	}
}

func startAuthority(ctx context.Context, t *testing.T, js jetstream.JetStream, scope string) *authority.Runtime {
	t.Helper()
	runtime, err := authority.Start(ctx, js, authority.Config{DeploymentID: "01ARZ3NDEKTSV4RRFFQ69G5FAV",
		Scope: scope, CandidateID: entityid.Derive("test-controller", scope), Replicas: 1,
		LeaseDuration: 5 * time.Second, RenewInterval: 500 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = runtime.Close() })
	for !runtime.Current().CanMutate() {
		if ctx.Err() != nil {
			t.Fatalf("%s authority never became leader", scope)
		}
		time.Sleep(20 * time.Millisecond)
	}
	return runtime
}

func newTestJetStream(t *testing.T) jetstream.JetStream {
	t.Helper()
	srv, err := server.NewServer(&server.Options{
		Host: "127.0.0.1", Port: -1, JetStream: true, StoreDir: filepath.Join(t.TempDir(), "jetstream"),
	})
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
	return js
}
