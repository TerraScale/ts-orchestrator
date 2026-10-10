package globalview

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	json "encoding/json/v2"

	natsserver "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/nodescale"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
)

var start = time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)

type fakeClock struct{ now time.Time }

func (c *fakeClock) Now() time.Time { return c.now }

func rollupAt(cell string, at time.Time) Rollup {
	return Rollup{
		Version:     Version,
		Cell:        cell,
		ObservedAt:  at,
		Health:      Health{Status: Healthy},
		Controllers: Controllers{Expected: 3, Ready: 3},
	}
}

func fullRollup(cell string, at time.Time, nodes int) Rollup {
	r := rollupAt(cell, at)
	for i := range nodes {
		cpu := float64(i) * 3.5
		r.Nodes = append(r.Nodes, Node{
			Name:            fmt.Sprintf("%s-node-%02d", cell, i),
			Health:          NodeOK,
			ReportedAt:      at,
			CPU:             &cpu,
			CPUCores:        8,
			MemoryBytes:     64 << 30,
			MemoryUsedBytes: 20 << 30,
			DiskBytes:       500 << 30,
			DiskUsedBytes:   120 << 30,
			Services: []Service{
				{Role: "controller", State: "running", Digest: "sha256:0123456789abcdef"},
				{Role: "terrabase", State: "running", Digest: "sha256:fedcba9876543210"},
				{Role: "nats", State: "running", Digest: "sha256:0011223344556677"},
				{Role: "host", State: "running", Digest: "sha256:8899aabbccddeeff"},
			},
			Filesystems: []Filesystem{
				{Role: "root", SizeBytes: 50 << 30, UsedBytes: 10 << 30},
				{Role: "data", SizeBytes: 450 << 30, UsedBytes: 110 << 30},
			},
		})
	}
	r.Totals = Totals{Nodes: nodes, Ready: nodes, CPUCores: 8 * nodes}
	return r
}

func startNATS(t *testing.T) (*nats.Conn, jetstream.JetStream) {
	t.Helper()
	server, err := natsserver.NewServer(&natsserver.Options{Host: "127.0.0.1", Port: -1, JetStream: true, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	server.Start()
	t.Cleanup(func() { server.Shutdown(); server.WaitForShutdown() })
	if !server.ReadyForConnections(5 * time.Second) {
		t.Fatal("nats not ready")
	}
	conn, err := nats.Connect(server.ClientURL())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(conn.Close)
	js, err := jetstream.New(conn)
	if err != nil {
		t.Fatal(err)
	}
	return conn, js
}

func closed(ch <-chan struct{}) bool {
	select {
	case <-ch:
		return true
	default:
		return false
	}
}

func waitClosed(t *testing.T, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(5 * time.Second):
		t.Fatal("no rollup accepted in 5s")
	}
}

// publishUntil republishes until ch closes, since a subscription made by a
// concurrent Follow may not exist yet when the first publish goes out.
func publishUntil(t *testing.T, ch <-chan struct{}, publish func()) {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		publish()
		select {
		case <-ch:
			return
		case <-time.After(50 * time.Millisecond):
		case <-deadline:
			t.Fatal("no rollup accepted in 5s")
		}
	}
}

func TestViewAccept(t *testing.T) {
	c := &fakeClock{now: start}
	view := NewView("gru", func() []string { return []string{"sfo"} }, c.Now)

	ch := view.Changed()
	if view.Accept(rollupAt("SFO", start)) {
		t.Fatal("accepted an uppercase cell")
	}
	if view.Accept(rollupAt("sfo", start.Add(2*time.Minute))) {
		t.Fatal("accepted a rollup from the future")
	}
	if closed(ch) {
		t.Fatal("Changed closed on a rejected rollup")
	}

	if !view.Accept(rollupAt("sfo", start)) {
		t.Fatal("rejected a new rollup")
	}
	if !closed(ch) {
		t.Fatal("Changed not closed on accept")
	}
	ch = view.Changed()

	if view.Accept(rollupAt("sfo", start.Add(-time.Second))) || view.Accept(rollupAt("sfo", start)) {
		t.Fatal("accepted an older or equal rollup")
	}
	if closed(ch) {
		t.Fatal("Changed closed on a rejected rollup")
	}

	if !view.Accept(rollupAt("sfo", start.Add(time.Second))) {
		t.Fatal("rejected a newer rollup")
	}
	if !closed(ch) {
		t.Fatal("Changed not closed on newer accept")
	}
	region, _ := view.Region("sfo")
	if !region.Rollup.ObservedAt.Equal(start.Add(time.Second)) {
		t.Fatalf("held ObservedAt = %s, want the newer one", region.Rollup.ObservedAt)
	}
}

func TestViewRegions(t *testing.T) {
	c := &fakeClock{now: start}
	regions := []string{"zrh", "SFO", "ams", "bogus!", "gru"}
	view := NewView("gru", func() []string { return regions }, c.Now)
	view.Accept(rollupAt("sfo", start))
	view.Accept(rollupAt("hidden", start))

	var cells []string
	for _, region := range view.Regions() {
		cells = append(cells, region.Cell)
	}
	if got := strings.Join(cells, ","); got != "gru,ams,sfo,zrh" {
		t.Fatalf("Regions() = %s, want gru,ams,sfo,zrh", got)
	}
	if _, ok := view.Region("hidden"); ok {
		t.Fatal("Region reported an unlisted cell")
	}
	if region, ok := view.Region("SFO"); !ok || region.Rollup == nil {
		t.Fatal("Region did not find listed cell sfo")
	}
	if region, _ := view.Region("gru"); region.Rollup != nil {
		t.Fatal("local region has a rollup before any arrived")
	}
}

func TestViewRegionsStale(t *testing.T) {
	c := &fakeClock{now: start}
	view := NewView("gru", func() []string { return []string{"sfo"} }, c.Now)
	view.Accept(rollupAt("sfo", start))

	c.now = start.Add(StaleAfter)
	if region, _ := view.Region("sfo"); region.Stale {
		t.Fatal("rollup stale at exactly StaleAfter")
	}
	c.now = start.Add(StaleAfter + time.Second)
	if region, _ := view.Region("sfo"); !region.Stale {
		t.Fatal("rollup not stale after StaleAfter")
	}
}

func TestDecodeRejectsInvalidRollups(t *testing.T) {
	now := time.Now()
	encode := func(t *testing.T, r Rollup) []byte {
		t.Helper()
		data, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	sfo := protocol.RegionRollupSubject("sfo")
	tests := map[string]struct {
		subject string
		data    []byte
	}{
		"wrong version":    {sfo, encode(t, Rollup{Version: Version + 1, Cell: "sfo", ObservedAt: now})},
		"subject mismatch": {protocol.RegionRollupSubject("lhr"), encode(t, rollupAt("sfo", now))},
		"uppercase cell":   {sfo, encode(t, rollupAt("SFO", now))},
		"future observed":  {sfo, encode(t, rollupAt("sfo", now.Add(2*time.Minute)))},
		"missing observed": {sfo, encode(t, rollupAt("sfo", time.Time{}))},
		"oversize":         {sfo, []byte(strings.Repeat(" ", MaxBytes+1))},
		"malformed JSON":   {sfo, []byte(`{"version":`)},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := decode(tc.subject, tc.data); err == nil {
				t.Fatal("decode accepted an invalid rollup")
			}
		})
	}
}

func TestDecodeAcceptsUnknownField(t *testing.T) {
	data, err := json.Marshal(rollupAt("sfo", time.Now()))
	if err != nil {
		t.Fatal(err)
	}
	data = append([]byte(`{"future_field":true,`), data[1:]...)
	r, err := decode(protocol.RegionRollupSubject("sfo"), data)
	if err != nil {
		t.Fatalf("decode rejected a newer region's extra field: %v", err)
	}
	if r.Cell != "sfo" {
		t.Fatalf("decoded cell %q, want sfo", r.Cell)
	}
}

func TestViewAcceptBoundsRegions(t *testing.T) {
	c := &fakeClock{now: start}
	var listed []string
	view := NewView("gru", func() []string { return listed }, c.Now)
	view.Accept(rollupAt("gru", start))
	for i := range maxRegions - 1 {
		cell := fmt.Sprintf("c%02d", i)
		listed = append(listed, cell)
		if !view.Accept(rollupAt(cell, start)) {
			t.Fatalf("rejected listed cell %d below the bound", i)
		}
	}
	if view.Accept(rollupAt("late", start)) {
		t.Fatal("accepted an unlisted cell past the bound")
	}

	listed = []string{"zrh"}
	if !view.Accept(rollupAt("zrh", start)) {
		t.Fatal("rejected a listed cell at the bound")
	}
	if len(view.rollups) != 2 {
		t.Fatalf("held %d rollups, want 2: gru and zrh", len(view.rollups))
	}
}

func TestFollowLoadsAndFollows(t *testing.T) {
	conn, js := startNATS(t)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	kv, err := OpenBucket(ctx, js, 1)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	last, err := json.Marshal(rollupAt("sfo", now.Add(-time.Second)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := kv.Put(ctx, "sfo", last); err != nil {
		t.Fatal(err)
	}

	view := NewView("gru", func() []string { return []string{"sfo"} }, nil)
	ch := view.Changed()
	done := make(chan error, 1)
	go view.KeepLastKnown(ctx, kv, func() bool { return false })
	go func() { done <- view.Follow(ctx, conn) }()
	waitClosed(t, ch)
	region, _ := view.Region("sfo")
	if region.Rollup == nil || !region.Rollup.ObservedAt.Equal(now.Add(-time.Second)) {
		t.Fatal("last-known rollup from the bucket not loaded")
	}

	newer := rollupAt("sfo", now)
	newer.Health = Health{Status: Degraded}
	data, err := json.Marshal(newer)
	if err != nil {
		t.Fatal(err)
	}
	publishUntil(t, view.Changed(), func() {
		if err := conn.Publish(protocol.RegionRollupSubject("sfo"), data); err != nil {
			t.Fatal(err)
		}
	})
	region, _ = view.Region("sfo")
	if region.Rollup.Health.Status != Degraded {
		t.Fatalf("held health %q, want the newer %q", region.Rollup.Health.Status, Degraded)
	}

	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Follow returned %v after cancel", err)
	}
}

func TestKeepLastKnownPersistsWhileLeading(t *testing.T) {
	_, js := startNATS(t)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	kv, err := OpenBucket(ctx, js, 1)
	if err != nil {
		t.Fatal(err)
	}
	view := NewView("gru", func() []string { return []string{"sfo"} }, nil)
	view.Accept(rollupAt("gru", time.Now()))
	go view.KeepLastKnown(ctx, kv, func() bool { return true })
	for {
		if _, err := kv.Get(ctx, "gru"); err == nil {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatal("the leader did not persist its rollup")
		case <-time.After(20 * time.Millisecond):
		}
	}
}

func TestPersistWritesOnCadence(t *testing.T) {
	_, js := startNATS(t)
	ctx := t.Context()
	kv, err := OpenBucket(ctx, js, 1)
	if err != nil {
		t.Fatal(err)
	}
	c := &fakeClock{now: start}
	view := NewView("gru", func() []string { return []string{"sfo"} }, c.Now)
	view.Accept(rollupAt("sfo", start))

	if err := view.Persist(ctx, kv); err != nil {
		t.Fatal(err)
	}
	first, err := kv.Get(ctx, "sfo")
	if err != nil {
		t.Fatalf("first Persist wrote nothing: %v", err)
	}

	c.now = start.Add(time.Second)
	view.Accept(rollupAt("sfo", start.Add(time.Second)))
	if err := view.Persist(ctx, kv); err != nil {
		t.Fatal(err)
	}
	if again, _ := kv.Get(ctx, "sfo"); again.Revision() != first.Revision() {
		t.Fatal("Persist wrote again within PersistEvery")
	}

	c.now = start.Add(PersistEvery)
	if err := view.Persist(ctx, kv); err != nil {
		t.Fatal(err)
	}
	later, err := kv.Get(ctx, "sfo")
	if err != nil || later.Revision() == first.Revision() {
		t.Fatalf("Persist did not write the newer rollup after PersistEvery: %v", err)
	}

	if _, err := kv.Put(ctx, "old", []byte("{}")); err != nil {
		t.Fatal(err)
	}
	if err := view.Persist(ctx, kv); err != nil {
		t.Fatal(err)
	}
	if _, err := kv.Get(ctx, "old"); !errors.Is(err, jetstream.ErrKeyNotFound) {
		t.Fatalf("key of an unlisted region not deleted: %v", err)
	}
}

func TestPersistKeepsKeysBeforeTheRegistryIsRead(t *testing.T) {
	_, js := startNATS(t)
	ctx := t.Context()
	kv, err := OpenBucket(ctx, js, 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := kv.Put(ctx, "sfo", []byte("{}")); err != nil {
		t.Fatal(err)
	}
	view := NewView("gru", func() []string { return nil }, nil)
	view.Accept(rollupAt("gru", time.Now()))
	if err := view.Persist(ctx, kv); err != nil {
		t.Fatal(err)
	}
	if _, err := kv.Get(ctx, "sfo"); err != nil {
		t.Fatalf("last-known key deleted before the registry listed any region: %v", err)
	}
}

func TestTwentyRegionsFollow(t *testing.T) {
	cells := []string{
		"gru", "sfo", "fra", "lhr", "nrt", "iad", "phx", "ams", "cdg", "mad",
		"mil", "zrh", "arn", "sin", "bom", "syd", "mel", "icn", "yyz", "jnb",
	}
	conn, _ := startNATS(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	view := NewView("gru", func() []string { return cells }, nil)
	done := make(chan error, 1)
	go func() { done <- view.Follow(ctx, conn) }()

	var sent int
	publishRound := func() {
		for _, cell := range cells {
			data, err := json.Marshal(fullRollup(cell, time.Now(), 12))
			if err != nil {
				t.Fatal(err)
			}
			sent += len(data)
			if err := conn.Publish(protocol.RegionRollupSubject(cell), data); err != nil {
				t.Fatal(err)
			}
		}
	}
	deadline := time.Now().Add(5 * time.Second)
	for !allHeld(view) {
		if time.Now().After(deadline) {
			t.Fatal("not every region held a rollup within 5s")
		}
		publishRound()
		time.Sleep(50 * time.Millisecond)
	}
	t.Logf("published %d bytes for %d regions", sent, len(cells))

	regions := view.Regions()
	if len(regions) != len(cells) {
		t.Fatalf("Regions() has %d entries, want %d", len(regions), len(cells))
	}
	for _, region := range regions {
		if region.Stale {
			t.Fatalf("region %s is stale", region.Cell)
		}
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Follow returned %v after cancel", err)
	}
}

func allHeld(view *View) bool {
	regions := view.Regions()
	if len(regions) != 20 {
		return false
	}
	for _, region := range regions {
		if region.Rollup == nil {
			return false
		}
	}
	return true
}

func TestPublishWhileLeading(t *testing.T) {
	conn, _ := startNATS(t)
	sub, err := conn.SubscribeSync(protocol.RegionRollupSubject("sfo"))
	if err != nil {
		t.Fatal(err)
	}
	if err := conn.Flush(); err != nil {
		t.Fatal(err)
	}

	view := NewView("sfo", nil, nil)
	ch := view.Changed()
	var leading atomic.Bool
	build := func(context.Context) Rollup { return rollupAt("sfo", time.Now()) }
	ctx, cancel := context.WithTimeout(t.Context(), 7*time.Second)
	defer cancel()
	done := make(chan struct{})
	go func() {
		Publish(ctx, conn, "sfo", leading.Load, build, view)
		close(done)
	}()

	if _, err := sub.NextMsg(time.Second); !errors.Is(err, nats.ErrTimeout) {
		t.Fatalf("published while not leading: %v", err)
	}
	leading.Store(true)
	if _, err := sub.NextMsg(6 * time.Second); err != nil {
		t.Fatalf("no rollup published while leading: %v", err)
	}
	waitClosed(t, ch)
	if region, _ := view.Region("sfo"); region.Rollup == nil {
		t.Fatal("view does not hold the published rollup")
	}
	cancel()
	<-done
}

func TestDecodeKeepsOnlyTheRegionsOwnScaleStatus(t *testing.T) {
	now := time.Now().UTC()
	own := nodescale.Status{Schema: nodescale.StatusSchema, Cell: "sfo", At: now, Nodes: 3, QuorumNodes: 3,
		Want: 3, Allowance: 3, Action: nodescale.Hold, Reason: "load within band"}
	other := own
	other.Cell = "gru"
	invalid := own
	invalid.Reason = ""
	for name, tc := range map[string]struct {
		scale nodescale.Status
		kept  bool
	}{"own": {own, true}, "another region's": {other, false}, "invalid": {invalid, false}} {
		t.Run(name, func(t *testing.T) {
			rollup := rollupAt("sfo", now)
			rollup.Scale = &tc.scale
			data, err := json.Marshal(rollup)
			if err != nil {
				t.Fatal(err)
			}
			r, err := decode(protocol.RegionRollupSubject("sfo"), data)
			if err != nil || (r.Scale != nil) != tc.kept {
				t.Fatalf("decode = %+v, %v; want scale kept %v", r.Scale, err, tc.kept)
			}
		})
	}
}
