package terrabasestats

import (
	"bytes"
	"context"
	json "encoding/json/v2"
	"fmt"
	"testing"
	"time"

	natsserver "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"

	"github.com/TerraScale/ts-orchestrator/internal/globalview"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
)

var start = time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)

type clock struct{ now time.Time }

func (c *clock) Now() time.Time { return c.now }

func startNATS(t *testing.T) *nats.Conn {
	t.Helper()
	// The default payload limit is 1 MiB; raise it so oversize rollups reach the follower's own limit.
	server, err := natsserver.NewServer(&natsserver.Options{Host: "127.0.0.1", Port: -1, NoLog: true, NoSigs: true, MaxPayload: 4 << 20})
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
	return conn
}

// publish sends one rollup of member on cell's TerraBase subject.
func publish(t *testing.T, conn *nats.Conn, cell string, r rollup) {
	t.Helper()
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	publishRaw(t, conn, cell, data)
}

func publishRaw(t *testing.T, conn *nats.Conn, cell string, data []byte) {
	t.Helper()
	if err := conn.Publish(protocol.TerraBaseObservabilitySubject(cell), data); err != nil {
		t.Fatal(err)
	}
}

func member(name string, at time.Time, top ...entry) rollup {
	return rollup{Version: version, Cell: "gru", Member: name, At: at, WindowMs: 5000, Top: top}
}

// awaitDatabases polls until the follower's list satisfies done.
func awaitDatabases(t *testing.T, f *Follower, done func([]globalview.Database) bool) []globalview.Database {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		list := f.Databases()
		if done(list) {
			return list
		}
		if time.Now().After(deadline) {
			t.Fatalf("databases never converged, last: %+v", list)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func hasID(list []globalview.Database, id string) bool {
	for _, d := range list {
		if d.ID == id {
			return true
		}
	}
	return false
}

func TestDatabasesMergeAcrossMembers(t *testing.T) {
	conn := startNATS(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	clk := &clock{now: start}
	f := follow(ctx, conn, "gru", clk.Now)

	publish(t, conn, "gru", member("gru-1-db-1", start,
		entry{Org: "org-a", Project: "proj-a", Database: "db-1", SentBytes: 1000, ReceivedBytes: 1000, LagSeconds: 3},
		entry{Org: "org-a", Project: "proj-a", Database: "db-2", ReceivedBytes: 5000}))
	publish(t, conn, "gru", member("gru-1-db-2", start,
		entry{Org: "org-a", Project: "proj-a", Database: "db-1", SentBytes: 500, ReceivedBytes: 500, LagSeconds: 7},
		entry{Org: "org-a", Project: "proj-a", Database: "db-3", SentBytes: 1500, ReceivedBytes: 1500}))

	list := awaitDatabases(t, f, func(list []globalview.Database) bool {
		return len(list) == 3
	})
	want := []globalview.Database{
		{ID: "db-2", Org: "org-a", Project: "proj-a", ReplicationBytesPerSecond: 1000, LagSeconds: 0},
		{ID: "db-1", Org: "org-a", Project: "proj-a", ReplicationBytesPerSecond: 600, LagSeconds: 7},
		{ID: "db-3", Org: "org-a", Project: "proj-a", ReplicationBytesPerSecond: 600, LagSeconds: 0},
	}
	for i := range want {
		if list[i].ID != want[i].ID || list[i].ReplicationBytesPerSecond != want[i].ReplicationBytesPerSecond || list[i].LagSeconds != want[i].LagSeconds {
			t.Fatalf("databases[%d] = %+v, want %+v", i, list[i], want[i])
		}
	}
}

func TestDatabasesMergeRatesPeersStorageAndOps(t *testing.T) {
	conn := startNATS(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	clk := &clock{now: start}
	f := follow(ctx, conn, "gru", clk.Now)

	// Each window is 5 s, so every counter divides by 5 to a rate.
	publish(t, conn, "gru", member("gru-1-db-1", start, entry{Database: "db-1", SentBytes: 5000, ReceivedBytes: 10000,
		Reads: 500, Writes: 250, StorageBytes: 300, Peers: []peer{
			{Region: "sjc", SentBytes: 5000, ReceivedBytes: 10000},
			{Region: "lhr", ReceivedBytes: 5000},
		}}))
	publish(t, conn, "gru", member("gru-1-db-2", start, entry{Database: "db-1", ReceivedBytes: 5000,
		Reads: 1000, StorageBytes: 700, Peers: []peer{{Region: "sjc", SentBytes: 2500, ReceivedBytes: 5000}}}))

	list := awaitDatabases(t, f, func(list []globalview.Database) bool {
		return len(list) == 1 && list[0].ReceivedBytesPerSecond == 3000
	})
	d := list[0]
	if d.SentBytesPerSecond != 1000 || d.ReplicationBytesPerSecond != 4000 || d.ReadsPerSecond != 300 || d.WritesPerSecond != 50 {
		t.Fatalf("rates = sent %v, replication %v, reads %v, writes %v; want 1000, 4000, 300, 50", d.SentBytesPerSecond, d.ReplicationBytesPerSecond, d.ReadsPerSecond, d.WritesPerSecond)
	}
	if d.StorageBytes != 700 {
		t.Fatalf("storage = %d, want the maximum 700", d.StorageBytes)
	}
	peers := map[string]globalview.DatabasePeer{}
	for _, p := range d.Peers {
		peers[p.Region] = p
	}
	if len(peers) != 2 || peers["sjc"].SentBytesPerSecond != 1500 || peers["sjc"].ReceivedBytesPerSecond != 3000 ||
		peers["lhr"].SentBytesPerSecond != 0 || peers["lhr"].ReceivedBytesPerSecond != 1000 {
		t.Fatalf("peers = %+v, want sjc 1500/3000 and lhr 0/1000", d.Peers)
	}
}

func TestDatabasesCapAtTen(t *testing.T) {
	conn := startNATS(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	clk := &clock{now: start}
	f := follow(ctx, conn, "gru", clk.Now)

	var top []entry
	for i := range 12 {
		top = append(top, entry{Database: fmt.Sprintf("db-%02d", i), SentBytes: uint64(i+1) * 1000})
	}
	publish(t, conn, "gru", member("gru-1-db-1", start, top...))

	list := awaitDatabases(t, f, func(list []globalview.Database) bool { return len(list) == 10 })
	if list[0].ID != "db-11" || list[9].ID != "db-02" {
		t.Fatalf("capped list = first %s, last %s; want db-11 and db-02", list[0].ID, list[9].ID)
	}
}

func TestStaleMemberDropped(t *testing.T) {
	conn := startNATS(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	clk := &clock{now: start}
	f := follow(ctx, conn, "gru", clk.Now)

	publish(t, conn, "gru", member("gru-1-db-1", start, entry{Database: "db-1", SentBytes: 5000}))
	awaitDatabases(t, f, func(list []globalview.Database) bool { return len(list) == 1 })

	clk.now = start.Add(31 * time.Second)
	if list := f.Databases(); len(list) != 0 {
		t.Fatalf("stale member still listed: %+v", list)
	}
}

func TestInvalidRollupsIgnored(t *testing.T) {
	conn := startNATS(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	clk := &clock{now: start}
	f := follow(ctx, conn, "gru", clk.Now)

	wrongCell := member("gru-1-db-1", start, entry{Database: "db-wrong-cell", SentBytes: 5000})
	wrongCell.Cell = "lhr"
	wrongVersion := member("gru-1-db-2", start, entry{Database: "db-wrong-version", SentBytes: 5000})
	wrongVersion.Version = 2
	noMember := member("", start, entry{Database: "db-no-member", SentBytes: 5000})
	noWindow := member("gru-1-db-3", start, entry{Database: "db-no-window", SentBytes: 5000})
	noWindow.WindowMs = 0
	for _, r := range []rollup{wrongCell, wrongVersion, noMember, noWindow} {
		publish(t, conn, "gru", r)
	}
	oversize, err := json.Marshal(member("gru-1-db-4", start, entry{Database: "db-oversize", SentBytes: 5000}))
	if err != nil {
		t.Fatal(err)
	}
	publishRaw(t, conn, "gru", append(oversize, bytes.Repeat([]byte(" "), maxMessage)...))

	// Delivery is ordered per subscription, so once the marker is listed every earlier message was handled.
	publish(t, conn, "gru", member("gru-1-db-9", start, entry{Database: "db-marker", SentBytes: 5000}))
	list := awaitDatabases(t, f, func(list []globalview.Database) bool { return hasID(list, "db-marker") })
	if len(list) != 1 {
		t.Fatalf("ignored rollups were merged: %+v", list)
	}
}
