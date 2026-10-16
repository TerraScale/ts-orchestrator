// Package terrabasestats feeds the dashboard's top databases (TS-806). Every
// TerraBase member publishes a rollup of its busiest databases on
// protocol.TerraBaseObservabilitySubject every few seconds. A Follower keeps
// the newest rollup per member and merges them per database when asked.
package terrabasestats

import (
	"cmp"
	"context"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/nats-io/nats.go"

	"github.com/TerraScale/ts-orchestrator/internal/globalview"
	"github.com/TerraScale/ts-orchestrator/internal/observability"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
)

const (
	// version is the rollup wire version this reader accepts.
	version = 1
	// maxMessage bounds one rollup. Larger messages are dropped undecoded.
	maxMessage = 1 << 20
	// maxMembers bounds the members kept. A full table prunes stale members first.
	maxMembers = 64
	// maxTop is the most databases a member lists, the producer's cap. It bounds memory.
	maxTop = 60
	// maxPeers is the most peer regions a member lists per database. It bounds memory.
	maxPeers = 64
	// maxDatabases matches globalview's cap on the dashboard list.
	maxDatabases = 10
	// staleAfter drops a member whose rollup is older: six missed publishes.
	staleAfter = 30 * time.Second
)

// rollup is the part of a member's TerraBase rollup the dashboard reads.
type rollup struct {
	Version  int       `json:"v"`
	Cell     string    `json:"cell"`
	Member   string    `json:"member"`
	At       time.Time `json:"at"`
	WindowMs int64     `json:"windowMs"`
	Top      []entry   `json:"top"`
}

// entry is one database in a member's rollup over its window.
type entry struct {
	Org           string  `json:"org"`
	Project       string  `json:"project"`
	Database      string  `json:"database"`
	SentBytes     uint64  `json:"sentBytes"`
	ReceivedBytes uint64  `json:"receivedBytes"`
	Reads         uint64  `json:"reads"`
	Writes        uint64  `json:"writes"`
	StorageBytes  uint64  `json:"storageBytes"` // zero when the member does not know it
	LagSeconds    float64 `json:"lagSeconds"`
	Peers         []peer  `json:"peers"`
}

// peer is one peer region's share of a database over the member's window.
type peer struct {
	Region        string `json:"region"`
	SentBytes     uint64 `json:"sentBytes"`
	ReceivedBytes uint64 `json:"receivedBytes"`
}

// peerKey names one peer region's share of one database.
type peerKey struct{ database, region string }

// Follower holds the newest rollup of each TerraBase member of one cell.
type Follower struct {
	now     func() time.Time
	mu      sync.Mutex
	members map[string]rollup
}

// Follow subscribes to the cell's TerraBase rollups until ctx ends.
func Follow(ctx context.Context, conn *nats.Conn, cell string) *Follower {
	return follow(ctx, conn, cell, time.Now)
}

func follow(ctx context.Context, conn *nats.Conn, cell string, now func() time.Time) *Follower {
	follower := &Follower{now: now, members: map[string]rollup{}}
	sub, err := conn.Subscribe(protocol.TerraBaseObservabilitySubject(cell), func(msg *nats.Msg) {
		follower.accept(cell, msg.Data)
	})
	if err != nil {
		slog.Warn("terrabase database stats not followed", observability.ComponentKey, "terrabasestats", "error", err)
		return follower
	}
	context.AfterFunc(ctx, func() {
		if err := sub.Unsubscribe(); err != nil {
			slog.Debug("terrabase database stats subscription not closed", observability.ComponentKey, "terrabasestats", "error", err)
		}
	})
	return follower
}

func (f *Follower) accept(cell string, data []byte) {
	var r rollup
	if err := protocol.DecodeTolerant(data, &r, maxMessage); err != nil {
		slog.Debug("terrabase rollup dropped", observability.ComponentKey, "terrabasestats", "error", err)
		return
	}
	if r.Version != version || r.Cell != cell || r.Member == "" || r.WindowMs <= 0 {
		return
	}
	r.Top = r.Top[:min(len(r.Top), maxTop)]
	for i := range r.Top {
		r.Top[i].Peers = r.Top[i].Peers[:min(len(r.Top[i].Peers), maxPeers)]
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if old, ok := f.members[r.Member]; ok {
		if r.At.Before(old.At) {
			return
		}
	} else {
		if len(f.members) >= maxMembers {
			f.prune(f.now())
		}
		if len(f.members) >= maxMembers {
			return
		}
	}
	f.members[r.Member] = r
}

// prune forgets members whose rollup is stale at now.
func (f *Follower) prune(now time.Time) {
	for name, r := range f.members {
		if r.At.Before(now.Add(-staleAfter)) {
			delete(f.members, name)
		}
	}
}

// Databases merges the fresh members' rollups by database. Rates are summed
// over the members, per peer region too. Storage is the maximum, since every
// member holds a replica, and lag is the maximum. The list is the top
// maxDatabases by bytes per second, then by ID. It does no I/O.
func (f *Follower) Databases() []globalview.Database {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.prune(f.now())
	merged := map[string]*globalview.Database{}
	peers := map[peerKey]*globalview.DatabasePeer{}
	for _, r := range f.members {
		seconds := float64(r.WindowMs) / 1000
		for _, e := range r.Top {
			if e.Database == "" {
				continue
			}
			d, ok := merged[e.Database]
			if !ok {
				d = &globalview.Database{ID: e.Database, Org: e.Org, Project: e.Project}
				merged[e.Database] = d
			}
			d.ReplicationBytesPerSecond += float64(e.SentBytes+e.ReceivedBytes) / seconds
			d.SentBytesPerSecond += float64(e.SentBytes) / seconds
			d.ReceivedBytesPerSecond += float64(e.ReceivedBytes) / seconds
			d.ReadsPerSecond += float64(e.Reads) / seconds
			d.WritesPerSecond += float64(e.Writes) / seconds
			d.StorageBytes = max(d.StorageBytes, int64(e.StorageBytes))
			d.LagSeconds = max(d.LagSeconds, e.LagSeconds)
			for _, p := range e.Peers {
				key := peerKey{database: e.Database, region: p.Region}
				sum, ok := peers[key]
				if !ok {
					sum = &globalview.DatabasePeer{Region: p.Region}
					peers[key] = sum
				}
				sum.SentBytesPerSecond += float64(p.SentBytes) / seconds
				sum.ReceivedBytesPerSecond += float64(p.ReceivedBytes) / seconds
			}
		}
	}
	for key, sum := range peers {
		merged[key.database].Peers = append(merged[key.database].Peers, *sum)
	}
	out := make([]globalview.Database, 0, len(merged))
	for _, d := range merged {
		out = append(out, *d)
	}
	slices.SortFunc(out, func(a, b globalview.Database) int {
		return cmp.Or(cmp.Compare(b.ReplicationBytesPerSecond, a.ReplicationBytesPerSecond), strings.Compare(a.ID, b.ID))
	})
	return out[:min(len(out), maxDatabases)]
}
