package app

import (
	"context"
	"errors"
	"log/slog"
	"maps"
	"slices"
	"strings"
	"sync"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/atlas"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/globalcontrol"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/naming"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/observability"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/regionlink"
	"github.com/nats-io/nats.go"
)

// maxHeartbeatBytes bounds one heartbeat; a valid one is a few hundred bytes.
const maxHeartbeatBytes = 1 << 10

// runRegionRegistry runs this region's part of the region registry until ctx
// ends: every region heartbeats, the home keeps the roster from the heartbeats
// it hears, and every region follows the roster for its peers.
func runRegionRegistry(ctx context.Context, conn *nats.Conn, cfg Config, fencer authority.Fencer,
	global *globalControl, peers *rosterPeers,
) {
	cell := cfg.NATS.Cell
	var loops sync.WaitGroup
	// A lab cell has no OCI region, so it has no heartbeat to send.
	if ociRegion := catalog.OCIRegion(strings.ToUpper(cell)); ociRegion != "" {
		loops.Go(func() { publishHeartbeats(ctx, conn, fencer, cell, ociRegion) })
	}
	if global.writer != nil {
		loops.Go(func() { keepRoster(ctx, conn, global, cell) })
	}
	loops.Go(func() { followRoster(ctx, global.reader, cell, peers.apply) })
	loops.Wait()
}

// publishHeartbeats sends this region's heartbeat every HeartbeatInterval
// while its regional leader can mutate.
func publishHeartbeats(ctx context.Context, conn *nats.Conn, fencer authority.Fencer, cell, ociRegion string) {
	var failures failureLog
	ticker := time.NewTicker(globalcontrol.HeartbeatInterval)
	defer ticker.Stop()
	for {
		if fencer.Current().CanMutate() {
			failures.report("region heartbeat not sent", sendHeartbeat(conn, cell, ociRegion, time.Now()))
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func sendHeartbeat(conn *nats.Conn, cell, ociRegion string, now time.Time) error {
	wire, err := protocol.EncodeJSON(globalcontrol.Heartbeat{Version: globalcontrol.HeartbeatVersion,
		Cell: cell, OCIRegion: ociRegion, SentAt: now.UTC()})
	if err != nil {
		return err
	}
	return conn.Publish(protocol.RegionHealthSubject(cell), wire)
}

// keepRoster is the home's loop: it records every region's heartbeat and
// refreshes the roster each HeartbeatInterval.
func keepRoster(ctx context.Context, conn *nats.Conn, global *globalControl, home string) {
	keeper := newRosterKeeper(global, home, time.Now())
	sub, err := conn.Subscribe(protocol.AnyRegionHealthSubject(), func(message *nats.Msg) {
		keeper.record(message, time.Now())
	})
	if err != nil {
		slog.Error("region heartbeats unavailable", observability.ComponentKey, "region", "error", err)
		return
	}
	defer func() { _ = sub.Unsubscribe() }()
	var failures failureLog
	ticker := time.NewTicker(globalcontrol.HeartbeatInterval)
	defer ticker.Stop()
	for {
		failures.report("global roster refresh failed", keeper.refresh(ctx, time.Now()))
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// rosterKeeper turns the heartbeats the home hears into its roster.
type rosterKeeper struct {
	global  *globalControl
	home    string
	started time.Time
	mu      sync.Mutex
	// seen holds each region's latest heartbeat, stamped with the time the home
	// received it.
	seen map[string]globalcontrol.Heartbeat
	// synced are the peers the mirror consumers were last synced to.
	synced []string
	primed bool
}

func newRosterKeeper(global *globalControl, home string, started time.Time) *rosterKeeper {
	return &rosterKeeper{global: global, home: home, started: started, seen: map[string]globalcontrol.Heartbeat{}}
}

// record keeps a valid heartbeat that arrived on its own cell's subject, and
// drops anything else.
func (keeper *rosterKeeper) record(message *nats.Msg, now time.Time) {
	var heartbeat globalcontrol.Heartbeat
	if protocol.DecodeStrict(message.Data, &heartbeat, maxHeartbeatBytes) != nil || heartbeat.Validate() != nil ||
		protocol.RegionHealthSubject(heartbeat.Cell) != message.Subject {
		return
	}
	heartbeat.SentAt = now.UTC()
	keeper.mu.Lock()
	defer keeper.mu.Unlock()
	keeper.seen[heartbeat.Cell] = heartbeat
}

// refresh rebuilds the roster from the heartbeats while this leader can
// mutate, writes it when it changed, and keeps the mirror consumers on its
// peers. A restarted home gives the regions of the stored roster a full
// RegionSilence from its start before it drops them.
func (keeper *rosterKeeper) refresh(ctx context.Context, now time.Time) error {
	snapshot := keeper.global.authority.Current()
	keeper.mu.Lock()
	seen := maps.Clone(keeper.seen)
	keeper.mu.Unlock()
	if !snapshot.CanMutate() {
		return nil
	}
	// The home's own entry needs its OCI region, which its heartbeat carries.
	if _, ok := seen[keeper.home]; !ok {
		return nil
	}
	current, _, err := keeper.global.reader.Roster(ctx)
	if errors.Is(err, globalcontrol.ErrNotFound) {
		current, err = globalcontrol.Roster{}, nil
	}
	if err != nil {
		return err
	}
	for _, entry := range current.Regions {
		if _, ok := seen[entry.Cell]; !ok && entry.Cell != keeper.home {
			seen[entry.Cell] = globalcontrol.Heartbeat{Version: globalcontrol.HeartbeatVersion, Cell: entry.Cell,
				OCIRegion: entry.OCIRegion, SentAt: keeper.started}
		}
	}
	next, changed := globalcontrol.NextRoster(current, keeper.home, seen, now)
	if changed {
		if _, err := keeper.global.writer.PutRoster(ctx, snapshot.Epoch, next); err != nil {
			return err
		}
	}
	peers := rosterPeersOf(next, keeper.home)
	if keeper.primed && slices.Equal(peers, keeper.synced) {
		return nil
	}
	if err := keeper.global.writer.SyncMirrors(ctx, peers); err != nil {
		return err
	}
	keeper.synced, keeper.primed = peers, true
	return nil
}

// followRoster offers every region's roster peers to apply each time they
// change, and every HeartbeatInterval otherwise. A roster that cannot be read
// keeps the last peers, so a partition does not unlink anyone.
func followRoster(ctx context.Context, reader *globalcontrol.Reader, local string, apply func([]string)) {
	var current []string
	var failures failureLog
	ticker := time.NewTicker(globalcontrol.HeartbeatInterval)
	defer ticker.Stop()
	for {
		roster, _, err := reader.Roster(ctx)
		if errors.Is(err, globalcontrol.ErrNotFound) {
			err = nil
		}
		failures.report("global roster unavailable", err)
		if peers := rosterPeersOf(roster, local); err == nil && !slices.Equal(peers, current) {
			apply(peers)
			current = peers
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// rosterPeersOf lists every roster region but local, in roster order.
func rosterPeersOf(roster globalcontrol.Roster, local string) []string {
	var peers []string
	for _, entry := range roster.Regions {
		if entry.Cell != local {
			peers = append(peers, entry.Cell)
		}
	}
	return peers
}

// rosterPeers is the set of roster regions other than this one, as
// followRoster last saw it. Subscribers hear every change.
type rosterPeers struct {
	mu          sync.Mutex
	list        []string
	known       bool // a roster has been read
	subscribers []func([]string)
}

// apply records peers as current and offers them to every subscriber.
func (peers *rosterPeers) apply(list []string) {
	peers.mu.Lock()
	defer peers.mu.Unlock()
	peers.list, peers.known = list, true
	for _, subscriber := range peers.subscribers {
		subscriber(list)
	}
}

// current returns the peers as followRoster last applied them.
func (peers *rosterPeers) current() []string {
	list, _ := peers.read()
	return list
}

// read returns the current peers and whether a roster has been read yet.
func (peers *rosterPeers) read() ([]string, bool) {
	peers.mu.Lock()
	defer peers.mu.Unlock()
	return slices.Clone(peers.list), peers.known
}

// follow offers the current peers to fn now, and every later change.
func (peers *rosterPeers) follow(fn func([]string)) {
	peers.mu.Lock()
	defer peers.mu.Unlock()
	peers.subscribers = append(peers.subscribers, fn)
	fn(peers.list)
}

// atlasRoster is the Atlas loop's config: the spec's section with its regions
// replaced by local and the roster peers, as Atlas region IDs (gru-1). Until
// the first roster is read, and when the roster cannot be listed, it keeps the
// spec's regions, so deploy targets never shrink at startup; each distinct
// error is logged once.
func atlasRoster(spec func() *atlas.Config, local string, peers *rosterPeers) func() *atlas.Config {
	var logged string
	return func() *atlas.Config {
		config := spec()
		peerCells, known := peers.read()
		if config == nil || !known {
			return config
		}
		var ids []string
		for _, cell := range append([]string{local}, peerCells...) {
			id, err := naming.RegionCell(cell).Name()
			if err != nil {
				return config
			}
			ids = append(ids, id)
		}
		next, err := config.WithRegions(ids)
		if err != nil {
			if message := err.Error(); message != logged {
				slog.Warn("Atlas keeps the spec's regions: the roster cannot be listed", observability.ComponentKey, "atlas", "error", err)
				logged = message
			}
			return config
		}
		logged = ""
		return &next
	}
}

// linkRoster keeps links connected to exactly the roster peers, over conn.
func linkRoster(links *regionlink.Links, conn *nats.Conn, peers *rosterPeers) {
	if peers == nil {
		return
	}
	var linked []string
	peers.follow(func(current []string) {
		for _, peer := range current {
			if !slices.Contains(linked, peer) {
				if err := links.Link(peer, conn); err != nil {
					slog.Warn("region link unavailable", observability.ComponentKey, "region", "peer", peer, "error", err)
				}
			}
		}
		for _, peer := range linked {
			if !slices.Contains(current, peer) {
				links.Unlink(peer)
			}
		}
		linked = current
	})
}

// failureLog reports each distinct failure once, until a pass succeeds.
type failureLog struct{ last string }

func (failures *failureLog) report(message string, err error) {
	if err == nil || errors.Is(err, context.Canceled) {
		failures.last = ""
		return
	}
	if err.Error() != failures.last {
		slog.Warn(message, observability.ComponentKey, "region", "error", err)
	}
	failures.last = err.Error()
}
