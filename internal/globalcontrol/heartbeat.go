package globalcontrol

import (
	"context"
	"errors"
	"slices"
	"strings"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
)

// HeartbeatVersion is the only Heartbeat wire version.
const HeartbeatVersion = 1

// HeartbeatInterval is how often every regional leader publishes its heartbeat
// and the home rebuilds the roster from them.
const HeartbeatInterval = 10 * time.Second

// RegionSilence is how long a region may stay silent before it leaves the roster.
const RegionSilence = 10 * time.Minute

// Heartbeat is a regional leader's liveness record on
// ts.orch.v1.<cell>.region.health. NATS grants each region publish rights only
// on its own cell's subject, so the home trusts a heartbeat only when its cell
// matches the subject it arrived on.
type Heartbeat struct {
	Version   int       `json:"version"`
	Cell      string    `json:"cell"`
	OCIRegion string    `json:"oci_region"`
	SentAt    time.Time `json:"sent_at"`
}

// Validate requires the version, a regional cell and a non-empty OCI region.
func (h Heartbeat) Validate() error {
	if h.Version != HeartbeatVersion || !cellToken.MatchString(h.Cell) || h.Cell == protocol.GlobalScope {
		return errors.New("region heartbeat needs version 1 and a regional cell")
	}
	// The same rule as a roster entry, so one bad heartbeat cannot stall roster writes.
	if !validOCIRegion(h.OCIRegion) {
		return errors.New("region heartbeat needs an OCI region the roster accepts")
	}
	if h.SentAt.IsZero() {
		return errors.New("region heartbeat needs a send time")
	}
	return nil
}

// NextRoster is the roster the heartbeats in seen imply. seen holds
// heartbeats stamped with the time the home received them, so SentAt is the
// receive time. The home is always Active; any other cell heard within
// RegionSilence is Active; every other cell leaves. It returns current and
// false when the entries and home match, otherwise the next generation.
func NextRoster(current Roster, home string, seen map[string]Heartbeat, now time.Time) (Roster, bool) {
	var regions []RosterEntry
	homeEntry := RosterEntry{Cell: home, State: RegionActive}
	if index := slices.IndexFunc(current.Regions, func(entry RosterEntry) bool { return entry.Cell == home }); index >= 0 {
		homeEntry.OCIRegion = current.Regions[index].OCIRegion
	}
	for cell, heartbeat := range seen {
		if cell == home {
			homeEntry.OCIRegion = heartbeat.OCIRegion
		} else if now.Sub(heartbeat.SentAt) < RegionSilence {
			regions = append(regions, RosterEntry{Cell: cell, OCIRegion: heartbeat.OCIRegion, State: RegionActive})
		}
	}
	regions = append(regions, homeEntry)
	slices.SortFunc(regions, func(a, b RosterEntry) int { return strings.Compare(a.Cell, b.Cell) })
	if current.HomeRegion == home && slices.Equal(regions, current.Regions) {
		return current, false
	}
	return Roster{Generation: current.Generation + 1, HomeRegion: home, Regions: regions}, true
}

// SyncMirrors creates the durable mirror consumer of every peer and deletes
// those of regions that are no longer peers, as OpenHome does at startup.
// peers must not include the home.
func (w *Writer) SyncMirrors(ctx context.Context, peers []string) error {
	if err := validMirrorPeers(w.home, peers); err != nil {
		return err
	}
	if err := ensureMirrorConsumers(ctx, w.stream, peers, w.replicas); err != nil {
		return err
	}
	return removeStaleMirrorConsumers(ctx, w.stream, peers)
}
