package regionplanner

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"slices"
	"strings"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/decisionlog"
)

// ClassifyHold maps a placement hold reason to a capacity or limit signal
// kind. Reasons that report neither OCI host capacity nor a service limit
// return "" and are not planner signals.
func ClassifyHold(reason string) SignalKind {
	reason = strings.ToLower(reason)
	switch {
	case strings.Contains(reason, "out of host capacity") || strings.Contains(reason, "outofhostcapacity") ||
		strings.Contains(reason, "insufficient capacity"):
		return SignalCapacityError
	case strings.Contains(reason, "limitexceeded") || strings.Contains(reason, "limit exceeded") ||
		strings.Contains(reason, "service limit"):
		return SignalLimitError
	}
	return ""
}

// Sources merges several signal sources. A failing source fails the round:
// planning on a silently partial view could skip a region that needs one,
// but never proposes one that does not, so the caller just retries later.
type Sources []Source

func (sources Sources) Signals(ctx context.Context, since time.Time) ([]Signal, error) {
	var all []Signal
	var errs []error
	for _, source := range sources {
		if source == nil {
			continue
		}
		signals, err := source.Signals(ctx, since)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		all = append(all, signals...)
	}
	return all, errors.Join(errs...)
}

// maxPeerHolds bounds one page of a peer's placement holds, and
// maxPeerHoldPages the pages read per peer and planning round. Holds of
// other kinds (managed updates, artifacts) share the query, so a truncated
// page is followed by older pages until the window is covered or the budget
// is spent; at most maxPeerHolds*maxPeerHoldPages holds are read.
const (
	maxPeerHolds     = 256
	maxPeerHoldPages = 8
)

// peerHoldPages reads one peer's placement holds in the window, newest
// first, paging back through truncated results. A failed page ends the read
// with what was gathered.
func peerHoldPages(ctx context.Context, source decisionlog.Source, peer string, since, now time.Time,
) []decisionlog.Decision {
	var decisions []decisionlog.Decision
	seen := map[string]bool{}
	until := now.Add(time.Second)
	for range maxPeerHoldPages {
		result, err := source.Query(ctx, decisionlog.Query{Regions: []string{peer},
			Kinds: []decisionlog.Kind{decisionlog.KindHeld}, Actors: []string{"placement"}, Since: since, Until: until,
			Limit: maxPeerHolds})
		if err != nil {
			break
		}
		oldest := until
		added := 0
		for _, decision := range result.Decisions {
			if decision.Time.Before(oldest) {
				oldest = decision.Time
			}
			if seen[decision.ID] {
				continue
			}
			seen[decision.ID] = true
			decisions = append(decisions, decision)
			added++
		}
		if !result.Truncated || !oldest.After(since) {
			break
		}
		if added == 0 {
			// A whole page shares the boundary timestamp: the query has no
			// ID cursor, so skip past that instant to the older holds
			// rather than stop.
			until = oldest
			continue
		}
		// Until is exclusive: step just past the oldest so holds sharing
		// its timestamp are read again and deduplicated, not skipped.
		until = oldest.Add(time.Nanosecond)
	}
	return decisions
}

// PeerHolds reads other regions' capacity and limit placement holds from
// their decision journals over the interregion observability contract
// (ts.orch.v1.<peer>.obs.decisions), so the home's planner sees a peer that
// is out of OCI capacity, not only its own holds.
//
// A peer's journal is data from another region, not a trusted statement:
// each peer is queried on its own and only decisions about that peer are
// kept, so one region can never raise signals for another. A forged hold can
// at most make the planner propose the peer's overflow region, and a
// proposal still needs a signed approval before anything is admitted or
// spent. An unreachable peer contributes nothing to the round.
type PeerHolds struct {
	// Decisions returns the federated decision source, or nil until the
	// controller has attached it.
	Decisions func() decisionlog.Source
	Peers     []string
	Now       func() time.Time
}

func (holds PeerHolds) Signals(ctx context.Context, since time.Time) ([]Signal, error) {
	if holds.Decisions == nil {
		return nil, nil
	}
	source := holds.Decisions()
	if source == nil {
		return nil, nil
	}
	now := time.Now()
	if holds.Now != nil {
		now = holds.Now()
	}
	var signals []Signal
	for _, peer := range slices.Sorted(slices.Values(holds.Peers)) {
		peer = strings.ToLower(peer)
		for _, decision := range peerHoldPages(ctx, source, peer, since, now) {
			if decision.Region != peer || decision.Actor.Slice != "placement" || decision.Kind != decisionlog.KindHeld ||
				decision.Time.Before(since) || decision.Time.After(now) {
				continue
			}
			kind := ClassifyHold(decision.Reason)
			if kind == "" {
				continue
			}
			evidence := sha256.Sum256([]byte("peer-hold\x00" + peer + "\x00" + decision.ID + "\x00" +
				decision.Time.UTC().Format(time.RFC3339Nano)))
			signals = append(signals, Signal{Kind: kind, Cell: peer, EvidenceDigest: hex.EncodeToString(evidence[:]),
				ObservedAt: decision.Time})
		}
	}
	return signals, nil
}
