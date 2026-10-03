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

// maxPeerHolds bounds one peer's placement holds read per planning round.
const maxPeerHolds = 256

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
		result, err := source.Query(ctx, decisionlog.Query{Regions: []string{peer}, Kinds: []decisionlog.Kind{decisionlog.KindHeld},
			Actors: []string{"placement"}, Since: since, Until: now.Add(time.Second), Limit: maxPeerHolds})
		if err != nil {
			continue
		}
		for _, decision := range result.Decisions {
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
