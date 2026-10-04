// Package regionplanner turns demand and failure signals into region
// proposals. It only ever proposes: every proposal starts in the lifecycle's
// Proposed phase and needs a signed human or policy approval before anything
// is admitted or spent. The planner never approves, admits, or executes.
package regionplanner

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/regionlifecycle"
)

// SignalKind classifies one observation that may justify a region.
type SignalKind string

const (
	// SignalUnplaceableIntent: a placement intent names a catalog cell with no
	// Active region. Cell is the requested cell.
	SignalUnplaceableIntent SignalKind = "unplaceable-intent"
	// SignalCapacityError: OCI reported out-of-host-capacity in Cell.
	SignalCapacityError SignalKind = "capacity-error"
	// SignalLimitError: OCI reported a service limit exceeded in Cell.
	SignalLimitError SignalKind = "limit-error"
	// SignalLatency: clients nearest to Cell observed LatencyMillis p95 while
	// being served from another region.
	SignalLatency SignalKind = "latency"
)

// Signal is one observation. EvidenceDigest is the SHA-256 of the evidence
// record that produced it (placement intent, OCI error, latency rollup).
type Signal struct {
	Kind           SignalKind `json:"kind"`
	Cell           string     `json:"cell"`
	EvidenceDigest string     `json:"evidence_digest"`
	ObservedAt     time.Time  `json:"observed_at"`
	LatencyMillis  uint32     `json:"latency_millis,omitzero"`
}

// Source yields signals observed since a time. Implementations read
// placement holds, classified Fleet.EnsureHost failures, and latency rollups.
type Source interface {
	Signals(ctx context.Context, since time.Time) ([]Signal, error)
}

// CatalogEntry is a region the planner may propose. Overflow names the cell
// to propose when this region is capacity- or limit-constrained.
type CatalogEntry struct {
	Cell                  string
	OCIRegion             string
	EstimatedMonthlyCents uint64
	Overflow              string
}

// Policy tunes the planner. Thresholds count signals within Window.
type Policy struct {
	Catalog                map[string]CatalogEntry
	Window                 time.Duration
	CapacityThreshold      int
	LatencyThresholdMillis uint32
	LatencySamples         int
	MaxRegions             int
	MonthlyCeilingCents    uint64
	// Home is the global home region. It has no lifecycle record but takes
	// a region slot and spends against the ceiling, and is never proposed.
	Home regionlifecycle.Home
}

var (
	digestToken = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

const (
	maxEvidence = 16
	// maxProposalID is the lifecycle's proposal ID length bound.
	maxProposalID = 63
)

func (p Policy) validate() error {
	if len(p.Catalog) == 0 || p.Window <= 0 || p.CapacityThreshold < 1 || p.LatencyThresholdMillis == 0 ||
		p.LatencySamples < 1 || p.MaxRegions < 1 || p.MonthlyCeilingCents == 0 {
		return errors.New("region planner policy is incomplete")
	}
	if err := p.Home.Validate(); err != nil {
		return err
	}
	for cell, entry := range p.Catalog {
		if cell != entry.Cell || !regionlifecycle.ValidCell(cell) || entry.OCIRegion == "" || entry.EstimatedMonthlyCents == 0 {
			return fmt.Errorf("region catalog entry %q is invalid", cell)
		}
		// A product cell must keep the OCI region the product catalog binds it
		// to; only cells outside that catalog may name a new region.
		if product, ok := catalog.Lookup(strings.ToUpper(cell)); ok && product.OCIRegion != entry.OCIRegion {
			return fmt.Errorf("region catalog entry %q names %s, but the product catalog binds it to %s",
				cell, entry.OCIRegion, product.OCIRegion)
		}
		if entry.Overflow != "" {
			if _, ok := p.Catalog[entry.Overflow]; !ok || entry.Overflow == cell {
				return fmt.Errorf("region catalog overflow of %q is not another catalog region", cell)
			}
		}
	}
	return nil
}

// Planner proposes regions from signals.
type Planner struct {
	Policy Policy
}

type candidate struct {
	kinds    map[SignalKind]int
	evidence map[string]struct{}
}

// Plan returns new proposals, sorted by cell. It skips cells that already
// have an open lifecycle record, cells rejected or retired within Window
// (to avoid flapping), and proposals that would exceed the region maximum
// or the global monthly ceiling, which admission would refuse anyway.
func (p Planner) Plan(signals []Signal, records []regionlifecycle.Record, now time.Time) ([]regionlifecycle.Proposal, error) {
	if err := p.Policy.validate(); err != nil {
		return nil, err
	}
	since := now.Add(-p.Policy.Window)
	capacity := map[string]map[string]struct{}{}
	latency := map[string]map[string]struct{}{}
	candidates := map[string]*candidate{}
	add := func(cell string, kind SignalKind, evidence ...string) {
		entry := candidates[cell]
		if entry == nil {
			entry = &candidate{kinds: map[SignalKind]int{}, evidence: map[string]struct{}{}}
			candidates[cell] = entry
		}
		entry.kinds[kind] += len(evidence)
		for _, digest := range evidence {
			entry.evidence[digest] = struct{}{}
		}
	}
	for _, signal := range signals {
		if signal.ObservedAt.Before(since) || signal.ObservedAt.After(now) ||
			!digestToken.MatchString(signal.EvidenceDigest) {
			continue
		}
		if _, known := p.Policy.Catalog[signal.Cell]; !known {
			continue
		}
		switch signal.Kind {
		case SignalUnplaceableIntent:
			add(signal.Cell, signal.Kind, signal.EvidenceDigest)
		case SignalCapacityError, SignalLimitError:
			if capacity[signal.Cell] == nil {
				capacity[signal.Cell] = map[string]struct{}{}
			}
			capacity[signal.Cell][signal.EvidenceDigest] = struct{}{}
		case SignalLatency:
			if signal.LatencyMillis >= p.Policy.LatencyThresholdMillis {
				if latency[signal.Cell] == nil {
					latency[signal.Cell] = map[string]struct{}{}
				}
				latency[signal.Cell][signal.EvidenceDigest] = struct{}{}
			}
		}
	}
	for cell, evidence := range capacity {
		overflow := p.Policy.Catalog[cell].Overflow
		if overflow != "" && len(evidence) >= p.Policy.CapacityThreshold {
			add(overflow, SignalCapacityError, slices.Collect(maps.Keys(evidence))...)
		}
	}
	for cell, evidence := range latency {
		if len(evidence) >= p.Policy.LatencySamples {
			add(cell, SignalLatency, slices.Collect(maps.Keys(evidence))...)
		}
	}

	fleet := regionlifecycle.FleetOf(records, "", p.Policy.Home)
	var proposals []regionlifecycle.Proposal
	for _, cell := range slices.Sorted(maps.Keys(candidates)) {
		if cell == p.Policy.Home.Cell || blocked(records, cell, since) {
			continue
		}
		entry := p.Policy.Catalog[cell]
		if fleet.Regions >= p.Policy.MaxRegions ||
			!regionlifecycle.FitsCeiling(fleet.CommittedMonthlyCents, entry.EstimatedMonthlyCents, p.Policy.MonthlyCeilingCents) {
			continue
		}
		proposal := p.proposal(entry, candidates[cell], nextProposalGeneration(records, cell), now)
		if err := proposal.Validate(); err != nil {
			return nil, err
		}
		proposals = append(proposals, proposal)
		// Count this round's proposals so one plan cannot overshoot.
		fleet.Regions++
		fleet.CommittedMonthlyCents = regionlifecycle.SaturatingAdd(fleet.CommittedMonthlyCents, entry.EstimatedMonthlyCents)
	}
	return proposals, nil
}

func blocked(records []regionlifecycle.Record, cell string, since time.Time) bool {
	for _, record := range records {
		if record.Cell != cell {
			continue
		}
		if record.Phase.Open() || record.UpdatedAt.After(since) {
			return true
		}
	}
	return false
}

// nextProposalGeneration is the ProposalGeneration a proposal for cell would
// get: 1 for a new cell, or the next record generation when it replaces a
// terminal record (Machine.Repropose).
func nextProposalGeneration(records []regionlifecycle.Record, cell string) uint64 {
	for _, record := range records {
		if record.Cell == cell {
			return record.Generation + 1
		}
	}
	return 1
}

func (p Planner) proposal(entry CatalogEntry, found *candidate, generation uint64, now time.Time) regionlifecycle.Proposal {
	evidence := slices.Sorted(maps.Keys(found.evidence))
	if len(evidence) > maxEvidence {
		evidence = evidence[:maxEvidence]
	}
	var reasons []string
	for _, kind := range slices.Sorted(maps.Keys(found.kinds)) {
		reasons = append(reasons, fmt.Sprintf("%s x%d", kind, found.kinds[kind]))
	}
	// The planning round (a Window bucket) is part of the identity: evidence
	// digests are stable across windows, and Repropose refuses the previous
	// proposal ID, so without it persistent demand could never propose the
	// cell again after a terminal decision.
	//
	// The target proposal generation is part of it too. Repropose refuses
	// only the immediately preceding ID, so an ID that could recur for a
	// later attempt would let that attempt share an earlier attempt's
	// identity in approvals, journal records and retry tokens. With the
	// generation, no two attempts on one cell ever share a proposal ID.
	round := now.UTC().Truncate(p.Policy.Window).Format(time.RFC3339)
	gen := strconv.FormatUint(generation, 10)
	identity := sha256.Sum256([]byte(entry.Cell + "\x00" + gen + "\x00" + round + "\x00" + strings.Join(evidence, ",")))
	id := entry.Cell + "-g" + gen + "-" + hex.EncodeToString(identity[:6])
	if len(id) > maxProposalID {
		// A long cell and generation still get a unique, valid ID: the
		// generation stays inside the hashed identity.
		id = entry.Cell + "-" + hex.EncodeToString(identity[:6])
	}
	return regionlifecycle.Proposal{
		ID: id, Cell: entry.Cell, OCIRegion: entry.OCIRegion,
		Reason: "planner: " + strings.Join(reasons, ", "), EvidenceDigests: evidence,
		EstimatedMonthlyCents: entry.EstimatedMonthlyCents, ProposedAt: now.UTC(),
	}
}

// Submit records proposals as Proposed lifecycle records under the global
// leader's epoch. A cell that already has a record is skipped. Nothing here
// approves or spends.
func Submit(ctx context.Context, store *regionlifecycle.Store, machine regionlifecycle.Machine, epoch uint64,
	proposals []regionlifecycle.Proposal, now time.Time,
) ([]string, error) {
	var submitted []string
	for _, proposal := range proposals {
		record, err := machine.Propose(proposal, now)
		if err != nil {
			return submitted, err
		}
		_, err = store.Create(ctx, epoch, record)
		if errors.Is(err, regionlifecycle.ErrConflict) {
			// The cell has a record: replace it only if it is terminal.
			prior, revision, getErr := store.Get(ctx, proposal.Cell)
			if getErr != nil {
				return submitted, getErr
			}
			if !prior.Phase.Terminal() {
				continue
			}
			if record, err = machine.Repropose(prior, proposal, now); err != nil {
				if errors.Is(err, regionlifecycle.ErrInvalidTransition) {
					continue // the same proposal was already decided
				}
				return submitted, err
			}
			_, err = store.Repropose(ctx, epoch, prior, record, revision)
			if errors.Is(err, regionlifecycle.ErrConflict) {
				continue
			}
		}
		if err != nil {
			return submitted, err
		}
		recordProposal(ctx, epoch, proposal)
		submitted = append(submitted, proposal.Cell)
	}
	return submitted, nil
}

// Run collects signals once, plans, and submits. Callers run it on the
// global leader on a slow interval.
func Run(ctx context.Context, source Source, planner Planner, store *regionlifecycle.Store,
	machine regionlifecycle.Machine, epoch uint64, now time.Time,
) ([]string, error) {
	signals, err := source.Signals(ctx, now.Add(-planner.Policy.Window))
	if err != nil {
		return nil, err
	}
	records, err := store.List(ctx)
	if err != nil {
		return nil, err
	}
	proposals, err := planner.Plan(signals, records, now)
	if err != nil {
		return nil, err
	}
	return Submit(ctx, store, machine, epoch, proposals, now)
}
