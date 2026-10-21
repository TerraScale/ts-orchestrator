package budget

import (
	"context"
	"errors"
	"fmt"
	"math"
	"slices"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/globalcontrol"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/capacityinventory"
	"github.com/TerraScale/ts-orchestrator/internal/region"
)

// AllocateInfrastructure permits candidate planning from signed infrastructure
// headroom. It authorizes no purchase: Reserve and Revalidate require the exact
// candidate quote before every mutation. Status prices and forecasts are unused.
// Region.At is the demand observation time, not a Usage API cost timestamp.
// An error returns a held document so callers can withdraw prior planning grants.
func AllocateInfrastructure(ctx context.Context, reader *globalcontrol.Reader, proof region.VerifiedInfrastructureSpend,
	snapshot capacityinventory.Snapshot, regions []Region, prior *Capacity, now time.Time,
) (Capacity, error) {
	c := Allocate(nil, regions, prior, now)
	c.Reason = "infrastructure candidate planning is held"
	fail := func(err error) (Capacity, error) {
		c.Reason = "infrastructure candidate planning is held: " + err.Error()
		return c, err
	}
	if reader == nil {
		return fail(errors.New("home global reader is unavailable"))
	}
	stored, exists, err := ReadCapacity(ctx, reader)
	if err != nil {
		return fail(err)
	}
	if exists {
		c.Spending, c.Reservations = stored.Spending, slices.Clone(stored.Reservations)
		c.BootstrapReservedCents = max(c.BootstrapReservedCents, stored.BootstrapReservedCents)
		if stored.BootstrapSHA256 != "" {
			c.BootstrapSHA256 = stored.BootstrapSHA256
		}
	} else if c.Spending != nil || len(c.Reservations) > 0 || c.BootstrapReservedCents > 0 || c.BootstrapSHA256 != "" {
		return fail(errors.New("previous infrastructure commitments are absent from the durable ledger"))
	}
	// Pin signed bootstrap commitments even when complete cost evidence is unavailable.
	if err := retainBootstrap(&c, proof); err != nil {
		return fail(err)
	}
	monthly, hasBudget, limit, err := spendingFacts(ctx, reader, proof, snapshot, now)
	if err != nil {
		return fail(err)
	}
	limit, err = bootstrapLimit(c, proof, limit)
	if err != nil {
		return fail(err)
	}
	if limit == 0 {
		return fail(errors.New("the full infrastructure ceiling is reserved for bootstrap"))
	}
	seen := map[string]bool{}
	for _, status := range regions {
		cell := strings.ToUpper(status.Cell)
		if cell == "" || seen[cell] || status.Nodes < 0 || status.Want < 0 || math.IsNaN(status.Pressure) || math.IsInf(status.Pressure, 0) {
			c.Regions = nil
			return fail(errors.New("regional demand lacks unique cells or valid node counts and pressure"))
		}
		seen[cell] = true
	}
	total := projection(c, snapshot, "")
	if c.Spending != nil {
		// A periodic planning write cannot release an older unresolved commitment.
		total = max(total, c.Spending.ProjectedCents)
	}
	latest, found, err := ReadBudget(ctx, reader)
	if err != nil {
		return fail(err)
	}
	if found != hasBudget || found && latest != monthly {
		return fail(errors.New("tenant spending ceiling changed during infrastructure planning"))
	}
	c.CapCents, c.Currency, c.ProjectedCents = limit, proof.Currency(), total
	c.Ratio = float64(total) / float64(limit)
	switch {
	case total >= limit:
		c.State = StateOver
		c.Reason = "complete infrastructure commitments leave no headroom for candidate planning"
	case c.Ratio >= WarnRatio:
		c.State = StateWarn
	default:
		c.State = StateOK
	}
	if total < limit {
		var planned []string
		scope := proof.Footprint()
		for _, status := range regions {
			owned := slices.ContainsFunc(scope.Regions, func(s capacityinventory.RegionScope) bool { return strings.EqualFold(s.Cell, status.Cell) })
			if !owned || status.At.IsZero() || now.Sub(status.At) > AllowanceMaxAge || status.At.Sub(now) > AllowanceMaxAge || status.Want <= status.Nodes || status.Nodes+1 <= status.Nodes {
				continue
			}
			i := slices.IndexFunc(c.Regions, func(r RegionAllowance) bool { return r.Cell == status.Cell })
			c.Regions[i].Allowance, c.Regions[i].GrantedAt = status.Nodes+1, now
			planned = append(planned, status.Cell)
		}
		if len(planned) == 0 {
			c.Reason = "no authorized region has fresh demand for candidate planning"
		} else {
			slices.Sort(planned)
			c.Reason = fmt.Sprintf("provisional candidate planning for %s; exact quoted spending reservation required", strings.Join(planned, ", "))
		}
	}
	if err := c.Validate(); err != nil {
		return Capacity{}, err
	}
	return c, nil
}
