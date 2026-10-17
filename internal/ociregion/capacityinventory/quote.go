package capacityinventory

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/capacityledger"
	"github.com/TerraScale/ts-orchestrator/internal/ocicost"
)

// Quote is minted only after reading current public tariffs for the exact
// requested billing geometry. It does not replace signed spend authority or a complete ledger.
type Quote struct {
	scopeSHA256, cell, compartment, shape, currency string
	ocpus, memoryGB, bootGB                         float64
	monthlyCents                                    uint64
	issuedAt, expiresAt                             time.Time
	prices                                          []ocicost.Price
}

func (q Quote) Prices() []ocicost.Price { return slices.Clone(q.prices) }
func (q Quote) Currency() string        { return q.currency }
func (q Quote) MonthlyCents() uint64    { return q.monthlyCents }
func (q Quote) IssuedAt() time.Time     { return q.issuedAt }
func (q Quote) ExpiresAt() time.Time    { return q.expiresAt }

// Original retains the exact quote for a protected financial receipt. The
// returned data does not carry the SDK producer's spending authority.
func (q Quote) Original() capacityledger.Quote {
	return capacityledger.Quote{ScopeSHA256: q.scopeSHA256, Cell: q.cell, CompartmentID: q.compartment,
		Shape: q.shape, Currency: q.currency, OCPUs: q.ocpus, MemoryGB: q.memoryGB, BootGB: q.bootGB,
		MonthlyCents: q.monthlyCents, IssuedAt: q.issuedAt, ExpiresAt: q.expiresAt, Prices: slices.Clone(q.prices)}
}

func (q Quote) Validate(scope Scope, cell, compartment, shape string, ocpus, memoryGB, bootGB float64, now time.Time) error {
	if err := scope.validate(now); err != nil {
		return err
	}
	if q.scopeSHA256 != scope.SHA256 || q.currency != scope.Currency || q.cell != cell || q.compartment != compartment || q.shape != shape || q.ocpus != ocpus || q.memoryGB != memoryGB || q.bootGB != bootGB || len(q.prices) != 4 || q.issuedAt.After(now) || now.Sub(q.issuedAt) > 2*time.Minute || !now.Before(q.expiresAt) || q.expiresAt.After(scope.ExpiresAt) {
		return errors.New("current tariff quote is absent, stale or differs from exact authorized geometry")
	}
	return nil
}

func (r *Reader) Quote(ctx context.Context, scope Scope, cell, compartment, shape string, ocpus, memoryGB, bootGB float64) (Quote, error) {
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	now := time.Now()
	if err := scope.validate(now); err != nil {
		return Quote{}, err
	}
	owned := false
	for _, region := range scope.Regions {
		owned = owned || region.Cell == cell && slices.Contains(region.CompartmentIDs, compartment)
	}
	if !owned {
		return Quote{}, errors.New("candidate quote lies outside authorized regional footprint")
	}
	prices, err := r.Prices(ctx, scope, []string{shape})
	if err != nil {
		return Quote{}, err
	}
	monthly, known := ocicost.NodeMonthlyCents(prices, shape, ocpus, memoryGB, bootGB)
	if !known {
		return Quote{}, errors.New("candidate quote has invalid billing dimensions or tariffs")
	}
	return Quote{scopeSHA256: scope.SHA256, cell: cell, compartment: compartment, shape: shape, currency: scope.Currency, ocpus: ocpus, memoryGB: memoryGB, bootGB: bootGB, monthlyCents: monthly, issuedAt: now, expiresAt: minTime(now.Add(2*time.Minute), scope.ExpiresAt), prices: prices}, nil
}
