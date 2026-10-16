package region

import (
	"context"
	"errors"
)

// FoundationResolver exposes only foundations still covered by authenticated
// scope. It grants neither host admission nor permission to found a cluster.
type FoundationResolver struct {
	Footprint Footprint
	Store     FoundationStore
}

func (r FoundationResolver) Resolve(ctx context.Context, cell string) (FoundationRecord, error) {
	if r.Footprint == nil || r.Store == nil {
		return FoundationRecord{}, errors.New("foundation discovery requires authenticated footprint and durable store")
	}
	footprint, err := r.Footprint.AuthorizedRegions(ctx)
	if err != nil {
		return FoundationRecord{}, err
	}
	if err := validateFootprint(footprint); err != nil {
		return FoundationRecord{}, err
	}
	for _, intent := range footprint.Regions {
		if intent.Plan["cell"] != cell {
			continue
		}
		record, _, err := r.Store.Load(ctx, cell)
		if err != nil {
			return FoundationRecord{}, err
		}
		if record.Generation != intent.Generation || record.TenancyID != footprint.TenancyID ||
			record.ParentCompartmentID != footprint.ParentCompartmentID || record.SharedCompartmentID != footprint.SharedCompartmentID || record.Stage != "reconciled" {
			return FoundationRecord{}, errors.New("authorized regional foundation is not reconciled at its current generation")
		}
		return record, nil
	}
	return FoundationRecord{}, errors.New("region is outside authenticated foundation footprint")
}
