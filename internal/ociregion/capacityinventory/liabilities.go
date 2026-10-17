package capacityinventory

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/capacityledger"
	"github.com/TerraScale/ts-orchestrator/internal/foundationbinding"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
)

// KnownLiabilities is an original-tariff subtotal, not complete accounting or
// spending authority. Unbound resources have no invented historical price.
type KnownLiabilities struct {
	ScopeSHA256, Currency string
	ObservedAt, ExpiresAt time.Time
	MonthlyCents          uint64
	Resources             []Resource
	Commitments           []capacityledger.Receipt
	UnknownOperations     []string
	UnboundResources      []string
	UnboundedCompartments []string
	Pending               []string
}

// ReadKnownLiabilities consumes only authenticated root records. It never reads
// a regional journal and never discovers financial membership through tags.
func (r *Reader) ReadKnownLiabilities(ctx context.Context, scope Scope, histories ...foundationbinding.VerifiedCapacityLedger) (KnownLiabilities, error) {
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	started := time.Now()
	view := KnownLiabilities{ScopeSHA256: scope.SHA256, Currency: scope.Currency, ObservedAt: started, ExpiresAt: minTime(started.Add(2*time.Minute), scope.ExpiresAt)}
	if err := scope.validate(started); err != nil {
		return view, err
	}
	tenancy, err := r.factory.Provider().TenancyOCID()
	if err != nil || tenancy != scope.TenancyID {
		return view, errors.New("financial inventory principal differs from signed tenancy")
	}
	actual := map[string]Resource{}
	for _, region := range scope.Regions {
		factory, err := r.factory.ForRegion(region.OCIRegion)
		if err != nil {
			return view, err
		}
		compute, err := factory.Compute()
		if err != nil {
			return view, err
		}
		block, err := factory.Blockstorage()
		if err != nil {
			return view, err
		}
		ociclient.PinHost(&compute.BaseClient, r.endpoint)
		ociclient.PinHost(&block.BaseClient, r.endpoint)
		for _, compartment := range region.CompartmentIDs {
			// Current protected host records do not prove all historical/non-node
			// charges in any compartment, including one whose lists are empty.
			view.UnboundedCompartments = append(view.UnboundedCompartments, region.Cell+"/"+compartment)
			items, err := directResources(ctx, compute, block, compartment)
			if err != nil {
				view.Pending = append(view.Pending, "direct financial inventory incomplete: "+region.Cell+"/"+compartment+": "+err.Error())
			}
			for _, item := range items {
				if item.Identifier == nil || *item.Identifier == "" || item.CompartmentId == nil || *item.CompartmentId != compartment {
					return view, errors.New("direct financial inventory has an absent or out-of-scope identity")
				}
				if _, seen := actual[*item.Identifier]; seen {
					return view, errors.New("direct financial inventory repeats a resource identity")
				}
				resource := Resource{ID: *item.Identifier, Cell: region.Cell, CompartmentID: compartment}
				if _, err := observedCost(ctx, compute, block, item, nil, &resource); err != nil {
					view.Pending = append(view.Pending, resource.ID+": "+err.Error())
				}
				// Tags cannot attach a resource to a financial reservation.
				resource.OperationID, resource.RecipeSHA256 = "", ""
				actual[resource.ID] = resource
			}
		}
	}
	seenCells, seenOps, boundIDs := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, history := range histories {
		if !history.ValidAt(time.Now()) || history.TenancyID() != scope.TenancyID || history.Currency() != scope.Currency || seenCells[history.Cell()] {
			return view, errors.New("financial history is stale, repeated or differs from authenticated scope")
		}
		index := slices.IndexFunc(scope.Regions, func(region RegionScope) bool { return region.Cell == history.Cell() })
		if index < 0 {
			return view, errors.New("financial history cell lies outside the signed scope")
		}
		seenCells[history.Cell()] = true
		view.ExpiresAt = minTime(view.ExpiresAt, history.ExpiresAt())
		ledger := history.Ledger()
		amount, err := ledger.Monthly(started)
		if err != nil || ^uint64(0)-view.MonthlyCents < amount {
			return view, errors.Join(err, errors.New("protected financial liability total is invalid or overflows"))
		}
		view.MonthlyCents += amount
		for _, host := range ledger.Hosts {
			receipt := host.Receipt
			if seenOps[receipt.OperationID] || !slices.Contains(scope.Regions[index].CompartmentIDs, receipt.Quote.CompartmentID) {
				return view, errors.New("financial history repeats an original operation or lies outside its physical compartment")
			}
			seenOps[receipt.OperationID] = true
			view.Commitments = append(view.Commitments, receipt)
			if host.BornAt.IsZero() {
				view.UnknownOperations = append(view.UnknownOperations, receipt.OperationID)
				continue
			}
			monthly, err := (capacityledger.Ledger{Version: capacityledger.Version, Hosts: []capacityledger.Host{host}}).Monthly(started)
			if err != nil {
				return view, err
			}
			for _, id := range []string{host.InstanceID, host.BootVolumeID} {
				if boundIDs[id] {
					return view, errors.New("protected histories bind one resource to more than one original liability")
				}
				boundIDs[id] = true
				resource, found := actual[id]
				retiredAt := host.InstanceRetiredAt
				if id == host.BootVolumeID {
					retiredAt = host.BootRetiredAt
				}
				if !found {
					resource = Resource{ID: id, Cell: history.Cell(), CompartmentID: receipt.Quote.CompartmentID, LifecycleState: "UNKNOWN"}
					if !retiredAt.IsZero() {
						resource.LifecycleState = "TERMINATED"
					} else {
						view.Pending = append(view.Pending, id+": original resource has no current SDK observation or positive terminal result")
					}
				} else if resource.Cell != history.Cell() || resource.CompartmentID != receipt.Quote.CompartmentID {
					return view, errors.New("actual resource escaped its exact original financial scope")
				} else if terminalState(resource.LifecycleState) != !retiredAt.IsZero() {
					view.Pending = append(view.Pending, id+": actual lifecycle differs from protected terminal history")
				} else if !terminalState(resource.LifecycleState) {
					q := receipt.Quote
					if id == host.InstanceID && (resource.Shape != q.Shape || resource.OCPUs != q.OCPUs || resource.MemoryGB != q.MemoryGB) ||
						id == host.BootVolumeID && (resource.SizeGB != q.BootGB || resource.VPUs != 10) {
						view.Pending = append(view.Pending, id+": actual dimensions have no immutable original tariff ceiling")
					}
				}
				resource.OperationID, resource.RecipeSHA256 = receipt.OperationID, receipt.RecipeSHA256
				if id == host.InstanceID {
					resource.MonthlyCents = monthly
				}
				view.Resources = append(view.Resources, resource)
			}
		}
	}
	for _, region := range scope.Regions {
		if !seenCells[region.Cell] {
			view.Pending = append(view.Pending, "protected financial history absent: "+region.Cell)
		}
	}
	for id, resource := range actual {
		if !boundIDs[id] {
			view.UnboundResources = append(view.UnboundResources, id)
			view.Resources = append(view.Resources, resource)
		}
	}
	slices.SortFunc(view.Resources, func(a, b Resource) int { return strings.Compare(a.ID, b.ID) })
	slices.SortFunc(view.Commitments, func(a, b capacityledger.Receipt) int { return strings.Compare(a.OperationID, b.OperationID) })
	slices.Sort(view.UnboundResources)
	slices.Sort(view.UnknownOperations)
	slices.Sort(view.UnboundedCompartments)
	slices.Sort(view.Pending)
	view.Pending = slices.Compact(view.Pending)
	for _, history := range histories {
		if err := history.Revalidate(ctx); err != nil {
			return view, fmt.Errorf("protected history changed during financial observation: %w", err)
		}
	}
	if !time.Now().Before(view.ExpiresAt) {
		return view, errors.New("financial inventory outlived its original observations or signed scope")
	}
	return view, nil
}
