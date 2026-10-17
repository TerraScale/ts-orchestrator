package app

import (
	"context"
	"strings"

	"github.com/TerraScale/ts-orchestrator/internal/dashboard"
	"github.com/TerraScale/ts-orchestrator/internal/rootoci"
)

// The controller shares collected observations so page ticks do not trigger OCI sweeps.
type dashboardInventory struct {
	source interface {
		Inventory(context.Context) (rootoci.InventoryObservation, error)
	}
}

func (source dashboardInventory) Inventory(ctx context.Context) (dashboard.InventoryObservation, error) {
	observed, err := source.source.Inventory(ctx)
	view := dashboard.InventoryObservation{
		ScopeSHA256: observed.ScopeSHA256, Currency: observed.Currency,
		ObservedAt: observed.ObservedAt, ExpiresAt: observed.ExpiresAt,
		MonthlyCents: observed.MonthlyCents, CoveredCompartments: observed.CoveredCompartments,
		Pending: observed.Pending, KnownLiabilities: observed.KnownLiabilities,
	}
	for _, resource := range observed.Resources {
		kind := "resource"
		if prefix, rest, ok := strings.Cut(resource.ID, "."); ok && prefix == "ocid1" {
			kind, _, _ = strings.Cut(rest, ".")
		}
		view.Items = append(view.Items, dashboard.InventoryItem{Kind: kind, ID: resource.ID,
			Region: resource.Cell, State: resource.LifecycleState, CompartmentID: resource.CompartmentID,
			OperationID: resource.OperationID, Drift: "unknown"})
	}
	return view, err
}

var _ dashboard.InventorySource = dashboardInventory{}
