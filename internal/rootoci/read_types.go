package rootoci

import (
	"context"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/ocicost"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/capacityinventory"
	"github.com/TerraScale/ts-orchestrator/internal/releasechannel"
)

// Reader exposes observations of root-derived signed scope, never SDK requests.
type Reader interface {
	Inventory(context.Context, Call) (InventoryObservation, error)
	ObserveLocalInstance(context.Context, Call) (bootstrapstart.InstanceObservation, error)
	ObserveFleet(context.Context, Call) ([]oci.Instance, error)
	Costs(context.Context, Call) (ocicost.Report, error)
	ObserveImage(context.Context, Call, ImageRequest) (ImageObservation, error)
	ReleaseChannel(context.Context, Call) (ChannelObservation, error)
}

// InventoryObservation carries no producer seal or authority to spend.
// Capacity admission consumes its sealed SDK snapshot inside the root process.
type InventoryObservation struct {
	ScopeSHA256, Currency string
	ObservedAt, ExpiresAt time.Time
	MonthlyCents          uint64
	Resources             []capacityinventory.Resource
	CoveredCompartments   []string
	Pending               []string
}

type ImageRequest struct {
	ImageID string
}

// ImageObservation covers the exact signed image and its admitted host shape.
type ImageObservation struct {
	ImageID, CompartmentID, State, Shape, Architecture string
}

type ChannelObservation struct {
	Found   bool
	Channel releasechannel.Channel
}
