package rootoci

import (
	"context"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/releasechannel"
)

const OperationReconcileContainerStatus Operation = "reconcile_container_status"

// Releases observes protected current runtime state before publishing telemetry.
// Socket callers cannot choose a status, object key, bytes or destination.
type Releases interface {
	ContainerReleases
	ChannelReleases
}

type ContainerReleases interface {
	ReconcileContainerStatus(context.Context, Call, ContainerStatusRequest) (ContainerStatusReceipt, error)
}

type ContainerStatusRequest struct {
	OperationID         string
	ExpectedFingerprint string
}

type ContainerStatusReceipt struct {
	OperationID string
	Status      releasechannel.ContainerStatus
	ExpiresAt   time.Time
}
