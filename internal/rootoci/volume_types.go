package rootoci

import (
	"context"

	"github.com/TerraScale/ts-orchestrator/internal/rootvolumeclient"
)

const (
	OperationInspectVolumeMount        Operation = rootvolumeclient.InspectOperation
	OperationObserveTerminatedInstance Operation = rootvolumeclient.TerminatedOperation
)

// VolumeReader is separate from startup observations: volume evidence requires
// the original live delegated workload session, including for terminal hosts.
type VolumeReader interface {
	InspectVolumeMount(context.Context, Call, rootvolumeclient.InspectRequest) (rootvolumeclient.MountObservation, error)
	ObserveTerminatedInstance(context.Context, Call, rootvolumeclient.TerminatedRequest) (rootvolumeclient.TerminatedObservation, error)
}
