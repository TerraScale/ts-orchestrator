package rootoci

import (
	"context"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/releasechannel"
)

const (
	OperationReconcileOrchestratorStatus  Operation = "reconcile_orchestrator_status"
	OperationNativeRelease                Operation = "native_release"
	OperationReleaseBinaryChunk           Operation = "release_binary_chunk"
	OperationNativeReleaseBinaryChunk     Operation = "native_release_binary_chunk"
	OperationReconcileNativeServiceStatus Operation = "reconcile_native_service_status"
	ReleaseBinaryChunkBytes                         = 256 << 10
)

// ChannelReleases reads finite release documents and derives telemetry from root's
// own retained history. Requests only narrow independently observed authority.
type ChannelReleases interface {
	ContainerRelease(context.Context, Call, ContainerReleaseRequest) (ContainerReleaseObservation, error)
	ReconcileOrchestratorStatus(context.Context, Call, OrchestratorStatusRequest) (OrchestratorStatusReceipt, error)
	NativeRelease(context.Context, Call, NativeReleaseRequest) (NativeReleaseObservation, error)
	ReleaseBinaryChunk(context.Context, Call, ReleaseBinaryChunkRequest) (ReleaseBinaryChunk, error)
	NativeReleaseBinaryChunk(context.Context, Call, NativeReleaseBinaryChunkRequest) (ReleaseBinaryChunk, error)
	ReconcileNativeServiceStatus(context.Context, Call, NativeServiceStatusRequest) (NativeServiceStatusReceipt, error)
}

type OrchestratorStatusRequest struct{ ExpectedChannelSHA256 string }
type OrchestratorStatusReceipt struct {
	Status    releasechannel.Status
	ExpiresAt time.Time
}
type NativeReleaseRequest struct{ Role string }
type NativeReleaseObservation struct {
	Found       bool
	Claim       []byte
	ClaimSHA256 string
	ExpiresAt   time.Time
}
type ReleaseBinaryChunkRequest struct {
	Digest string
	Offset int64
}
type NativeReleaseBinaryChunkRequest struct {
	Role                string
	ExpectedClaimSHA256 string
	Offset              int64
}
type ReleaseBinaryChunk struct {
	Data      []byte
	Size      int64
	Digest    string
	ExpiresAt time.Time
}
type NativeServiceStatusRequest struct {
	Role                string
	ExpectedClaimSHA256 string
}
type NativeServiceStatusReceipt struct {
	Status    releasechannel.ServiceStatus
	ExpiresAt time.Time
}
