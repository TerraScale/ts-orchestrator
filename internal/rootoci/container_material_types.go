package rootoci

import (
	"context"
	"time"
)

const (
	OperationContainerEvidence   Operation = "container_evidence"
	OperationContainerAllocation Operation = "container_allocation"
	ContainerEvidenceChunkBytes            = 1 << 20
)

// ContainerMaterial reads only signed material named by a retained authenticated
// operation. No caller may choose an OCI location or object name.
type ContainerMaterial interface {
	RetainedContainerMaterial
	ContainerEvidence(context.Context, Call, ContainerEvidenceRequest) (ContainerEvidenceChunk, error)
	ContainerAllocation(context.Context, Call, ContainerAllocationRequest) (ContainerAllocationObservation, error)
}

type ContainerEvidenceRequest struct {
	OperationID         string
	ExpectedFingerprint string
	EvidenceSHA256      string
	Offset              int64
}
type ContainerEvidenceChunk struct {
	OperationID    string
	Fingerprint    string
	EvidenceSHA256 string
	Offset         int64
	TotalBytes     int64
	Data           []byte
	ExpiresAt      time.Time
}
type ContainerAllocationRequest struct {
	OperationID         string
	ExpectedFingerprint string
}
type ContainerAllocationObservation struct {
	OperationID string
	Fingerprint string
	Namespace   string
	Bucket      string
	ObjectName  string
	Data        []byte
	ExpiresAt   time.Time
}
