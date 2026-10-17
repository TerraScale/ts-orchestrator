package rootoci

import "context"

const (
	OperationRetainedContainerEvidence   Operation = "retained_container_evidence"
	OperationRetainedContainerAllocation Operation = "retained_container_allocation"
)

// RetainedContainerMaterial observes immutable historical provenance only.
// These bytes grant no current execution, status, spending or volume authority.
type RetainedContainerMaterial interface {
	RetainedContainerEvidence(context.Context, Call, RetainedContainerEvidenceRequest) (RetainedContainerEvidenceChunk, error)
	RetainedContainerAllocation(context.Context, Call, RetainedContainerAllocationRequest) (RetainedContainerAllocationObservation, error)
}

type RetainedContainerEvidenceRequest ContainerEvidenceRequest
type RetainedContainerAllocationRequest ContainerAllocationRequest

// RetainedContainerEvidenceChunk must be verified against the independently
// recorded prior-writer/volume proof; it is not a current-admission receipt.
type RetainedContainerEvidenceChunk ContainerEvidenceChunk

// RetainedContainerAllocationObservation has historical provenance semantics.
type RetainedContainerAllocationObservation ContainerAllocationObservation
