//go:build linux

package rootoci

import (
	"context"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/host"
)

const (
	OperationMaterializeContainer       Operation = "materialize_container"
	OperationObserveContainerGeneration Operation = "observe_container_generation"
)

type MaterializeContainerRequest struct {
	Evidence host.ContainerMaterialEvidence `json:"evidence"`
}

type ContainerSecretMetadata struct {
	ID        string    `json:"id"`
	Version   int64     `json:"version"`
	ExpiresAt time.Time `json:"expires_at,omitzero"`
}

// ContainerSecretValue is delivered only for the exact signed host request.
type ContainerSecretValue struct {
	ID        string    `json:"id"`
	Version   int64     `json:"version"`
	ExpiresAt time.Time `json:"expires_at,omitzero"`
	Value     string    `json:"value"`
}

type ContainerMaterialReceipt struct {
	Task   ContainerTaskMaterial           `json:"task"`
	Values map[string]ContainerSecretValue `json:"values"`
}

// ContainerTaskMaterial is root-checked output for file delivery and version CAS.
type ContainerTaskMaterial struct {
	Binding      host.ContainerMaterialBinding `json:"binding"`
	OperationID  string                        `json:"operation_id"`
	ConfigDigest string                        `json:"config_digest"`
	Generation   uint64                        `json:"generation"`
	User         string                        `json:"user"`
	ExpiresAt    time.Time                     `json:"expires_at"`
}

// ObserveContainerGenerationRequest selects an actual task, never Vault refs.
type ObserveContainerGenerationRequest struct {
	TaskID string `json:"task_id"`
}

type ContainerGenerationReceipt struct {
	Task   ContainerTaskMaterial              `json:"task"`
	Values map[string]ContainerSecretMetadata `json:"values"`
}

type WorkloadCredentials interface {
	MaterializeContainer(context.Context, Call, MaterializeContainerRequest) (ContainerMaterialReceipt, error)
	ObserveContainerGeneration(context.Context, Call, ObserveContainerGenerationRequest) (ContainerGenerationReceipt, error)
	MaterializeNativeCanary(context.Context, Call, NativeCanaryRequest) (NativeCanaryReceipt, error)
}
