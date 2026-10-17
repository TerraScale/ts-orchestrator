//go:build linux

package rootoci

import (
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/managedmaterial"
)

const OperationManagedMaterialCurrent Operation = "managed_material_current"

const MaxManagedMaterialCurrentBytes = 64 << 10

// ManagedMaterialCurrentRequest selects public metadata in the accepted domain.
// Repository locations and immutable versions come only from current R3.
type ManagedMaterialCurrentRequest struct {
	DatabaseID  string `json:"database_id"`
	PartitionID string `json:"partition_id"`
}

// ManagedMaterialCurrentReceipt contains signed public pins, never bundle data.
type ManagedMaterialCurrentReceipt struct {
	Preparation managedmaterial.PreparationReceipt `json:"preparation"`
	ExpiresAt   time.Time                          `json:"expires_at"`
}
