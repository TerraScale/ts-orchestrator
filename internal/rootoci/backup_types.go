package rootoci

import (
	"context"
	"time"
)

const OperationReconcileVolumeBackups Operation = "reconcile_volume_backups"

// VolumeBackups evaluates the fixed block-volume policy using only root-owned
// placement and authority. Requests cannot select volumes or provider payloads.
type VolumeBackups interface {
	ReconcileVolumeBackups(context.Context, Call) (VolumeBackupReport, error)
}

// VolumeBackupReport is descriptive and grants no authority to mutate a volume.
type VolumeBackupReport struct {
	Created    []string  `json:"created,omitempty"`
	Deleted    []string  `json:"deleted,omitempty"`
	Skipped    []string  `json:"skipped,omitempty"`
	Epoch      uint64    `json:"epoch"`
	ObservedAt time.Time `json:"observed_at"`
	ExpiresAt  time.Time `json:"expires_at"`
}
