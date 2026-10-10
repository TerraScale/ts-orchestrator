// Package backup schedules crash-consistent OCI block volume backups of
// retained TerraBase volumes and prunes owned backups beyond retention.
// Every OCI mutation is preceded by an authority epoch guard.
package backup

import "time"

// Backup types accepted by OCI CreateVolumeBackup.
const (
	TypeFull        = "FULL"
	TypeIncremental = "INCREMENTAL"
)

const (
	backupInterval  = 24 * time.Hour
	runInterval     = 15 * time.Minute
	orphanRetention = 30 * 24 * time.Hour
	// Keeping a complete full-backup cadence preserves its latest FULL.
	retain    = 7
	fullEvery = 7
)

// Retention must preserve a complete FULL backup cadence.
var _ [retain - fullEvery]struct{}
