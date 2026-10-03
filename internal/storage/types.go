// Package storage is the feature slice that owns retained block-volume
// lifecycle policy, host volume operations, capacity telemetry, OCI volume
// backups, and host-loss reattachment. The OCI mutation authority (journal,
// ownership, epoch fencing) stays in internal/oci; storage composes it and
// never adopts a resource from tags alone.
//
// Subpackages:
//
//	lifecycle   pure volume state machine with Stuck/Held states and deadlines
//	hostvolume  host-side mount hardening, filesystem format and online grow
//	capacity    statfs collector, JetStream KV usage publisher, pressure signals
//	backup      OCI volume backup policy, planner and fenced retention runner
//	failover    reattach-on-host-loss core gated by terminated-instance proof
package storage

import (
	"errors"
	"time"
)

var (
	// ErrVolumeStuck reports a volume whose lifecycle phase exceeded its deadline.
	ErrVolumeStuck = errors.New("retained volume lifecycle phase exceeded its deadline")
	// ErrVolumeHeld reports a fail-closed hold that only an operator can
	// clear (a foreign or unknown attachment); retrying cannot resolve it,
	// unlike the deadline stall ErrVolumeStuck reports.
	ErrVolumeHeld = errors.New("retained volume is held for an operator")
	// ErrWriterNotFenced reports that the previous writer has not been proven
	// stopped, so the volume must not be attached anywhere else.
	ErrWriterNotFenced = errors.New("retained volume writer is not proven fenced")
	// ErrDisabled reports a storage feature that is off in configuration.
	ErrDisabled = errors.New("storage feature is disabled in configuration")
)

// VolumeRole names what a measured or managed volume is used for.
type VolumeRole string

const (
	RoleTerraBaseData VolumeRole = "terrabase-data"
	RoleJetStream     VolumeRole = "jetstream"
	RoleBoot          VolumeRole = "boot"
)

// Valid reports whether role is one of the known roles.
func (role VolumeRole) Valid() bool {
	switch role {
	case RoleTerraBaseData, RoleJetStream, RoleBoot:
		return true
	default:
		return false
	}
}

// Supported managed filesystems. Both are accepted as signed pins.
const (
	FileSystemExt4 = "ext4"
	FileSystemXFS  = "xfs"
)

// ValidFileSystem reports whether fsType can be formatted, mounted and grown.
func ValidFileSystem(fsType string) bool {
	return fsType == FileSystemExt4 || fsType == FileSystemXFS
}

// Telemetry defaults applied when the matching Config field is zero. Phase
// deadlines default through lifecycle.DefaultDeadlines, not here.
const (
	DefaultUsageTTL        = 2 * time.Minute
	DefaultCollectInterval = 30 * time.Second
)
