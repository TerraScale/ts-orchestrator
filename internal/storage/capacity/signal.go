// Package capacity measures real filesystem usage (managed data mounts, the
// boot root and the embedded JetStream StoreDir), publishes it to a regional
// JetStream KV with a TTL, and turns it into pressure signals that placement
// and TerraBase autoscaling can consume. Host disk capacity used to be a fixed
// config number; these records are measurements.
package capacity

import (
	"fmt"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/storage"
)

// VolumeUsage is one statfs measurement. It is published with a TTL, so a
// silent host ages out instead of reporting stale headroom.
type VolumeUsage struct {
	Cell        string             `json:"cell"`
	Node        string             `json:"node"`
	Role        storage.VolumeRole `json:"role"`
	VolumeID    string             `json:"volume_id,omitempty"`
	MountPath   string             `json:"mount_path"`
	TotalBytes  uint64             `json:"total_bytes"`
	UsedBytes   uint64             `json:"used_bytes"`
	AvailBytes  uint64             `json:"avail_bytes"`
	InodesTotal uint64             `json:"inodes_total"`
	InodesFree  uint64             `json:"inodes_free"`
	// ReservedBytes is space a consumer has been promised but not yet used,
	// such as the unused part of the JetStream max-store reservation.
	ReservedBytes uint64    `json:"reserved_bytes,omitzero"`
	ObservedAt    time.Time `json:"observed_at"`
}

// Utilization is the used fraction of space visible to unprivileged writers
// (used / (used + avail)), which is what statfs-based tools report as Use%.
func (usage VolumeUsage) Utilization() float64 {
	visible := usage.UsedBytes + usage.AvailBytes
	if visible == 0 {
		return 1
	}
	return float64(usage.UsedBytes) / float64(visible)
}

// Level is a coarse pressure level, ordered by severity.
type Level int

const (
	LevelOK Level = iota
	// LevelWarn suggests growing the volume.
	LevelWarn
	// LevelScaleOut suggests adding capacity (shard split or new member).
	LevelScaleOut
	// LevelCritical means new writes or placements must be refused.
	LevelCritical
)

// Policy holds utilization thresholds in percent and an absolute free-space
// floor. Zero fields use DefaultPolicy values.
type Policy struct {
	WarnPercent     float64 `json:"warn_percent,omitzero"`
	ScaleOutPercent float64 `json:"scale_out_percent,omitzero"`
	RefusePercent   float64 `json:"refuse_percent,omitzero"`
	MinFreeBytes    uint64  `json:"min_free_bytes,omitzero"`
	MinFreeInodes   uint64  `json:"min_free_inodes,omitzero"`
}

// DefaultPolicy grows at 70%, scales out at 85% and refuses at 95% or below
// 1 GiB free.
func DefaultPolicy() Policy {
	return Policy{WarnPercent: 70, ScaleOutPercent: 85, RefusePercent: 95, MinFreeBytes: 1 << 30, MinFreeInodes: 1024}
}

// WithDefaults fills zero thresholds.
func (policy Policy) WithDefaults() Policy {
	defaults := DefaultPolicy()
	if policy.WarnPercent == 0 {
		policy.WarnPercent = defaults.WarnPercent
	}
	if policy.ScaleOutPercent == 0 {
		policy.ScaleOutPercent = defaults.ScaleOutPercent
	}
	if policy.RefusePercent == 0 {
		policy.RefusePercent = defaults.RefusePercent
	}
	if policy.MinFreeBytes == 0 {
		policy.MinFreeBytes = defaults.MinFreeBytes
	}
	if policy.MinFreeInodes == 0 {
		policy.MinFreeInodes = defaults.MinFreeInodes
	}
	return policy
}

// Signal is the consumable pressure verdict for one measured volume.
type Signal struct {
	Usage       VolumeUsage `json:"usage"`
	Level       Level       `json:"level"`
	Utilization float64     `json:"utilization"`
	Reason      string      `json:"reason,omitempty"`
}

// Evaluate classifies one measurement. Reserved bytes count as used: a
// JetStream store whose reservation exceeds free disk is already at risk.
func Evaluate(usage VolumeUsage, policy Policy) Signal {
	policy = policy.WithDefaults()
	effective := usage
	effective.AvailBytes -= min(effective.AvailBytes, usage.ReservedBytes)
	effective.UsedBytes += usage.AvailBytes - effective.AvailBytes
	utilization := effective.Utilization()
	signal := Signal{Usage: usage, Utilization: utilization}
	percent := utilization * 100
	switch {
	case effective.AvailBytes < policy.MinFreeBytes:
		signal.Level, signal.Reason = LevelCritical, fmt.Sprintf("%d bytes free after reservations, below the %d byte floor", effective.AvailBytes, policy.MinFreeBytes)
	case usage.InodesTotal > 0 && usage.InodesFree < policy.MinFreeInodes:
		signal.Level, signal.Reason = LevelCritical, fmt.Sprintf("%d inodes free, below the %d inode floor", usage.InodesFree, policy.MinFreeInodes)
	case percent >= policy.RefusePercent:
		signal.Level, signal.Reason = LevelCritical, fmt.Sprintf("%.1f%% used, at or above refuse threshold %.0f%%", percent, policy.RefusePercent)
	case percent >= policy.ScaleOutPercent:
		signal.Level, signal.Reason = LevelScaleOut, fmt.Sprintf("%.1f%% used, at or above scale-out threshold %.0f%%", percent, policy.ScaleOutPercent)
	case percent >= policy.WarnPercent:
		signal.Level, signal.Reason = LevelWarn, fmt.Sprintf("%.1f%% used, at or above grow threshold %.0f%%", percent, policy.WarnPercent)
	}
	return signal
}
