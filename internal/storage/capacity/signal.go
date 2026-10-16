// Package capacity measures real filesystem usage (managed data mounts, the
// boot root and the embedded JetStream StoreDir), publishes it to a regional
// JetStream KV with a TTL, and turns it into pressure signals that placement
// and TerraBase autoscaling can consume. Host disk capacity used to be a fixed
// config number; these records are measurements.
package capacity

import (
	"context"
	"errors"
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

// Validate rejects incomplete or inconsistent measurements.
func (usage VolumeUsage) Validate() error {
	if usage.Cell == "" || usage.Node == "" || !usage.Role.Valid() || usage.MountPath == "" || usage.ObservedAt.IsZero() {
		return errors.New("storage usage record is incomplete")
	}
	if usage.TotalBytes == 0 || usage.UsedBytes > usage.TotalBytes || usage.AvailBytes > usage.TotalBytes ||
		usage.InodesFree > usage.InodesTotal {
		return errors.New("storage usage record is inconsistent")
	}
	return nil
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

func (level Level) String() string {
	switch level {
	case LevelOK:
		return "ok"
	case LevelWarn:
		return "warn"
	case LevelScaleOut:
		return "scale-out"
	case LevelCritical:
		return "critical"
	default:
		return fmt.Sprintf("level(%d)", int(level))
	}
}

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

// Validate requires strictly increasing thresholds within (0, 100].
func (policy Policy) Validate() error {
	policy = policy.WithDefaults()
	if policy.WarnPercent <= 0 || policy.WarnPercent >= policy.ScaleOutPercent ||
		policy.ScaleOutPercent >= policy.RefusePercent || policy.RefusePercent > 100 {
		return errors.New("storage capacity thresholds must increase strictly within (0, 100]")
	}
	return nil
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

// SignalSource is consumed by placement and autoscaling. Implementations
// return only current (unexpired) measurements.
type SignalSource interface {
	Signals(context.Context) ([]Signal, error)
}

// Worst returns the most severe signal, preferring the higher utilization on
// ties. ok is false for an empty slice.
func Worst(signals []Signal) (Signal, bool) {
	if len(signals) == 0 {
		return Signal{}, false
	}
	worst := signals[0]
	for _, signal := range signals[1:] {
		if signal.Level > worst.Level || signal.Level == worst.Level && signal.Utilization > worst.Utilization {
			worst = signal
		}
	}
	return worst, true
}

// NodeHeadroomBytes returns the measured free boot-volume bytes of node after
// reservations, the value placement should use instead of a configured disk
// capacity. ok is false when no current boot measurement exists.
//
// Reservations are aggregated across the node's records: a reservation made
// on another mount (the JetStream max-store reserve on its StoreDir) counts
// against the boot headroom when that mount is the boot filesystem. The two
// records describe the same filesystem when they report identical byte and
// inode totals; a coincidental match only under-reports headroom, which is
// the safe direction.
func NodeHeadroomBytes(signals []Signal, node string) (uint64, bool) {
	var boot VolumeUsage
	found := false
	for _, signal := range signals {
		if usage := signal.Usage; usage.Node == node && usage.Role == storage.RoleBoot {
			boot, found = usage, true
			break
		}
	}
	if !found {
		return 0, false
	}
	reserved := boot.ReservedBytes
	for _, signal := range signals {
		usage := signal.Usage
		if usage.Node != node || usage.Role == storage.RoleBoot || usage.ReservedBytes == 0 {
			continue
		}
		if usage.TotalBytes == boot.TotalBytes && usage.InodesTotal == boot.InodesTotal {
			reserved += usage.ReservedBytes
		}
	}
	return boot.AvailBytes - min(boot.AvailBytes, reserved), true
}
