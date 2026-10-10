package capacity

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/storage"
)

// FSStat is the subset of statfs(2) the collector needs, in bytes and inodes.
type FSStat struct {
	TotalBytes  uint64
	FreeBytes   uint64
	AvailBytes  uint64
	InodesTotal uint64
	InodesFree  uint64
}

// Target is one measured mount. Reserve, when set, reports bytes promised to
// a consumer on that filesystem but not yet written.
type Target struct {
	Role     storage.VolumeRole
	Path     string
	VolumeID string
	Reserve  func(context.Context) (uint64, error)
}

// Collector measures its targets with statfs. Statfs and Now are injectable
// for tests; zero values use the real system.
type Collector struct {
	Cell    string
	Node    string
	Targets []Target
	Statfs  func(string) (FSStat, error)
	Now     func() time.Time
}

// Collect measures every target. A failing target is reported in the joined
// error while the remaining measurements are still returned.
func (collector Collector) Collect(ctx context.Context) ([]VolumeUsage, error) {
	statfs := collector.Statfs
	if statfs == nil {
		statfs = Statfs
	}
	now := time.Now
	if collector.Now != nil {
		now = collector.Now
	}
	var usages []VolumeUsage
	var failures []error
	for _, target := range collector.Targets {
		stat, err := statfs(target.Path)
		if err != nil {
			failures = append(failures, fmt.Errorf("measure %s %s: %w", target.Role, target.Path, err))
			continue
		}
		usage := VolumeUsage{
			Cell: collector.Cell, Node: collector.Node, Role: target.Role, VolumeID: target.VolumeID,
			MountPath: target.Path, TotalBytes: stat.TotalBytes, UsedBytes: stat.TotalBytes - min(stat.TotalBytes, stat.FreeBytes),
			AvailBytes: stat.AvailBytes, InodesTotal: stat.InodesTotal, InodesFree: stat.InodesFree,
			ObservedAt: now().UTC(),
		}
		if target.Reserve != nil {
			reserved, err := target.Reserve(ctx)
			if err != nil {
				failures = append(failures, fmt.Errorf("measure %s reservation: %w", target.Role, err))
				continue
			}
			usage.ReservedBytes = reserved
		}
		if err := usage.Validate(); err != nil {
			failures = append(failures, fmt.Errorf("measure %s %s: %w", target.Role, target.Path, err))
			continue
		}
		usages = append(usages, usage)
	}
	return usages, errors.Join(failures...)
}

// StoreUsage reports how many bytes the embedded JetStream server stores on
// this node. It must be node-local: an account's usage also counts the
// replicas other nodes store.
type StoreUsage func(context.Context) (uint64, error)

// JetStreamReservation reports the unused part of this node's JetStream
// max-store limit: space the embedded server may still claim on its
// StoreDir. The limit is per node, so it is compared with node-local usage.
func JetStreamReservation(used StoreUsage, maxStoreBytes int64) func(context.Context) (uint64, error) {
	return func(ctx context.Context) (uint64, error) {
		if used == nil || maxStoreBytes <= 0 {
			return 0, errors.New("JetStream reservation requires a node-local usage source and a positive store limit")
		}
		stored, err := used(ctx)
		if err != nil {
			return 0, fmt.Errorf("read JetStream node usage: %w", err)
		}
		limit := uint64(maxStoreBytes)
		return limit - min(limit, stored), nil
	}
}

// ControllerTargets measures a controller node: its boot root and the
// embedded JetStream StoreDir, whose unused max-store reservation counts as
// promised space.
func ControllerTargets(storeDir string, used StoreUsage, maxStoreBytes int64) []Target {
	return []Target{
		{Role: storage.RoleBoot, Path: "/"},
		{Role: storage.RoleJetStream, Path: storeDir, Reserve: JetStreamReservation(used, maxStoreBytes)},
	}
}

// LogSignal reports a pressure signal; critical JetStream or boot pressure is
// an error because a full store silently stops journal and placement writes.
func LogSignal(signal Signal) {
	attrs := []any{"node", signal.Usage.Node, "role", signal.Usage.Role, "path", signal.Usage.MountPath,
		"level", signal.Level.String(), "utilization", signal.Utilization, "reason", signal.Reason}
	if signal.Level == LevelCritical {
		slog.Error("storage capacity critical", attrs...)
		return
	}
	slog.Warn("storage capacity pressure", attrs...)
}

// Publisher stores measurements for consumers.
type Publisher interface {
	Publish(context.Context, VolumeUsage) error
}

// Run collects every interval, publishes each measurement and reports every
// non-OK signal through onSignal. It returns when ctx ends.
func Run(ctx context.Context, collector Collector, publisher Publisher, policy Policy, interval time.Duration, onSignal func(Signal)) error {
	if publisher == nil || interval <= 0 {
		return errors.New("storage capacity collector requires a publisher and a positive interval")
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		usages, err := collector.Collect(ctx)
		if err != nil {
			slog.WarnContext(ctx, "storage capacity measurement failed", "error", err)
		}
		for _, usage := range usages {
			if err := publisher.Publish(ctx, usage); err != nil && ctx.Err() == nil {
				slog.WarnContext(ctx, "storage capacity publish failed", "role", usage.Role, "path", usage.MountPath, "error", err)
			}
			if signal := Evaluate(usage, policy); signal.Level != LevelOK && onSignal != nil {
				onSignal(signal)
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}
