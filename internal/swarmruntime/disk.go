package swarmruntime

import (
	"context"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"slices"
	"strconv"

	"github.com/TerraScale/ts-orchestrator/internal/storage/capacity"
	containerd "github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/core/images"
	"github.com/containerd/containerd/v2/core/snapshots"
	"github.com/containerd/containerd/v2/plugins"
	"github.com/opencontainers/image-spec/identity"
	imagespec "github.com/opencontainers/image-spec/specs-go/v1"
	"golang.org/x/sys/unix"
)

var ErrDiskPending = errors.New("task disk capacity or retained storage is unavailable")

// The local daemon supplies its actual roots; a caller cannot substitute a
// nominal OCI volume size or a different filesystem for the runtime's storage.
func (e *Executor) diskPaths(ctx context.Context) ([]string, error) {
	response, err := e.client.IntrospectionService().Plugins(runtimeContext(ctx))
	if err != nil {
		return nil, err
	}
	found := make(map[string]string)
	for _, plugin := range response.Plugins {
		key := plugin.Type + "/" + plugin.ID
		if key != string(plugins.SnapshotPlugin)+"/"+imageSnapshotter && key != string(plugins.ContentPlugin)+"/content" {
			continue
		}
		if plugin.InitErr != nil || found[key] != "" || !filepath.IsAbs(plugin.Exports["root"]) {
			return nil, ErrDiskPending
		}
		found[key] = plugin.Exports["root"]
	}
	if len(found) != 2 {
		return nil, ErrDiskPending
	}
	return []string{e.logRoot, found[string(plugins.SnapshotPlugin)+"/"+imageSnapshotter], found[string(plugins.ContentPlugin)+"/content"]}, nil
}

func (e *Executor) diskCapacity(ctx context.Context) (int64, error) {
	paths, err := e.diskPaths(ctx)
	if err != nil {
		return 0, err
	}
	available := int64(math.MaxInt64)
	seen := make(map[uint64]bool)
	for _, path := range paths {
		file, err := os.Open(path)
		if err != nil {
			return 0, err
		}
		info, statErr := file.Stat()
		var identity unix.Stat_t
		identityErr := unix.Fstat(int(file.Fd()), &identity)
		var stat unix.Statfs_t
		fsErr := unix.Fstatfs(int(file.Fd()), &stat)
		closeErr := file.Close()
		if err := errors.Join(statErr, identityErr, fsErr, closeErr); err != nil {
			return 0, err
		}
		if !info.IsDir() {
			return 0, ErrDiskPending
		}
		if seen[uint64(identity.Dev)] {
			continue
		}
		seen[uint64(identity.Dev)] = true
		headroom, err := diskHeadroom(stat)
		if err != nil {
			return 0, fmt.Errorf("runtime filesystem %s: %w", path, err)
		}
		available = min(available, headroom)
	}
	return available, ctx.Err()
}

// schedulableDisk is the disk a node offers the scheduler: its free headroom
// plus the budgets its live and prepared containers already hold. The
// scheduler subtracts those budgets again, and they are mostly unwritten, so
// offering only the free headroom counted them twice: a 2-CPU host with
// TerraBase and whoami (10 GiB budgets each) and ~21 GiB free had no room for
// ts-auth. Prepare still refuses a container the free headroom cannot hold.
// shortcut: bytes a container already wrote count in both, overstating the offer by that much; measure per-task usage if hosts run near full.
func (e *Executor) schedulableDisk(ctx context.Context) (int64, error) {
	free, err := e.diskCapacity(ctx)
	if err != nil {
		return 0, err
	}
	containers, err := e.client.Containers(runtimeContext(ctx))
	if err != nil {
		return 0, err
	}
	for _, container := range containers {
		labels, err := container.Labels(runtimeContext(ctx))
		if err != nil {
			return 0, err
		}
		budget, err := strconv.ParseInt(labels[diskBytesLabel], 10, 64)
		if err != nil || budget <= 0 {
			continue
		}
		if holder, err := portHolderState(runtimeContext(ctx), container); err != nil || holder == holderExited {
			continue
		}
		free += budget
	}
	return free, nil
}

func diskHeadroom(stat unix.Statfs_t) (int64, error) {
	if stat.Bsize <= 0 || stat.Blocks == 0 || stat.Blocks > math.MaxInt64/uint64(stat.Bsize) ||
		stat.Bfree > stat.Blocks || stat.Bavail > stat.Bfree || stat.Ffree > stat.Files ||
		stat.Type == unix.TMPFS_MAGIC || stat.Type == unix.RAMFS_MAGIC || stat.Flags&unix.ST_RDONLY != 0 {
		return 0, ErrDiskPending
	}
	usage := capacity.VolumeUsage{TotalBytes: stat.Blocks * uint64(stat.Bsize),
		UsedBytes: (stat.Blocks - stat.Bfree) * uint64(stat.Bsize), AvailBytes: stat.Bavail * uint64(stat.Bsize),
		InodesTotal: stat.Files, InodesFree: stat.Ffree}
	// Reuse the existing storage policy's 1 GiB/1024 inode floor and 95% refusal
	// boundary. No independent executor reserve or tuning value is introduced.
	policy := capacity.DefaultPolicy()
	if capacity.Evaluate(usage, policy).Level == capacity.LevelCritical {
		return 0, nil
	}
	low, high := uint64(0), usage.AvailBytes
	for low < high {
		mid := low + (high-low+1)/2
		usage.ReservedBytes = mid
		if capacity.Evaluate(usage, policy).Level == capacity.LevelCritical {
			high = mid - 1
		} else {
			low = mid
		}
	}
	return int64(low), nil
}

// Charge every retained blob and committed chain step to each task, even when
// tasks share them; an overlayfs step holds only its own layer's files.
func (e *Executor) retainedImageDisk(ctx context.Context, image containerd.Image) (int64, error) {
	paths, err := e.diskPaths(ctx)
	if err != nil {
		return 0, err
	}
	store := e.client.ContentStore()
	var total int64
	seen := make(map[string]bool)
	err = images.Walk(ctx, images.HandlerFunc(func(ctx context.Context, descriptor imagespec.Descriptor) ([]imagespec.Descriptor, error) {
		if seen[descriptor.Digest.String()] {
			return nil, images.ErrSkipDesc
		}
		seen[descriptor.Digest.String()] = true
		if descriptor.Digest.Validate() != nil || descriptor.Digest.Algorithm().String() != "sha256" {
			return nil, ErrDiskPending
		}
		info, err := store.Info(ctx, descriptor.Digest)
		if err != nil || info.Size != descriptor.Size {
			return nil, errors.Join(ErrDiskPending, err)
		}
		path := filepath.Join(paths[2], "blobs", "sha256", descriptor.Digest.Encoded())
		stat, err := diskFileStat(path)
		if err != nil || stat.Size != info.Size || stat.Blocks > math.MaxInt64/512 || total > math.MaxInt64-stat.Blocks*512 {
			return nil, errors.Join(ErrDiskPending, err)
		}
		total += stat.Blocks * 512
		return images.Children(ctx, store, descriptor)
	}), image.Target())
	if err != nil {
		return 0, err
	}
	diffIDs, err := image.RootFS(ctx)
	if err != nil || len(diffIDs) == 0 {
		return 0, errors.Join(ErrDiskPending, err)
	}
	storeSnapshots := e.client.SnapshotService(imageSnapshotter)
	parent := ""
	// ChainIDs rewrites its argument, and containerd caches this slice in the
	// image: chaining it in place corrupts every later RootFS of a multi-layer image.
	for _, chain := range identity.ChainIDs(slices.Clone(diffIDs)) {
		info, err := storeSnapshots.Stat(ctx, chain.String())
		if err != nil || info.Kind != snapshots.KindCommitted || info.Name != chain.String() || info.Parent != parent {
			return 0, errors.Join(ErrDiskPending, err)
		}
		usage, err := storeSnapshots.Usage(ctx, chain.String())
		if err != nil || usage.Size < 0 || total > math.MaxInt64-usage.Size {
			return 0, errors.Join(ErrDiskPending, err)
		}
		total += usage.Size
		parent = chain.String()
	}
	return total, ctx.Err()
}

func diskFileStat(path string) (unix.Stat_t, error) {
	var stat unix.Stat_t
	if err := unix.Lstat(path, &stat); err != nil {
		return stat, err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Nlink != 1 || stat.Uid != uint32(os.Geteuid()) || stat.Blocks < 0 {
		return stat, ErrDiskPending
	}
	return stat, nil
}
