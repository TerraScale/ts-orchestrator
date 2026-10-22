package swarmruntime

import (
	"context"
	"encoding/json/v2"
	"errors"
	"io"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	containerd "github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/core/snapshots"
	"github.com/opencontainers/image-spec/identity"
	"golang.org/x/sys/unix"
)

const diskWitnessName = "disk.json"
const diskBytesLabel = "terrascale.disk-bytes"
const diskImageBytesLabel = "terrascale.disk-image-bytes"

type runtimeDiskWitness struct {
	TaskID         string `json:"task_id"`
	Fingerprint    string `json:"fingerprint"`
	Image          string `json:"image"`
	SnapshotParent string `json:"snapshot_parent"`
	DiskBytes      int64  `json:"disk_bytes"`
	ImageBytes     int64  `json:"image_bytes"`
	LogBytes       int64  `json:"log_bytes"`
}

func (w runtimeDiskWitness) valid() bool {
	return strings.HasPrefix(w.TaskID, "ts-") && !strings.ContainsAny(w.TaskID, "/\\") && len(w.Fingerprint) == 64 &&
		w.Image != "" && w.SnapshotParent != "" && w.ImageBytes > 0 && w.LogBytes >= 2*logSegmentBytes &&
		w.DiskBytes >= w.LogBytes && w.ImageBytes <= w.DiskBytes-w.LogBytes
}

func (c *controller) diskAccounted() bool {
	return c.stateful == nil && c.task.ServiceAnnotations.Labels[LabelRole] != FunctionWorkerRole
}

// diskAvailable refuses a new container while the host cannot hold its whole budget.
func (c *controller) diskAvailable(ctx context.Context) error {
	if !c.diskAccounted() {
		return nil
	}
	budget, budgetErr := DiskBytes(c.task.Spec.Resources)
	available, capacityErr := c.executor.diskCapacity(ctx)
	if budgetErr != nil || capacityErr != nil || available < budget {
		return errors.Join(ErrDiskPending, budgetErr, capacityErr)
	}
	return nil
}

func (c *controller) prepareDisk(ctx context.Context, image containerd.Image) (*runtimeDiskWitness, error) {
	budget, err := DiskBytes(c.task.Spec.Resources)
	if err != nil {
		return nil, err
	}
	retained, err := c.executor.retainedImageDisk(ctx, image)
	if err != nil {
		return nil, err
	}
	diffIDs, err := image.RootFS(ctx)
	if err != nil {
		return nil, err
	}
	var filesystem unix.Statfs_t
	if err := unix.Statfs(c.executor.logRoot, &filesystem); err != nil {
		return nil, err
	}
	block := filesystem.Bsize
	if block <= 0 || block > math.MaxInt64/8 {
		return nil, ErrDiskPending
	}
	// Two bounded files, their directory and the immutable witness, rounded
	// to this filesystem's blocks rather than an invented task disk allowance.
	logs := 2*((logSegmentBytes+block-1)/block)*block + 2*block
	witness := &runtimeDiskWitness{TaskID: c.id, Fingerprint: c.fingerprint, Image: c.spec.Image,
		SnapshotParent: identity.ChainID(diffIDs).String(), DiskBytes: budget, ImageBytes: retained, LogBytes: logs}
	if !witness.valid() {
		return nil, ErrDiskPending
	}
	available, err := c.executor.diskCapacity(ctx)
	if err != nil || available < logs {
		return nil, errors.Join(ErrDiskPending, err)
	}
	if err := writeDiskWitness(c.executor.logRoot, *witness); err != nil {
		return nil, err
	}
	return witness, nil
}

func writeDiskWitness(root string, witness runtimeDiskWitness) error {
	if !witness.valid() {
		return ErrDiskPending
	}
	dir := filepath.Join(root, witness.TaskID)
	if err := os.Mkdir(dir, 0700); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	if err := verifyDiskDirectory(dir); err != nil {
		return err
	}
	if _, err := os.Lstat(filepath.Join(dir, diskWitnessName)); err == nil {
		confirmed, err := readDiskWitness(root, witness.TaskID)
		if err != nil || confirmed != witness {
			return errors.Join(ErrDiskPending, err)
		}
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 0 {
		return errors.Join(ErrDiskPending, err)
	}
	data, err := json.Marshal(witness)
	if err != nil {
		return err
	}
	file, err := os.CreateTemp(dir, ".disk-")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return err
	}
	syncErr := file.Sync()
	if err := errors.Join(syncErr, file.Close()); err != nil {
		return err
	}
	if err := unix.Renameat2(unix.AT_FDCWD, file.Name(), unix.AT_FDCWD, filepath.Join(dir, diskWitnessName), unix.RENAME_NOREPLACE); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	confirmed, err := readDiskWitness(root, witness.TaskID)
	if err != nil || confirmed != witness {
		return errors.Join(ErrDiskPending, err)
	}
	directory, err := os.Open(dir)
	if err != nil {
		return err
	}
	syncErr = directory.Sync()
	return errors.Join(syncErr, directory.Close())
}

func verifyDiskDirectory(path string) error {
	var stat unix.Stat_t
	if err := unix.Lstat(path, &stat); err != nil {
		return err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Mode&0077 != 0 || stat.Uid != uint32(os.Geteuid()) {
		return ErrDiskPending
	}
	return nil
}

func readDiskWitness(root, taskID string) (runtimeDiskWitness, error) {
	var witness runtimeDiskWitness
	if !strings.HasPrefix(taskID, "ts-") || strings.ContainsAny(taskID, "/\\") {
		return witness, ErrDiskPending
	}
	dir := filepath.Join(root, taskID)
	if err := verifyDiskDirectory(dir); err != nil {
		return witness, err
	}
	path := filepath.Join(dir, diskWitnessName)
	stat, err := diskFileStat(path)
	if err != nil || stat.Size > 4096 || stat.Mode&0077 != 0 {
		return witness, errors.Join(ErrDiskPending, err)
	}
	file, err := os.OpenFile(path, os.O_RDONLY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return witness, err
	}
	data, readErr := io.ReadAll(io.LimitReader(file, 4097))
	if err := errors.Join(readErr, file.Close()); err != nil {
		return witness, err
	}
	if err := json.Unmarshal(data, &witness, json.RejectUnknownMembers(true)); err != nil {
		return witness, err
	}
	if !witness.valid() || witness.TaskID != taskID {
		return witness, ErrDiskPending
	}
	var directory unix.Stat_t
	if err := unix.Lstat(dir, &directory); err != nil {
		return witness, err
	}
	used := int64(0)
	for _, blocks := range []int64{stat.Blocks, directory.Blocks} {
		if blocks < 0 || blocks > (witness.LogBytes-used)/512 {
			return witness, ErrDiskPending
		}
		used += blocks * 512
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return witness, err
	}
	for _, entry := range entries {
		if entry.Name() != diskWitnessName && entry.Name() != "stdout" && entry.Name() != "stderr" {
			return witness, ErrDiskPending
		}
	}
	for _, name := range []string{"stdout", "stderr"} {
		stat, err := diskFileStat(filepath.Join(dir, name))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil || stat.Size > logSegmentBytes || stat.Mode&0077 != 0 {
			return witness, errors.Join(ErrDiskPending, err)
		}
		if stat.Blocks > (witness.LogBytes-used)/512 {
			return witness, ErrDiskPending
		}
		used += stat.Blocks * 512
	}
	return witness, nil
}

func (c *controller) verifyDisk(ctx context.Context, ctr containerd.Container) error {
	if !c.diskAccounted() {
		return nil
	}
	witness, err := readDiskWitness(c.executor.logRoot, c.id)
	if err != nil {
		return err
	}
	budget, err := DiskBytes(c.task.Spec.Resources)
	if err != nil || witness.Fingerprint != c.fingerprint || witness.Image != c.spec.Image || witness.DiskBytes != budget {
		return errors.Join(ErrDiskPending, err)
	}
	info, err := ctr.Info(ctx)
	if err != nil {
		return err
	}
	// Containers prepared before the overlayfs switch keep their native snapshot.
	if (info.Snapshotter != imageSnapshotter && info.Snapshotter != "native") || info.SnapshotKey != c.id || info.Labels[diskBytesLabel] != strconv.FormatInt(witness.DiskBytes, 10) ||
		info.Labels[diskImageBytesLabel] != strconv.FormatInt(witness.ImageBytes, 10) {
		return ErrDiskPending
	}
	snapshot, err := c.executor.client.SnapshotService(info.Snapshotter).Stat(ctx, c.id)
	if err != nil || snapshot.Kind != snapshots.KindActive || snapshot.Parent != witness.SnapshotParent ||
		snapshot.Labels["terrascale.task"] != c.task.ID || snapshot.Labels["terrascale.spec"] != c.fingerprint {
		return errors.Join(ErrDiskPending, err)
	}
	spec, err := ctr.Spec(ctx)
	if err != nil || spec.Root == nil || !spec.Root.Readonly {
		return errors.Join(ErrDiskPending, err)
	}
	return ctx.Err()
}

func (c *controller) removeDiskLogs() error {
	dir := filepath.Join(c.executor.logRoot, c.id)
	if c.diskAccounted() {
		if _, err := os.Lstat(dir); errors.Is(err, os.ErrNotExist) {
			return nil
		}
		witness, err := readDiskWitness(c.executor.logRoot, c.id)
		if err != nil || witness.Fingerprint != c.fingerprint || witness.Image != c.spec.Image {
			return errors.Join(ErrDiskPending, err)
		}
	}
	return os.RemoveAll(dir)
}
