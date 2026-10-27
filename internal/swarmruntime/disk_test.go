package swarmruntime

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/storage/capacity"
	"golang.org/x/sys/unix"
)

func TestDiskHeadroomPreservesExistingStoragePolicy(t *testing.T) {
	stat := unix.Statfs_t{Bsize: 4096, Blocks: 32 << 18, Bfree: 8 << 18, Bavail: 8 << 18, Files: 1 << 20, Ffree: 1 << 19}
	available, err := diskHeadroom(stat)
	if err != nil || available <= 0 || uint64(available) >= stat.Bavail*uint64(stat.Bsize) {
		t.Fatalf("allocatable storage = %d, %v", available, err)
	}
	usage := capacity.VolumeUsage{TotalBytes: stat.Blocks * uint64(stat.Bsize), UsedBytes: (stat.Blocks - stat.Bfree) * uint64(stat.Bsize),
		AvailBytes: stat.Bavail * uint64(stat.Bsize), InodesTotal: stat.Files, InodesFree: stat.Ffree, ReservedBytes: uint64(available)}
	if capacity.Evaluate(usage, capacity.DefaultPolicy()).Level == capacity.LevelCritical {
		t.Fatal("advertised reservation violates existing storage policy")
	}
	usage.ReservedBytes++
	if capacity.Evaluate(usage, capacity.DefaultPolicy()).Level != capacity.LevelCritical {
		t.Fatal("headroom does not reach the existing policy boundary")
	}
	for _, name := range []string{"no free space", "inode floor", "overflow", "tmpfs", "read only", "inconsistent free blocks"} {
		t.Run(name, func(t *testing.T) {
			changed := stat
			switch name {
			case "no free space":
				changed.Bavail = 0
			case "inode floor":
				changed.Ffree = capacity.DefaultPolicy().MinFreeInodes - 1
			case "overflow":
				changed.Blocks = math.MaxUint64
			case "tmpfs":
				changed.Type = unix.TMPFS_MAGIC
			case "read only":
				changed.Flags = unix.ST_RDONLY
			case "inconsistent free blocks":
				changed.Bavail = changed.Blocks + 1
			}
			if got, _ := diskHeadroom(changed); got != 0 {
				t.Fatalf("advertised %d bytes from unusable storage", got)
			}
		})
	}
}

func TestDiskWitnessRetainsExactOwnershipAcrossReopen(t *testing.T) {
	root := t.TempDir()
	witness := runtimeDiskWitness{TaskID: "ts-diskfixture", Fingerprint: strings.Repeat("a", 64), Image: "registry.example/app@sha256:" + strings.Repeat("b", 64),
		SnapshotParent: "sha256:" + strings.Repeat("c", 64), DiskBytes: 64 << 20, ImageBytes: 16 << 20, LogBytes: 2*logSegmentBytes + 8192}
	if err := writeDiskWitness(root, witness); err != nil {
		t.Fatal(err)
	}
	if err := writeDiskWitness(root, witness); err != nil {
		t.Fatalf("idempotent preparation: %v", err)
	}
	if reopened, err := readDiskWitness(root, witness.TaskID); err != nil || reopened != witness {
		t.Fatalf("restart readback changed immutable storage identity: %+v, %v", reopened, err)
	}
	changed := witness
	changed.Fingerprint = strings.Repeat("d", 64)
	if err := writeDiskWitness(root, changed); !errors.Is(err, ErrDiskPending) {
		t.Fatalf("reassigned an existing disk witness: %v", err)
	}
	for _, name := range []string{"symlink log", "hardlinked log", "oversized log", "unaccounted file"} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			if err := writeDiskWitness(root, witness); err != nil {
				t.Fatal(err)
			}
			log := filepath.Join(root, witness.TaskID, "stdout")
			switch name {
			case "symlink log", "hardlinked log":
				foreign := filepath.Join(t.TempDir(), "foreign")
				if err := os.WriteFile(foreign, []byte("preserve"), 0600); err != nil {
					t.Fatal(err)
				}
				link := os.Link
				if name == "symlink log" {
					link = os.Symlink
				}
				if err := link(foreign, log); err != nil {
					t.Fatal(err)
				}
			case "oversized log":
				if err := os.WriteFile(log, bytes.Repeat([]byte("x"), logSegmentBytes+1), 0600); err != nil {
					t.Fatal(err)
				}
			case "unaccounted file":
				if err := os.WriteFile(filepath.Join(root, witness.TaskID, "foreign"), []byte("preserve"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := readDiskWitness(root, witness.TaskID); !errors.Is(err, ErrDiskPending) {
				t.Fatalf("accepted unaccounted or foreign task storage: %v", err)
			}
		})
	}
}

func TestBoundedDiskLogSurvivesReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "stdout")
	for range 3 {
		file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0600)
		if err != nil {
			t.Fatal(err)
		}
		err = copyBoundedLog(file, bytes.NewReader(bytes.Repeat([]byte("x"), 3*logSegmentBytes+19)))
		if err := errors.Join(err, file.Close()); err != nil {
			t.Fatal(err)
		}
		info, err := os.Stat(path)
		if err != nil || info.Size() <= 0 || info.Size() > logSegmentBytes {
			t.Fatalf("reopened logger exceeded its existing bound: %v, %v", info, err)
		}
	}
}

// A full log keeps its newest lines, whole, rather than restarting empty.
func TestBoundedDiskLogKeepsNewestLines(t *testing.T) {
	path := filepath.Join(t.TempDir(), "stdout")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0600)
	if err != nil {
		t.Fatal(err)
	}
	var lines bytes.Buffer
	for i := 0; lines.Len() <= 3*logSegmentBytes; i++ {
		fmt.Fprintf(&lines, "line %07d %s\n", i, bytes.Repeat([]byte("x"), 90))
	}
	last := bytes.LastIndexByte(lines.Bytes()[:lines.Len()-1], '\n')
	want := string(lines.Bytes()[last+1:])
	err = copyBoundedLog(file, bytes.NewReader(lines.Bytes()))
	if err := errors.Join(err, file.Close()); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) < logSegmentBytes/2-len(want) || len(data) > logSegmentBytes || !bytes.HasPrefix(data, []byte("line ")) || !strings.HasSuffix(string(data), want) {
		t.Fatalf("kept %d bytes starting %q", len(data), data[:min(len(data), 20)])
	}
}
