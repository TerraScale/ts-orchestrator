// Command stablemtime gives every tracked file and directory of a clean
// checkout a modification time derived from its git object id.
//
// Go's test cache keys each repository file a test reads (directly, or
// through script.Track for the inputs of the commands it runs) on the
// file's size and modification time. A fresh CI checkout writes every file
// now, so before this stamp no such test could ever be served from the
// persistent cache. After it, an unchanged file has the same modification
// time in every checkout, and a changed file, whose blob id differs, almost
// surely does not: the stamp spreads 64 bits of the object id over a
// 34-year window ending in 2014, at nanosecond resolution.
//
// It runs only on a checkout whose tracked files match HEAD (CI checks this
// just before), because a modified file would otherwise receive the stamp of
// content it does not have. Untracked files keep their times.
//
// Usage: go run ./scripts/ci/stablemtime [repository]
package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// epoch starts the stamp window: 1980-01-01T00:00:00Z. The window is 2^30
// seconds, so every stamp lies years in the past, as Go's cache requires.
const epoch = 315532800

func main() {
	root := "."
	if len(os.Args) > 2 {
		fmt.Fprintln(os.Stderr, "usage: stablemtime [repository]")
		os.Exit(2)
	}
	if len(os.Args) == 2 {
		root = os.Args[1]
	}
	stamped, err := Stamp(root)
	if err != nil {
		fmt.Fprintln(os.Stderr, "stablemtime:", err)
		os.Exit(1)
	}
	fmt.Printf("stablemtime: stamped %d tracked paths from their object ids\n", stamped)
}

// Stamp sets the modification time of the repository root, every tracked
// directory and every tracked file or symlink under root from its object id
// in HEAD. It returns how many paths it stamped.
func Stamp(root string) (int, error) {
	status, err := git(root, "status", "--porcelain=v1", "-z", "--untracked-files=no")
	if err != nil {
		return 0, err
	}
	if len(status) != 0 {
		return 0, errors.New("tracked files differ from HEAD; refusing to stamp content they do not have")
	}
	tree, err := git(root, "rev-parse", "HEAD^{tree}")
	if err != nil {
		return 0, err
	}
	if err := stamp(root, strings.TrimSpace(string(tree))); err != nil {
		return 0, err
	}
	stamped := 1
	// Each record: <mode> SP <type> SP <object> TAB <path> NUL, with -t
	// listing every tree (directory) as well as its blobs.
	entries, err := git(root, "ls-tree", "-r", "-t", "-z", "--full-tree", "HEAD")
	if err != nil {
		return 0, err
	}
	for record := range bytes.SplitSeq(entries, []byte{0}) {
		if len(record) == 0 {
			continue
		}
		meta, path, ok := strings.Cut(string(record), "\t")
		fields := strings.Fields(meta)
		if !ok || len(fields) != 3 || path == "" {
			return 0, fmt.Errorf("unexpected ls-tree record %q", record)
		}
		if fields[1] == "commit" {
			// A submodule's files are not part of this tree.
			continue
		}
		if err := stamp(filepath.Join(root, filepath.FromSlash(path)), fields[2]); err != nil {
			return 0, err
		}
		stamped++
	}
	return stamped, nil
}

// Time is the modification time stablemtime gives content with this git
// object id.
func Time(object string) (time.Time, error) {
	id, err := hex.DecodeString(object)
	if err != nil || len(id) < 8 {
		return time.Time{}, fmt.Errorf("invalid git object id %q", object)
	}
	bits := binary.BigEndian.Uint64(id[:8])
	seconds := int64(bits >> 34)               // 30 bits
	nanoseconds := int64(bits&(1<<34-1)) % 1e9 // the remaining 34 bits
	return time.Unix(epoch+seconds, nanoseconds).UTC(), nil
}

func stamp(path, object string) error {
	at, err := Time(object)
	if err != nil {
		return err
	}
	spec := unix.NsecToTimespec(at.UnixNano())
	// A symlink keeps its own time; its target is stamped as its own entry.
	if err := unix.UtimesNanoAt(unix.AT_FDCWD, path, []unix.Timespec{spec, spec}, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return fmt.Errorf("stamp %s: %w", path, err)
	}
	return nil
}

func git(root string, args ...string) ([]byte, error) {
	command := exec.Command("git", append([]string{"-C", root}, args...)...)
	var stderr bytes.Buffer
	command.Stderr = &stderr
	output, err := command.Output()
	if err != nil {
		return nil, fmt.Errorf("git %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return output, nil
}
