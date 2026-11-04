package bootstrapstart

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func testFounderFloor(t *testing.T) *FounderSelectionFloorStore {
	t.Helper()
	directory := filepath.Join(t.TempDir(), "controller")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	return &FounderSelectionFloorStore{directory: directory, ownerUID: uint32(os.Geteuid()), allowUnsafeAncestors: true}
}

func testFounderServiceIdentity() (uint32, uint32) {
	if os.Geteuid() == 0 {
		return 65534, 65534
	}
	return uint32(os.Geteuid()), uint32(os.Getegid())
}

func testServiceFounderFloor(t *testing.T) (*FounderSelectionFloorStore, uint32, uint32) {
	t.Helper()
	uid, gid := testFounderServiceIdentity()
	directory := filepath.Join(t.TempDir(), "service-controller")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	if os.Geteuid() == 0 {
		if err := os.Chown(directory, int(uid), int(gid)); err != nil {
			t.Fatal(err)
		}
	}
	store := &FounderSelectionFloorStore{directory: directory, ownerUID: uid, allowUnsafeAncestors: true}
	if err := prepareFounderFloorOwner(store, uid, gid); err != nil {
		t.Fatal(err)
	}
	return store, uid, gid
}

func TestServicePeerFloorCrashReplayAdvancesWithoutLosingOwner(t *testing.T) {
	store, uid, gid := testServiceFounderFloor(t)
	a, b := strings.Repeat("a", 64), strings.Repeat("b", 64)
	if err := store.InitializePeerForService(1, a, gid); err != nil {
		t.Fatalf("first peer floor publication: %v", err)
	}
	if err := store.InitializePeerForService(2, b, gid); err != nil {
		t.Fatalf("replay after selector advance: %v", err)
	}
	if err := store.Check(2, b); err != nil {
		t.Fatalf("advanced peer floor was not readable by service: %v", err)
	}
	if err := store.InitializePeerForService(2, b, gid); err != nil {
		t.Fatalf("same-selector crash replay: %v", err)
	}
	if err := store.InitializePeerForService(1, a, gid); !errors.Is(err, ErrFounderSelectionFloor) {
		t.Fatalf("peer floor accepted rollback: %v", err)
	}
	if err := store.InitializePeerForService(2, a, gid); !errors.Is(err, ErrFounderSelectionFloor) {
		t.Fatalf("peer floor accepted same-generation equivocation: %v", err)
	}
	var stat unix.Stat_t
	if err := unix.Stat(filepath.Join(store.directory, founderSelectionFloorName), &stat); err != nil ||
		stat.Uid != uid || stat.Gid != gid || stat.Mode&0o777 != 0o600 {
		t.Fatalf("replayed peer floor lost service owner/mode: stat=%+v err=%v", stat, err)
	}
}
