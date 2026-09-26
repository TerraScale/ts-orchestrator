package bootstrapstart

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
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

func TestFounderSelectionFloorRequiresProvisioningAndRejectsRollback(t *testing.T) {
	store := testFounderFloor(t)
	a := strings.Repeat("a", 64)
	b := strings.Repeat("b", 64)
	if err := store.Check(1, a); !errors.Is(err, ErrFounderSelectionFloor) {
		t.Fatalf("missing floor: %v", err)
	}
	if err := store.Initialize(1, a); err != nil {
		t.Fatal(err)
	}
	if err := store.Initialize(1, a); err == nil {
		t.Fatal("replaced provisioned floor")
	}
	if err := store.Observe(2, b); err != nil {
		t.Fatal(err)
	}
	restarted := *store
	if err := restarted.Check(1, a); !errors.Is(err, ErrFounderSelectionFloor) {
		t.Fatalf("rollback across restart: %v", err)
	}
	if err := restarted.Check(2, a); !errors.Is(err, ErrFounderSelectionFloor) {
		t.Fatalf("same-generation equivocation: %v", err)
	}
	if err := restarted.Check(2, b); err != nil {
		t.Fatalf("current generation: %v", err)
	}
}

func TestServiceFounderFloorPublishesCompleteOwnerCheckedFileAfterOrphanTemp(t *testing.T) {
	store, uid, gid := testServiceFounderFloor(t)
	orphan := filepath.Join(store.directory, ".founder-selection-initial.interrupted")
	if err := os.WriteFile(orphan, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	digest := strings.Repeat("a", 64)
	if err := store.InitializeForService(1, digest, gid); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(filepath.Join(store.directory, founderSelectionFloorName))
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		t.Fatalf("published floor is incomplete: %v, %v", info, err)
	}
	var stat unix.Stat_t
	if err := unix.Stat(filepath.Join(store.directory, founderSelectionFloorName), &stat); err != nil ||
		stat.Uid != uid || stat.Gid != gid {
		t.Fatalf("published floor has wrong service owner: %v, %v", stat, err)
	}
	if err := store.Observe(1, digest); err != nil {
		t.Fatalf("replay after initial publication: %v", err)
	}
	if err := store.InitializeForService(1, digest, gid); err == nil {
		t.Fatal("existing floor was silently replaced")
	}
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

func TestServicePeerFloorRootReplayPreservesDistinctServiceOwner(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root to publish for a distinct service UID")
	}
	const serviceUID, serviceGID = uint32(65534), uint32(65534)
	directory := filepath.Join(t.TempDir(), "peer-controller")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(directory, int(serviceUID), int(serviceGID)); err != nil {
		t.Fatal(err)
	}
	store := &FounderSelectionFloorStore{directory: directory, ownerUID: serviceUID,
		allowUnsafeAncestors: true}
	if err := prepareFounderFloorOwner(store, serviceUID, serviceGID); err != nil {
		t.Fatalf("prepare service-owned lock: %v", err)
	}
	a, b := strings.Repeat("a", 64), strings.Repeat("b", 64)
	if err := store.InitializePeerForService(1, a, serviceGID); err != nil {
		t.Fatalf("first root-run publication: %v", err)
	}
	if err := store.InitializePeerForService(2, b, serviceGID); err != nil {
		t.Fatalf("root-run crash replay to higher generation: %v", err)
	}
	if err := store.Check(2, b); err != nil {
		t.Fatalf("replayed service floor cannot be read: %v", err)
	}
	for _, name := range []string{founderSelectionLockName, founderSelectionFloorName} {
		var stat unix.Stat_t
		if err := unix.Stat(filepath.Join(directory, name), &stat); err != nil ||
			stat.Uid != serviceUID || stat.Gid != serviceGID || stat.Mode&0o777 != 0o600 {
			t.Fatalf("root-run replay left %s with wrong owner/mode: stat=%+v err=%v", name, stat, err)
		}
	}
}

func TestServiceFounderFloorReplaysVisiblePublicationAndRejectsIncompleteDestination(t *testing.T) {
	store, uid, gid := testServiceFounderFloor(t)
	digest := strings.Repeat("a", 64)
	path := filepath.Join(store.directory, founderSelectionFloorName)
	wire, err := protocol.EncodeJSON(founderSelectionFloor{SchemaVersion: 1,
		Generation: 1, SelectionSHA256: digest})
	if err != nil {
		t.Fatal(err)
	}
	// Model a crash after no-replace publication but before directory sync.
	// The next Observe must sync the visible exact floor before an effect.
	if err := os.WriteFile(path, wire, 0o600); err != nil {
		t.Fatal(err)
	}
	if os.Geteuid() == 0 {
		if err := os.Chown(path, int(uid), int(gid)); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.Observe(1, digest); err != nil {
		t.Fatalf("visible exact floor could not be replayed: %v", err)
	}
	if err := store.InitializeForService(1, digest, gid); err == nil {
		t.Fatal("replay silently replaced an existing floor")
	}
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := store.Observe(1, digest); !errors.Is(err, ErrFounderSelectionFloor) {
		t.Fatalf("incomplete published floor was accepted: %v", err)
	}
	if err := store.InitializeForService(1, digest, gid); err == nil {
		t.Fatal("incomplete published floor was overwritten")
	}
}

func TestFounderSelectionFloorRejectsTamperedFileAndDirectory(t *testing.T) {
	store := testFounderFloor(t)
	digest := strings.Repeat("a", 64)
	if err := store.Initialize(1, digest); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(store.directory, founderSelectionFloorName)
	if err := os.Chmod(path, 0o666); err != nil {
		t.Fatal(err)
	}
	if err := store.Check(1, digest); !errors.Is(err, ErrFounderSelectionFloor) {
		t.Fatalf("writable floor: %v", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(`{"schemaVersion":1,"generation":1,"selectionSha256":"bad"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := store.Check(1, digest); !errors.Is(err, ErrFounderSelectionFloor) {
		t.Fatalf("invalid floor content: %v", err)
	}
	if err := os.Chmod(store.directory, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := store.Check(1, digest); !errors.Is(err, ErrFounderSelectionFloor) {
		t.Fatalf("writable directory: %v", err)
	}
}
