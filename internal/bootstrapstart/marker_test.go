package bootstrapstart

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func testMarker() AcceptedInstall {
	digest := strings.Repeat("a", 64)
	return AcceptedInstall{
		SchemaVersion: 1, AnchorSHA256: digest, ManifestSHA256: digest,
		ReceiptSHA256: digest, ImageReceiptSHA256: digest,
		DeploymentID: "deployment-a", Cell: "GRU", Slot: "controller-a", SeedSlot: "seed-a",
		ImageOCID:       "ocid1.image.oc1.sa-saopaulo-1.example",
		InstanceOCID:    "ocid1.instance.oc1.sa-saopaulo-1.example",
		PrimaryVNICOCID: "ocid1.vnic.oc1.sa-saopaulo-1.example", PrimaryPrivateIP: "10.0.0.3",
		HeadAttempt: 1, HeadGeneration: 1, ResultSHA256: digest,
		BinarySHA256: digest, MaterialSHA256: map[string]string{"controller-creds": digest},
		AcceptedAt: time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC),
	}
}

func TestMarkerRequiresPrimaryVNICIdentity(t *testing.T) {
	marker := testMarker()
	marker.PrimaryVNICOCID = ""
	if !errors.Is(marker.validate(), ErrInvalidMarker) {
		t.Fatal("accepted marker without primary VNIC OCID")
	}
	marker = testMarker()
	marker.PrimaryPrivateIP = "127.0.0.1"
	if !errors.Is(marker.validate(), ErrInvalidMarker) {
		t.Fatal("accepted marker with loopback primary address")
	}
}

func TestMarkerRequiresSignedSeedRole(t *testing.T) {
	marker := testMarker()
	marker.SeedSlot = ""
	if !errors.Is(marker.validate(), ErrInvalidMarker) {
		t.Fatal("accepted marker without seed role")
	}
	marker = testMarker()
	marker.SeedSlot = "not a slot"
	if !errors.Is(marker.validate(), ErrInvalidMarker) {
		t.Fatal("accepted marker with malformed seed role")
	}
}

func testMarkerStore(t *testing.T) MarkerStore {
	t.Helper()
	directory := filepath.Join(t.TempDir(), "bootstrap")
	if err := os.Mkdir(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	return MarkerStore{directory: directory, ownerUID: uint32(os.Getuid()), allowUnsafeAncestors: true}
}

func TestMarkerAtomicNoReplaceAndTamper(t *testing.T) {
	store := testMarkerStore(t)
	marker := testMarker()
	if err := store.WriteNew(marker); err != nil {
		t.Fatal(err)
	}
	read, err := store.Read()
	if err != nil || read.BinarySHA256 != marker.BinarySHA256 {
		t.Fatalf("read accepted marker: %+v, %v", read, err)
	}
	if err := store.WriteNew(marker); !errors.Is(err, unix.EEXIST) {
		t.Fatalf("duplicate marker write = %v, want EEXIST", err)
	}
	path := filepath.Join(store.directory, markerName)
	if err := os.Chmod(path, 0o666); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Read(); !errors.Is(err, ErrInvalidMarker) {
		t.Fatalf("writable marker read = %v, want invalid marker", err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(`{"schemaVersion":1}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Read(); !errors.Is(err, ErrInvalidMarker) {
		t.Fatalf("tampered marker read = %v, want invalid marker", err)
	}
}

func TestMarkerRejectsSymlinkAndUntrustedParent(t *testing.T) {
	store := testMarkerStore(t)
	if err := os.Symlink(filepath.Join(store.directory, "missing"), filepath.Join(store.directory, markerName)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Read(); err == nil {
		t.Fatal("accepted symlink marker")
	}
	unsafe := store
	unsafe.allowUnsafeAncestors = false
	unsafe.ownerUID = 0
	if _, err := unsafe.Read(); !errors.Is(err, ErrInvalidMarker) {
		t.Fatalf("untrusted parent read = %v, want invalid marker", err)
	}
}
