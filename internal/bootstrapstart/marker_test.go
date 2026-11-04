package bootstrapstart

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testMarker() AcceptedInstall {
	digest := strings.Repeat("a", 64)
	return AcceptedInstall{
		SchemaVersion: 1, AnchorSHA256: digest, ManifestSHA256: digest,
		ReceiptSHA256: digest, ImageReceiptSHA256: digest,
		DeploymentID: "0000000000F9PR1WNVDTEXS31Z", Cell: "GRU", Slot: "controller-a", SeedSlot: "seed-a",
		ImageOCID:       "ocid1.image.oc1.sa-saopaulo-1.example",
		InstanceOCID:    "ocid1.instance.oc1.sa-saopaulo-1.example",
		PrimaryVNICOCID: "ocid1.vnic.oc1.sa-saopaulo-1.example", PrimaryPrivateIP: "10.0.0.3",
		HeadAttempt: 1, HeadGeneration: 1, ResultSHA256: digest,
		BinarySHA256: digest, MaterialSHA256: map[string]string{"controller-creds": digest},
		AcceptedAt: time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC),
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
