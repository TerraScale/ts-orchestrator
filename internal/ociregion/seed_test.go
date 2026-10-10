package ociregion

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestSeedLaunchRequiresCurrentManifestSchema(t *testing.T) {
	for _, version := range []int{0, 1, 2, 3} {
		t.Run(fmt.Sprint(version), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "manifest.json")
			wire := fmt.Sprintf(`{"schemaVersion":1,"keyId":"root","signature":"signed","scope":{"domain":"terrascale.bootstrap.manifest","role":"controller","slot":"controller-a","cell":"GRU"},"payload":{"schemaVersion":%d,"slot":"controller-a","seedSlot":"controller-a","cell":"GRU"}}`, version)
			if err := os.WriteFile(path, []byte(wire), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := capture(func() any { return validateManifest(path, "GRU") })
			if (err == nil) != (version == 1) {
				t.Fatalf("manifest schema %d: %v", version, err)
			}
		})
	}
}

func TestSeedPreflightRejectsRetiredToolSwitches(t *testing.T) {
	for _, flag := range []string{"--legacy-bootstrap-tool", "--legacy-release-tool"} {
		engine := &Engine{Context: t.Context()}
		if err := engine.Run([]string{"seed-preflight", flag}, io.Discard); err == nil {
			t.Fatalf("accepted retired switch %s", flag)
		}
	}
}
