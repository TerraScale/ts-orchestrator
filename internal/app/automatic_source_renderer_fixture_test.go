//go:build fixturetest

package app

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapmaterial"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart/materialsource"
	"github.com/TerraScale/ts-orchestrator/internal/roleconfig"
)

func TestAutomaticSourceUsesRootApprovedV2Renderer(t *testing.T) {
	seen := map[string]bool{}
	materialsource.ExerciseColdMaterialSource(t, func(manifest bootstrap.Manifest, record bootstrapmaterial.Record, link bootstrapmaterial.LinkRecord, signers []byte, now time.Time) (bootstrap.Manifest, error) {
		rendered, err := automaticControllerConfigWithLink(manifest, record, link, signers, now)
		if err != nil {
			return bootstrap.Manifest{}, err
		}
		path := filepath.Join(t.TempDir(), "controller.json")
		if err := os.WriteFile(path, rendered.ControllerConfig, 0o600); err != nil {
			return bootstrap.Manifest{}, err
		}
		loaded, err := LoadConfig(path)
		if err != nil {
			return bootstrap.Manifest{}, err
		}
		if loaded.Version != roleconfig.Version {
			return bootstrap.Manifest{}, fmt.Errorf("fresh source config version %d", loaded.Version)
		}
		wire, err := loaded.signedWire()
		if err != nil || !bytes.Equal(wire, rendered.ControllerConfig) {
			return bootstrap.Manifest{}, fmt.Errorf("fresh source changed signed config bytes: %w", err)
		}
		address := ""
		for _, slot := range record.Config.Slots {
			if slot.Name == manifest.Slot {
				address = slot.PrivateIP
			}
		}
		if address == "" {
			return bootstrap.Manifest{}, fmt.Errorf("source omitted slot %s", manifest.Slot)
		}
		if _, err := ValidateSignedControllerConfig(rendered, address); err != nil {
			return bootstrap.Manifest{}, err
		}
		seen[manifest.Slot] = true
		return rendered, nil
	})
	if len(seen) != 3 {
		t.Fatalf("source renderer bound %d slots, want all three", len(seen))
	}
}
