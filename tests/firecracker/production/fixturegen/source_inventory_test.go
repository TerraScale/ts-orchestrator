package fixturegen

import (
	"path/filepath"
	"slices"
	"testing"
)

func TestCurrentCompletedSourcePinsCoverRecipeAndVerify(t *testing.T) {
	root, err := filepath.Abs("../../../..")
	if err != nil {
		t.Fatal(err)
	}
	pins, err := CurrentCompletedSourcePins(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{
		"cmd/terrascale-orchestrator/main.go",
		"internal/cli/cli.go",
		"internal/commandio/io.go",
		"internal/bootstrap/cli/commands.go",
		"internal/release/cli/commands.go",
		"internal/bootstrapstart/founder_floor_artifact.go",
		"internal/bootstrapstart/founder_selection_floor.go",
		"internal/bootstrapstart/founder_continuation.go",
		"tests/firecracker/production/fixturegen/guest_material.go",
	} {
		if !slices.ContainsFunc(pins, func(pin SourcePin) bool { return pin.Path == path }) {
			t.Fatalf("completed source pins omit %q", path)
		}
	}
	if err := VerifyCompletedSourcePins(root, pins); err != nil {
		t.Fatalf("current source pins did not verify: %v", err)
	}
	for _, omitted := range []string{
		"internal/bootstrapstart/founder_floor_artifact.go",
		"internal/cli/cli.go",
		"internal/bootstrap/cli/commands.go",
		"internal/release/cli/commands.go",
	} {
		withoutSource := slices.DeleteFunc(slices.Clone(pins), func(pin SourcePin) bool {
			return pin.Path == omitted
		})
		if err := VerifyCompletedSourcePins(root, withoutSource); err == nil {
			t.Fatalf("completed source inventory accepted omitted implementation %q", omitted)
		}
	}
}
