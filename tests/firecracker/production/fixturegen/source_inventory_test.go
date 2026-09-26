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
	withoutFloor := slices.DeleteFunc(slices.Clone(pins), func(pin SourcePin) bool {
		return pin.Path == "internal/bootstrapstart/founder_floor_artifact.go"
	})
	if err := VerifyCompletedSourcePins(root, withoutFloor); err == nil {
		t.Fatal("completed source inventory accepted omitted floor implementation")
	}
}
