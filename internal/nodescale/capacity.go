package nodescale

import (
	"fmt"
	"regexp"
)

// Capacity identifies hosts with the same isolation role and native platform.
// Image compatibility and availability come from OCI, never from a shape's name.
type Capacity struct {
	Role         string
	Architecture string
	Shape        string
}

const (
	RoleManager    = "manager"
	RoleContainer  = "container"
	RoleWasm       = "wasm"
	PreferredShape = "VM.Standard.A1.Flex"
)

var shapePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

// Validate checks identity syntax; it does not qualify a runtime or image.
func (c Capacity) Validate() error {
	switch c.Role {
	case RoleManager, RoleContainer, RoleWasm:
	default:
		return fmt.Errorf("unknown node capacity role %q", c.Role)
	}
	if c.Architecture != "arm64" && c.Architecture != "amd64" {
		return fmt.Errorf("unknown node architecture %q", c.Architecture)
	}
	if !shapePattern.MatchString(c.Shape) {
		return fmt.Errorf("node capacity needs an OCI shape, got %q", c.Shape)
	}
	return nil
}
