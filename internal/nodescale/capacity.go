package nodescale

import (
	"fmt"
	"math"
	"regexp"

	"github.com/oracle/oci-go-sdk/v65/core"
)

// Capacity identifies hosts with the same isolation role and native platform.
// Image compatibility and availability come from OCI, never from a shape's name.
type Capacity struct {
	Role         string
	Architecture string
	Shape        string
}

// ValidateResources requires OCI's complete limits for the flexible launch configuration.
func ValidateResources(shape core.Shape, ocpus, memoryGB float32) error {
	cpu, memory := shape.OcpuOptions, shape.MemoryOptions
	if !deref(shape.IsFlexible) || cpu == nil || memory == nil {
		return fmt.Errorf("shape has no qualified flexible CPU and memory limits")
	}
	for _, value := range []*float32{new(ocpus), new(memoryGB), cpu.Min, cpu.Max, memory.MinInGBs, memory.MaxInGBs, memory.MinPerOcpuInGBs, memory.MaxPerOcpuInGBs} {
		if value == nil || !(*value > 0) || math.IsInf(float64(*value), 0) {
			return fmt.Errorf("shape CPU and memory limits must be known, finite and positive")
		}
	}
	if ocpus < *cpu.Min || ocpus > *cpu.Max || memoryGB < *memory.MinInGBs || memoryGB > *memory.MaxInGBs ||
		memoryGB/ocpus < *memory.MinPerOcpuInGBs || memoryGB/ocpus > *memory.MaxPerOcpuInGBs {
		return fmt.Errorf("requested CPU and memory exceed the shape's supported limits")
	}
	return nil
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
