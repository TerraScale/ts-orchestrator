package hostadmission

import (
	"github.com/TerraScale/ts-orchestrator/internal/qualification"
	"github.com/oracle/oci-go-sdk/v65/core"
	"testing"
)

func TestCurrentReaderGeometryRejectsResizeAndForeignBoot(t *testing.T) {
	h := BoundHost{InstanceID: "instance", ImageID: "image"}
	spec := qualification.HostSpec{Shape: "VM.Standard.A1.Flex", AvailabilityDomain: "ad", FaultDomain: "fd", OCPUs: 1, MemoryGB: 6, BootGB: 50}
	instance := core.Instance{Id: new("instance"), ImageId: new("image"), CompartmentId: new("compartment"), Shape: new(spec.Shape), AvailabilityDomain: new("ad"), FaultDomain: new("fd"), LifecycleState: core.InstanceLifecycleStateRunning, ShapeConfig: &core.InstanceShapeConfig{Ocpus: new(float32(1)), MemoryInGBs: new(float32(6))}}
	volume := core.BootVolume{Id: new("boot"), ImageId: new("image"), CompartmentId: new("compartment"), AvailabilityDomain: new("ad"), SizeInGBs: new(int64(50)), LifecycleState: core.BootVolumeLifecycleStateAvailable}
	if !matchesGeometry(instance, volume, h, spec, "compartment", "boot") {
		t.Fatal("exact current geometry rejected")
	}
	for _, test := range []struct {
		name   string
		change func(*core.Instance, *core.BootVolume)
	}{
		{"ocpus", func(i *core.Instance, _ *core.BootVolume) {
			copy := *i.ShapeConfig
			copy.Ocpus = new(float32(2))
			i.ShapeConfig = &copy
		}},
		{"memory", func(i *core.Instance, _ *core.BootVolume) {
			copy := *i.ShapeConfig
			copy.MemoryInGBs = new(float32(12))
			i.ShapeConfig = &copy
		}},
		{"boot-resize", func(_ *core.Instance, v *core.BootVolume) { v.SizeInGBs = new(int64(100)) }},
		{"boot-image", func(_ *core.Instance, v *core.BootVolume) { v.ImageId = new("other") }},
		{"fault-domain", func(i *core.Instance, _ *core.BootVolume) { i.FaultDomain = new("other") }},
	} {
		t.Run(test.name, func(t *testing.T) {
			i, v := instance, volume
			test.change(&i, &v)
			if matchesGeometry(i, v, h, spec, "compartment", "boot") {
				t.Fatal("changed live geometry admitted")
			}
		})
	}
}
