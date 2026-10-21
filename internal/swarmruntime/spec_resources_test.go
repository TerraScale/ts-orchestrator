package swarmruntime

import (
	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/storage/execution"
	"github.com/gogo/protobuf/types"
	"github.com/moby/swarmkit/v2/api"
	"github.com/moby/swarmkit/v2/api/genericresource"
)

func containerTestResources(cpu, memory int64) *api.ResourceRequirements {
	limits := &api.Resources{NanoCPUs: cpu, MemoryBytes: memory, Generic: []*api.GenericResource{genericresource.NewDiscrete(DiskResource, 64<<20)}}
	return &api.ResourceRequirements{Limits: limits, Reservations: limits.Copy()}
}

func TestContainerDiskBudget(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*api.ResourceRequirements)
	}{
		{"missing limits", func(r *api.ResourceRequirements) { r.Limits = nil }},
		{"missing reservations", func(r *api.ResourceRequirements) { r.Reservations = nil }},
		{"absent", func(r *api.ResourceRequirements) { r.Limits.Generic = nil; r.Reservations.Generic = nil }},
		{"unreserved", func(r *api.ResourceRequirements) { r.Reservations.Generic = nil }},
		{"different budget", func(r *api.ResourceRequirements) { r.Reservations.Generic[0].GetDiscreteResourceSpec().Value-- }},
		{"partial CPU reservation", func(r *api.ResourceRequirements) { r.Reservations.NanoCPUs-- }},
		{"partial memory reservation", func(r *api.ResourceRequirements) { r.Reservations.MemoryBytes-- }},
		{"zero", func(r *api.ResourceRequirements) {
			r.Limits.Generic[0].GetDiscreteResourceSpec().Value = 0
			r.Reservations = r.Limits.Copy()
		}},
		{"negative", func(r *api.ResourceRequirements) {
			r.Limits.Generic[0].GetDiscreteResourceSpec().Value = -1
			r.Reservations = r.Limits.Copy()
		}},
		{"duplicate", func(r *api.ResourceRequirements) {
			r.Limits.Generic = append(r.Limits.Generic, r.Limits.Generic[0].Copy())
			r.Reservations = r.Limits.Copy()
		}},
		{"named", func(r *api.ResourceRequirements) {
			r.Limits.Generic[0] = genericresource.NewString(DiskResource, "64MiB")
			r.Reservations = r.Limits.Copy()
		}},
		// Copy panics on a nil entry, so nil both sides directly.
		{"nil", func(r *api.ResourceRequirements) { r.Limits.Generic[0] = nil; r.Reservations.Generic[0] = nil }},
		{"empty", func(r *api.ResourceRequirements) {
			r.Limits.Generic[0] = &api.GenericResource{}
			r.Reservations = r.Limits.Copy()
		}},
		{"unknown", func(r *api.ResourceRequirements) {
			r.Limits.Generic = append(r.Limits.Generic, genericresource.NewDiscrete("unknown", 1))
			r.Reservations = r.Limits.Copy()
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			r := containerTestResources(100_000_000, 64<<20)
			test.mutate(r)
			if _, err := DiskBytes(r); err == nil {
				t.Fatal("invalid disk reservation accepted")
			}
		})
	}
	if _, err := DiskBytes(nil); err == nil {
		t.Fatal("nil resources accepted")
	}
	r := containerTestResources(100_000_000, 64<<20)
	if disk, err := DiskBytes(r); err != nil || disk != 64<<20 {
		t.Fatalf("exact disk pair: disk=%d err=%v", disk, err)
	}
}

func TestContainerResourceContracts(t *testing.T) {
	intent := serviceIntent()
	runtime, err := ContainerRuntime(intent.Container)
	if err != nil {
		t.Fatal(err)
	}
	task := &api.Task{ID: "resourcefixture", ServiceID: "resources", NodeID: "node", Spec: api.TaskSpec{Runtime: runtime, Resources: intent.Resources.Copy()}}
	if _, err := DecodeContainer(task); err != nil {
		t.Fatalf("reserved generic disk: %v", err)
	}
	for _, mutate := range []func(*api.Task){
		func(task *api.Task) { task.Spec.Resources.SwapBytes = &types.Int64Value{} },
		func(task *api.Task) { task.Spec.Resources.MemorySwappiness = &types.Int64Value{} },
		func(task *api.Task) { task.Spec.Resources.Limits.NanoCPUs = 1 },
		func(task *api.Task) { task.Spec.Resources.Limits.MemoryBytes = 1 },
		func(task *api.Task) {
			task.Spec.Resources.Limits.Generic = append(task.Spec.Resources.Limits.Generic, genericresource.NewDiscrete(FunctionWorkerSlot, 1))
			task.Spec.Resources.Reservations = task.Spec.Resources.Limits.Copy()
		},
	} {
		invalid := task.Copy()
		mutate(invalid)
		if _, err := DecodeContainer(invalid); err == nil {
			t.Fatal("unsupported generic resource controls accepted")
		}
	}
	task.Spec.Resources.Limits.Generic = nil
	task.Spec.Resources.Reservations.Generic = nil
	if _, err := DecodeContainer(task); err == nil {
		t.Fatal("generic task accepted without disk")
	}
	intent.Resources = task.Spec.Resources.Copy()
	if _, err := intent.serviceSpec(); err == nil {
		t.Fatal("generic service accepted without disk")
	}
	task.ServiceAnnotations.Labels = map[string]string{LabelRole: FunctionWorkerRole}
	if _, err := DecodeContainer(task); err == nil {
		t.Fatal("function role alone bypassed disk contract")
	}
	task.Spec.Resources.Limits.Generic = []*api.GenericResource{genericresource.NewDiscrete(FunctionWorkerSlot, 1)}
	task.Spec.Resources.Reservations = task.Spec.Resources.Limits.Copy()
	if _, err := DecodeContainer(task); err != nil {
		t.Fatalf("existing dedicated function contract: %v", err)
	}
	task.ServiceAnnotations.Labels = map[string]string{LabelRole: "terrabase", "terrascale.stateful": "true"}
	task.Spec.Resources.Limits.Generic = nil
	task.Spec.Resources.Reservations.Generic = nil
	task.Spec.GetGeneric().Kind = execution.StatefulContainerKind
	task.Spec.GetGeneric().Payload.TypeUrl = execution.StatefulContainerTypeURL
	if _, err := DecodeContainer(task); err == nil {
		t.Fatal("stateful contract accepted by generic decoder")
	}
	if _, err := decodeStateful(task); err != nil {
		t.Fatalf("existing typed stateful structural contract: %v", err)
	}
	task.Spec.Resources.Limits.Generic = []*api.GenericResource{genericresource.NewDiscrete(DiskResource, -1)}
	if _, err := decodeStateful(task); err == nil {
		t.Fatal("typed stateful path ignored malformed disk")
	}
}

func TestFunctionWorkerSlotWithDiskAdvertisement(t *testing.T) {
	resources := []*api.GenericResource{genericresource.NewDiscrete(DiskResource, 64<<20), genericresource.NewDiscrete(FunctionWorkerSlot, 1)}
	if !hasFunctionWorkerSlot(resources) {
		t.Fatal("disk advertisement hid dedicated function slot")
	}
	for _, invalid := range []*api.GenericResource{nil, genericresource.NewString(DiskResource, "64MiB"), genericresource.NewDiscrete(DiskResource, 1), genericresource.NewDiscrete(FunctionWorkerSlot, 1), genericresource.NewDiscrete("unknown", 1)} {
		if hasFunctionWorkerSlot(append(resources[:len(resources):len(resources)], invalid)) {
			t.Fatal("invalid resource advertisement accepted")
		}
	}
}
