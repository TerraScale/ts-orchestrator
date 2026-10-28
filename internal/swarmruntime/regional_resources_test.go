package swarmruntime

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"testing"

	"github.com/TerraScale/ts-orchestrator/deploy/m1"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/moby/swarmkit/v2/api"
	runtimespec "github.com/opencontainers/runtime-spec/specs-go"
)

func TestTerraBaseRenderUnchanged(t *testing.T) {
	data, err := os.ReadFile("../../deploy/m1/services/terrabase.json")
	if err != nil {
		t.Fatal(err)
	}
	var declaration ServiceSpec
	if err := protocol.DecodeStrict(data, &declaration, 64<<10); err != nil {
		t.Fatal(err)
	}
	spec, err := declaration.SwarmSpec()
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(spec)
	if err != nil {
		t.Fatal(err)
	}
	// Captured from main 784000657 before changing the renderer, then with
	// BUCKET_NAME set to the -b12 bucket the live service already uses. Hash the
	// full service (including task/update/endpoint), not only its resource fields.
	const before = "90cbcc1924fbf53160ec76a5531d0f10293b030294882853a01f800074fb350a"
	if got := fmt.Sprintf("%x", sha256.Sum256(encoded)); got != before {
		t.Fatalf("TerraBase render changed: %s; binary reconciliation must not replace its task", got)
	}
	// The same apply path used by mesh startup/sync must issue zero writes.
	// Repeat for each region with persisted generation/scope metadata.
	for _, region := range []string{"gru", "sjc", "fra"} {
		local := declaration
		local.Generation, local.Region, local.Node = 123, region, region+"-1"
		rendered, err := local.SwarmSpec()
		if err != nil {
			t.Fatal(err)
		}
		client := &safetyControl{service: &api.Service{ID: "terrabase", Spec: *rendered}}
		if _, err := ApplyServiceSpec(t.Context(), client, local); err != nil {
			t.Fatal(err)
		}
		if client.writes != 0 {
			t.Fatalf("%s reconciliation rewrote TerraBase", region)
		}
	}
}

func TestRegionalAppResourceBudgets(t *testing.T) {
	for _, name := range []string{"ts-auth", "ts-dashboard"} {
		t.Run(name, func(t *testing.T) {
			data, err := m1.Files.ReadFile("services/" + name + ".json")
			if err != nil {
				t.Fatal(err)
			}
			var declaration ServiceSpec
			if err := protocol.DecodeStrict(data, &declaration, 64<<10); err != nil {
				t.Fatal(err)
			}
			cpu := int64(200_000_000)
			if name == "ts-auth" {
				cpu = 500_000_000
				if !slices.Equal(declaration.Regions, []string{"gru"}) {
					t.Fatal("auth must remain gru-only until its regional startup and write-safety constraints are resolved")
				}
			} else if len(declaration.Regions) != 0 {
				t.Fatal("dashboard must follow every admitted region")
			}
			for _, startFirst := range []bool{true, false} {
				candidate := declaration
				if !startFirst {
					candidate.Env = nil
				}
				spec, err := candidate.SwarmSpec()
				if err != nil {
					t.Fatal(err)
				}
				r := spec.Task.Resources
				limit, disk := int64(2_000_000_000), int64(2<<30)
				order := api.UpdateConfig_START_FIRST
				if !startFirst {
					// Without volumes the disk budget stays 2 GiB either way.
					limit, order = cpu, api.UpdateConfig_STOP_FIRST
				}
				if r.Reservations.NanoCPUs != cpu || r.Limits.NanoCPUs != limit || r.Reservations.MemoryBytes != 2048<<20 || r.Limits.MemoryBytes != r.Reservations.MemoryBytes || spec.Update.Order != order {
					t.Fatalf("unexpected resource/order contract: %v, %v", r, spec.Update.Order)
				}
				if got, err := DiskBytes(r); err != nil || got != disk {
					t.Fatalf("disk = %d, %v", got, err)
				}
				task := &api.Task{ID: "validation", ServiceID: "validation", Spec: spec.Task, ServiceAnnotations: spec.Annotations}
				if _, err := DecodeContainer(task); err != nil {
					t.Fatal(err)
				}
				inspected, err := InspectService(&api.Service{Spec: *spec})
				if err != nil || inspected.Spec.MilliCPU != uint32(cpu/1_000_000) || inspected.Spec.MemoryMiB != 2048 {
					t.Fatalf("inspect lost reservations: %v, %v", inspected, err)
				}
			}
		})
	}

}

func TestContainerCPUKeepsDefaultWeight(t *testing.T) {
	for _, burst := range []bool{false, true} {
		r := containerTestResources(200_000_000, 2048<<20)
		if burst {
			r.Limits.NanoCPUs = 2_000_000_000
		}
		spec := runtimespec.Spec{Linux: &runtimespec.Linux{}}
		if err := containerCPU(r)(t.Context(), nil, nil, &spec); err != nil {
			t.Fatal(err)
		}
		cpu := spec.Linux.Resources.CPU
		if cpu.Quota == nil || *cpu.Quota != r.Limits.NanoCPUs/10_000 || cpu.Period == nil || *cpu.Period != 100_000 {
			t.Fatalf("wrong CFS limit: %+v", cpu)
		}
		// A bursting app competes at TerraBase's weight; a reservation-sized
		// weight starved its startup under load.
		if cpu.Shares != nil {
			t.Fatalf("burst=%v set a scheduler weight: %+v", burst, cpu)
		}
	}
}
