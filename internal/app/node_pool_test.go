package app

import (
	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/cellspec"
	"github.com/TerraScale/ts-orchestrator/internal/hostboot"
	"github.com/TerraScale/ts-orchestrator/internal/hostenroll"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/placement"
	"github.com/TerraScale/ts-orchestrator/internal/tsauth"
	"github.com/TerraScale/ts-orchestrator/internal/workload"
)

// reconcile adopts a cell spec reconciling the tsauth role, as apply would.
func (lab staticEnrollmentLab) reconcile() {
	set := lab.enrollment.services.current
	set.Generation++
	set.Services = []cellspec.Service{{Role: tsauth.Role,
		Profile: cellspec.Profile{Resources: placement.Resources{CPU: 1, MemoryBytes: 1 << 30, DiskBytes: 2 << 30}},
		Spec:    &workload.ServiceSpec{Role: tsauth.Role}}}
	lab.enrollment.services.adopt(set, set.Generation)
}

// launchPoolNode records a node pool instance named node at ip, of the 2 OCPU,
// 12 GB shape the pool launches, and returns its host-setup metadata.
func (lab staticEnrollmentLab) launchPoolNode(t *testing.T, id, node, ip string) hostenroll.InstanceMetadata {
	t.Helper()
	descriptor := hostboot.Static("gru", "GRU", node)
	wire, err := descriptor.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	ocpus, memory := float32(2), float32(12)
	lab.fleet.instances[id] = oci.CloudInstance{ID: id, DisplayName: node, PrivateIP: ip, FaultDomain: "FAULT-DOMAIN-1",
		LifecycleState: "RUNNING", Ocpus: &ocpus, MemoryInGBs: &memory,
		FreeformTags: map[string]string{"ts-cell": "gru", "ts-role": "node"}}
	return hostenroll.InstanceMetadata{InstanceID: id, Descriptor: descriptor, Wire: wire}
}
