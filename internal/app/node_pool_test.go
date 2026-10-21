package app

import (
	"context"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/cellspec"
	"github.com/TerraScale/ts-orchestrator/internal/hostboot"
	"github.com/TerraScale/ts-orchestrator/internal/hostenroll"
	"github.com/TerraScale/ts-orchestrator/internal/nodescale"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/placement"
	"github.com/TerraScale/ts-orchestrator/internal/tsauth"
	"github.com/TerraScale/ts-orchestrator/internal/workload"
)

// fakeNodePool is the cell's pool as OCI lists it.
type fakeNodePool struct{ state nodescale.PoolState }

func (pool fakeNodePool) Observe(context.Context) (nodescale.PoolState, error) {
	return pool.state, nil
}

func poolOf(members ...nodescale.PoolInstance) fakeNodePool {
	return fakeNodePool{state: nodescale.PoolState{Exists: true, Instances: members}}
}

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

// Every other fact a pool node is admitted on must hold; any doubt refuses.
func TestPoolNodeEnrollmentRefusesUnprovenNodes(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()
	lab := startStaticEnrollmentLab(t, ctx, controllerHostWorkloads())
	lab.reconcile()
	const id, ip = "ocid1.instance.oc1.sa-saopaulo-1.pool4", "10.251.0.14"
	member := nodescale.PoolInstance{ID: id, Name: "ts-gru-4", State: "RUNNING", PrivateIP: ip}
	for _, tc := range []struct {
		name   string
		pool   nodePoolMembers
		mutate func(*oci.CloudInstance)
	}{
		{name: "not in the pool", pool: poolOf()},
		{name: "another name", pool: poolOf(nodescale.PoolInstance{ID: id, Name: "ts-gru-5", State: "RUNNING", PrivateIP: ip})},
		{name: "not running", pool: poolOf(nodescale.PoolInstance{ID: id, Name: "ts-gru-4", State: "STOPPED", PrivateIP: ip})},
		{name: "another private IP", pool: poolOf(member), mutate: func(instance *oci.CloudInstance) {
			instance.PrivateIP = "10.251.0.99"
		}},
		{name: "another cell", pool: poolOf(member), mutate: func(instance *oci.CloudInstance) {
			instance.FreeformTags["ts-cell"] = "sjc"
		}},
		{name: "not a node", pool: poolOf(member), mutate: func(instance *oci.CloudInstance) {
			instance.FreeformTags["ts-role"] = "node-pool"
		}},
		{name: "no shape", pool: poolOf(member), mutate: func(instance *oci.CloudInstance) {
			instance.Ocpus = nil
		}},
		{name: "no pool", pool: nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			metadata := lab.launchPoolNode(t, id, "ts-gru-4", ip)
			if tc.mutate != nil {
				instance := lab.fleet.instances[id]
				tc.mutate(&instance)
				lab.fleet.instances[id] = instance
			}
			lab.enrollment.pool = tc.pool
			if err := lab.setup(ctx, t.TempDir(), metadata, ip); err == nil {
				t.Fatal("pool node was admitted")
			}
		})
	}
}

// Nodes 1 to 3 are the quorum nodes: a pool instance OCI shows under one of
// their names is refused.
func TestPoolNodeEnrollmentRefusesAQuorumNodeName(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()
	lab := startStaticEnrollmentLab(t, ctx, controllerHostWorkloads())
	lab.reconcile()
	const id, ip = "ocid1.instance.oc1.sa-saopaulo-1.pool3", "10.251.0.14"
	lab.enrollment.pool = poolOf(nodescale.PoolInstance{ID: id, Name: "ts-gru-3", State: "RUNNING", PrivateIP: ip})
	if err := lab.setup(ctx, t.TempDir(), lab.launchPoolNode(t, id, "ts-gru-3", ip), ip); err == nil {
		t.Fatal("a pool instance took a quorum node's name")
	}
}

// OCI's actual image-specific shape response supplies observation identity;
// recipe metadata still excludes the leader's controller slot.
