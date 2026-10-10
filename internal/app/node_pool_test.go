package app

import (
	"context"
	"encoding/json/v2"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/cellspec"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/host"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/hostboot"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/hostenroll"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/nodescale"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/oci"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/placement"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/tsauth"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/workload"
	"github.com/oracle/oci-go-sdk/v65/core"
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

// A node pool instance that OCI shows running in the cell's pool under its
// node name at its private address enrolls with the cell's service roles and
// its shape's capacity.
func TestPoolNodeEnrollsWithTheServiceRolesAndItsShape(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()
	lab := startStaticEnrollmentLab(t, ctx, controllerHostWorkloads())
	lab.reconcile()
	const id, ip = "ocid1.instance.oc1.sa-saopaulo-1.pool4", "10.251.0.14"
	lab.enrollment.pool = poolOf(nodescale.PoolInstance{ID: id, Name: "ts-gru-4", State: "RUNNING", PrivateIP: ip})
	metadata := lab.launchPoolNode(t, id, "ts-gru-4", ip)
	root := t.TempDir()
	if err := lab.setup(ctx, root, metadata, ip); err != nil {
		t.Fatalf("pool node setup: %v", err)
	}
	var installed Config
	wire, err := os.ReadFile(filepath.Join(root, "host.json"))
	if err != nil || json.Unmarshal(wire, &installed) != nil ||
		installed.Host.Node != "ts-gru-4" || !slices.Equal(installed.Host.Roles, []string{tsauth.Role}) {
		t.Fatalf("installed pool node config = %+v, %v", installed.Host, err)
	}
	registration := lab.registration(t, ctx, "ts-gru-4")
	if !slices.Equal(registration.Roles, []string{tsauth.Role}) || registration.FailureDomain != "fault-domain-1" ||
		registration.Environment != "production" ||
		registration.Capacity != (host.Capacity{CPU: 2, MemoryBytes: 12 << 30, DiskBytes: nodescale.BootVolumeGB << 30}) ||
		registration.ManagedOCI != nil || registration.ManagedPlacement != nil || registration.ManagedMember != nil {
		t.Fatalf("pool node registration = %+v", registration)
	}
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
			instance.FreeformTags["ts-cell"] = "sfo"
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

// A scale-down retires a node's name; the next instance OCI shows under that
// name is the same node, so the name is taken again.
func TestPoolNodeNameReuseUnretiresTheRetiredNode(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()
	lab := startStaticEnrollmentLab(t, ctx, controllerHostWorkloads())
	lab.reconcile()
	const ip = "10.251.0.14"
	lab.enrollment.pool = poolOf(nodescale.PoolInstance{ID: "ocid1.instance.oc1.sa-saopaulo-1.pool4", Name: "ts-gru-4", State: "RUNNING", PrivateIP: ip})
	first := lab.launchPoolNode(t, "ocid1.instance.oc1.sa-saopaulo-1.pool4", "ts-gru-4", ip)
	if err := lab.setup(ctx, t.TempDir(), first, ip); err != nil {
		t.Fatalf("first pool node setup: %v", err)
	}
	if retired, err := lab.controller.RetireIdle(ctx, "ts-gru-4"); err != nil || !retired {
		t.Fatalf("retire idle pool node = %v, %v", retired, err)
	}
	const reused = "ocid1.instance.oc1.sa-saopaulo-1.pool5"
	lab.enrollment.pool = poolOf(nodescale.PoolInstance{ID: reused, Name: "ts-gru-4", State: "RUNNING", PrivateIP: ip})
	second := lab.launchPoolNode(t, reused, "ts-gru-4", ip)
	if err := lab.setup(ctx, t.TempDir(), second, ip); err != nil {
		t.Fatalf("reused pool node setup: %v", err)
	}
	if registered := lab.registration(t, ctx, "ts-gru-4"); registered.Node != "ts-gru-4" {
		t.Fatalf("reused pool node registration = %+v", registered)
	}
	statuses, err := lab.controller.ListHosts(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, status := range statuses {
		if status.Registration.Node == "ts-gru-4" && status.Retired {
			t.Fatal("reused pool node name is still retired")
		}
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

// A draining pool node keeps its retire mark when the same host enrolls again.
func TestPoolNodeReenrollmentKeepsItsRetireMark(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()
	lab := startStaticEnrollmentLab(t, ctx, controllerHostWorkloads())
	lab.reconcile()
	const id, ip = "ocid1.instance.oc1.sa-saopaulo-1.pool4", "10.251.0.14"
	lab.enrollment.pool = poolOf(nodescale.PoolInstance{ID: id, Name: "ts-gru-4", State: "RUNNING", PrivateIP: ip})
	metadata := lab.launchPoolNode(t, id, "ts-gru-4", ip)
	root := t.TempDir()
	if err := lab.setup(ctx, root, metadata, ip); err != nil {
		t.Fatalf("pool node setup: %v", err)
	}
	if retired, err := lab.controller.RetireIdle(ctx, "ts-gru-4"); err != nil || !retired {
		t.Fatalf("retire idle pool node = %v, %v", retired, err)
	}
	if err := lab.setup(ctx, root, metadata, ip); err != nil {
		t.Fatalf("pool node setup again: %v", err)
	}
	statuses, err := lab.controller.ListHosts(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(statuses, func(status host.HostStatus) bool {
		return status.Registration.Node == "ts-gru-4" && status.Retired
	}) {
		t.Fatal("the same pool node enrolling again lost its retire mark")
	}
}

// A pool node copies its leader's image, shape, network and enrollment bundle,
// and never the leader's controller slot. A missing piece makes no recipe.
func TestPoolRecipeCopiesTheLeaderButNotItsSlot(t *testing.T) {
	ocpus, memory := float32(2), float32(12)
	leader := core.Instance{CompartmentId: new("ocid1.compartment.a"),
		SourceDetails: core.InstanceSourceViaImageDetails{ImageId: new("ocid1.image.a")},
		ShapeConfig:   &core.InstanceShapeConfig{Ocpus: &ocpus, MemoryInGBs: &memory},
		Metadata: map[string]string{"ssh_authorized_keys": "ssh-ed25519 AAAA", hostboot.EnrollmentMetadataKey: "bundle",
			"terrascale-bootstrap": "controller slot"}}
	vnic := core.Vnic{SubnetId: new("ocid1.subnet.a"), NsgIds: []string{"ocid1.nsg.a"}}
	recipe, err := poolRecipe("gru", leader, vnic, []string{"AD-1", "AD-2", "AD-3"})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"ssh_authorized_keys": "ssh-ed25519 AAAA", hostboot.EnrollmentMetadataKey: "bundle",
		hostboot.NodePoolMetadataKey: `{"schemaVersion":1}`}
	if !maps.Equal(recipe.Metadata, want) || recipe.ImageID != "ocid1.image.a" ||
		recipe.SubnetID != "ocid1.subnet.a" || !slices.Equal(recipe.NSGIDs, []string{"ocid1.nsg.a"}) ||
		!slices.Equal(recipe.AvailabilityDomains, []string{"AD-1", "AD-2", "AD-3"}) || recipe.OCPUs != 2 || recipe.MemoryGB != 12 {
		t.Fatalf("recipe = %+v", recipe)
	}
	leader.Metadata = map[string]string{"ssh_authorized_keys": "ssh-ed25519 AAAA"}
	if _, err := poolRecipe("gru", leader, vnic, []string{"AD-1"}); err == nil {
		t.Fatal("a leader without its enrollment bundle made a pool recipe")
	}
}
