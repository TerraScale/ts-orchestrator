package containermaterial

import (
	"errors"
	"strings"
	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/cellspec"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/host"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
	"github.com/moby/swarmkit/v2/api"
)

// These checks isolate recipient selection; they do not manufacture a trusted
// manager proof or qualify release, upstream assignment or live OCI admission.
func TestTaskRecipientRequiresRoleSpecificAuthority(t *testing.T) {
	hostID := entityid.Derive("container-recipient", "worker")
	registration := host.Registration{ID: hostID, Cell: "gru", Node: "worker", Environment: "production", Roles: []string{"ts-auth"},
		ManagedOCI: &host.ManagedOCIBinding{InstanceID: "ocid1.instance.oc1.sa-saopaulo-1.worker", Region: "sa-saopaulo-1"}}
	binding := host.ContainerMaterialBinding{HostID: hostID, InstanceID: registration.ManagedOCI.InstanceID, Region: registration.ManagedOCI.Region}
	node := &api.Node{Role: api.NodeRoleWorker, Spec: api.NodeSpec{Annotations: api.Annotations{Labels: map[string]string{swarmruntime.LabelHostRole: "container"}}}}
	if err := verifyTaskRecipient(Profile{}, registration, binding, node, nil); err != nil {
		t.Fatalf("exact managed worker recipient: %v", err)
	}
	for _, name := range []string{"missing OCI identity", "other instance", "other region", "other host", "manager proof on worker"} {
		t.Run(name, func(t *testing.T) {
			candidate := registration
			candidate.ManagedOCI = new(*registration.ManagedOCI)
			var controller *bootstrapstart.ControllerHostRecipient
			switch name {
			case "missing OCI identity":
				candidate.ManagedOCI = nil
			case "other instance":
				candidate.ManagedOCI.InstanceID += "-replacement"
			case "other region":
				candidate.ManagedOCI.Region = "us-ashburn-1"
			case "other host":
				candidate.ID = entityid.Derive("container-recipient", "other")
			case "manager proof on worker":
				controller = new(bootstrapstart.ControllerHostRecipient)
			}
			if err := verifyTaskRecipient(Profile{}, candidate, binding, node, controller); !errors.Is(err, ErrPending) {
				t.Fatalf("substituted worker authority admitted: %v", err)
			}
		})
	}
	registration.Node, registration.ManagedOCI = "manager", nil
	binding.HostID = "controller-b"
	node.Role = api.NodeRoleManager
	node.Spec.Annotations.Labels[swarmruntime.LabelHostRole] = "manager"
	profile := Profile{role: "ts-auth", specSHA256: "exact-signed-profile", hosts: []cellspec.HostGrant{{Node: registration.Node, Environment: registration.Environment,
		Controller: binding.HostID, Roles: []string{"ts-auth"}}}}
	for _, controller := range []*bootstrapstart.ControllerHostRecipient{nil, new(bootstrapstart.ControllerHostRecipient)} {
		if err := verifyTaskRecipient(profile, registration, binding, node, controller); !errors.Is(err, ErrPending) {
			t.Fatalf("signed manager slot without opaque current authority admitted: %v", err)
		}
	}
}

func TestTaskAssignmentRejectsChangesDuringVerification(t *testing.T) {
	runtime, err := swarmruntime.ContainerRuntime(&api.ContainerSpec{Image: "registry.example/auth@sha256:" + strings.Repeat("a", 64), User: "65532:65532"})
	if err != nil {
		t.Fatal(err)
	}
	task := &api.Task{ID: "task1", ServiceID: "service1", NodeID: "node1", DesiredState: api.TaskStateRunning,
		Status: api.TaskStatus{State: api.TaskStateRunning}, Spec: api.TaskSpec{Runtime: runtime,
			Resources: &api.ResourceRequirements{Limits: &api.Resources{NanoCPUs: 1_000_000_000, MemoryBytes: 32 << 20}}}}
	fingerprint, err := swarmruntime.ContainerTaskFingerprint(task)
	if err != nil {
		t.Fatal(err)
	}
	binding := host.ContainerMaterialBinding{TaskID: task.ID, ServiceID: task.ServiceID, NodeID: task.NodeID, Fingerprint: fingerprint}
	if err := verifyTaskAssignment(task, binding); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"reassigned", "shutdown", "failed", "resource drift", "removed"} {
		t.Run(name, func(t *testing.T) {
			current := task.Copy()
			switch name {
			case "reassigned":
				current.NodeID = "replacement"
			case "shutdown":
				current.DesiredState = api.TaskStateShutdown
			case "failed":
				current.Status.State = api.TaskStateFailed
			case "resource drift":
				current.Spec.Resources.Limits.MemoryBytes *= 2
			case "removed":
				current = nil
			}
			if err := verifyTaskAssignment(current, binding); !errors.Is(err, ErrPending) {
				t.Fatalf("changed assignment admitted: %v", err)
			}
		})
	}
}

func TestTaskNodeRejectsChangesDuringVerification(t *testing.T) {
	binding := host.ContainerMaterialBinding{NodeID: "node1", HostID: "controller-b", InstanceID: "ocid1.instance.oc1.sa-saopaulo-1.manager", Region: "sa-saopaulo-1"}
	node := &api.Node{ID: binding.NodeID, Role: api.NodeRoleManager, Certificate: api.Certificate{Role: api.NodeRoleManager},
		Spec: api.NodeSpec{Membership: api.NodeMembershipAccepted, Availability: api.NodeAvailabilityActive, DesiredRole: api.NodeRoleManager,
			Annotations: api.Annotations{Name: binding.HostID, Labels: map[string]string{swarmruntime.LabelInstanceID: binding.InstanceID,
				swarmruntime.LabelRegion: binding.Region, swarmruntime.LabelExecutionScope: "platform"}}},
		Status: api.NodeStatus{State: api.NodeStatus_READY}, Description: &api.NodeDescription{Platform: &api.Platform{OS: "linux", Architecture: "arm64"}}}
	if err := verifyTaskNode(node, binding, "arm64"); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"drained", "down", "revoked", "certificate role changed", "platform changed"} {
		t.Run(name, func(t *testing.T) {
			current := node.Copy()
			switch name {
			case "drained":
				current.Spec.Availability = api.NodeAvailabilityDrain
			case "down":
				current.Status.State = api.NodeStatus_DOWN
			case "revoked":
				current.Spec.Membership = api.NodeMembershipPending
			case "certificate role changed":
				current.Certificate.Role = api.NodeRoleWorker
			case "platform changed":
				current.Description.Platform.Architecture = "amd64"
			}
			if err := verifyTaskNode(current, binding, "arm64"); !errors.Is(err, ErrPending) {
				t.Fatalf("changed node admission accepted: %v", err)
			}
		})
	}
}
