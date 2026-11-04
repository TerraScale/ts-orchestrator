package containermaterial

import (
	"errors"
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
	if err := verifyAllocationRecipient(Profile{}, registration, binding, node, "arm64", nil, swarmruntime.VerifiedWorkerMembership{}); !errors.Is(err, ErrPending) {
		t.Fatal("worker allocation accepted without independently verified membership")
	}
	for _, name := range []string{
		"other instance",
	} {
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
	for _, controller := range []*bootstrapstart.ControllerHostRecipient{
		new(bootstrapstart.ControllerHostRecipient),
	} {
		if err := verifyTaskRecipient(profile, registration, binding, node, controller); !errors.Is(err, ErrPending) {
			t.Fatalf("signed manager slot without opaque current authority admitted: %v", err)
		}
	}
}
