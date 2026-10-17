package swarmruntime

import (
	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/host"
	"github.com/TerraScale/ts-orchestrator/internal/hostboot"
	"github.com/TerraScale/ts-orchestrator/internal/hostenroll"
	"github.com/moby/swarmkit/v2/api"
)

func TestManagerHostRecipientRequiresExactNativeTarget(t *testing.T) {
	b := host.ManagerRuntimeBinding{NodeID: "native-target", InstanceID: "ocid1.instance.target", OCIRegion: "sa-saopaulo-1"}
	native := &api.Node{ID: b.NodeID, Role: api.NodeRoleManager,
		Spec: api.NodeSpec{DesiredRole: api.NodeRoleManager, Membership: api.NodeMembershipAccepted,
			Annotations: api.Annotations{Name: "controller-b", Labels: map[string]string{
				LabelInstanceID: b.InstanceID, LabelRegion: b.OCIRegion, LabelHostRole: "manager", LabelExecutionScope: "platform",
			}}}, Status: api.NodeStatus{State: api.NodeStatus_READY}}
	native.Certificate.CN, native.Certificate.Role, native.Certificate.Certificate = b.NodeID, api.NodeRoleManager, []byte("original certificate")
	if err := verifyManagerHostNative(native, b, "controller-b", native.Certificate.Certificate); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*api.Node){
		"other target":       func(n *api.Node) { n.ID = "another-native-node" },
		"other slot":         func(n *api.Node) { n.Spec.Annotations.Name = "controller-a" },
		"other instance":     func(n *api.Node) { n.Spec.Annotations.Labels[LabelInstanceID] = "ocid1.instance.other" },
		"other region":       func(n *api.Node) { n.Spec.Annotations.Labels[LabelRegion] = "us-sanjose-1" },
		"worker role":        func(n *api.Node) { n.Role = api.NodeRoleWorker },
		"pending demotion":   func(n *api.Node) { n.Spec.DesiredRole = api.NodeRoleWorker },
		"unaccepted member":  func(n *api.Node) { n.Spec.Membership = api.NodeMembershipPending },
		"not ready":          func(n *api.Node) { n.Status.State = api.NodeStatus_DOWN },
		"worker certificate": func(n *api.Node) { n.Certificate.Role = api.NodeRoleWorker },
		"other certificate":  func(n *api.Node) { n.Certificate.Certificate = []byte("successor certificate") },
		"other cert subject": func(n *api.Node) { n.Certificate.CN = "another-native-node" },
		"tenant scope":       func(n *api.Node) { n.Spec.Annotations.Labels[LabelExecutionScope] = "tenant" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := native.Copy()
			change(changed)
			if verifyManagerHostNative(changed, b, "controller-b", native.Certificate.Certificate) == nil {
				t.Fatal("accepted a different or unready native target")
			}
		})
	}
}

func TestManagerHostRecipientRequiresOriginalCompletedEnrollment(t *testing.T) {
	query := WorkerRegistrationQuery{Request: []byte("original signed request"), Response: []byte("original signed response")}
	request := hostenroll.Request{InstanceID: "ocid1.instance.target", IdentityPublicKey: "host-public", NATSUserPublicKey: "nats-public"}
	descriptor := hostboot.Static("gru", "GRU", "ts-gru-1")
	response := hostenroll.Response{Roles: []string{"api"}, RegistrationReceipt: host.Receipt{Generation: 3, Revision: 7}}
	snapshot := WorkerRegistrationSnapshot{InstanceID: request.InstanceID, RequestSHA256: hostenroll.RequestSHA256(query.Request), Sequence: 7,
		Registration: host.Registration{Cell: "gru", Node: "ts-gru-1", Environment: "production", PublicKey: request.IdentityPublicKey,
			NATSUserPublicKey: request.NATSUserPublicKey, Generation: 3, Roles: []string{"api"}}}
	if err := verifyManagerHostEnrollment(query, snapshot, request, descriptor, response, "production"); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*WorkerRegistrationSnapshot){
		"pending":              func(s *WorkerRegistrationSnapshot) { s.Pending = true },
		"retired":              func(s *WorkerRegistrationSnapshot) { s.Retired = true },
		"disabled":             func(s *WorkerRegistrationSnapshot) { s.Disabled = true },
		"terminal":             func(s *WorkerRegistrationSnapshot) { s.TerminalOperationID = "operation" },
		"identity reset":       func(s *WorkerRegistrationSnapshot) { s.IdentityResetOperationID = "operation" },
		"other instance":       func(s *WorkerRegistrationSnapshot) { s.InstanceID = "ocid1.instance.other" },
		"successor request":    func(s *WorkerRegistrationSnapshot) { s.RequestSHA256 = hostenroll.RequestSHA256([]byte("renewal")) },
		"successor revision":   func(s *WorkerRegistrationSnapshot) { s.Sequence++ },
		"successor generation": func(s *WorkerRegistrationSnapshot) { s.Registration.Generation++ },
		"other host key":       func(s *WorkerRegistrationSnapshot) { s.Registration.PublicKey = "another-public" },
		"other nats key":       func(s *WorkerRegistrationSnapshot) { s.Registration.NATSUserPublicKey = "another-public" },
		"other node":           func(s *WorkerRegistrationSnapshot) { s.Registration.Node = "ts-gru-2" },
		"other roles":          func(s *WorkerRegistrationSnapshot) { s.Registration.Roles = []string{"auth"} },
	} {
		t.Run(name, func(t *testing.T) {
			changed := snapshot
			change(&changed)
			if verifyManagerHostEnrollment(query, changed, request, descriptor, response, "production") == nil {
				t.Fatal("accepted incomplete, revoked or changed enrollment")
			}
		})
	}
}
