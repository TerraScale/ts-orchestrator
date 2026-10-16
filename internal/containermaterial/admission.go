// Package containermaterial authenticates a root-owned container profile and
// the actual upstream task before any task-bound secret or no-secret delivery.
package containermaterial

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"maps"
	"slices"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/cellspec"
	"github.com/TerraScale/ts-orchestrator/internal/delivery"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/host"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/TerraScale/ts-orchestrator/internal/vaultsecret"
	"github.com/gogo/protobuf/proto"
	"github.com/moby/swarmkit/v2/api"
	"github.com/moby/swarmkit/v2/ca"
)

var ErrPending = errors.New("container material authority is pending")

// Profile's zero value grants nothing. A signed no-secret profile is checked
// through the same path as a profile with exact OCI Vault references.
type Profile struct {
	profile     cellspec.Profile
	identity    cellspec.Identity
	role        string
	fingerprint string
	specSHA256  string
	hosts       []cellspec.HostGrant
	intent      delivery.Intent
}

func (proof Profile) Profile() cellspec.Profile {
	profile := proof.profile
	profile.Args = slices.Clone(profile.Args)
	profile.Env = maps.Clone(profile.Env)
	profile.Secrets = maps.Clone(profile.Secrets)
	return profile
}

func (proof Profile) NoSecrets() bool {
	return proof.fingerprint != "" && len(proof.profile.Secrets) == 0
}

func (proof Profile) Intent() delivery.Intent     { return proof.intent.Clone() }
func (proof Profile) Identity() cellspec.Identity { return proof.identity }

// VerifyProfile verifies already adopted root-owned profile authority. Accepted
// cell specs remain in force after their submission envelope expires.
func VerifyProfile(wire []byte, roots trust.Keyring, identity cellspec.Identity, intent delivery.Intent) (Profile, error) {
	if intent.Validate() != nil || intent.Container == nil || identity.Cell != intent.Cell || identity.Environment != intent.Environment {
		return Profile{}, ErrPending
	}
	signed, err := cellspec.VerifyHistorical(wire, roots, identity)
	if err != nil {
		return Profile{}, err
	}
	if !signed.RootSigned {
		return Profile{}, ErrPending
	}
	for _, service := range signed.Services {
		if service.Role != intent.Role {
			continue
		}
		profile := service.Profile
		if intent.ConfigDigest != delivery.ConfigDigestOf(profile.Args, profile.Env, profile.Secrets) ||
			vaultsecret.ValidateRefs(intent.Cell, intent.Role, profile.Secrets, profile.Env) != nil {
			return Profile{}, ErrPending
		}
		fingerprint, err := intent.Fingerprint()
		if err != nil {
			return Profile{}, err
		}
		specSHA256 := sha256.Sum256(wire)
		proof := Profile{profile: profile, identity: identity, role: intent.Role, fingerprint: fingerprint, specSHA256: hex.EncodeToString(specSHA256[:]), hosts: slices.Clone(signed.HostGrants), intent: intent.Clone()}
		proof.profile = proof.Profile()
		return proof, nil
	}
	return Profile{}, ErrPending
}

// VerifyTask authenticates the complete signed profile, OCI release and current
// upstream assignment. Registration must come from the existing ownhost session.
// Managers additionally require current requested-controller authority.
func VerifyTask(ctx context.Context, client api.ControlClient, task *api.Task, expected swarmruntime.ServiceIntent,
	verified release.VerifiedContainer, roots trust.Keyring, proof Profile, registration host.Registration, binding host.ContainerMaterialBinding,
	controller *bootstrapstart.ControllerHostRecipient,
) error {
	if client == nil || verifyExpected(proof, expected, verified) != nil || registration.Cell != proof.identity.Cell || registration.Environment != proof.identity.Environment ||
		binding.Region != expected.Region || !slices.Contains(registration.Roles, proof.role) {
		return ErrPending
	}
	if err := verifyTaskAssignment(task, binding); err != nil {
		return err
	}
	node, err := client.GetNode(ctx, &api.GetNodeRequest{NodeID: binding.NodeID})
	if err != nil {
		return err
	}
	if node == nil || verifyTaskNode(node.Node, binding, expected.Architecture) != nil {
		return ErrPending
	}
	if err := verifyTaskRecipient(proof, registration, binding, node.Node, controller); err != nil {
		return err
	}
	if controller != nil {
		if err := controller.VerifyRegistration(ctx, registration); err != nil {
			return err
		}
	}
	return VerifyCurrentTask(ctx, client, task, expected, verified, roots, proof, registration, binding, controller)
}

// VerifyCurrentTask repeats final assignment, certificate and finite authority
// checks without observing OCI again. Registry pulls may retain PreviousSpec;
// material callers must additionally require the current service revision.
func VerifyCurrentTask(ctx context.Context, client api.ControlClient, task *api.Task, expected swarmruntime.ServiceIntent,
	verified release.VerifiedContainer, roots trust.Keyring, proof Profile, registration host.Registration, binding host.ContainerMaterialBinding,
	controller *bootstrapstart.ControllerHostRecipient,
) error {
	if err := verifyCurrentAuthority(ctx, client, task, expected, verified, roots, proof, registration, binding); err != nil {
		return err
	}
	return verifyCurrentRecipient(ctx, client, task, expected, verified, proof, registration, binding, controller)
}

// VerifyCurrentMaterialTask additionally requires the current service revision
// before the final task and node reads. It never repeats OCI verification.
func VerifyCurrentMaterialTask(ctx context.Context, client api.ControlClient, task *api.Task, expected swarmruntime.ServiceIntent,
	verified release.VerifiedContainer, roots trust.Keyring, proof Profile, registration host.Registration, binding host.ContainerMaterialBinding,
	controller *bootstrapstart.ControllerHostRecipient,
) error {
	if err := verifyCurrentAuthority(ctx, client, task, expected, verified, roots, proof, registration, binding); err != nil {
		return err
	}
	service, err := client.GetService(ctx, &api.GetServiceRequest{ServiceID: binding.ServiceID})
	if err != nil {
		return err
	}
	if service == nil || service.Service == nil || service.Service.ID != binding.ServiceID || service.Service.PendingDelete ||
		!proto.Equal(&service.Service.Spec.Task, &task.Spec) || !proto.Equal(&service.Service.Spec.Annotations, &task.ServiceAnnotations) {
		return ErrPending
	}
	return verifyCurrentRecipient(ctx, client, task, expected, verified, proof, registration, binding, controller)
}

func verifyCurrentAuthority(ctx context.Context, client api.ControlClient, task *api.Task, expected swarmruntime.ServiceIntent,
	verified release.VerifiedContainer, roots trust.Keyring, proof Profile, registration host.Registration, binding host.ContainerMaterialBinding,
) error {
	if client == nil || verifyExpected(proof, expected, verified) != nil || registration.Cell != proof.identity.Cell || registration.Environment != proof.identity.Environment ||
		binding.Region != expected.Region || !slices.Contains(registration.Roles, proof.role) {
		return ErrPending
	}
	if err := verifyTaskAssignment(task, binding); err != nil {
		return err
	}
	return swarmruntime.VerifyRegistryTask(ctx, client, task, expected, verified, roots)
}

func verifyCurrentRecipient(ctx context.Context, client api.ControlClient, task *api.Task, expected swarmruntime.ServiceIntent,
	verified release.VerifiedContainer, proof Profile, registration host.Registration, binding host.ContainerMaterialBinding,
	controller *bootstrapstart.ControllerHostRecipient,
) error {
	// Source reads can outlast an assignment or node admission change.
	currentTask, err := client.GetTask(ctx, &api.GetTaskRequest{TaskID: binding.TaskID})
	if err != nil {
		return err
	}
	if currentTask == nil || verifyTaskAssignment(currentTask.Task, binding) != nil ||
		!proto.Equal(&currentTask.Task.Spec, &task.Spec) || !proto.Equal(&currentTask.Task.ServiceAnnotations, &task.ServiceAnnotations) {
		return ErrPending
	}
	currentNode, err := client.GetNode(ctx, &api.GetNodeRequest{NodeID: binding.NodeID})
	if err != nil {
		return err
	}
	if currentNode == nil || verifyTaskNode(currentNode.Node, binding, expected.Architecture) != nil {
		return ErrPending
	}
	if err := verifyTaskRecipient(proof, registration, binding, currentNode.Node, controller); err != nil {
		return err
	}
	now := time.Now().UTC()
	if !verified.Valid(now) || controller != nil && !controller.Valid(now) {
		return ErrPending
	}
	return ctx.Err()
}

func verifyTaskAssignment(task *api.Task, binding host.ContainerMaterialBinding) error {
	if task == nil || task.ID != binding.TaskID || task.ServiceID != binding.ServiceID || task.NodeID != binding.NodeID ||
		task.DesiredState != api.TaskStateRunning || task.Status.State < api.TaskStateAssigned || task.Status.State > api.TaskStateRunning {
		return ErrPending
	}
	fingerprint, err := swarmruntime.ContainerTaskFingerprint(task)
	if err != nil || fingerprint != binding.Fingerprint {
		return ErrPending
	}
	return nil
}

func verifyTaskNode(node *api.Node, binding host.ContainerMaterialBinding, architecture string) error {
	if node == nil || node.ID != binding.NodeID || node.Spec.Membership != api.NodeMembershipAccepted || node.Status.State != api.NodeStatus_READY ||
		node.Spec.Availability != api.NodeAvailabilityActive || node.Spec.Annotations.Name != binding.HostID ||
		node.Spec.Annotations.Labels[swarmruntime.LabelInstanceID] != binding.InstanceID ||
		node.Spec.Annotations.Labels[swarmruntime.LabelRegion] != binding.Region ||
		node.Spec.Annotations.Labels[swarmruntime.LabelExecutionScope] != "platform" ||
		node.Role != node.Certificate.Role || node.Role != node.Spec.DesiredRole || node.Certificate.CN != node.ID || node.Certificate.Status.State != api.IssuanceStateIssued ||
		node.Description == nil || node.Description.Platform == nil ||
		node.Description.Platform.OS != "linux" || node.Description.Platform.Architecture != architecture {
		return ErrPending
	}
	role := ca.WorkerRole
	if node.Role == api.NodeRoleManager {
		role = ca.ManagerRole
	} else if node.Role != api.NodeRoleWorker {
		return ErrPending
	}
	block, _ := pem.Decode(node.Certificate.Certificate)
	if block == nil || block.Type != "CERTIFICATE" {
		return ErrPending
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	now := time.Now().UTC()
	if err != nil || certificate.Subject.CommonName != node.ID || !slices.Equal(certificate.Subject.OrganizationalUnit, []string{role}) ||
		now.Before(certificate.NotBefore) || !now.Before(certificate.NotAfter) {
		return ErrPending
	}
	return nil
}

func verifyTaskRecipient(proof Profile, registration host.Registration, binding host.ContainerMaterialBinding,
	node *api.Node, controller *bootstrapstart.ControllerHostRecipient,
) error {
	if node.Role == api.NodeRoleWorker {
		if controller != nil || registration.ManagedOCI == nil || registration.ManagedOCI.InstanceID != binding.InstanceID || registration.ManagedOCI.Region != binding.Region ||
			binding.HostID != registration.ID || !entityid.Valid(registration.ID) || node.Spec.Annotations.Labels[swarmruntime.LabelHostRole] != "container" {
			return ErrPending
		}
	} else if node.Role == api.NodeRoleManager {
		if controller == nil || registration.ManagedOCI != nil || proof.specSHA256 == "" || controller.SpecSHA256() != proof.specSHA256 ||
			controller.ControllerSlot() != binding.HostID || controller.Node() != registration.Node || controller.Environment() != registration.Environment ||
			controller.InstanceID() != binding.InstanceID || controller.OCIRegion() != binding.Region || node.Status.Addr != controller.PrivateIP() {
			return ErrPending
		}
		matched := false
		for _, grant := range proof.hosts {
			if grant.Node == registration.Node && grant.Environment == registration.Environment && grant.Controller == binding.HostID &&
				grant.Controller != "" && slices.Contains(grant.Roles, proof.role) {
				matched = true
			}
		}
		if !matched || node.Spec.Annotations.Labels[swarmruntime.LabelHostRole] != "manager" {
			return ErrPending
		}
	} else {
		return ErrPending
	}
	return nil
}

func verifyExpected(proof Profile, expected swarmruntime.ServiceIntent, verified release.VerifiedContainer) error {
	region, known := catalog.LookupName(proof.identity.Cell)
	claim := verified.Claim()
	profile := proof.profile
	if proof.fingerprint == "" || !known || !verified.Valid(time.Now().UTC()) || expected.Container == nil ||
		expected.ID != entityid.Derive("platform-service", proof.role, proof.identity.Environment, region.OCIRegion) ||
		expected.Role != proof.role || expected.Environment != proof.identity.Environment || expected.Region != region.OCIRegion ||
		claim.Cell != region.Cell || claim.Role != proof.role || claim.Environment != proof.identity.Environment || claim.Architecture != expected.Architecture ||
		expected.Container.Image != claim.Image || expected.Container.User != "65532:65532" || len(expected.Container.Command) != 0 ||
		!slices.Equal(expected.Container.Args, profile.Args) || expected.Container.Dir != "" || expected.Resources == nil {
		return ErrPending
	}
	mapped, err := ServiceIntent(proof, expected.Architecture)
	if err != nil || !proto.Equal(expected.Container, mapped.Container) || !proto.Equal(expected.Resources, mapped.Resources) ||
		expected.OperationID != mapped.OperationID || len(expected.Ports) != len(mapped.Ports) {
		return ErrPending
	}
	for i, port := range mapped.Ports {
		if !proto.Equal(expected.Ports[i], port) {
			return ErrPending
		}
	}
	envelope, err := trust.DecodeEnvelope(proof.intent.Container.Claim)
	if err != nil {
		return err
	}
	fingerprint, err := trust.Fingerprint(envelope)
	if err != nil || fingerprint != verified.Fingerprint() {
		return ErrPending
	}
	return nil
}

// ServiceIntent maps the verified root profile and retained container intent;
// VerifyTask still requires current cryptographic release qualification.
func ServiceIntent(proof Profile, architecture string) (swarmruntime.ServiceIntent, error) {
	intent, profile := proof.intent, proof.profile
	region, known := catalog.LookupName(proof.identity.Cell)
	if proof.fingerprint == "" || !known || intent.Container == nil {
		return swarmruntime.ServiceIntent{}, ErrPending
	}
	envelope, err := trust.DecodeEnvelope(intent.Container.Claim)
	if err != nil {
		return swarmruntime.ServiceIntent{}, err
	}
	var claim release.ContainerClaim
	if protocol.DecodeStrict(envelope.Payload, &claim, trust.MaxPayloadBytes) != nil || claim.Validate() != nil ||
		claim.Cell != region.Cell || claim.Environment != intent.Environment || claim.Role != intent.Role || claim.Architecture != architecture {
		return swarmruntime.ServiceIntent{}, ErrPending
	}
	environment := make([]string, 0, len(profile.Env))
	for _, key := range slices.Sorted(maps.Keys(profile.Env)) {
		environment = append(environment, key+"="+profile.Env[key])
	}
	limits := &api.Resources{NanoCPUs: int64(profile.Resources.CPU) * 1_000_000_000, MemoryBytes: profile.Resources.MemoryBytes}
	expected := swarmruntime.ServiceIntent{ID: entityid.Derive("platform-service", intent.Role, intent.Environment, region.OCIRegion), OperationID: intent.OperationID,
		Role: intent.Role, Region: region.OCIRegion, Environment: intent.Environment, Architecture: architecture, Replicas: uint64(intent.DesiredReplicas),
		Container: &api.ContainerSpec{Image: claim.Image, User: "65532:65532", Args: slices.Clone(profile.Args), Env: environment},
		Resources: &api.ResourceRequirements{Limits: limits, Reservations: limits.Copy()}}
	if intent.Role == "ts-auth" {
		expected.Ports = []*api.PortConfig{{Protocol: api.ProtocolTCP, TargetPort: 8080, PublishedPort: 8080, PublishMode: api.PublishModeHost}}
	}
	return expected, nil
}
