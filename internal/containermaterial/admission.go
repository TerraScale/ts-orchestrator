// Package containermaterial authenticates a root-owned container profile and
// the actual upstream task before any task-bound secret or no-secret delivery.
package containermaterial

import (
	"context"
	"errors"
	"maps"
	"slices"
	"time"

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
)

var ErrPending = errors.New("container material authority is pending")

// Profile's zero value grants nothing. A signed no-secret profile is checked
// through the same path as a profile with exact OCI Vault references.
type Profile struct {
	profile     cellspec.Profile
	identity    cellspec.Identity
	role        string
	fingerprint string
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
		proof := Profile{profile: profile, identity: identity, role: intent.Role, fingerprint: fingerprint, hosts: slices.Clone(signed.HostGrants), intent: intent.Clone()}
		proof.profile = proof.Profile()
		return proof, nil
	}
	return Profile{}, ErrPending
}

// VerifyTask authenticates the complete signed profile, OCI release and current
// upstream assignment. Registration must come from the existing ownhost session.
func VerifyTask(ctx context.Context, client api.ControlClient, task *api.Task, expected swarmruntime.ServiceIntent,
	verified release.VerifiedContainer, roots trust.Keyring, proof Profile, registration host.Registration, binding host.ContainerMaterialBinding,
) error {
	if client == nil || verifyExpected(proof, expected, verified) != nil || registration.Cell != proof.identity.Cell || registration.Environment != proof.identity.Environment ||
		registration.ManagedOCI == nil || registration.ManagedOCI.InstanceID != binding.InstanceID || registration.ManagedOCI.Region != binding.Region || binding.Region != expected.Region ||
		task == nil || task.ID != binding.TaskID || task.ServiceID != binding.ServiceID || task.NodeID != binding.NodeID ||
		task.DesiredState != api.TaskStateRunning || task.Status.State > api.TaskStateRunning ||
		!slices.Contains(registration.Roles, proof.role) {
		return ErrPending
	}
	actualFingerprint, err := swarmruntime.ContainerTaskFingerprint(task)
	if err != nil || actualFingerprint != binding.Fingerprint {
		return ErrPending
	}
	node, err := client.GetNode(ctx, &api.GetNodeRequest{NodeID: binding.NodeID})
	if err != nil {
		return err
	}
	if node == nil || node.Node == nil {
		return ErrPending
	}
	n := node.Node
	if n.Spec.Membership != api.NodeMembershipAccepted || n.Status.State != api.NodeStatus_READY ||
		n.Spec.Availability != api.NodeAvailabilityActive || n.Spec.Annotations.Name != binding.HostID ||
		n.Spec.Annotations.Labels[swarmruntime.LabelInstanceID] != binding.InstanceID ||
		n.Spec.Annotations.Labels[swarmruntime.LabelRegion] != binding.Region ||
		n.Spec.Annotations.Labels[swarmruntime.LabelExecutionScope] != "platform" ||
		n.Role != n.Certificate.Role || n.Role != n.Spec.DesiredRole {
		return ErrPending
	}
	if n.Role == api.NodeRoleWorker {
		if binding.HostID != registration.ID || !entityid.Valid(registration.ID) || n.Spec.Annotations.Labels[swarmruntime.LabelHostRole] != "container" {
			return ErrPending
		}
	} else if n.Role == api.NodeRoleManager {
		matched := false
		for _, grant := range proof.hosts {
			if grant.Node == registration.Node && grant.Environment == registration.Environment && grant.Controller == binding.HostID &&
				grant.Controller != "" && slices.Contains(grant.Roles, proof.role) {
				matched = true
			}
		}
		if !matched || n.Spec.Annotations.Labels[swarmruntime.LabelHostRole] != "manager" {
			return ErrPending
		}
	} else {
		return ErrPending
	}
	if err := swarmruntime.VerifyRegistryTask(ctx, client, task, expected, verified, roots); err != nil {
		return err
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
