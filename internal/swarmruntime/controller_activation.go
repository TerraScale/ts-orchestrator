//go:build linux

package swarmruntime

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/gogo/protobuf/types"
	"github.com/moby/swarmkit/v2/api"
	"github.com/moby/swarmkit/v2/manager"
)

const (
	labelEpoch              = "terrascale.controller-admission-epoch"
	labelOperation          = "terrascale.controller-admission-operation"
	labelAvailabilityDomain = "terrascale.controller-availability-domain"
	labelFaultDomain        = "terrascale.controller-fault-domain"
)

// Activate makes one observation-based decision. A conflict or uncertain
// proposal requires a new observation; this operation never retries a CAS.
func (admitted *controllerActivationAdmission) activate(ctx context.Context, nodeID string, expectedVersion uint64) (*api.Node, error) {
	if err := admitted.guard(ctx); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithDeadline(ctx, admitted.deadline)
	stop := context.AfterFunc(admitted.original, cancel)
	defer cancel()
	defer stop()
	nodes := admitted.local.nodesSnapshot()
	tasks := admitted.local.tasksSnapshot()
	index := slices.IndexFunc(nodes, func(node *api.Node) bool { return node.ID == nodeID })
	if index < 0 || nodes[index].Meta.Version.Index != expectedVersion {
		return nil, ErrControllerActivationPending
	}
	candidate := nodes[index]
	cluster, err := admitted.local.clusterIdentity(ctx)
	if err != nil {
		return nil, err
	}
	if err := verifyNode(candidate, admitted.recipient, cluster); err != nil {
		return nil, err
	}
	if candidate.Spec.Availability == api.NodeAvailabilityDrain {
		return nil, ErrControllerActivationPending
	}
	conflicts, err := admitted.conflictingOwners(ctx, nodes, candidate, tasks, cluster)
	if err != nil {
		return nil, err
	}
	// The original source must prove execution history even when a task has
	// disappeared or a previous manager row was already removed.
	if err := admitted.executionLineage(ctx, candidate, conflicts, tasks); err != nil {
		return nil, err
	}
	epoch := strconv.FormatUint(admitted.origin.LeaseEpoch(), 10)
	hash := sha256.Sum256([]byte(fmt.Sprintf("%s/%s/%s/%d/%s", admitted.origin.BindingSHA256(), admitted.origin.Identity().RuntimeCandidateID, nodeID, expectedVersion, epoch)))
	operation := hex.EncodeToString(hash[:])
	// Every observed manager gets a fresh version barrier on lease takeover,
	// so a delayed prior-owner ACTIVE proposal cannot reuse its old version.
	for index, current := range nodes {
		if current.Role != api.NodeRoleManager && current.Spec.DesiredRole != api.NodeRoleManager {
			continue
		}
		if current.Spec.Annotations.Labels[labelEpoch] == epoch && current.ID != candidate.ID {
			continue
		}
		spec := current.Spec.Copy()
		spec.Annotations.Labels = maps.Clone(spec.Annotations.Labels)
		if spec.Annotations.Labels == nil {
			spec.Annotations.Labels = map[string]string{}
		}
		spec.Annotations.Labels[labelEpoch] = epoch
		if current.ID == candidate.ID {
			spec.Availability = api.NodeAvailabilityPause
			spec.Annotations.Labels[labelOperation] = operation
		}
		if err := admitted.guard(ctx); err != nil {
			return nil, err
		}
		updated, err := admitted.local.update(ctx, current, spec, protectedNodes(nodes, conflicts), nil, nil, admitted.retirements)
		if err != nil {
			return nil, err
		}
		nodes[index] = updated
		if current.ID == candidate.ID {
			candidate = updated
		}
	}
	var stopped []*api.Task
	for _, conflict := range conflicts {
		index := slices.IndexFunc(nodes, func(node *api.Node) bool { return node.ID == conflict.ID })
		current := nodes[index]
		if current.Spec.Availability != api.NodeAvailabilityDrain {
			spec := current.Spec.Copy()
			spec.Availability = api.NodeAvailabilityDrain
			if err := admitted.guard(ctx); err != nil {
				return nil, err
			}
			updated, err := admitted.local.update(ctx, current, spec, protectedNodes(nodes, conflicts), nil, nil, admitted.retirements)
			if err != nil {
				return nil, err
			}
			nodes[index] = updated
		}
		captured := ownerTasks(tasks, conflict.ID)
		if len(captured) == 0 || !allStopped(captured) {
			retired, err := admitted.verifyTerminatedOwner(ctx, conflict, cluster)
			if err != nil {
				return nil, ErrControllerActivationPending
			}
			admitted.retirements = append(admitted.retirements, retired)
			if retired.ExpiresAt().Before(admitted.deadline) {
				admitted.deadline = retired.ExpiresAt()
			}
			bounded, release := context.WithDeadline(ctx, retired.ExpiresAt())
			defer release()
			ctx = bounded
		}
		stopped = append(stopped, captured...)
	}
	if err := admitted.guard(ctx); err != nil {
		return nil, err
	}
	// Repeat other-manager source verification immediately before the only
	// ACTIVE mutation, retaining the captured task IDs in the native CAS.
	if _, err := admitted.conflictingOwners(ctx, nodes, candidate, tasks, cluster); err != nil {
		return nil, err
	}
	spec := candidate.Spec.Copy()
	spec.Availability = api.NodeAvailabilityActive
	spec.Annotations.Labels[labelAvailabilityDomain] = admitted.recipient.FailureDomain().AvailabilityDomain
	spec.Annotations.Labels[labelFaultDomain] = admitted.recipient.FailureDomain().FaultDomain
	owners := make([]string, len(conflicts))
	for index, owner := range conflicts {
		owners[index] = owner.ID
	}
	if err := admitted.guard(ctx); err != nil {
		return nil, err
	}
	updated, err := admitted.local.update(ctx, candidate, spec, protectedNodes(nodes, conflicts), stopped, owners, admitted.retirements)
	if err != nil {
		return nil, err
	}
	if err := admitted.guard(ctx); err != nil {
		return nil, fmt.Errorf("%w: %w", manager.ErrMutationAmbiguous, err)
	}
	return updated, nil
}

func protectedNodes(nodes, conflicts []*api.Node) []*api.Node {
	return slices.DeleteFunc(slices.Clone(nodes), func(node *api.Node) bool {
		return node.Role != api.NodeRoleManager && node.Spec.DesiredRole != api.NodeRoleManager &&
			!slices.ContainsFunc(conflicts, func(conflict *api.Node) bool { return conflict.ID == node.ID })
	})
}

func ownerTasks(tasks []*api.Task, nodeID string) []*api.Task {
	return slices.DeleteFunc(slices.Clone(tasks), func(task *api.Task) bool { return task.NodeID != nodeID })
}

func allStopped(tasks []*api.Task) bool {
	return len(tasks) > 0 && !slices.ContainsFunc(tasks, func(task *api.Task) bool {
		if task == nil || task.Status.State != api.TaskStateShutdown && task.Status.State != api.TaskStateCompleted {
			return true
		}
		stoppedAt, err := types.TimestampFromProto(task.Status.Timestamp)
		return err != nil || stoppedAt.IsZero() || stoppedAt.After(time.Now().Add(2*time.Second))
	})
}

func verifyNode(node *api.Node, proof *bootstrapstart.ControllerHostRecipient, cluster *manager.ClusterIdentity) error {
	if node == nil || proof == nil || cluster == nil || node.Role != api.NodeRoleManager || node.Spec.DesiredRole != api.NodeRoleManager ||
		node.Spec.Membership != api.NodeMembershipAccepted || node.Status.State != api.NodeStatus_READY ||
		node.Spec.Annotations.Name != proof.ControllerSlot() || node.Status.Addr != proof.PrivateIP() ||
		node.Spec.Annotations.Labels[LabelInstanceID] != proof.InstanceID() ||
		node.Spec.Annotations.Labels[LabelRegion] != proof.OCIRegion() ||
		node.Spec.Annotations.Labels[LabelHostRole] != "manager" || node.Spec.Annotations.Labels[LabelExecutionScope] != "platform" {
		return ErrControllerActivationPending
	}
	return verifyNodeCertificate(node, cluster)
}

func verifyNodeCertificate(node *api.Node, cluster *manager.ClusterIdentity) error {
	if node == nil || cluster == nil || node.Certificate.CN != node.ID || node.Certificate.Role != api.NodeRoleManager ||
		node.Certificate.Status.State != api.IssuanceStateIssued {
		return ErrControllerActivationPending
	}
	block, _ := pem.Decode(node.Certificate.Certificate)
	if block == nil {
		return ErrControllerActivationPending
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(cluster.RootCACert) || certificate.Subject.CommonName != node.ID ||
		!slices.Equal(certificate.Subject.Organization, []string{cluster.ID}) || !slices.Equal(certificate.Subject.OrganizationalUnit, []string{"swarm-manager"}) {
		return ErrControllerActivationPending
	}
	_, err = certificate.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: time.Now(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
	return err
}

func (admitted *controllerActivationAdmission) verifyTerminatedOwner(ctx context.Context, node *api.Node, cluster *manager.ClusterIdentity) (*bootstrapstart.ManagerRetirement, error) {
	if node == nil || node.Spec.Membership != api.NodeMembershipAccepted ||
		node.Spec.Annotations.Labels[LabelRegion] != admitted.binding.Identity().OCIRegion ||
		node.Spec.Annotations.Labels[LabelHostRole] != "manager" ||
		node.Spec.Annotations.Labels[LabelExecutionScope] != "platform" || verifyNodeCertificate(node, cluster) != nil {
		return nil, ErrControllerActivationPending
	}
	return admitted.recipient.ReadManagerRetirement(ctx, node.Spec.Annotations.Name, node.Spec.Annotations.Labels[LabelInstanceID])
}

func (admitted *controllerActivationAdmission) conflictingOwners(ctx context.Context, nodes []*api.Node, candidate *api.Node, tasks []*api.Task, cluster *manager.ClusterIdentity) ([]*api.Node, error) {
	var conflicts []*api.Node
	seen := map[string]bool{admitted.recipient.ControllerSlot(): true}
	for _, node := range nodes {
		if node.ID == candidate.ID {
			continue
		}
		if node.Role != api.NodeRoleManager && node.Spec.DesiredRole != api.NodeRoleManager &&
			!slices.ContainsFunc(ownerTasks(tasks, node.ID), func(task *api.Task) bool { return task.ServiceAnnotations.Labels[LabelRole] == "ts-auth" }) {
			continue
		}
		slot := node.Spec.Annotations.Name
		proof, err := admitted.recipient.ReadSlotRecipient(ctx, slot, node.Spec.Annotations.Labels[LabelInstanceID])
		if err != nil || seen[slot] || verifyNode(node, proof, cluster) != nil || admitted.domains[slot] != proof.FailureDomain() {
			conflicts = append(conflicts, node)
			continue
		}
		seen[slot] = true
	}
	// A task whose owner row disappeared still represents unknown execution.
	for _, task := range tasks {
		if task.NodeID != "" && task.ServiceAnnotations.Labels[LabelRole] == "ts-auth" &&
			!slices.ContainsFunc(nodes, func(node *api.Node) bool { return node.ID == task.NodeID }) {
			return nil, ErrControllerActivationPending
		}
	}
	return conflicts, nil
}
