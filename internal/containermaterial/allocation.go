package containermaterial

import (
	"context"
	"slices"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/host"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/gogo/protobuf/proto"
	"github.com/moby/swarmkit/v2/api"
)

// VerifyTaskAllocation authenticates a nonterminal resource reservation against
// its signed profile and current recipient. It grants no execution or material.
func VerifyTaskAllocation(ctx context.Context, client api.ControlReader, task *api.Task, expected swarmruntime.ServiceIntent,
	verified release.VerifiedContainer, roots trust.Keyring, proof Profile, registration host.Registration, binding host.ContainerMaterialBinding,
	controller *bootstrapstart.ControllerHostRecipient, worker swarmruntime.VerifiedWorkerMembership,
) error {
	ctx, cancel := allocationContext(ctx, verified.ExpiresAt(), controller, worker)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return err
	}
	if now := time.Now().UTC(); !verified.Valid(now) || controller != nil && !controller.Valid(now) || controller == nil && worker.Validate() != nil {
		return ErrPending
	}
	if client == nil || verifyAllocationProfile(task, expected, verified, proof, registration, binding) != nil {
		return ErrPending
	}
	node, err := client.GetNode(ctx, &api.GetNodeRequest{NodeID: binding.NodeID})
	if err != nil {
		return err
	}
	if node == nil || verifyTaskNodeIdentity(node.Node, binding, expected.Architecture) != nil {
		return ErrPending
	}
	if err := verifyAllocationRecipient(proof, registration, binding, node.Node, expected.Architecture, controller, worker); err != nil {
		return err
	}
	if controller != nil {
		if err := controller.VerifyRegistration(ctx, registration); err != nil {
			return err
		}
	}
	return VerifyCurrentTaskAllocation(ctx, client, task, expected, verified, roots, proof, registration, binding, controller, worker)
}

// VerifyCurrentTaskAllocation repeats exact assignment, certificate and finite
// recipient checks without repeating OCI observation or authorizing credentials.
func VerifyCurrentTaskAllocation(ctx context.Context, client api.ControlReader, task *api.Task, expected swarmruntime.ServiceIntent,
	verified release.VerifiedContainer, roots trust.Keyring, proof Profile, registration host.Registration, binding host.ContainerMaterialBinding,
	controller *bootstrapstart.ControllerHostRecipient, worker swarmruntime.VerifiedWorkerMembership,
) error {
	ctx, cancel := allocationContext(ctx, verified.ExpiresAt(), controller, worker)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return err
	}
	if now := time.Now().UTC(); !verified.Valid(now) || controller != nil && !controller.Valid(now) || controller == nil && worker.Validate() != nil {
		return ErrPending
	}
	if err := verifyAllocationAuthority(ctx, client, task, expected, verified, roots, proof, registration, binding); err != nil {
		return err
	}
	currentTask, err := client.GetTask(ctx, &api.GetTaskRequest{TaskID: binding.TaskID})
	if err != nil {
		return err
	}
	if currentTask == nil || verifyAllocatedTask(currentTask.Task, binding) != nil || !proto.Equal(currentTask.Task, task) {
		return ErrPending
	}
	currentNode, err := client.GetNode(ctx, &api.GetNodeRequest{NodeID: binding.NodeID})
	if err != nil {
		return err
	}
	// PAUSE, DRAIN and DOWN do not prove an assigned process has stopped.
	if currentNode == nil || verifyTaskNodeIdentity(currentNode.Node, binding, expected.Architecture) != nil {
		return ErrPending
	}
	if err := verifyAllocationRecipient(proof, registration, binding, currentNode.Node, expected.Architecture, controller, worker); err != nil {
		return err
	}
	now := time.Now().UTC()
	if !verified.Valid(now) || controller != nil && !controller.Valid(now) {
		return ErrPending
	}
	return ctx.Err()
}

func verifyAllocationAuthority(ctx context.Context, client api.ControlReader, task *api.Task, expected swarmruntime.ServiceIntent,
	verified release.VerifiedContainer, roots trust.Keyring, proof Profile, registration host.Registration, binding host.ContainerMaterialBinding,
) error {
	if client == nil || verifyAllocationProfile(task, expected, verified, proof, registration, binding) != nil {
		return ErrPending
	}
	return swarmruntime.VerifyTaskAllocation(ctx, client, task, expected, verified, roots)
}

func verifyAllocationProfile(task *api.Task, expected swarmruntime.ServiceIntent, verified release.VerifiedContainer,
	proof Profile, registration host.Registration, binding host.ContainerMaterialBinding,
) error {
	if verifyExpected(proof, expected, verified) != nil || expected.Generation != proof.intent.Generation || registration.Cell != proof.identity.Cell || registration.Environment != proof.identity.Environment ||
		binding.Region != expected.Region || !slices.Contains(registration.Roles, proof.role) {
		return ErrPending
	}
	return verifyAllocatedTask(task, binding)
}

func verifyAllocationRecipient(proof Profile, registration host.Registration, binding host.ContainerMaterialBinding,
	node *api.Node, architecture string, controller *bootstrapstart.ControllerHostRecipient, worker swarmruntime.VerifiedWorkerMembership,
) error {
	if err := verifyTaskRecipient(proof, registration, binding, node, controller); err != nil {
		return err
	}
	if node.Role == api.NodeRoleManager {
		if worker.NodeID() != "" {
			return ErrPending
		}
		return nil
	}
	info := worker.Info()
	if worker.Validate() != nil || worker.NodeID() != binding.NodeID || worker.RegistrationID() != registration.ID ||
		worker.InstanceID() != binding.InstanceID || worker.OCIRegion() != binding.Region || !strings.EqualFold(worker.Cell(), registration.Cell) ||
		worker.Role() != "container" || worker.Architecture() != architecture || worker.PrivateIP() != node.Status.Addr ||
		info.PublicKey != registration.PublicKey || info.NATSUserPublicKey != registration.NATSUserPublicKey || info.Generation != registration.Generation {
		return ErrPending
	}
	return nil
}

func verifyAllocatedTask(task *api.Task, binding host.ContainerMaterialBinding) error {
	if task == nil || task.NodeID == "" || task.ID != binding.TaskID || task.ServiceID != binding.ServiceID || task.NodeID != binding.NodeID || task.Status.State >= api.TaskStateCompleted {
		return ErrPending
	}
	if _, known := api.TaskState_name[int32(task.Status.State)]; !known {
		return ErrPending
	}
	if _, known := api.TaskState_name[int32(task.DesiredState)]; !known {
		return ErrPending
	}
	fingerprint, err := swarmruntime.ContainerTaskFingerprint(task)
	if err != nil || fingerprint != binding.Fingerprint {
		return ErrPending
	}
	return nil
}

func allocationContext(ctx context.Context, deadline time.Time, controller *bootstrapstart.ControllerHostRecipient, worker swarmruntime.VerifiedWorkerMembership) (context.Context, context.CancelFunc) {
	if controller != nil && controller.Deadline().Before(deadline) {
		deadline = controller.Deadline()
	}
	if expires := worker.Info().ExpiresAt; worker.NodeID() != "" && expires.Before(deadline) {
		deadline = expires
	}
	return context.WithDeadline(ctx, deadline)
}
