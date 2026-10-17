package app

import (
	"context"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/host"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
	"github.com/moby/swarmkit/v2/api"
)

// verifyAllocation observes resources without preparing or admitting credentials.
func (controller functionController) verifyAllocation(ctx context.Context, registration host.Registration, task *api.Task,
	membership func(context.Context, string) (swarmruntime.VerifiedWorkerMembership, error),
) error {
	config := controller.config
	if config.Authority == nil || config.JS == nil || config.Roots == nil || config.Client == nil || config.Factory == nil || config.Evidence == nil || membership == nil ||
		task == nil || task.NodeID == "" || !entityid.Valid(registration.ID) || registration.Cell != strings.ToLower(config.Cell) ||
		registration.Environment != config.Environment || !slices.Equal(registration.Roles, []string{swarmruntime.FunctionWorkerRole}) || registration.ManagedOCI == nil {
		return errors.New("function allocation requires its exact registered worker and current sources")
	}
	ctx, cancelStartup := context.WithDeadline(ctx, config.Startup.ExpiresAt())
	defer cancelStartup()
	if err := config.Startup.VerifyCurrent(ctx, time.Now().UTC()); err != nil {
		return err
	}
	epoch, head := config.Authority.Current().Epoch, config.Roots.reply("").Head
	if err := config.Authority.Guard(ctx, epoch); err != nil {
		return err
	}
	// shortcut: the live membership source refuses DRAIN; keep the whole usage
	// sample unknown until an allocation-only authenticated recipient reader exists.
	member, err := membership(ctx, task.NodeID)
	if err != nil {
		return err
	}
	info := member.Info()
	if member.Validate() != nil || member.NodeID() != task.NodeID || member.RegistrationID() != registration.ID || member.Role() != "wasm" ||
		!strings.EqualFold(member.Cell(), config.Cell) || member.OCIRegion() != catalog.OCIRegion(strings.ToUpper(config.Cell)) ||
		member.InstanceID() != registration.ManagedOCI.InstanceID || info.Generation != registration.Generation ||
		info.PublicKey != registration.PublicKey || info.NATSUserPublicKey != registration.NATSUserPublicKey {
		return errors.New("function allocation lacks current independent worker membership")
	}
	ctx, cancelMembership := context.WithDeadline(ctx, info.ExpiresAt)
	defer cancelMembership()
	node, err := config.Client.GetNode(ctx, &api.GetNodeRequest{NodeID: task.NodeID})
	if err != nil {
		return err
	}
	if node == nil || node.Node == nil || node.Node.Spec.Annotations.Name != registration.ID ||
		node.Node.Spec.Annotations.Labels[swarmruntime.LabelInstanceID] != member.InstanceID() || node.Node.Description == nil ||
		node.Node.Description.Platform == nil || node.Node.Description.Platform.Architecture != member.Architecture() {
		return errors.New("function allocation manager recipient differs from independent membership")
	}
	reader := config.Material.Reader
	reader.Authority = config.Authority
	current := functionIntentSource{reader: reader, js: config.JS, authority: config.Authority, epoch: epoch, roots: config.Roots, rootHead: head}
	labels := task.ServiceAnnotations.Labels
	proof, err := current.CurrentFunction(ctx, labels[swarmruntime.LabelFunctionTenant], labels[swarmruntime.LabelFunctionID])
	if err != nil {
		return err
	}
	if claim := proof.Claim(); claim.Cell != strings.ToUpper(config.Cell) || claim.Environment != config.Environment {
		return release.ErrExpectationMismatch
	}
	ctx, cancelFunction := context.WithDeadline(ctx, proof.ExpiresAt())
	defer cancelFunction()
	intent := functionServiceTarget(proof, member.Architecture())
	bundle, err := intent.WorkerBundleForTask(ctx, config.Client, task)
	if err != nil {
		return err
	}
	target := release.ContainerTarget{Cell: strings.ToUpper(config.Cell), Environment: config.Environment, Role: swarmruntime.FunctionWorkerRole, Architecture: intent.Architecture}
	allocations, err := currentContainerAllocations(ctx, config.Factory, bundle, config.Roots.current(), target)
	if err != nil {
		return err
	}
	deadline := time.Now().UTC().Add(5 * time.Second)
	if limit, exists := ctx.Deadline(); exists && limit.Before(deadline) {
		deadline = limit
	}
	worker, err := release.VerifyContainerCurrent(ctx, bundle, config.Roots.current(), target, time.Now().UTC(), deadline, config.Evidence, allocations)
	if err != nil {
		return err
	}
	ctx, cancelWorker := context.WithDeadline(ctx, worker.ExpiresAt())
	defer cancelWorker()
	if err := swarmruntime.VerifyFunctionTaskAllocation(ctx, config.Client, task, intent, current, worker); err != nil {
		return err
	}
	confirmed, err := membership(ctx, task.NodeID)
	if err != nil || confirmed.Validate() != nil || member.Validate() != nil {
		return errors.New("function allocation membership is unavailable after qualification")
	}
	before, after := member.Info(), confirmed.Info()
	before.ObservedAt, before.ExpiresAt, after.ObservedAt, after.ExpiresAt = time.Time{}, time.Time{}, time.Time{}, time.Time{}
	if before != after {
		return errors.New("function allocation membership changed during observation")
	}
	if err := config.Startup.VerifyCurrent(ctx, time.Now().UTC()); err != nil {
		return err
	}
	if err := swarmruntime.VerifyFunctionTaskAllocation(ctx, config.Client, task, intent, current, worker); err != nil {
		return err
	}
	if err := config.Authority.Guard(ctx, epoch); err != nil {
		return err
	}
	if err := rootTrustHeadCurrent(ctx, config.JS, config.Roots, head); err != nil {
		return err
	}
	state := config.Authority.Current()
	if !state.CanMutate() || state.Epoch != epoch || config.Roots.reply("").Head != head || !proof.Valid() || !worker.Valid(time.Now().UTC()) || member.Validate() != nil || confirmed.Validate() != nil {
		return errors.New("function allocation authority changed during observation")
	}
	return ctx.Err()
}

func (controller functionController) taskLoadRoles(ctx context.Context, registration host.Registration,
	membership func(context.Context, string) (swarmruntime.VerifiedWorkerMembership, error),
) ([]string, error) {
	if !slices.Contains(registration.Roles, swarmruntime.FunctionWorkerRole) {
		return nil, nil
	}
	if controller.config.Client == nil || controller.config.JS == nil || !slices.Equal(registration.Roles, []string{swarmruntime.FunctionWorkerRole}) {
		return nil, errors.New("function task roles require their dedicated registered worker")
	}
	nodes, err := controller.config.Client.ListNodes(ctx, &api.ListNodesRequest{})
	if err != nil {
		return nil, err
	}
	if nodes == nil {
		return nil, errors.New("function task roles require current manager nodes")
	}
	nodeID := ""
	for _, node := range nodes.Nodes {
		if node == nil || node.Spec.Annotations.Name != registration.ID {
			continue
		}
		if nodeID != "" || node.ID == "" {
			return nil, errors.New("function task host assignment is ambiguous")
		}
		nodeID = node.ID
	}
	if nodeID == "" {
		return nil, errors.New("function task host assignment is unavailable")
	}
	listed, err := controller.config.Client.ListTasks(ctx, &api.ListTasksRequest{Filters: &api.ListTasksRequest_Filters{NodeIDs: []string{nodeID}}})
	if err != nil {
		return nil, err
	}
	if listed == nil || len(listed.Tasks) > 4096 {
		return nil, errors.New("function task inventory is unavailable or oversized")
	}
	roles := []string{}
	for _, task := range listed.Tasks {
		if task == nil {
			return nil, errors.New("function task inventory contains an unavailable assignment")
		}
		switch task.Status.State {
		case api.TaskStateCompleted, api.TaskStateShutdown, api.TaskStateFailed, api.TaskStateRejected, api.TaskStateRemove, api.TaskStateOrphaned:
			continue
		}
		if task.NodeID != nodeID {
			return nil, errors.New("function task inventory differs from its requested host")
		}
		if err := controller.verifyAllocation(ctx, registration, task, membership); err != nil {
			return nil, err
		}
		roles = []string{swarmruntime.FunctionWorkerRole}
	}
	return roles, nil
}
