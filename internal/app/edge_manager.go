package app

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/host"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"github.com/TerraScale/ts-orchestrator/internal/seatrollout"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
	"github.com/gogo/protobuf/proto"
	"github.com/moby/swarmkit/v2/api"
)

type managerEdgeState struct {
	ready      bool
	observedAt time.Time
	tasks      []*api.Task
}

type managerEdgeNode struct {
	ready bool
	roles map[string]managerEdgeState
}

type managerEdgeSnapshot map[string]managerEdgeNode

// managerEdgeSource binds readiness to an original local source and guard.
// The root traffic boundary constructs its own source; a controller snapshot
// never authorizes an OCI mutation.
type managerEdgeRecipient struct {
	deadline time.Time
	current  func(context.Context) error
}

type managerEdgeSource struct {
	client    api.ControlReader
	specs     *specRegistry
	hosts     seatrollout.Hosts
	probe     func(context.Context, *api.Task) error
	guard     func(context.Context) error
	recipient func(context.Context, *api.Node, host.Registration) (managerEdgeRecipient, error)
}

func (f *releaseFence) managerSnapshot(ctx context.Context) (managerEdgeSnapshot, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	view := f.manager
	if view == nil || view.authority == nil {
		return nil, errors.New("manager task readiness source is unavailable")
	}
	original := view.authority.Current()
	epoch := original.Epoch
	source := managerEdgeSource{client: view.client, specs: view.specs, hosts: f.hosts, probe: view.probe, recipient: f.recipient, guard: func(ctx context.Context) error {
		current := view.authority.Current()
		if !time.Now().Before(original.ExpiresAt) || current.Scope != original.Scope || current.DeploymentID != original.DeploymentID || current.CandidateID != original.CandidateID || current.OwnerID != original.OwnerID || current.Epoch != original.Epoch || current.Revision < original.Revision || !view.leader(ctx, epoch) {
			return errors.New("manager readiness authority is unavailable")
		}
		return nil
	}}
	snapshot, _, err := source.snapshot(ctx)
	return snapshot, err
}

// snapshot uses host registrations only to bind actual manager nodes to current
// enrolled recipients. It returns a guard for the exact observed assignments.
func (source managerEdgeSource) snapshot(ctx context.Context) (managerEdgeSnapshot, func(context.Context) error, error) {
	fail := func(err error) (managerEdgeSnapshot, func(context.Context) error, error) { return nil, nil, err }
	if ctx == nil {
		return fail(errors.New("manager readiness requires a context"))
	}
	if source.client == nil || source.specs == nil || source.probe == nil || source.recipient == nil || source.guard == nil {
		return fail(errors.New("manager task readiness source is unavailable"))
	}
	originalContext := ctx
	originalDeadline, hasDeadline := ctx.Deadline()
	if !hasDeadline || ctx.Done() == nil || ctx.Err() != nil {
		return fail(errors.New("manager readiness requires an original bounded source context"))
	}
	guard := func(ctx context.Context) error {
		if originalContext.Err() != nil || ctx.Err() != nil || !time.Now().Before(originalDeadline) {
			return errors.New("manager readiness original source expired")
		}
		return source.guard(ctx)
	}
	if err := guard(ctx); err != nil {
		return fail(err)
	}
	source.specs.mu.Lock()
	specRevision := source.specs.revision
	source.specs.mu.Unlock()
	hosts, err := source.readinessHosts(ctx)
	if err != nil {
		return fail(err)
	}
	nodes, err := source.client.ListNodes(ctx, &api.ListNodesRequest{})
	if err != nil {
		return fail(err)
	}
	services, err := source.client.ListServices(ctx, &api.ListServicesRequest{})
	if err != nil {
		return fail(err)
	}
	tasks, err := source.client.ListTasks(ctx, &api.ListTasksRequest{Filters: &api.ListTasksRequest_Filters{DesiredStates: []api.TaskState{api.TaskStateRunning}, UpToDate: true}})
	if err != nil {
		return fail(err)
	}
	if nodes == nil || services == nil || tasks == nil || len(hosts) > 4096 || len(nodes.Nodes) > 4096 || len(services.Services) > 4096 || len(tasks.Tasks) > 4096 {
		return fail(errors.New("manager readiness inventory is unavailable or exceeds bounds"))
	}
	region := catalog.OCIRegion(strings.ToUpper(source.specs.cell))
	nodeNames := map[string]string{}
	nodeReady := map[string]bool{}
	nodeEnvironment := map[string]string{}
	nodeSessionDeadline := map[string]time.Time{}
	recipients := map[string]managerEdgeRecipient{}
	snapshot := managerEdgeSnapshot{}
	for _, node := range nodes.Nodes {
		if node == nil || node.ID == "" || node.Spec.Annotations.Labels[swarmruntime.LabelRegion] != region {
			continue
		}
		for _, status := range hosts {
			registration := status.Registration
			if catalog.OCIRegion(strings.ToUpper(registration.Cell)) != region {
				continue
			}
			matches := node.Spec.Annotations.Name == registration.ID
			if node.Role == api.NodeRoleManager {
				matches = source.specs.controllerNode(registration.Cell, node.Spec.Annotations.Name) == registration.Node
			}
			if !matches {
				continue
			}
			if nodeNames[node.ID] != "" || snapshot[registration.Node].roles != nil {
				return fail(errors.New("manager readiness recipient is ambiguous"))
			}
			if registration.ManagedOCI != nil && registration.ManagedOCI.InstanceID != node.Spec.Annotations.Labels[swarmruntime.LabelInstanceID] {
				return fail(errors.New("manager readiness instance differs from its registration"))
			}
			nodeNames[node.ID] = registration.Node
			nodeEnvironment[node.ID] = registration.Environment
			nodeSessionDeadline[node.ID] = status.SessionExpiresAt
			nodeReady[node.ID] = !status.Retired && status.Verified && time.Now().Before(status.SessionExpiresAt) && node.Status.State == api.NodeStatus_READY && node.Spec.Membership == api.NodeMembershipAccepted && (node.Spec.Availability == api.NodeAvailabilityActive || node.Spec.Availability == api.NodeAvailabilityPause)
			if nodeReady[node.ID] {
				recipientCtx, cancel := context.WithDeadline(ctx, status.SessionExpiresAt)
				recipient, err := source.recipient(recipientCtx, node, registration)
				cancel()
				nodeReady[node.ID] = err == nil && recipient.current != nil && time.Now().Before(recipient.deadline)
				if nodeReady[node.ID] {
					recipients[node.ID] = recipient
					if recipient.deadline.Before(nodeSessionDeadline[node.ID]) {
						nodeSessionDeadline[node.ID] = recipient.deadline
					}
				}
			} else {
				nodeReady[node.ID] = false
			}
			snapshot[registration.Node] = managerEdgeNode{ready: nodeReady[node.ID], roles: map[string]managerEdgeState{}}
		}
	}
	owned := map[string]*api.Service{}
	for _, service := range services.Services {
		if service == nil || service.PendingDelete || service.Spec.Annotations.Labels[swarmruntime.LabelRegion] != region {
			continue
		}
		owned[service.ID] = service
	}
	for _, task := range tasks.Tasks {
		if task == nil || task.DesiredState != api.TaskStateRunning || task.NodeID == "" {
			continue
		}
		service := owned[task.ServiceID]
		if service == nil {
			continue
		}
		role := service.Spec.Annotations.Labels[swarmruntime.LabelRole]
		name := nodeNames[task.NodeID]
		if name == "" {
			return fail(errors.New("assigned task has no current enrolled manager recipient"))
		}
		if role == "" || service.Spec.Annotations.Labels[swarmruntime.LabelEnvironment] != nodeEnvironment[task.NodeID] || task.ServiceAnnotations.Labels[swarmruntime.LabelRole] != role || task.ServiceAnnotations.Labels[swarmruntime.LabelEnvironment] != service.Spec.Annotations.Labels[swarmruntime.LabelEnvironment] || task.ServiceAnnotations.Labels[swarmruntime.LabelRegion] != region {
			return fail(errors.New("manager task readiness scope differs from its service"))
		}
		state, exists := snapshot[name].roles[role]
		ready := nodeReady[task.NodeID] && task.Status.State == api.TaskStateRunning
		if ready {
			probeCtx, cancel := context.WithDeadline(ctx, nodeSessionDeadline[task.NodeID])
			ready = source.probe(probeCtx, task) == nil
			cancel()
		}
		if exists {
			ready = ready && state.ready
		}
		snapshot[name].roles[role] = managerEdgeState{ready: ready, observedAt: time.Now(), tasks: append(state.tasks, task.Copy())}
	}
	// Probe success belongs to these exact assignments and sessions, not an
	// earlier service generation or a replaced manager source.
	check := func(ctx context.Context) error {
		if err := guard(ctx); err != nil {
			return err
		}
		source.specs.mu.Lock()
		sameSpec := source.specs.revision == specRevision
		source.specs.mu.Unlock()
		if !sameSpec {
			return errors.New("signed readiness spec changed during observation")
		}
		for nodeID, recipient := range recipients {
			deadline := nodeSessionDeadline[nodeID]
			if !time.Now().Before(deadline) {
				return errors.New("manager readiness original recipient expired")
			}
			checkCtx, cancel := context.WithDeadline(ctx, deadline)
			err := recipient.current(checkCtx)
			cancel()
			if err != nil {
				return err
			}
		}
		confirmedNodes, err := source.client.ListNodes(ctx, &api.ListNodesRequest{})
		if err != nil {
			return err
		}
		confirmedServices, err := source.client.ListServices(ctx, &api.ListServicesRequest{})
		if err != nil {
			return err
		}
		confirmedTasks, err := source.client.ListTasks(ctx, &api.ListTasksRequest{Filters: &api.ListTasksRequest_Filters{DesiredStates: []api.TaskState{api.TaskStateRunning}, UpToDate: true}})
		if err != nil {
			return err
		}
		confirmedHosts, err := source.readinessHosts(ctx)
		if err != nil {
			return err
		}
		for _, status := range confirmedHosts {
			if snapshot[status.Registration.Node].ready && !time.Now().Before(status.SessionExpiresAt) {
				return errors.New("manager readiness host session expired")
			}
		}
		if !proto.Equal(nodes, confirmedNodes) || !proto.Equal(services, confirmedServices) || !proto.Equal(tasks, confirmedTasks) || !reflect.DeepEqual(hosts, confirmedHosts) {
			return errors.New("manager readiness assignments or sessions changed during observation")
		}
		source.specs.mu.Lock()
		sameSpec = source.specs.revision == specRevision
		source.specs.mu.Unlock()
		if !sameSpec {
			return errors.New("signed readiness spec changed during observation")
		}
		for nodeID := range recipients {
			if !time.Now().Before(nodeSessionDeadline[nodeID]) {
				return errors.New("manager readiness original recipient expired")
			}
		}
		return guard(ctx)
	}
	if err := check(ctx); err != nil {
		return fail(err)
	}
	return snapshot, check, nil
}

func (source managerEdgeSource) readinessHosts(ctx context.Context) ([]host.HostStatus, error) {
	if source.hosts == nil {
		return nil, errors.New("manager readiness recipient source is unavailable")
	}
	statuses, err := source.hosts.ListHosts(ctx)
	if err != nil {
		return nil, err
	}
	statuses = slices.Clone(statuses)
	for i := range statuses {
		statuses[i].Reports = nil
	}
	return statuses, nil
}

func (f *releaseFence) nodeRolesServing(ctx context.Context, node string, since time.Time) (string, error) {
	snapshot, err := f.managerSnapshot(ctx)
	if err != nil {
		return "", err
	}
	nodeState, found := snapshot[node]
	if !found || !nodeState.ready {
		return "its manager recipient is not currently ready", nil
	}
	for role, state := range nodeState.roles {
		if !state.ready || !state.observedAt.After(since) {
			return fmt.Sprintf("%s has no current ready manager task", role), nil
		}
	}
	return "", nil
}

// edgeRecipient verifies idle nodes too: an empty task list is not an enrolled
// identity, and a task's advertised host address never supplies membership.
func (controller *containerMaterialController) edgeRecipient(ctx context.Context, node *api.Node, registration host.Registration) (managerEdgeRecipient, error) {
	fail := func(err error) (managerEdgeRecipient, error) { return managerEdgeRecipient{}, err }
	if controller == nil || controller.config.Specs == nil || controller.config.Specs.kv == nil || controller.config.Client == nil || controller.config.Hosts == nil || node == nil || node.ID == "" {
		return fail(errors.New("manager readiness node is unavailable"))
	}
	if node.Role == api.NodeRoleManager {
		if err := controller.managerSession(ctx, node.ID); err != nil {
			return fail(err)
		}
		enrollment, err := completedControllerEnrollment(ctx, controller.config, registration, node.Spec.Annotations.Labels[swarmruntime.LabelInstanceID])
		if err != nil {
			return fail(err)
		}
		entry, err := controller.config.Specs.kv.Get(ctx, cellSpecKey)
		if err != nil {
			return fail(err)
		}
		proof, err := bootstrapstart.ReadControllerHostRecipient(ctx, controller.config.Founders, controller.config.Accepted, entry.Value(), registration.Node, node.Spec.Annotations.Labels[swarmruntime.LabelInstanceID], node.Status.Addr)
		if err != nil {
			return fail(err)
		}
		deadline := enrollment.ExpiresAt
		if proof.Deadline().Before(deadline) {
			deadline = proof.Deadline()
		}
		current := func(ctx context.Context) error {
			if !time.Now().Before(deadline) {
				return errors.New("original controller readiness enrollment expired")
			}
			if err := proof.VerifyRegistration(ctx, registration); err != nil {
				return err
			}
			confirmed, err := completedControllerEnrollment(ctx, controller.config, registration, proof.InstanceID())
			if err != nil {
				return err
			}
			if !reflect.DeepEqual(enrollment, confirmed) {
				return errors.New("controller readiness enrollment changed")
			}
			return nil
		}
		return managerEdgeRecipient{deadline: deadline, current: current}, current(ctx)
	}
	if controller.config.WorkerMembership == nil {
		return fail(errors.New("worker readiness membership is unavailable"))
	}
	membership, err := controller.config.WorkerMembership(ctx, node.ID)
	if err != nil {
		return fail(err)
	}
	if err := membership.Validate(); err != nil {
		return fail(err)
	}
	if registration.ManagedOCI == nil || membership.NodeID() != node.ID || membership.RegistrationID() != registration.ID || membership.InstanceID() != registration.ManagedOCI.InstanceID || membership.InstanceID() != node.Spec.Annotations.Labels[swarmruntime.LabelInstanceID] || membership.OCIRegion() != node.Spec.Annotations.Labels[swarmruntime.LabelRegion] {
		return fail(errors.New("worker readiness recipient differs from its current membership"))
	}
	original := membership.Info()
	current := func(ctx context.Context) error {
		if err := membership.Validate(); err != nil {
			return err
		}
		confirmed, err := controller.config.WorkerMembership(ctx, node.ID)
		if err != nil {
			return err
		}
		if err := confirmed.Validate(); err != nil {
			return err
		}
		info := confirmed.Info()
		info.ObservedAt, info.ExpiresAt = original.ObservedAt, original.ExpiresAt
		if info != original {
			return errors.New("worker readiness membership changed")
		}
		return membership.Validate()
	}
	return managerEdgeRecipient{deadline: original.ExpiresAt, current: current}, current(ctx)
}
