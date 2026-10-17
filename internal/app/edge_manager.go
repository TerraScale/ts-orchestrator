package app

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"time"

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

type managerEdgeSnapshot map[string]map[string]managerEdgeState

// managerEdgeSource binds readiness to an original local source and guard.
// The root traffic boundary constructs its own source; a controller snapshot
// never authorizes an OCI mutation.
type managerEdgeSource struct {
	client api.ControlReader
	specs  *specRegistry
	hosts  seatrollout.Hosts
	probe  func(context.Context, *api.Task) error
	guard  func(context.Context) error
}

func (f *releaseFence) managerSnapshot(ctx context.Context) (managerEdgeSnapshot, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	view := f.manager
	if view == nil || view.authority == nil {
		return nil, errors.New("manager task readiness source is unavailable")
	}
	epoch := view.authority.Current().Epoch
	source := managerEdgeSource{client: view.client, specs: view.specs, hosts: f.hosts, probe: view.probe, guard: func(ctx context.Context) error {
		if !view.leader(ctx, epoch) {
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
	if source.client == nil || source.specs == nil || source.probe == nil || source.guard == nil {
		return fail(errors.New("manager task readiness source is unavailable"))
	}
	if err := source.guard(ctx); err != nil {
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
	region := catalog.OCIRegion(source.specs.cell)
	nodeNames := map[string]string{}
	nodeReady := map[string]bool{}
	nodeEnvironment := map[string]string{}
	snapshot := managerEdgeSnapshot{}
	for _, node := range nodes.Nodes {
		if node == nil || node.ID == "" || node.Spec.Annotations.Labels[swarmruntime.LabelRegion] != region {
			continue
		}
		for _, status := range hosts {
			registration := status.Registration
			if catalog.OCIRegion(registration.Cell) != region {
				continue
			}
			matches := node.Spec.Annotations.Name == registration.ID
			if node.Role == api.NodeRoleManager {
				matches = source.specs.controllerNode(registration.Cell, node.Spec.Annotations.Name) == registration.Node
			}
			if !matches {
				continue
			}
			if nodeNames[node.ID] != "" || snapshot[registration.Node] != nil {
				return fail(errors.New("manager readiness recipient is ambiguous"))
			}
			if registration.ManagedOCI != nil && registration.ManagedOCI.InstanceID != node.Spec.Annotations.Labels[swarmruntime.LabelInstanceID] {
				return fail(errors.New("manager readiness instance differs from its registration"))
			}
			nodeNames[node.ID] = registration.Node
			nodeEnvironment[node.ID] = registration.Environment
			nodeReady[node.ID] = !status.Retired && status.Verified && time.Now().Before(status.SessionExpiresAt) && node.Status.State == api.NodeStatus_READY && node.Spec.Membership == api.NodeMembershipAccepted && (node.Spec.Availability == api.NodeAvailabilityActive || node.Spec.Availability == api.NodeAvailabilityPause)
			snapshot[registration.Node] = map[string]managerEdgeState{}
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
		state, exists := snapshot[name][role]
		ready := nodeReady[task.NodeID] && task.Status.State == api.TaskStateRunning
		if ready {
			ready = source.probe(ctx, task) == nil
		}
		if exists {
			ready = ready && state.ready
		}
		snapshot[name][role] = managerEdgeState{ready: ready, observedAt: time.Now(), tasks: append(state.tasks, task.Copy())}
	}
	// Probe success belongs to these exact assignments and sessions, not an
	// earlier service generation or a replaced manager source.
	check := func(ctx context.Context) error {
		if err := source.guard(ctx); err != nil {
			return err
		}
		source.specs.mu.Lock()
		sameSpec := source.specs.revision == specRevision
		source.specs.mu.Unlock()
		if !sameSpec {
			return errors.New("signed readiness spec changed during observation")
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
			roles := snapshot[status.Registration.Node]
			for _, state := range roles {
				if state.ready && !time.Now().Before(status.SessionExpiresAt) {
					return errors.New("manager readiness host session expired")
				}
			}
		}
		if !proto.Equal(nodes, confirmedNodes) || !proto.Equal(services, confirmedServices) || !proto.Equal(tasks, confirmedTasks) || !reflect.DeepEqual(hosts, confirmedHosts) {
			return errors.New("manager readiness assignments or sessions changed during observation")
		}
		return source.guard(ctx)
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
	roles, found := snapshot[node]
	if !found || len(roles) == 0 {
		return "its manager recipient has no current assigned tasks", nil
	}
	for role, state := range roles {
		if !state.ready || !state.observedAt.After(since) {
			return fmt.Sprintf("%s has no current ready manager task", role), nil
		}
	}
	return "", nil
}
