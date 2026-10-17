package app

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/autoscale"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/machines"
	"github.com/TerraScale/ts-orchestrator/internal/machinesapi"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"github.com/TerraScale/ts-orchestrator/internal/placement"
	"github.com/TerraScale/ts-orchestrator/internal/storage/execution"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
	"github.com/gogo/protobuf/types"
	"github.com/moby/swarmkit/v2/api"
)

type managerMachinesView struct{ manager *managerWorkloadView }

func newManagerMachinesView(manager *managerWorkloadView) machinesapi.AppSource {
	return &managerMachinesView{manager: manager}
}

// Snapshot never retains an earlier result when authority or manager reads fail.
func (view *managerMachinesView) Snapshot(ctx context.Context) ([]machinesapi.AppSnapshot, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	m := view.manager
	if m == nil || m.specs == nil || m.authority == nil || m.client == nil {
		return nil, errors.New("machines manager is unavailable")
	}
	epoch := m.authority.Current().Epoch
	if !m.leader(ctx, epoch) {
		return nil, errors.New("machines manager authority is unavailable")
	}
	profiles, policies := m.specs.effective()
	region := catalog.OCIRegion(strings.ToUpper(m.specs.cell))
	filters := &api.ListServicesRequest_Filters{Labels: map[string]string{
		swarmruntime.LabelRegion: region, swarmruntime.LabelEnvironment: m.specs.identity.Environment,
	}}
	listed, err := m.client.ListServices(ctx, &api.ListServicesRequest{Filters: filters})
	if err != nil || listed == nil {
		return nil, fmt.Errorf("read machines manager services: %w", err)
	}
	snapshots := []machinesapi.AppSnapshot{}
	seen := map[string]bool{}
	nodes := map[string]uint64{}
	for _, service := range listed.Services {
		if service == nil {
			return nil, errors.New("nil machines manager service")
		}
		labels := service.Spec.Annotations.Labels
		if service.PendingDelete {
			continue
		}
		if labels[swarmruntime.LabelRegion] != region || labels[swarmruntime.LabelEnvironment] != m.specs.identity.Environment {
			return nil, errors.New("machines manager service scope changed")
		}
		role, intent := labels[swarmruntime.LabelRole], labels[swarmruntime.LabelIntentID]
		if !entityid.Valid(intent) || service.ID == "" || service.Spec.GetReplicated() == nil || service.Spec.GetReplicated().Replicas > autoscale.MaxReplicas {
			return nil, errors.New("machines manager service identity or mode is invalid")
		}
		name, class, tenantID := role, machines.ClassPlatform, ""
		switch {
		case role == swarmruntime.FunctionWorkerRole:
			tenantID = labels[swarmruntime.LabelFunctionTenant]
			function := labels[swarmruntime.LabelFunctionID]
			if !entityid.Valid(tenantID) || function == "" || intent != entityid.Derive("function-service", m.specs.identity.Environment, region, tenantID, function) {
				return nil, errors.New("machines function ownership is invalid")
			}
			name, class = "fn-"+strings.ToLower(intent), machines.ClassTenant
		case role == "terrabase":
			// Member services have no tenant binding; only the platform may see them.
			if labels["terrascale.stateful"] != "true" || !entityid.Valid(labels["terrascale.database-id"]) || !entityid.Valid(labels["terrascale.partition-id"]) || !entityid.Valid(labels["terrascale.member-id"]) {
				return nil, errors.New("machines stateful member identity is invalid")
			}
			if intent != entityid.Derive("stateful-service", m.specs.identity.Environment, m.specs.cell, labels["terrascale.database-id"], labels["terrascale.partition-id"], labels["terrascale.member-id"]) {
				return nil, errors.New("machines stateful service ownership is invalid")
			}
			name = "db-" + strings.ToLower(intent)
		default:
			if _, admitted := profiles[role]; !admitted {
				continue
			}
			if intent != entityid.Derive("platform-service", role, m.specs.identity.Environment, region) {
				return nil, errors.New("machines platform service ownership is invalid")
			}
		}
		if seen[name] {
			return nil, errors.New("ambiguous machines manager app identity")
		}
		seen[name] = true
		config, err := managerMachineConfig(service.Spec.Task, service.Spec.Annotations)
		if err != nil {
			return nil, err
		}
		app := machines.App{Name: name, ID: entityid.Derive("manager-app", service.ID), Class: class, Tenant: tenantID,
			Version: service.Meta.Version.Index, Config: config, Regions: map[string]int{m.specs.cell: int(service.Spec.GetReplicated().Replicas)}}
		tasks, err := m.client.ListTasks(ctx, &api.ListTasksRequest{Filters: &api.ListTasksRequest_Filters{ServiceIDs: []string{service.ID}}})
		if err != nil || tasks == nil {
			return nil, fmt.Errorf("read machines manager tasks: %w", err)
		}
		snapshot := machinesapi.AppSnapshot{App: app, Machines: []machinesapi.MachineView{}}
		for _, task := range tasks.Tasks {
			if task == nil || task.ID == "" || task.ServiceID != service.ID || task.ServiceAnnotations.Labels[swarmruntime.LabelIntentID] != intent {
				return nil, errors.New("machines task ownership is invalid")
			}
			taskConfig, err := managerMachineConfig(task.Spec, task.ServiceAnnotations)
			if err != nil {
				return nil, err
			}
			id := entityid.Derive("manager-machine", task.ID)
			machine := machines.Machine{ID: id, App: name, AppID: app.ID, Region: m.specs.cell,
				Version: task.Meta.Version.Index, Config: taskConfig, Desired: managerMachineDesired(task.DesiredState)}
			state := managerMachineState(task.Status.State)
			if task.NodeID != "" {
				response, err := m.client.GetNode(ctx, &api.GetNodeRequest{NodeID: task.NodeID})
				if err != nil || response == nil || response.Node == nil || response.Node.ID != task.NodeID {
					return nil, errors.New("machines task host is unavailable")
				}
				node := response.Node
				if node.Spec.Annotations.Labels[swarmruntime.LabelRegion] != region {
					return nil, errors.New("machines task host is outside the admitted region")
				}
				nodes[node.ID] = node.Meta.Version.Index
				machine.Host = node.Spec.Annotations.Name
				machine.FailureDomain = node.Spec.Annotations.Labels["terrascale.failure-domain"]
				if node.Status.State == api.NodeStatus_DOWN {
					state = machines.StateLost
				}
			}
			// RUNNING is a lifecycle observation, not proof that the application serves.
			if state == machines.StateStarting && task.Status.State == api.TaskStateRunning && task.DesiredState == api.TaskStateRunning && m.probe != nil {
				if err := m.probe(ctx, task); err == nil {
					state = machines.StateStarted
				}
			}
			updated, err := types.TimestampFromProto(task.Status.Timestamp)
			if err != nil {
				updated = time.Time{}
			}
			snapshot.Machines = append(snapshot.Machines, machinesapi.MachineView{Machine: machine,
				Status: &machines.Status{ID: id, App: name, State: state, UpdatedAt: updated}})
		}
		// A replacement or status update during probes must never become a mixed snapshot.
		confirmed, err := m.client.ListTasks(ctx, &api.ListTasksRequest{Filters: &api.ListTasksRequest_Filters{ServiceIDs: []string{service.ID}}})
		if err != nil || confirmed == nil || !sameManagerTasks(tasks.Tasks, confirmed.Tasks) {
			return nil, errors.New("machines manager tasks changed during observation")
		}
		slices.SortFunc(snapshot.Machines, func(a, b machinesapi.MachineView) int { return strings.Compare(a.ID, b.ID) })
		snapshots = append(snapshots, snapshot)
	}
	confirmed, err := m.client.ListServices(ctx, &api.ListServicesRequest{Filters: filters})
	if err != nil || confirmed == nil || !sameManagerServices(listed.Services, confirmed.Services) {
		return nil, errors.New("machines manager services changed during observation")
	}
	for id, version := range nodes {
		current, err := m.client.GetNode(ctx, &api.GetNodeRequest{NodeID: id})
		if err != nil || current == nil || current.Node == nil || current.Node.ID != id || current.Node.Meta.Version.Index != version {
			return nil, errors.New("machines manager host changed during observation")
		}
	}
	currentProfiles, currentPolicies := m.specs.effective()
	if !reflect.DeepEqual(profiles, currentProfiles) || !reflect.DeepEqual(policies, currentPolicies) || !m.leader(ctx, epoch) || ctx.Err() != nil {
		return nil, errors.New("machines manager authority changed during observation")
	}
	slices.SortFunc(snapshots, func(a, b machinesapi.AppSnapshot) int { return strings.Compare(a.App.Name, b.App.Name) })
	return snapshots, nil
}

// Return only public image/resource metadata: container env, files and arguments may contain secrets.
func managerMachineConfig(spec api.TaskSpec, annotations api.Annotations) (machines.MachineConfig, error) {
	generic := spec.GetGeneric()
	if generic == nil || generic.Payload == nil || generic.Kind != swarmruntime.ContainerKind && generic.Kind != execution.StatefulContainerKind {
		return machines.MachineConfig{}, errors.New("machines task runtime is unsupported")
	}
	container := new(api.ContainerSpec)
	if err := container.Unmarshal(generic.Payload.Value); err != nil {
		return machines.MachineConfig{}, err
	}
	_, digest, ok := strings.Cut(container.Image, "@sha256:")
	if !ok || len(digest) != 64 || spec.Resources == nil || spec.Resources.Limits == nil {
		return machines.MachineConfig{}, errors.New("machines task image or resources are invalid")
	}
	if _, err := hex.DecodeString(digest); err != nil || strings.ToLower(digest) != digest {
		return machines.MachineConfig{}, errors.New("machines task digest is invalid")
	}
	limits := spec.Resources.Limits
	disk := int64(0)
	if generic.Kind == swarmruntime.ContainerKind && annotations.Labels[swarmruntime.LabelRole] != swarmruntime.FunctionWorkerRole {
		var err error
		disk, err = swarmruntime.DiskBytes(spec.Resources)
		if err != nil {
			return machines.MachineConfig{}, err
		}
	}
	return machines.MachineConfig{Role: annotations.Labels[swarmruntime.LabelRole], Digest: digest,
		Resources: placement.Resources{CPU: int((limits.NanoCPUs + 999_999_999) / 1_000_000_000), MemoryBytes: limits.MemoryBytes, DiskBytes: disk}}, nil
}

func managerMachineDesired(state api.TaskState) machines.DesiredState {
	if state == api.TaskStateRemove {
		return machines.DesiredDestroyed
	}
	if state >= api.TaskStateShutdown {
		return machines.DesiredStopped
	}
	return machines.DesiredStarted
}

func managerMachineState(state api.TaskState) machines.State {
	switch state {
	case api.TaskStateNew, api.TaskStatePending, api.TaskStateAllocated, api.TaskStateAssigned:
		return machines.StatePending
	case api.TaskStateAccepted, api.TaskStatePreparing, api.TaskStateReady, api.TaskStateStarting, api.TaskStateRunning:
		return machines.StateStarting
	case api.TaskStateCompleted, api.TaskStateShutdown:
		return machines.StateStopped
	case api.TaskStateFailed, api.TaskStateRejected:
		return machines.StateFailed
	case api.TaskStateRemove:
		return machines.StateDestroyed
	case api.TaskStateOrphaned:
		return machines.StateLost
	default:
		return machines.StatePending
	}
}

func sameManagerTasks(before, after []*api.Task) bool {
	versions := make(map[string]uint64, len(before))
	for _, task := range before {
		if task == nil {
			return false
		}
		versions[task.ID] = task.Meta.Version.Index
	}
	if len(versions) != len(before) || len(before) != len(after) {
		return false
	}
	for _, task := range after {
		if task == nil || versions[task.ID] != task.Meta.Version.Index {
			return false
		}
		delete(versions)
	}
	return len(versions) == 0
}

func sameManagerServices(before, after []*api.Service) bool {
	versions := make(map[string]uint64, len(before))
	for _, service := range before {
		if service == nil {
			return false
		}
		versions[service.ID] = service.Meta.Version.Index
	}
	if len(versions) != len(before) || len(before) != len(after) {
		return false
	}
	for _, service := range after {
		if service == nil || versions[service.ID] != service.Meta.Version.Index {
			return false
		}
		delete(versions)
	}
	return len(versions) == 0
}
