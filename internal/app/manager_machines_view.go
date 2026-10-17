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
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type managerMachinePlacements interface {
	ListIntents(context.Context) ([]placement.Intent, error)
	ReadMember(context.Context, string, string, string) (placement.VersionedMemberState, error)
}

type managerMachinesView struct {
	manager    *managerWorkloadView
	placements managerMachinePlacements
}

func newManagerMachinesView(manager *managerWorkloadView, placements managerMachinePlacements) machinesapi.AppSource {
	return &managerMachinesView{manager: manager, placements: placements}
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
	seen := map[string]int{}
	databaseScopes := map[string]string{}
	var intents []placement.Intent
	var memberPins []placement.VersionedMemberState
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
		appID := entityid.Derive("manager-app", service.ID)
		var member *placement.VersionedMemberState
		switch {
		case role == swarmruntime.FunctionWorkerRole:
			tenantID = labels[swarmruntime.LabelFunctionTenant]
			function := labels[swarmruntime.LabelFunctionID]
			if !entityid.Valid(tenantID) || function == "" || intent != entityid.Derive("function-service", m.specs.identity.Environment, region, tenantID, function) {
				return nil, errors.New("machines function ownership is invalid")
			}
			name, class = "fn-"+strings.ToLower(intent), machines.ClassTenant
		case role == "terrabase":
			if view.placements == nil {
				return nil, errors.New("machines stateful placement authority is unavailable")
			}
			if intents == nil {
				intents, err = view.placements.ListIntents(ctx)
				if err != nil {
					return nil, err
				}
			}
			owner, pin, err := view.statefulOwner(ctx, service, intents)
			if err != nil {
				return nil, err
			}
			tenantID, class = owner.CanonicalRoster.TenantID, machines.ClassTenant
			name = "db-" + strings.ToLower(owner.DatabaseID)
			appID = entityid.Derive("manager-database-app", owner.DatabaseID)
			scope := tenantID + "/" + owner.CanonicalRoster.ClusterID + "/" + owner.CanonicalRoster.DatabaseID
			if previous, exists := databaseScopes[name]; exists && previous != scope {
				return nil, errors.New("machines database app has ambiguous authenticated ownership")
			}
			databaseScopes[name] = scope
			member = &pin
			memberPins = append(memberPins, pin)
		default:
			if _, admitted := profiles[role]; !admitted {
				continue
			}
			if intent != entityid.Derive("platform-service", role, m.specs.identity.Environment, region) {
				return nil, errors.New("machines platform service ownership is invalid")
			}
		}
		if index, exists := seen[name]; exists && (role != "terrabase" || snapshots[index].App.ID != appID || snapshots[index].App.Class != class || snapshots[index].App.Tenant != tenantID) {
			return nil, errors.New("ambiguous machines manager app identity")
		}
		config, err := managerMachineConfig(service.Spec.Task, service.Spec.Annotations)
		if err != nil {
			return nil, err
		}
		app := machines.App{Name: name, ID: appID, Class: class, Tenant: tenantID,
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
				if status.Code(err) == codes.NotFound {
					state = machines.StateLost
				} else {
					if err != nil || response == nil || response.Node == nil || response.Node.ID != task.NodeID {
						return nil, errors.New("machines task host is unavailable")
					}
					node := response.Node
					if node.Spec.Annotations.Labels[swarmruntime.LabelRegion] != region {
						return nil, errors.New("machines task host is outside the admitted region")
					}
					// Retained shutdown tasks may still name a member's previous host.
					if member != nil && task.DesiredState == api.TaskStateRunning && (node.Spec.Annotations.Name != member.State.HostNode || node.Spec.Annotations.Labels[swarmruntime.LabelInstanceID] != member.State.InstanceID) {
						return nil, errors.New("machines current task host differs from current member placement")
					}
					nodes[node.ID] = node.Meta.Version.Index
					machine.Host = node.Spec.Annotations.Name
					machine.FailureDomain = node.Spec.Annotations.Labels["terrascale.failure-domain"]
					if member != nil && node.Spec.Annotations.Name == member.State.HostNode {
						machine.FailureDomain = strings.ToLower(member.State.FailureDomain)
					}
					if node.Status.State == api.NodeStatus_DOWN {
						state = machines.StateLost
					}
				}
			}
			// RUNNING is a lifecycle observation, not proof that the application serves.
			if state == machines.StateStarting && task.Status.State == api.TaskStateRunning && task.DesiredState == api.TaskStateRunning && m.probe != nil {
				if err := m.probe(ctx, task); err == nil {
					state = machines.StateStarted
				}
			}
			machineView := machinesapi.MachineView{Machine: machine}
			if updated, err := types.TimestampFromProto(task.Status.Timestamp); err == nil && !updated.IsZero() {
				machineView.Status = &machines.Status{ID: id, App: name, State: state, UpdatedAt: updated}
			}
			snapshot.Machines = append(snapshot.Machines, machineView)
		}
		// A replacement or status update during probes must never become a mixed snapshot.
		confirmed, err := m.client.ListTasks(ctx, &api.ListTasksRequest{Filters: &api.ListTasksRequest_Filters{ServiceIDs: []string{service.ID}}})
		if err != nil || confirmed == nil || !sameManagerTasks(tasks.Tasks, confirmed.Tasks) {
			return nil, errors.New("machines manager tasks changed during observation")
		}
		slices.SortFunc(snapshot.Machines, func(a, b machinesapi.MachineView) int { return strings.Compare(a.ID, b.ID) })
		if index, exists := seen[name]; exists {
			previous := &snapshots[index]
			previous.Machines = append(previous.Machines, snapshot.Machines...)
			previous.App.Regions[m.specs.cell] += snapshot.App.Regions[m.specs.cell]
			if snapshot.App.Version > previous.App.Version {
				previous.App.Version, previous.App.Config = snapshot.App.Version, snapshot.App.Config
			}
		} else {
			seen[name] = len(snapshots)
			snapshots = append(snapshots, snapshot)
		}
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
	if len(memberPins) > 0 {
		currentIntents, err := view.placements.ListIntents(ctx)
		if err != nil || !reflect.DeepEqual(intents, currentIntents) {
			return nil, errors.New("machines placement authority changed during observation")
		}
		for _, pin := range memberPins {
			state := pin.State
			current, err := view.placements.ReadMember(ctx, state.DatabaseID, state.PartitionID, state.MemberID)
			if err != nil || current.Revision != pin.Revision || !reflect.DeepEqual(current.State, pin.State) {
				return nil, errors.New("machines placement member changed during observation")
			}
		}
	}
	for index := range snapshots {
		slices.SortFunc(snapshots[index].Machines, func(a, b machinesapi.MachineView) int { return strings.Compare(a.ID, b.ID) })
	}
	currentProfiles, currentPolicies := m.specs.effective()
	if !reflect.DeepEqual(profiles, currentProfiles) || !reflect.DeepEqual(policies, currentPolicies) || !m.leader(ctx, epoch) || ctx.Err() != nil {
		return nil, errors.New("machines manager authority changed during observation")
	}
	slices.SortFunc(snapshots, func(a, b machinesapi.AppSnapshot) int { return strings.Compare(a.App.Name, b.App.Name) })
	return snapshots, nil
}

// Resolve business database/partition labels only through current admitted R3
// placement; canonical TerraBase database identity is a separate signed scope.
func (view *managerMachinesView) statefulOwner(ctx context.Context, service *api.Service, intents []placement.Intent) (placement.Intent, placement.VersionedMemberState, error) {
	labels := service.Spec.Annotations.Labels
	deny := func() (placement.Intent, placement.VersionedMemberState, error) {
		return placement.Intent{}, placement.VersionedMemberState{}, errors.New("machines stateful service differs from admitted placement")
	}
	if labels["terrascale.stateful"] != "true" || labels["terrascale.member-id"] == "" || labels["terrascale.placement-sha256"] == "" {
		return deny()
	}
	var matched *placement.Intent
	for index := range intents {
		intent := &intents[index]
		if intent.DatabaseID == labels["terrascale.database-id"] && intent.PartitionID == labels["terrascale.partition-id"] {
			if matched != nil || intent.PayloadDigest() != labels["terrascale.placement-sha256"] || intent.ValidateForAdmission() != nil {
				return deny()
			}
			matched = intent
		}
	}
	if matched == nil {
		return deny()
	}
	m := view.manager
	if labels[swarmruntime.LabelIntentID] != entityid.Derive("stateful-service", m.specs.identity.Environment, m.specs.cell, matched.DatabaseID, matched.PartitionID, labels["terrascale.member-id"]) {
		return deny()
	}
	pin, err := view.placements.ReadMember(ctx, matched.DatabaseID, matched.PartitionID, labels["terrascale.member-id"])
	if err != nil {
		return placement.Intent{}, placement.VersionedMemberState{}, err
	}
	state := pin.State
	region, err := state.Region.OCIRegion()
	if err != nil || state.Validate() != nil || pin.Revision == 0 || state.DatabaseID != matched.DatabaseID || state.PartitionID != matched.PartitionID || state.MemberID != labels["terrascale.member-id"] || region != labels[swarmruntime.LabelRegion] || state.IntentGeneration != matched.Generation || state.IntentPayloadDigest != matched.PayloadDigest() {
		return deny()
	}
	if state.Stage != placement.StageServing && state.Stage != placement.StageAwaitingHealthy && state.Stage != placement.StageDraining && state.Stage != placement.StageDrained {
		return deny()
	}
	row, err := matched.RosterRowForSeat(placement.Seat{MemberID: state.MemberID, Region: state.Region, FailureDomain: state.FailureDomain, Kind: state.Kind})
	if err != nil || row != state.CanonicalRosterRow {
		return deny()
	}
	rosterDigest, err := matched.CanonicalRosterDigest()
	if err != nil || rosterDigest != state.CanonicalRosterDigest {
		return deny()
	}
	return *matched, pin, nil
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
	if limits.NanoCPUs < 10_000_000 || limits.NanoCPUs > 1_000_000_000_000 || limits.MemoryBytes < 16<<20 {
		return machines.MachineConfig{}, errors.New("machines task resource limits are invalid")
	}
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
		delete(versions, task.ID)
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
		delete(versions, service.ID)
	}
	return len(versions) == 0
}
