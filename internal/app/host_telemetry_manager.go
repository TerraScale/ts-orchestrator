package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"maps"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/host"
	"github.com/TerraScale/ts-orchestrator/internal/hostload"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
	"github.com/gogo/protobuf/proto"
	"github.com/moby/swarmkit/v2/api"
)

// shortcut: native history cannot prove manager allocations; replace this refusal
// when an authenticated, durable manager allocation timeline is available.
func managerExpectedUsage(context.Context, time.Time, time.Time) ([]hostload.UsageInterval, error) {
	return nil, errors.New("historical manager task allocations are unavailable")
}

// recordManaged retains native DATA reservations and replaces migrated roles
// with each host's actual admitted task resources, including rollback tasks.
func (t *hostTelemetry) recordManaged(ctx context.Context, history *nativeHistory, usage *runtimeObservability,
	client api.ControlClient, observer swarmruntime.ManagementObservationClient, owns func(string) bool, verify func(context.Context, host.Registration, *api.Task) error,
	origin hostload.Origin, report hostload.Report,
) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if history == nil || history.hosts == nil || history.services == nil || client == nil || owns == nil || verify == nil || usage == nil {
		return errors.New("manager telemetry requires current host, task and reservation sources")
	}
	epoch := t.fencer.Current().Epoch
	if !t.fencer.Current().CanMutate() {
		return authority.ErrFenced
	}
	registration, err := telemetryRegistration(ctx, history, origin)
	if err != nil {
		return err
	}
	desired, err := history.hosts.ListDesired(ctx, "")
	if err != nil {
		return err
	}
	desired = slices.DeleteFunc(desired, func(d host.Desired) bool {
		return owns(d.Role) || d.Node != registration.Node || d.Environment != registration.Environment
	})
	profiles := profileResources(history.services.profiles())
	for role := range profiles {
		if owns(role) {
			delete(profiles, role)
		}
	}
	resources, err := history.resources(ctx, desired, profiles)
	if err != nil {
		return err
	}
	requests := loadRequests(resources)
	t.mu.Lock()
	if !t.current() {
		t.mu.Unlock()
		return authority.ErrFenced
	}
	previous := slices.Clone(t.usagePoints[origin])
	t.mu.Unlock()
	snapshot, source, continuous, err := readUsageSnapshot(ctx, observer, previous)
	if err != nil {
		return err
	}
	spec, err := history.services.kv.Get(ctx, cellSpecKey)
	if err != nil {
		return err
	}
	history.services.mu.Lock()
	adopted := history.services.revision
	history.services.mu.Unlock()
	if spec.Revision() != adopted {
		return errors.New("usage spec is not the adopted signed revision")
	}
	specDigest := fmt.Sprintf("%x", sha256.Sum256(spec.Value()))
	tasks, err := telemetrySnapshotTasks(history.services, snapshot.Nodes, snapshot.Tasks, registration, owns)
	if err != nil {
		return err
	}
	slices.SortFunc(tasks, func(a, b *api.Task) int { return strings.Compare(a.ID, b.ID) })
	managed := make(map[string]hostload.Request)
	pins := make(map[string][]hostload.TaskPin)
	var accepted []*api.Task
	var allocations []host.UsageTask
	for _, task := range tasks {
		role := task.ServiceAnnotations.Labels[swarmruntime.LabelRole]
		if !owns(role) {
			return errors.New("manager allocation role has no verified usage source")
		}
		if err := verify(ctx, registration, task); err != nil {
			return err
		}
		if _, err := swarmruntime.DecodeContainer(task); err != nil {
			return err
		}
		fingerprint, err := swarmruntime.ContainerTaskFingerprint(task)
		if err != nil {
			return err
		}
		pin := hostload.TaskPin{TaskID: task.ID, ServiceID: task.ServiceID, NodeID: task.NodeID, Fingerprint: fingerprint}
		pins[role] = append(pins[role], pin)
		requirements := task.Spec.Resources
		if requirements.Reservations == nil || !proto.Equal(requirements.Reservations, requirements.Limits) {
			return errors.New("manager task reservations differ from its executable limits")
		}
		allocations = append(allocations, host.UsageTask{Role: role, Task: pin,
			Request:       hostload.Request{CPUCores: float64(requirements.Reservations.NanoCPUs) / 1_000_000_000, MemoryBytes: requirements.Reservations.MemoryBytes},
			ReleaseSHA256: task.ServiceAnnotations.Labels["terrascale.release-fingerprint"], SpecSHA256: specDigest})
		request := managed[role]
		request.CPUCores += float64(requirements.Reservations.NanoCPUs) / 1_000_000_000
		memory := requirements.Reservations.MemoryBytes
		if memory <= 0 || request.MemoryBytes > hostload.MaxMemoryBytes-memory || request.CPUCores > hostload.MaxCPUCores {
			return errors.New("manager task reservations exceed host telemetry bounds")
		}
		request.MemoryBytes += memory
		managed[role] = request
		accepted = append(accepted, task)
	}
	for role, request := range managed {
		requests[role] = request
	}
	measured := make(map[string]hostload.RoleUsage)
	for _, role := range report.Roles {
		if !owns(role.Role) {
			continue
		}
		if _, allocated := managed[role.Role]; !allocated {
			return errors.New("host reported a managed role without a matching manager allocation")
		}
		measured[role.Role] = role
	}
	report.Roles = slices.DeleteFunc(slices.Clone(report.Roles), func(role hostload.RoleUsage) bool { return owns(role.Role) })
	for _, role := range slices.Sorted(maps.Keys(managed)) {
		value, exists := measured[role]
		if !exists {
			value = hostload.RoleUsage{Role: role, Tasks: pins[role]}
		} else {
			actual := make(map[string]hostload.TaskPin)
			for _, pin := range value.Tasks {
				actual[pin.TaskID] = pin
			}
			expected := make(map[string]hostload.TaskPin)
			for _, pin := range pins[role] {
				expected[pin.TaskID] = pin
			}
			if !maps.Equal(actual, expected) {
				return errors.New("host role measurements differ from its exact manager task set")
			}
		}
		report.Roles = append(report.Roles, value)
	}
	recheck := func(ctx context.Context) error {
		// Recheck inside the same authority CAS retry as the durable append.
		for _, task := range accepted {
			latest, err := client.GetTask(ctx, &api.GetTaskRequest{TaskID: task.ID})
			if err != nil {
				return err
			}
			if latest == nil || latest.Task == nil || latest.Task.NodeID != task.NodeID || latest.Task.DesiredState != task.DesiredState ||
				!proto.Equal(&latest.Task.Spec, &task.Spec) || !proto.Equal(&latest.Task.ServiceAnnotations, &task.ServiceAnnotations) {
				return errors.New("manager allocation changed while reading host telemetry")
			}
			if err := verify(ctx, registration, latest.Task); err != nil {
				return err
			}
		}
		confirmedTasks, err := telemetryTasks(ctx, history.services, client, registration, owns)
		if err != nil {
			return err
		}
		remaining := make(map[string]*api.Task)
		for _, task := range accepted {
			remaining[task.ID] = task
		}
		for _, task := range confirmedTasks {
			if !owns(task.ServiceAnnotations.Labels[swarmruntime.LabelRole]) {
				return errors.New("manager allocation role has no verified usage source")
			}
			before, exists := remaining[task.ID]
			if !exists || !proto.Equal(task, before) {
				return errors.New("manager task set changed while reading host telemetry")
			}
			if err := verify(ctx, registration, task); err != nil {
				return err
			}
			delete(remaining, task.ID)
		}
		if len(remaining) != 0 {
			return errors.New("manager task set changed while reading host telemetry")
		}
		current, err := telemetryRegistration(ctx, history, origin)
		if err != nil {
			return err
		}
		if !reflect.DeepEqual(current, registration) {
			return errors.New("host registration changed while reading task resources")
		}
		currentDesired, err := history.hosts.ListDesired(ctx, "")
		if err != nil {
			return err
		}
		currentDesired = slices.DeleteFunc(currentDesired, func(d host.Desired) bool {
			return owns(d.Role) || d.Node != registration.Node || d.Environment != registration.Environment
		})
		if !reflect.DeepEqual(currentDesired, desired) {
			return errors.New("native allocations changed while reading host telemetry")
		}
		currentProfiles := profileResources(history.services.profiles())
		for role := range currentProfiles {
			if owns(role) {
				delete(currentProfiles, role)
			}
		}
		currentResources, err := history.resources(ctx, currentDesired, currentProfiles)
		if err != nil {
			return err
		}
		if !maps.Equal(resources, currentResources) {
			return errors.New("native signed resources changed while reading host telemetry")
		}
		latestSpec, err := history.services.kv.Get(ctx, cellSpecKey)
		if err != nil {
			return err
		}
		history.services.mu.Lock()
		adopted := history.services.revision
		history.services.mu.Unlock()
		if latestSpec.Revision() != spec.Revision() || adopted != spec.Revision() || !bytes.Equal(latestSpec.Value(), spec.Value()) {
			return errors.New("adopted signed spec changed while reading host telemetry")
		}
		return nil
	}
	if err := recheck(ctx); err != nil {
		return err
	}
	// Only allocated roles belong to this recipient's historical requests.
	for role := range requests {
		if !slices.ContainsFunc(report.Roles, func(value hostload.RoleUsage) bool { return value.Role == role }) {
			delete(requests, role)
		}
	}
	slices.SortFunc(allocations, func(a, b host.UsageTask) int { return strings.Compare(a.Task.TaskID, b.Task.TaskID) })
	observation := host.UsageObservation{Registration: registration, DeploymentID: t.fencer.Current().DeploymentID, Epoch: epoch,
		Source: host.UsageSource{Version: source.Version, NodeID: source.NodeID, ClusterID: source.ClusterID, ServerEpoch: source.ServerEpoch, Term: source.Term, Leader: source.Leader},
		Tasks:  allocations, Requests: requests, Report: report}
	if continuous && len(previous) == 2 {
		observation.PriorSequence = previous[1].Entry.Sequence
		observation.PreviousSequence, observation.CoveredSequence = previous[0].Entry.Sequence, previous[1].Entry.Sequence
	}
	committed, err := history.hosts.CommitUsageObservation(ctx, observation, recheck)
	if err != nil {
		return err
	}
	// Recover retained points before appending a live point, including on the first report after restart.
	if _, err := t.restoreManagedUsage(ctx, history.hosts, usage); err != nil && !errors.Is(err, authority.ErrUsageHistoryTruncated) {
		return err
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if err := t.fencer.Guard(ctx, epoch); err != nil {
		return err
	}
	if !t.current() || t.epoch != epoch {
		return authority.ErrFenced
	}
	if t.managedRequests == nil {
		t.managedRequests = make(map[hostload.Origin]map[string]hostload.Request)
	}
	if before, known := t.managedRequests[origin]; known && !maps.Equal(before, requests) {
		t.load.Reset()
	}
	if len(t.managedRequests) >= 4096 {
		nodes := t.load.Nodes()
		for candidate := range t.managedRequests {
			if !slices.ContainsFunc(nodes, func(node hostload.NodeLoad) bool { return node.Origin == candidate }) {
				delete(t.managedRequests, candidate)
				delete(t.usagePoints, candidate)
			}
		}
		if _, exists := t.managedRequests[origin]; !exists && len(t.managedRequests) >= 4096 {
			return hostload.ErrTooManyNodes
		}
	}
	t.managedRequests[origin] = maps.Clone(requests)
	if t.usagePoints == nil {
		t.usagePoints = make(map[hostload.Origin][]host.CommittedUsage)
	}
	points := append(previous, committed)
	if len(points) > 2 {
		points = points[len(points)-2:]
	}
	t.usagePoints[origin] = points
	return t.load.RecordRequests(origin, report, requests)
}

func telemetryRegistration(ctx context.Context, history *nativeHistory, origin hostload.Origin) (host.Registration, error) {
	hosts, err := history.hosts.ListHosts(ctx)
	if err != nil {
		return host.Registration{}, err
	}
	var registration host.Registration
	for _, status := range hosts {
		candidate := status.Registration
		if candidate.Node != origin.Node || candidate.Cell != origin.Cell || candidate.Environment != origin.Environment {
			continue
		}
		if registration.ID != "" || status.Retired {
			return host.Registration{}, errors.New("telemetry host registration is retired or ambiguous")
		}
		registration = candidate
	}
	if registration.ID == "" {
		return host.Registration{}, errors.New("telemetry host registration is unavailable")
	}
	return registration, nil
}

func telemetryTasks(ctx context.Context, specs *specRegistry, client api.ControlReader, registration host.Registration, owns func(string) bool) ([]*api.Task, error) {
	response, err := client.ListNodes(ctx, &api.ListNodesRequest{})
	if err != nil {
		return nil, err
	}
	if response == nil {
		return nil, errors.New("manager node inventory is unavailable")
	}
	listed, err := client.ListTasks(ctx, &api.ListTasksRequest{})
	if err != nil {
		return nil, err
	}
	if listed == nil {
		return nil, errors.New("manager task inventory is unavailable")
	}
	return telemetrySnapshotTasks(specs, response.Nodes, listed.Tasks, registration, owns)
}

func telemetrySnapshotTasks(specs *specRegistry, nodes []*api.Node, allTasks []*api.Task, registration host.Registration, owns func(string) bool) ([]*api.Task, error) {
	if owns == nil {
		return nil, errors.New("manager allocation role source is unavailable")
	}
	if len(nodes) > 4096 || len(allTasks) > 4096 {
		return nil, errors.New("manager inventory exceeds telemetry bounds")
	}
	region := catalog.OCIRegion(strings.ToUpper(registration.Cell))
	nodeID := ""
	for _, node := range nodes {
		if node == nil || node.Spec.Membership != api.NodeMembershipAccepted || node.Spec.Annotations.Labels[swarmruntime.LabelRegion] != region {
			continue
		}
		matches := node.Spec.Annotations.Name == registration.ID
		if node.Role == api.NodeRoleManager {
			matches = specs.controllerNode(registration.Cell, node.Spec.Annotations.Name) == registration.Node
		}
		if !matches {
			continue
		}
		if nodeID != "" {
			return nil, errors.New("manager has ambiguous telemetry host assignments")
		}
		nodeID = node.ID
	}
	if nodeID == "" {
		if slices.ContainsFunc(registration.Roles, owns) {
			return nil, errors.New("manager allocation node is unavailable for its registered role")
		}
		return nil, nil
	}
	var tasks []*api.Task
	for _, task := range allTasks {
		if task == nil || task.NodeID != nodeID {
			continue
		}
		if _, known := api.TaskState_name[int32(task.Status.State)]; !known {
			return nil, fmt.Errorf("manager task %s has an unknown allocation state", task.ID)
		}
		if task.Status.State >= api.TaskStateCompleted {
			continue
		}
		labels := task.ServiceAnnotations.Labels
		if task.NodeID != nodeID || labels[swarmruntime.LabelRegion] != region || labels[swarmruntime.LabelEnvironment] != registration.Environment {
			return nil, fmt.Errorf("manager task %s differs from its telemetry recipient", task.ID)
		}
		tasks = append(tasks, task)
	}
	return tasks, nil
}
