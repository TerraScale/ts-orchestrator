package app

import (
	"context"
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

// recordManaged retains native DATA reservations and replaces migrated roles
// with each host's actual admitted task resources, including rollback tasks.
func (t *hostTelemetry) recordManaged(ctx context.Context, history *nativeHistory, usage *runtimeObservability,
	client api.ControlClient, owns func(string) bool, verify func(context.Context, host.Registration, *api.Task) error,
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
	desired = slices.DeleteFunc(desired, func(d host.Desired) bool { return owns(d.Role) })
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
	tasks, err := telemetryTasks(ctx, history.services, client, registration)
	if err != nil {
		return err
	}
	managed := make(map[string]hostload.Request)
	var accepted []*api.Task
	for _, task := range tasks {
		role := task.ServiceAnnotations.Labels[swarmruntime.LabelRole]
		if !owns(role) {
			continue
		}
		if err := verify(ctx, registration, task); err != nil {
			return err
		}
		if _, err := swarmruntime.DecodeContainer(task); err != nil {
			return err
		}
		requirements := task.Spec.Resources
		if requirements.Reservations == nil || !proto.Equal(requirements.Reservations, requirements.Limits) {
			return errors.New("manager task reservations differ from its executable limits")
		}
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
		measured[role.Role] = role
	}
	report.Roles = slices.DeleteFunc(slices.Clone(report.Roles), func(role hostload.RoleUsage) bool { return owns(role.Role) })
	for _, role := range slices.Sorted(maps.Keys(managed)) {
		value, exists := measured[role]
		if !exists {
			value = hostload.RoleUsage{Role: role}
		}
		report.Roles = append(report.Roles, value)
	}
	// Assignment or enrollment changes during the read invalidate this sample;
	// prior accounting history remains retained, never rewritten to new requests.
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
	current, err := telemetryRegistration(ctx, history, origin)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(current, registration) {
		return errors.New("host registration changed while reading task resources")
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
			}
		}
		if _, exists := t.managedRequests[origin]; !exists && len(t.managedRequests) >= 4096 {
			return hostload.ErrTooManyNodes
		}
	}
	t.managedRequests[origin] = maps.Clone(requests)
	return usage.recordHostLoad(func(origin hostload.Origin, report hostload.Report) error {
		return t.load.RecordRequests(origin, report, requests)
	}, origin, report, requests)
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

func telemetryTasks(ctx context.Context, specs *specRegistry, client api.ControlClient, registration host.Registration) ([]*api.Task, error) {
	response, err := client.ListNodes(ctx, &api.ListNodesRequest{})
	if err != nil {
		return nil, err
	}
	if response == nil {
		return nil, errors.New("manager node inventory is unavailable")
	}
	region := catalog.OCIRegion(strings.ToUpper(registration.Cell))
	nodeID := ""
	for _, node := range response.Nodes {
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
		return nil, nil
	}
	listed, err := client.ListTasks(ctx, &api.ListTasksRequest{Filters: &api.ListTasksRequest_Filters{NodeIDs: []string{nodeID}}})
	if err != nil {
		return nil, err
	}
	if listed == nil || len(listed.Tasks) > 4096 {
		return nil, errors.New("manager task inventory is unavailable or oversized")
	}
	var tasks []*api.Task
	for _, task := range listed.Tasks {
		if task == nil || task.DesiredState > api.TaskStateRunning {
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
