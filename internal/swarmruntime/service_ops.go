package swarmruntime

import (
	"cmp"
	"context"
	jsonv1 "encoding/json"
	"fmt"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/gogo/protobuf/types"
	"github.com/moby/swarmkit/v2/api"
)

// RuntimeLogFile is where the executor's containerd logger writes one task's
// "stdout" or "stderr"; each file is truncated when it reaches its bounded size.
func RuntimeLogFile(stateDir, taskID, stream string) string {
	return filepath.Join(stateDir, "runtime-logs", "ts-"+taskID, stream)
}

// ServiceByName returns the named service of any kind, for read-only operator views.
func ServiceByName(ctx context.Context, client api.ControlClient, name string) (*api.Service, error) {
	listed, err := client.ListServices(ctx, &api.ListServicesRequest{Filters: &api.ListServicesRequest_Filters{Names: []string{name}}})
	if err != nil {
		return nil, err
	}
	for _, service := range listed.Services {
		if service.Spec.Annotations.Name == name {
			return service, nil
		}
	}
	return nil, fmt.Errorf("service %q not found; list services with `ts-orch service ls`", name)
}

// TaskRow is one `service ps` row. Restarts counts the exited tasks its slot
// retains; Exit is -1 until the container reports a status.
type TaskRow struct {
	ID, Node, State, Desired, Error string
	Since                           time.Time
	Slot                            uint64
	Restarts                        int
	Exit                            int32
	Terminal                        bool
}

// ServiceTasks lists the service's tasks, newest first, with node hostnames.
func ServiceTasks(ctx context.Context, client api.ControlClient, service *api.Service) ([]TaskRow, error) {
	listed, err := client.ListTasks(ctx, &api.ListTasksRequest{Filters: &api.ListTasksRequest_Filters{ServiceIDs: []string{service.ID}}})
	if err != nil {
		return nil, err
	}
	hosts := map[string]string{}
	for _, task := range listed.Tasks {
		if _, ok := hosts[task.NodeID]; !ok && task.NodeID != "" {
			hosts[task.NodeID] = task.NodeID
			if node, err := client.GetNode(ctx, &api.GetNodeRequest{NodeID: task.NodeID}); err == nil && node.Node.Description != nil {
				hosts[task.NodeID] = node.Node.Description.Hostname
			}
		}
	}
	return TaskRows(listed.Tasks, hosts, time.Now()), nil
}

// TaskRows builds newest-first rows; the newest task of a slot with
// CrashLoopFailures failures within CrashLoopWindow shows state CRASH-LOOP.
func TaskRows(tasks []*api.Task, hosts map[string]string, now time.Time) []TaskRow {
	restarts, recent := map[uint64]int{}, map[uint64]int{}
	rows := make([]TaskRow, 0, len(tasks))
	for _, task := range tasks {
		row := TaskRow{ID: task.ID, Node: hosts[task.NodeID], State: task.Status.State.String(), Slot: task.Slot,
			Desired: task.DesiredState.String(), Error: task.Status.Err, Since: TaskTime(task), Exit: -1,
			Terminal: task.Status.State > api.TaskStateRunning}
		if container := task.Status.GetContainer(); container != nil {
			row.Exit = container.ExitCode
		}
		switch task.Status.State {
		case api.TaskStateFailed, api.TaskStateRejected:
			if now.Sub(row.Since) < CrashLoopWindow {
				recent[task.Slot]++
			}
			restarts[task.Slot]++
		case api.TaskStateCompleted:
			restarts[task.Slot]++
		}
		rows = append(rows, row)
	}
	slices.SortFunc(rows, func(a, b TaskRow) int { return cmp.Or(b.Since.Compare(a.Since), strings.Compare(a.ID, b.ID)) })
	seen := map[uint64]bool{}
	for i := range rows {
		rows[i].Restarts = restarts[rows[i].Slot]
		if !seen[rows[i].Slot] && recent[rows[i].Slot] >= CrashLoopFailures {
			rows[i].State = "CRASH-LOOP"
		}
		seen[rows[i].Slot] = true
	}
	return rows
}

// TaskTime is when the task entered its current state.
func TaskTime(task *api.Task) time.Time {
	if t, err := types.TimestampFromProto(task.Status.Timestamp); err == nil {
		return t
	}
	return time.Time{}
}

// ServiceInspection is `service inspect` output: the declared spec with
// secret names only (their values never enter the service spec).
type ServiceInspection struct {
	ID          string      `json:"id"`
	Version     uint64      `json:"version"`
	CreatedAt   time.Time   `json:"createdAt"`
	UpdatedAt   time.Time   `json:"updatedAt"`
	ImageDigest string      `json:"imageDigest"`
	Spec        ServiceSpec `json:"spec"`
}

// InspectService maps the stored upstream service back to its declaration.
func InspectService(service *api.Service) (ServiceInspection, error) {
	container, err := containerOf(service.Spec)
	if err != nil {
		return ServiceInspection{}, err
	}
	labels := service.Spec.Annotations.Labels
	spec := ServiceSpec{Name: service.Spec.Annotations.Name, Image: container.Image, Args: container.Args,
		ReadyPath: labels[LabelReadyPath], Hostnames: splitLabel(labels[LabelHostnames])}
	if seconds, err := strconv.ParseUint(labels[LabelReadyTimeout], 10, 32); err == nil {
		spec.ReadyTimeoutSeconds = uint32(seconds)
	}
	if refs := labels[LabelSecretRefs]; refs != "" {
		if err := jsonv1.Unmarshal([]byte(refs), &spec.Secrets); err != nil {
			return ServiceInspection{}, fmt.Errorf("decode %s: %w", LabelSecretRefs, err)
		}
	}
	if replicated := service.Spec.GetReplicated(); replicated != nil {
		spec.Replicas = replicated.Replicas
	}
	// The fully reserved budget, so inspect shows what the service holds on its host.
	if r := service.Spec.Task.Resources; r != nil && r.Reservations != nil {
		spec.MilliCPU, spec.MemoryMiB = uint32(r.Reservations.NanoCPUs/1_000_000), uint32(r.Reservations.MemoryBytes>>20)
	}
	for _, entry := range container.Env {
		if spec.Env == nil {
			spec.Env = map[string]string{}
		}
		key, value, _ := strings.Cut(entry, "=")
		spec.Env[key] = value
	}
	for _, m := range container.Mounts {
		spec.Mounts = append(spec.Mounts, ServiceMount{Source: m.Source, Target: m.Target})
	}
	if port, err := strconv.ParseUint(labels[LabelPort], 10, 16); err == nil {
		spec.Port = uint32(port)
	}
	if service.Spec.Endpoint != nil && len(service.Spec.Endpoint.Ports) != 0 {
		spec.Port = service.Spec.Endpoint.Ports[0].PublishedPort
		if host := labels[LabelPostgres]; host != "" && len(service.Spec.Endpoint.Ports) == 2 {
			spec.Postgres = &ServicePostgres{Port: service.Spec.Endpoint.Ports[1].PublishedPort, Hostname: host}
		}
	}
	created, _ := types.TimestampFromProto(service.Meta.CreatedAt)
	updated, _ := types.TimestampFromProto(service.Meta.UpdatedAt)
	_, digest, _ := strings.Cut(container.Image, "@")
	return ServiceInspection{ID: service.ID, Version: service.Meta.Version.Index, CreatedAt: created, UpdatedAt: updated, ImageDigest: digest, Spec: spec}, nil
}

func splitLabel(value string) []string {
	if value == "" {
		return nil
	}
	return strings.Split(value, ",")
}
