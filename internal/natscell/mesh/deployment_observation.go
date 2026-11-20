package mesh

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"strconv"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/appregistry"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/releasepush"
	"github.com/TerraScale/ts-orchestrator/internal/secretpreflight"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
	"github.com/moby/swarmkit/v2/api"
)

func ObserveDeployments(ctx context.Context, state, region string) (releasepush.DeploymentObservation, error) {
	conn, err := Connect(state)
	if err != nil {
		return releasepush.DeploymentObservation{}, err
	}
	defer conn.Close()
	payload, err := json.Marshal(map[string]string{"view": "deployments", "region": region})
	if err != nil {
		return releasepush.DeploymentObservation{}, err
	}
	var report releasepush.DeploymentObservation
	var decodeErr error
	err = collect(ctx, conn, StateSubject, payload, 1, 15*time.Second, func(data []byte) bool {
		decodeErr = protocol.DecodeTolerant(data, &report, maxWire)
		return false
	})
	err = errors.Join(err, decodeErr)
	if err == nil && (report.Region != region || report.Apps == nil) {
		err = errors.New("regional deployment inventory did not answer")
	}
	return report, err
}

func (n *Node) observeDeployments() releasepush.DeploymentObservation {
	ctx, cancel := context.WithTimeout(n.ctx, 10*time.Second)
	defer cancel()
	report := releasepush.DeploymentObservation{Region: n.cfg.region, Host: n.cfg.server, Apps: map[string]releasepush.AppDeployment{}}
	a, ok := n.cfg.applier.(swarmApplier)
	if !ok {
		report.Error = "regional runtime observation unavailable"
		return report
	}
	client, close, err := a.control()
	if err != nil {
		report.Error = err.Error()
		return report
	}
	defer close()
	nodes, err := client.ListNodes(ctx, &api.ListNodesRequest{})
	if err != nil {
		report.Error = err.Error()
		return report
	}
	hosts := map[string]string{}
	for _, node := range nodes.Nodes {
		if node.Description != nil {
			hosts[node.ID] = node.Description.Hostname
		}
	}
	desired := n.stateDesired.Load()
	for _, target := range appregistry.Targets {
		if target.Service == "app-canary" {
			continue
		}
		app := releasepush.AppDeployment{Host: n.cfg.server}
		state := (*desired)[target.Service]
		entry := state.entry()
		if entry.Spec != nil {
			app.Placement = &releasepush.Placement{Generation: entry.Generation, RollbackOf: entry.RollbackOf, Regions: entry.Spec.Regions}
		}
		services, err := client.ListServices(ctx, &api.ListServicesRequest{Filters: &api.ListServicesRequest_Filters{Names: []string{target.Service}}})
		if err != nil {
			app.Error = err.Error()
			report.Apps[target.Service] = app
			continue
		}
		var ids []string
		for _, service := range services.Services {
			ids = append(ids, service.ID)
			if replicated := service.Spec.GetReplicated(); replicated != nil {
				app.Replicas += replicated.Replicas
			}
			if service.UpdateStatus != nil {
				app.Reason = service.UpdateStatus.Message
				app.Failed = service.UpdateStatus.State == api.UpdateStatus_PAUSED || service.UpdateStatus.State == api.UpdateStatus_ROLLBACK_PAUSED
			}
		}
		if len(ids) == 0 {
			switch {
			case entry.Spec == nil:
				app.Reason = "this region holds no desired spec for the service"
			case entry.Spec.RunsIn(n.cfg.region):
				app.Reason = "service is declared in this region but not created"
			default:
				app.Reason = "service is not declared in this region"
			}
			report.Apps[target.Service] = app
			continue
		}
		tasks, err := client.ListTasks(ctx, &api.ListTasksRequest{Filters: &api.ListTasksRequest_Filters{ServiceIDs: ids}})
		if err != nil {
			app.Error = err.Error()
			report.Apps[target.Service] = app
			continue
		}
		for _, task := range tasks.Tasks {
			row := releasepush.DeploymentTask{ID: task.ID, Host: hosts[task.NodeID], State: task.Status.State.String(), Error: secretpreflight.Scrub(task.Status.Err), StatusAt: swarmruntime.TaskTime(task)}
			row.Generation, _ = strconv.ParseInt(task.ServiceAnnotations.Labels[swarmruntime.LabelGeneration], 10, 64)
			if !row.StatusAt.IsZero() {
				row.StatusAgeSeconds = max(0, int64(time.Since(row.StatusAt).Seconds()))
			}
			row.Reason = row.Error
			if task.Status.State != api.TaskStateRunning && row.Reason == "" {
				row.Reason = secretpreflight.Scrub(task.Status.Message)
			}
			if task.Status.State == api.TaskStateFailed || task.Status.State == api.TaskStateRejected {
				app.FailedTasks = append(app.FailedTasks, row)
			}
			if task.Status.State != api.TaskStateRunning && task.DesiredState != api.TaskStateRunning {
				continue
			}
			container, err := swarmruntime.DecodeContainer(task)
			if err == nil && task.Status.State == api.TaskStateRunning {
				row.Image = container.Image
				row.Revision, err = swarmruntime.ImageRevision(ctx, swarmruntime.HostContainerdSocket, container.Image)
			}
			if err != nil {
				app.Error = "task revision unavailable: " + err.Error()
			}
			app.Failed = app.Failed || task.Status.State == api.TaskStateFailed || task.Status.State == api.TaskStateRejected
			app.Tasks = append(app.Tasks, row)
		}
		if entry.Spec != nil && entry.Spec.RunsIn(n.cfg.region) {
			generation := entry.Generation
			if entry.RollbackOf != 0 {
				generation = entry.RollbackOf
				app.Failed = true
				app.Reason = fmt.Sprintf("rolled back generation %d", generation)
			}
			record, err := n.readBake(target.Service, generation)
			if snapshot := n.stateUnsaved.Load(); snapshot != nil {
				if retained, ok := (*snapshot)[n.bakePath(target.Service, generation)]; ok {
					record, err = retained, nil
				}
			}
			if err != nil && !errors.Is(err, os.ErrNotExist) {
				app.Error = "bake record unreadable: " + err.Error()
			}
			if err == nil {
				identity, identityErr := bakeIdentity(state)
				app.Complete = identityErr == nil && record.Identity == identity && !record.Bake.Finished.IsZero() && record.Bake.Reason == "" && !record.Bake.Unsaved && entry.RollbackOf == 0
				if app.Complete {
					app.PassedAt = record.Bake.Finished
				}
				if !app.Complete && app.Reason == "" {
					app.Reason = "regional bake has not completed"
				}
				if record.Bake.LastFailure != "" {
					app.Reason = record.Bake.LastFailure
				}
				if record.Bake.Reason != "" {
					app.Failed, app.Reason = true, record.Bake.Reason
				}
			}
		}
		slices.SortFunc(app.Tasks, func(a, b releasepush.DeploymentTask) int {
			return slices.Compare([]string{a.Host, a.Revision, a.State}, []string{b.Host, b.Revision, b.State})
		})
		slices.SortFunc(app.FailedTasks, func(a, b releasepush.DeploymentTask) int {
			return slices.Compare([]string{a.Host, a.ID}, []string{b.Host, b.ID})
		})
		if len(app.Tasks) == 0 {
			app.Reason = fmt.Sprintf("%s reports no running or pending %s task", n.cfg.server, target.Service)
		}
		report.Apps[target.Service] = app
	}
	return report
}
