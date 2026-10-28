package swarmruntime

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/gogo/protobuf/proto"
	"github.com/gogo/protobuf/types"
	"github.com/moby/swarmkit/v2/api"
)

// startFirstPlacementGrace is how long a start-first candidate may stay
// unplaced for lack of resources before its update falls back to stop-first.
const startFirstPlacementGrace = 5 * time.Second

// unplacedCandidate returns a start-first candidate the scheduler has refused
// for lack of resources since at least startFirstPlacementGrace ago: the old
// task's reservation leaves no room for both (E16: 2-CPU hosts).
func unplacedCandidate(service *api.Service, tasks []*api.Task, now time.Time) *api.Task {
	if service.Spec.Update == nil || service.Spec.Update.Order != api.UpdateConfig_START_FIRST {
		return nil
	}
	for _, task := range tasks {
		created, err := types.TimestampFromProto(task.Meta.CreatedAt)
		// SwarmKit's scheduler writes "no suitable node (insufficient resources on N node(s))".
		if err == nil && task.NodeID == "" && task.Status.State == api.TaskStatePending &&
			strings.Contains(task.Status.Err, "insufficient resources") && now.Sub(created) >= startFirstPlacementGrace {
			return task
		}
	}
	return nil
}

// stopFirst is update with the old task stopped before the candidate starts.
// The rewrite makes the candidate SwarmKit's previous spec, so a rollback would
// restore the candidate itself; pause instead and let the release roll back.
func stopFirst(update *api.UpdateConfig) *api.UpdateConfig {
	update = update.Copy()
	update.Order, update.FailureAction = api.UpdateConfig_STOP_FIRST, api.UpdateConfig_PAUSE
	return update
}

// candidateFailed reports a task of service's template that failed since the
// fallback. The restarted updater adopts the candidate without tracking its
// failures, so SwarmKit itself would neither pause nor roll back.
func candidateFailed(ctx context.Context, client api.ControlClient, service *api.Service, since time.Time) error {
	listed, err := client.ListTasks(ctx, &api.ListTasksRequest{Filters: &api.ListTasksRequest_Filters{ServiceIDs: []string{service.ID}, UpToDate: true}})
	if err != nil {
		return err
	}
	for _, task := range listed.Tasks {
		if (task.Status.State == api.TaskStateFailed || task.Status.State == api.TaskStateRejected) && TaskTime(task).After(since) {
			return fmt.Errorf("service %s candidate failed after the stop-first fallback: %s", service.Spec.Annotations.Name, task.Status.Err)
		}
	}
	return nil
}

// writeUpdatePolicy rewrites only the update policy of the spec service was
// read at; labels, generation and task template stay as written. SwarmKit then
// restarts the updater, which adopts the existing candidate and stops the old task.
func writeUpdatePolicy(ctx context.Context, client api.ControlClient, service *api.Service, update *api.UpdateConfig) (*api.Service, error) {
	unlock, err := lockServiceSpecs(ctx, client)
	if err != nil {
		return nil, err
	}
	defer unlock()
	latest, err := client.GetService(ctx, &api.GetServiceRequest{ServiceID: service.ID})
	if err != nil {
		return nil, err
	}
	if proto.Equal(latest.Service.Spec.Update, update) && sameWorkload(&latest.Service.Spec, &service.Spec) {
		return latest.Service, nil
	}
	if !proto.Equal(latest.Service.SpecVersion, service.SpecVersion) {
		return nil, fmt.Errorf("service %s changed during its update policy write", service.Spec.Annotations.Name)
	}
	spec := latest.Service.Spec.Copy()
	spec.Update = update.Copy()
	updated, err := client.UpdateService(ctx, &api.UpdateServiceRequest{ServiceID: service.ID, ServiceVersion: &latest.Service.Meta.Version, Spec: spec})
	if err != nil {
		return nil, err
	}
	return updated.Service, nil
}
