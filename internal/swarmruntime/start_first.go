package swarmruntime

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/gogo/protobuf/proto"
	"github.com/gogo/protobuf/types"
	"github.com/moby/swarmkit/v2/api"
	"github.com/moby/swarmkit/v2/manager/orchestrator"
)

// startFirstPlacementGrace is how long a start-first candidate may stay
// unplaced for lack of resources before its update falls back to stop-first.
const startFirstPlacementGrace = 5 * time.Second

func unplacedCandidates(requested *api.UpdateConfig, tasks []*api.Task, now time.Time) []*api.Task {
	if requested == nil || requested.Order != api.UpdateConfig_START_FIRST {
		return nil
	}
	var unplaced []*api.Task
	for _, task := range tasks {
		created, err := types.TimestampFromProto(task.Meta.CreatedAt)
		if err == nil && task.NodeID == "" && task.Status.State == api.TaskStatePending &&
			strings.Contains(task.Status.Err, "insufficient resources") && now.Sub(created) >= startFirstPlacementGrace {
			unplaced = append(unplaced, task)
		}
	}
	return unplaced
}

type UnplacedCandidateError struct {
	Service, Task, Reason string
	Serving               int
	Restored              bool
}

func (e *UnplacedCandidateError) Error() string {
	refused := fmt.Sprintf("service %s update refused: start-first candidate %s cannot be placed (%s) without stopping the last of %d serving tasks", e.Service, e.Task, e.Reason, e.Serving)
	if e.Restored {
		return refused + "; the previous spec is restored and its serving tasks keep serving"
	}
	return refused + "; they run neither this nor the previous spec, so they keep serving and the candidate stays pending"
}

type serviceRoom struct {
	serving      int
	endsService  bool
	servingSlots map[uint64]bool
}

func roomForCandidates(ctx context.Context, client api.ControlClient, service *api.Service, upToDate []*api.Task) (serviceRoom, error) {
	room := serviceRoom{servingSlots: map[uint64]bool{}}
	listed, err := client.ListTasks(ctx, &api.ListTasksRequest{Filters: &api.ListTasksRequest_Filters{ServiceIDs: []string{service.ID}}})
	if err != nil {
		return room, err
	}
	current := make(map[string]bool, len(upToDate))
	for _, task := range upToDate {
		current[task.ID] = true
	}
	var old uint64
	for _, task := range listed.Tasks {
		if task.Status.State != api.TaskStateRunning {
			continue
		}
		room.servingSlots[task.Slot] = true
		if task.DesiredState != api.TaskStateRunning {
			continue
		}
		room.serving++
		if !current[task.ID] {
			old++
		}
	}
	stopped := old
	if parallelism := service.Spec.Update.Parallelism; parallelism != 0 && parallelism < old {
		stopped = parallelism
	}
	room.endsService = room.serving != 0 && stopped == uint64(room.serving)
	return room, nil
}

func refuseUnplaced(ctx context.Context, client api.ControlClient, service *api.Service, previous *api.Service, requested *api.UpdateConfig, candidate *api.Task) error {
	unlock, err := lockServiceSpecs(ctx, client)
	if err != nil {
		return err
	}
	defer unlock()
	latest, err := client.GetService(ctx, &api.GetServiceRequest{ServiceID: service.ID})
	if err != nil {
		return err
	}
	if !proto.Equal(latest.Service.SpecVersion, service.SpecVersion) {
		return fmt.Errorf("service %s changed during its refused update", service.Spec.Annotations.Name)
	}
	listed, err := client.ListTasks(ctx, &api.ListTasksRequest{Filters: &api.ListTasksRequest_Filters{ServiceIDs: []string{service.ID}, DesiredStates: []api.TaskState{api.TaskStateRunning}}})
	if err != nil {
		return err
	}
	refusal := &UnplacedCandidateError{Service: service.Spec.Annotations.Name, Task: candidate.ID, Reason: candidate.Status.Err, Restored: previous != nil}
	for _, task := range listed.Tasks {
		if task.Status.State == api.TaskStateRunning {
			refusal.Serving++
			refusal.Restored = refusal.Restored && !orchestrator.IsTaskDirty(previous, task, nil)
		}
	}
	spec := latest.Service.Spec.Copy()
	spec.Update = requested.Copy()
	if refusal.Restored {
		spec = previous.Spec.Copy()
	} else if proto.Equal(latest.Service.Spec.Update, requested) {
		return refusal
	}
	if _, err := client.UpdateService(ctx, &api.UpdateServiceRequest{ServiceID: service.ID, ServiceVersion: &latest.Service.Meta.Version, Spec: spec}); err != nil {
		return err
	}
	return refusal
}

func previousService(service *api.Service) *api.Service {
	if service.PreviousSpec == nil {
		return nil
	}
	return &api.Service{ID: service.ID, Spec: *service.PreviousSpec.Copy(), SpecVersion: service.PreviousSpecVersion.Copy()}
}

// stopFirst is update with the old task stopped before the candidate starts.
// The rewrite makes the candidate SwarmKit's previous spec, so a rollback would
// restore the candidate itself; pause instead and let the release roll back.
func stopFirst(update *api.UpdateConfig) *api.UpdateConfig {
	update = update.Copy()
	update.Order, update.FailureAction = api.UpdateConfig_STOP_FIRST, api.UpdateConfig_PAUSE
	return update
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
