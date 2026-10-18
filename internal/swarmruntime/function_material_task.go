package swarmruntime

import (
	"context"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/gogo/protobuf/proto"
	"github.com/moby/swarmkit/v2/api"
)

// VerifyFunctionMaterialTask authorizes only an exact current manager recipe.
// Callers independently verify the pinned worker bundle and allocation winner,
// then recheck recipient, current roots/epoch and live grants before delivery.
func VerifyFunctionMaterialTask(ctx context.Context, client api.ControlClient, task *api.Task, intent FunctionServiceIntent, current CurrentFunctionIntent, worker release.VerifiedContainer) error {
	if client == nil || current == nil || task == nil || task.ID == "" || task.ServiceID == "" || task.NodeID == "" || task.DesiredState != api.TaskStateRunning {
		return errors.New("function material requires current authority and an assigned task")
	}
	function, err := current.CurrentFunction(ctx, intent.TenantID, intent.FunctionID)
	if err != nil {
		return err
	}
	expected, err := ContainerTaskFingerprint(task)
	if err != nil {
		return err
	}
	readCurrent := func() (*api.Task, *api.Service, error) {
		assignment, err := client.GetTask(ctx, &api.GetTaskRequest{TaskID: task.ID})
		if err != nil {
			return nil, nil, err
		}
		if assignment == nil || assignment.Task == nil || assignment.Task.ID != task.ID || assignment.Task.NodeID != task.NodeID || assignment.Task.ServiceID != task.ServiceID || assignment.Task.DesiredState != api.TaskStateRunning || assignment.Task.Status.State < api.TaskStateAssigned || assignment.Task.Status.State > api.TaskStateRunning || !proto.Equal(&assignment.Task.Spec, &task.Spec) || !proto.Equal(&assignment.Task.ServiceAnnotations, &task.ServiceAnnotations) {
			return nil, nil, errors.New("function material task differs from the current manager assignment")
		}
		fingerprint, err := ContainerTaskFingerprint(assignment.Task)
		if err != nil || fingerprint != expected {
			return nil, nil, errors.New("function material task fingerprint differs from the current assignment")
		}
		service, err := client.GetService(ctx, &api.GetServiceRequest{ServiceID: task.ServiceID})
		if err != nil {
			return nil, nil, err
		}
		if service == nil || service.Service == nil || service.Service.ID != task.ServiceID {
			return nil, nil, errors.New("function material requires an available current service")
		}
		if err := intent.VerifyTask(assignment.Task, service.Service, function, worker); err != nil {
			return nil, nil, err
		}
		return assignment.Task, service.Service, nil
	}
	assigned, service, err := readCurrent()
	if err != nil {
		return err
	}
	if functionServiceRollback(service) {
		if err := intent.verifyRetainedWorkerFloor(ctx, client, worker); err != nil {
			return err
		}
	} else if err := intent.VerifyWorkerFloor(ctx, client, worker); err != nil {
		return err
	}
	latestTask, latestService, err := readCurrent()
	if err != nil {
		return err
	}
	if !proto.Equal(assigned, latestTask) || !proto.Equal(service, latestService) {
		return errors.New("function material manager assignment or current recipe changed during admission")
	}
	latest, err := current.CurrentFunction(ctx, intent.TenantID, intent.FunctionID)
	if err != nil {
		return err
	}
	if !latest.Valid() || latest.EnvelopeSHA256() != function.EnvelopeSHA256() || !worker.Valid(time.Now().UTC()) {
		return errors.New("function material authority changed during current-task admission")
	}
	return ctx.Err()
}

func functionServiceRollback(service *api.Service) bool {
	if service == nil || service.UpdateStatus == nil {
		return false
	}
	switch service.UpdateStatus.State {
	case api.UpdateStatus_ROLLBACK_STARTED, api.UpdateStatus_ROLLBACK_COMPLETED, api.UpdateStatus_ROLLBACK_PAUSED:
		return true
	default:
		return false
	}
}

// The caller must first authorize the exact recipe; this comparison grants no task authority.
func (intent FunctionServiceIntent) verifyRetainedWorkerFloor(ctx context.Context, client api.ControlClient, worker release.VerifiedContainer) error {
	claim := worker.Claim()
	workerIntent := ServiceIntent{ID: entityid.Derive("function-worker-release", intent.Environment, intent.Region), Role: FunctionWorkerRole, Region: intent.Region, Environment: intent.Environment, Architecture: intent.Architecture}
	name, err := releaseFloorName(workerIntent, worker)
	if err != nil {
		return err
	}
	listed, err := client.ListConfigs(ctx, &api.ListConfigsRequest{Filters: &api.ListConfigsRequest_Filters{Names: []string{name}}})
	if err != nil {
		return err
	}
	if listed == nil || len(listed.Configs) != 1 || listed.Configs[0] == nil {
		return errors.New("retained function worker task has no unique durable worker floor")
	}
	floor := listed.Configs[0]
	for key, value := range map[string]string{LabelIntentID: workerIntent.ID, LabelRole: FunctionWorkerRole, LabelRegion: intent.Region, LabelEnvironment: intent.Environment, labelReleaseArchitecture: intent.Architecture} {
		if floor.Spec.Annotations.Labels[key] != value {
			return errors.New("retained function worker floor ownership differs")
		}
	}
	if worker.Genesis().IsVerified() {
		if err := authenticateReleaseFloor(ctx, client, workerIntent, worker, nil, floor); err != nil {
			return err
		}
	} else {
		migration, err := trust.DecodeEnvelope(floor.Spec.Data)
		if err != nil {
			return err
		}
		migrationFingerprint, err := trust.Fingerprint(migration)
		if err != nil || migrationFingerprint != claim.SequenceMigrationSHA256 {
			return errors.New("retained function worker ordering namespace differs")
		}
	}
	labels := floor.Spec.Annotations.Labels
	sequence, err := strconv.ParseUint(labels[labelReleaseSequence], 10, 64)
	_, digestErr := hex.DecodeString(labels[labelReleaseFingerprint])
	if floor.Spec.Annotations.Name != name || err != nil || sequence < claim.ReleaseSequence || digestErr != nil || len(labels[labelReleaseFingerprint]) != 64 || strings.ToLower(labels[labelReleaseFingerprint]) != labels[labelReleaseFingerprint] || sequence == claim.ReleaseSequence && labels[labelReleaseFingerprint] != worker.ReleaseIdentity() {
		return errors.New("retained function worker is not admitted by the durable floor")
	}
	return ctx.Err()
}
