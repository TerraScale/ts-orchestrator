package app

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/functionmaterial"
	"github.com/moby/swarmkit/v2/api"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (controller functionController) retireMaterial(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	retired, err := controller.config.Material.RetireExpired(ctx, controller.config.Retirement, controller.requireUnusedMaterial)
	for _, secret := range retired {
		if secret.TaskID != "" {
			slog.InfoContext(ctx, "expired function material retirement scheduled", "secret_id", secret.SecretID,
				"name", secret.Name, "task_id", secret.TaskID, "material_sha256", secret.MaterialSHA256,
				"expires_at", secret.ExpiresAt, "delete_at", secret.DeleteAt)
		}
	}
	return err
}

func (controller functionController) requireUnusedMaterial(ctx context.Context, binding functionmaterial.Binding) error {
	epoch := controller.config.Authority.Current().Epoch
	if err := controller.config.Authority.Guard(ctx, epoch); err != nil {
		return err
	}
	response, err := controller.config.Client.GetTask(ctx, &api.GetTaskRequest{TaskID: binding.TaskID})
	if status.Code(err) == codes.NotFound {
		return controller.config.Authority.Guard(ctx, epoch)
	}
	if err != nil {
		return err
	}
	if response == nil || response.Task == nil {
		return errors.New("function material retirement requires an authoritative task observation")
	}
	task := response.Task
	if task.ID != binding.TaskID || task.ServiceID != binding.ServiceID || task.NodeID != binding.NodeID {
		return errors.New("function material retirement task differs from its immutable recipient")
	}
	// Desired shutdown alone does not prove that the assigned process stopped.
	switch task.Status.State {
	case api.TaskStateCompleted, api.TaskStateShutdown, api.TaskStateFailed, api.TaskStateRejected, api.TaskStateRemove, api.TaskStateOrphaned:
		return controller.config.Authority.Guard(ctx, epoch)
	default:
		return errors.New("function material remains referenced by an assigned task")
	}
}
