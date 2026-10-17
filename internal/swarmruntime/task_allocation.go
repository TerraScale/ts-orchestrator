package swarmruntime

import (
	"context"
	"errors"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/gogo/protobuf/proto"
	"github.com/moby/swarmkit/v2/api"
)

// VerifyTaskAllocation verifies a current nonterminal resource reservation.
// It grants no registry, material or execution authority.
func VerifyTaskAllocation(ctx context.Context, client api.ControlReader, task *api.Task, intent ServiceIntent, verified release.VerifiedContainer, roots trust.Keyring) error {
	ctx, cancel := context.WithDeadline(ctx, verified.ExpiresAt())
	defer cancel()
	if err := ctx.Err(); err != nil {
		return err
	}
	allocated := func(current *api.Task) bool {
		if current == nil || current.NodeID == "" || current.Status.State >= api.TaskStateCompleted {
			return false
		}
		_, knownStatus := api.TaskState_name[int32(current.Status.State)]
		_, knownDesired := api.TaskState_name[int32(current.DesiredState)]
		return knownStatus && knownDesired && proto.Equal(current, task)
	}
	if err := verifyServiceTask(ctx, client, task, intent, verified, roots, allocated); err != nil {
		return err
	}
	current, err := client.GetTask(ctx, &api.GetTaskRequest{TaskID: task.ID})
	if err != nil {
		return err
	}
	if current == nil || !allocated(current.Task) || !verified.Valid(time.Now().UTC()) {
		return errors.New("task reservation changed during allocation verification")
	}
	return ctx.Err()
}
