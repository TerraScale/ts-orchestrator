package swarmruntime

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"

	"github.com/moby/swarmkit/v2/api"
)

func ServingService(ctx context.Context, client api.ControlClient, name string) error {
	service, err := ServiceByName(ctx, client, name)
	if err != nil {
		return err
	}
	if service.Spec.GetReplicated() == nil || service.Spec.GetReplicated().Replicas == 0 {
		return fmt.Errorf("%s has no serving replicas", name)
	}
	if status := service.UpdateStatus; status != nil && status.State != api.UpdateStatus_UPDATING && status.State != api.UpdateStatus_COMPLETED && status.State != api.UpdateStatus_ROLLBACK_COMPLETED {
		return fmt.Errorf("%s update is not serving", name)
	}
	local, err := os.Hostname()
	if err != nil {
		return err
	}
	ready, err := ReadyService(ctx, client, service, func(ctx context.Context, task *api.Task) error {
		response, err := client.GetNode(ctx, &api.GetNodeRequest{NodeID: task.NodeID})
		if err != nil {
			return err
		}
		node := response.Node
		if node == nil || node.Description == nil || node.Status.State != api.NodeStatus_READY {
			return errors.New("service node is not ready")
		}
		if service.Spec.Annotations.Labels[LabelReadyPath] == "" {
			return nil
		}
		if node.Description.Hostname == local || node.Description.Hostname == singleHostID {
			return ProbeLocalTask(ctx, task)
		}
		address, err := netip.ParseAddr(node.Status.Addr)
		if err != nil || !address.Is4() || !address.IsPrivate() {
			return errors.New("service node has no private readiness address")
		}
		return ProbeTask(ctx, task, address)
	})
	if err != nil {
		return err
	}
	if !ready {
		return fmt.Errorf("%s is not serving its desired replicas", name)
	}
	return nil
}
