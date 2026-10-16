package app

import (
	"context"
	"errors"

	"github.com/TerraScale/ts-orchestrator/internal/host"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
)

// containerMaterialSource reuses the worker's existing authenticated ownhost
// session. The controller independently authenticates every task selector.
type containerMaterialSource struct{ agent *host.Agent }

func (source containerMaterialSource) CurrentContainerMaterial(ctx context.Context, binding swarmruntime.ContainerTaskBinding) (swarmruntime.ContainerMaterial, error) {
	if source.agent == nil {
		return swarmruntime.ContainerMaterial{}, errors.New("container material requires the existing ownhost session")
	}
	files, err := source.agent.CurrentContainerFiles(ctx, host.ContainerMaterialBinding{
		TaskID: binding.TaskID, ServiceID: binding.ServiceID, NodeID: binding.NodeID,
		InstanceID: binding.InstanceID, Region: binding.Region, HostID: binding.HostID, Fingerprint: binding.Fingerprint,
	})
	if err != nil {
		return swarmruntime.ContainerMaterial{}, err
	}
	return swarmruntime.ContainerMaterial{Binding: binding, ExpiresAt: files.ExpiresAt, CredentialExpiresAt: files.CredentialExpiresAt,
		User: files.User, Files: files.Files, FileEnvironment: files.FileEnvironment}, nil
}
