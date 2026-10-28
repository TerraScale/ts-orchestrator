package swarmruntime

import (
	"context"
	"path/filepath"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/storage/execution"
	"github.com/containerd/containerd/v2/core/images"
	"github.com/containerd/errdefs"
	"github.com/gofrs/flock"
	"github.com/moby/swarmkit/v2/api"
)

// Shared across executor instances and processes, including mesh pre-pulls.
func (e *Executor) imageGuard(ctx context.Context) (*flock.Flock, error) {
	guard := flock.New(filepath.Join(e.logRoot, "image-gc.lock"))
	if _, err := guard.TryRLockContext(ctx, 100*time.Millisecond); err != nil {
		_ = guard.Close()
		return nil, err
	}
	return guard, nil
}

// CollectImages removes only image records; containerd collects unleased content
// and snapshots. The caller holds desired-state serialization until this returns.
func (e *Executor) CollectImages(ctx context.Context, services []*api.Service, retained string) error {
	guard := flock.New(filepath.Join(e.logRoot, "image-gc.lock"))
	defer guard.Close()
	// A busy pull/prepare defers collection; it never delays a rollout.
	if locked, err := guard.TryLock(); err != nil || !locked {
		return err
	}
	for _, service := range services {
		for _, spec := range []*api.ServiceSpec{&service.Spec, service.PreviousSpec} {
			if spec == nil {
				continue
			}
			copy := spec.Copy()
			if g := copy.Task.GetGeneric(); g != nil && g.Kind == execution.StatefulContainerKind {
				g.Kind = ContainerKind
			}
			retained += runtimeDigest(*copy)
			retained += spec.Annotations.Labels[LabelDeploymentFloor]
		}
	}
	ctx = runtimeContext(ctx)
	containers, err := e.client.ContainerService().List(ctx)
	if err != nil {
		return err
	}
	for _, container := range containers {
		retained += container.Image // Includes stopped containers and unfinished prepares.
	}
	listed, err := e.client.ImageService().List(ctx)
	if err != nil {
		return err
	}
	for _, image := range listed {
		if strings.Contains(retained, image.Name) || strings.Contains(retained, image.Target.Digest.String()) {
			continue
		}
		if err := e.client.ImageService().Delete(ctx, image.Name, images.DeleteTarget(&image.Target)); err != nil && !errdefs.IsNotFound(err) {
			return err
		}
	}
	return nil
}
