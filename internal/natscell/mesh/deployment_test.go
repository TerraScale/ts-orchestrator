package mesh

import (
	"context"
	"fmt"

	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
	"github.com/moby/swarmkit/v2/api"
)

type evidenceApplier struct {
	fakeApplier
	revision    string
	waiting     func(swarmruntime.ServiceSpec)
	waitFailure error
}

func (a *evidenceApplier) Wait(_ context.Context, spec swarmruntime.ServiceSpec, _ *api.Service) (swarmruntime.ServiceRollout, error) {
	a.mu.Lock()
	unready := spec.Image == a.unready
	a.mu.Unlock()
	if unready {
		return swarmruntime.ServiceRollout{}, fmt.Errorf("test image not ready")
	}
	if a.waiting != nil {
		a.waiting(spec)
	}
	return swarmruntime.ServiceRollout{Revision: a.revision, Tasks: []swarmruntime.ServiceTaskEvidence{{Machine: spec.Node, Image: spec.Image, Generation: spec.Generation, Ready: true}}}, a.waitFailure
}
