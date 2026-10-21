package app

import (
	"context"
	"errors"
	"sync/atomic"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/containermaterial"
	"github.com/TerraScale/ts-orchestrator/internal/delivery"
	"github.com/TerraScale/ts-orchestrator/internal/host"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/placement"
	"github.com/TerraScale/ts-orchestrator/internal/storage/execution"
	"github.com/TerraScale/ts-orchestrator/internal/storage/executionleader"
	"github.com/TerraScale/ts-orchestrator/internal/storage/executionwire"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
	"github.com/TerraScale/ts-orchestrator/internal/terrabase"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/moby/swarmkit/v2/api"
)

type statefulRuntimeConfig struct {
	Hosts               *host.Controller
	Client              api.ControlClient
	Authority           *authority.Runtime
	Members             placement.Store
	Delivery            *delivery.Service
	Volumes             *oci.VolumeMountObserver
	Roots               trust.Keyring
	HistoricalRoots     trust.Keyring
	Evidence            executionleader.EvidenceReader
	Allocations         executionleader.AllocationResolver
	RetainedEvidence    executionleader.EvidenceReader
	RetainedAllocations executionleader.AllocationResolver
	SessionGuard        func(context.Context) error
	Cell, Environment   string
}

type statefulRuntime struct {
	producer *executionleader.Producer
	effects  *swarmruntime.EffectSessions
	guard    func(context.Context) error
}

func newStatefulRuntime(config statefulRuntimeConfig) (*statefulRuntime, error) {
	if config.SessionGuard == nil {
		return nil, errors.New("stateful runtime requires the current admitted manager session")
	}
	producer, err := executionleader.NewProducer(config.Client, config.Authority, config.Members, config.Delivery,
		config.Volumes, config.Roots, config.Evidence, config.Cell, config.Environment, config.Allocations, config.RetainedEvidence, config.RetainedAllocations, config.HistoricalRoots, config.Hosts)
	if err != nil {
		return nil, err
	}
	effects, err := swarmruntime.NewEffectSessions(config.Client, config.Authority, producer, config.Volumes)
	if err != nil {
		return nil, err
	}
	return &statefulRuntime{producer: producer, effects: effects, guard: config.SessionGuard}, nil
}

// The host controller opens before the root manager connection is admitted.
// Requests remain pending until the complete producer and session pair exists.
type statefulRuntimeSlot struct {
	atomic.Pointer[statefulRuntime]
}

func (slot *statefulRuntimeSlot) apply(ctx context.Context, intent delivery.Intent) error {
	if intent.Role != terrabase.Role || intent.Container == nil {
		return execution.ErrUnsafe
	}
	runtime := slot.Load()
	if runtime == nil {
		return containermaterial.ErrPending
	}
	if err := runtime.guard(ctx); err != nil {
		return err
	}
	if err := runtime.producer.Apply(ctx, intent); err != nil {
		return err
	}
	return runtime.guard(ctx)
}

func (slot *statefulRuntimeSlot) HandleRuntimeEffect(ctx context.Context, caller host.RuntimeEffectCaller, query executionwire.RuntimeEffectQuery) (executionwire.WorkerGrantPayload, error) {
	runtime := slot.Load()
	if runtime == nil {
		return executionwire.WorkerGrantPayload{}, containermaterial.ErrPending
	}
	if err := runtime.guard(ctx); err != nil {
		return executionwire.WorkerGrantPayload{}, err
	}
	payload, err := runtime.effects.HandleRuntimeEffect(ctx, caller, query)
	if err != nil {
		return executionwire.WorkerGrantPayload{}, err
	}
	if err := runtime.guard(ctx); err != nil {
		return executionwire.WorkerGrantPayload{}, err
	}
	return payload, nil
}
