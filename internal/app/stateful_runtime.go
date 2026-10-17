package app

import (
	"context"
	"errors"
	"sync/atomic"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/containermaterial"
	"github.com/TerraScale/ts-orchestrator/internal/delivery"
	"github.com/TerraScale/ts-orchestrator/internal/host"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/placement"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/storage/execution"
	"github.com/TerraScale/ts-orchestrator/internal/storage/executionleader"
	"github.com/TerraScale/ts-orchestrator/internal/storage/executionwire"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
	"github.com/TerraScale/ts-orchestrator/internal/terrabase"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/moby/swarmkit/v2/api"
)

type statefulRuntimeConfig struct {
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
		config.Volumes, config.Roots, config.Evidence, config.Cell, config.Environment, config.Allocations, config.RetainedEvidence, config.RetainedAllocations, config.HistoricalRoots)
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

func (slot *statefulRuntimeSlot) ObserveRuntimeReadiness(ctx context.Context, challenge host.ContainerReadinessChallenge, hosts *host.Controller) (protocol.Envelope, error) {
	runtime := slot.Load()
	if runtime == nil {
		return protocol.Envelope{}, containermaterial.ErrPending
	}
	if err := runtime.guard(ctx); err != nil {
		return protocol.Envelope{}, err
	}
	envelope, err := runtime.effects.ObserveRuntimeReadiness(ctx, challenge, hosts)
	if err != nil {
		return protocol.Envelope{}, err
	}
	if err := runtime.guard(ctx); err != nil {
		return protocol.Envelope{}, err
	}
	return envelope, nil
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

func (slot *statefulRuntimeSlot) CheckTaskReadiness(ctx context.Context, task *api.Task, hosts *host.Controller) error {
	_, err := slot.CaptureTaskReadiness(ctx, task, hosts)
	return err
}

type statefulTaskReadiness struct {
	slot    *statefulRuntimeSlot
	runtime *statefulRuntime
	witness *swarmruntime.TaskReadinessWitness
}

func (w *statefulTaskReadiness) Deadline() time.Time {
	if w == nil {
		return time.Time{}
	}
	return w.witness.Deadline()
}

func (w *statefulTaskReadiness) Recheck(ctx context.Context) error {
	if w == nil || w.slot == nil || w.runtime == nil || w.slot.Load() != w.runtime {
		return execution.ErrUnsafe
	}
	if err := w.runtime.guard(ctx); err != nil {
		return err
	}
	if err := w.witness.Recheck(ctx); err != nil {
		return err
	}
	if w.slot.Load() != w.runtime {
		return execution.ErrUnsafe
	}
	return w.runtime.guard(ctx)
}

func (slot *statefulRuntimeSlot) CaptureTaskReadiness(ctx context.Context, task *api.Task, hosts *host.Controller) (*statefulTaskReadiness, error) {
	runtime := slot.Load()
	if runtime == nil {
		return nil, containermaterial.ErrPending
	}
	if err := runtime.guard(ctx); err != nil {
		return nil, err
	}
	witness, err := runtime.effects.CaptureTaskReadiness(ctx, task, hosts)
	if err != nil {
		return nil, err
	}
	if slot.Load() != runtime {
		return nil, execution.ErrUnsafe
	}
	if err := runtime.guard(ctx); err != nil {
		return nil, err
	}
	return &statefulTaskReadiness{slot: slot, runtime: runtime, witness: witness}, nil
}
