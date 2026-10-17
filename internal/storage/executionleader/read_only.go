package executionleader

import (
	"context"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/delivery"
	"github.com/TerraScale/ts-orchestrator/internal/host"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/placement"
	"github.com/TerraScale/ts-orchestrator/internal/storage/execution"
	"github.com/TerraScale/ts-orchestrator/internal/storage/executionwire"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/moby/swarmkit/v2/api"
)

type ReadOnlyVerifierConfig struct {
	Client                           api.ControlReader
	Authority                        *authority.Reader
	Lease                            *authority.LeaseAdmission
	Members                          placement.MemberPinReader
	Delivery                         *delivery.Service
	Volumes                          *oci.VolumeMountObserver
	Roots, HistoricalRoots           trust.Keyring
	Evidence, RetainedEvidence       EvidenceReader
	Allocations, RetainedAllocations AllocationResolver
	Cell, Environment                string
}

// ReadOnlyVerifier shares the production material verifier, without service writes.
type ReadOnlyVerifier struct{ *producerVerifier }

func (v *ReadOnlyVerifier) Resolve(ctx context.Context, task *api.Task, caller host.RuntimeEffectCaller) (executionwire.WorkerGrantMaterial, error) {
	if v == nil || v.producerVerifier == nil {
		return executionwire.WorkerGrantMaterial{}, execution.ErrUnsafe
	}
	return v.producerVerifier.Resolve(ctx, task, caller)
}

func (v *ReadOnlyVerifier) VerifyCurrent(ctx context.Context, task *api.Task, caller host.RuntimeEffectCaller, material executionwire.WorkerGrantMaterial) error {
	if v == nil || v.producerVerifier == nil {
		return execution.ErrUnsafe
	}
	return v.producerVerifier.VerifyCurrent(ctx, task, caller, material)
}

func NewReadOnlyVerifier(c ReadOnlyVerifierConfig) (*ReadOnlyVerifier, error) {
	if c.Authority == nil || c.Lease == nil {
		return nil, execution.ErrUnsafe
	}
	v, err := newProducerVerifier(c.Client, readOnlyProducerAuthority{Reader: c.Authority, lease: c.Lease}, c.Members,
		c.Delivery, c.Volumes, c.Roots, c.Evidence, c.Cell, c.Environment, c.Allocations, c.RetainedEvidence, c.RetainedAllocations, c.HistoricalRoots)
	if err != nil {
		return nil, err
	}
	return &ReadOnlyVerifier{producerVerifier: v}, nil
}

type readOnlyProducerAuthority struct {
	*authority.Reader
	lease *authority.LeaseAdmission
}

func (a readOnlyProducerAuthority) Guard(ctx context.Context, epoch uint64) error {
	if a.lease == nil || epoch != a.lease.Epoch() {
		return authority.ErrFenced
	}
	return a.lease.Guard(ctx)
}
