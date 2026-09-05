package vmqualsuite

import (
	"context"
	"encoding/hex"
	"strings"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/bootstrap"
)

// runtimeControlProvider translates only fresh runtime proofs into the public
// bootstrap protocol. It never observes OCI metadata or manufactures digests.
type runtimeControlProvider struct {
	runtime    bootstrap.ControlRuntime
	calls      []ControlContractCall
	candidates map[string]bootstrap.CandidateEvidence
}

var _ bootstrap.ControlPlaneProvider = (*runtimeControlProvider)(nil)

func (provider *runtimeControlProvider) execute(ctx context.Context, request bootstrap.ControlActionRequest) (bootstrap.ControlRuntimeEvidence, error) {
	evidence, err := provider.runtime.Execute(ctx, request)
	if err != nil {
		return evidence, err
	}
	for _, digest := range []string{evidence.IdentityDigest, evidence.StorageDigest, evidence.HealthDigest} {
		raw, err := hex.DecodeString(digest)
		if err != nil || len(raw) != 32 || strings.ToLower(digest) != digest {
			return bootstrap.ControlRuntimeEvidence{}, bootstrap.ErrControlRuntimeUnavailable
		}
	}
	now := time.Now()
	if evidence.ObservedAt.IsZero() || evidence.ObservedAt.After(now.Add(time.Second)) || now.Sub(evidence.ObservedAt) > 30*time.Second {
		return bootstrap.ControlRuntimeEvidence{}, bootstrap.ErrControlRuntimeUnavailable
	}
	provider.calls = append(provider.calls, ControlContractCall{Sequence: uint64(len(provider.calls) + 1), Kind: request.Action.Kind, Region: request.Action.Region, ExpectedEpoch: request.Action.ExpectedEpoch, TargetEpoch: request.Action.TargetEpoch})
	return evidence, nil
}
func (provider *runtimeControlProvider) receipt(ctx context.Context, request bootstrap.ControlActionRequest) (bootstrap.ControlReceipt, error) {
	if _, err := provider.execute(ctx, request); err != nil {
		return bootstrap.ControlReceipt{}, err
	}
	return bootstrap.ControlReceipt{ID: request.Action.IdempotencyKey}, nil
}
func (p *runtimeControlProvider) StartTemporaryR1(ctx context.Context, r bootstrap.ControlActionRequest) (bootstrap.ControlReceipt, error) {
	return p.receipt(ctx, r)
}
func (p *runtimeControlProvider) FenceTemporaryR1(ctx context.Context, r bootstrap.ControlActionRequest) (bootstrap.ControlReceipt, error) {
	return p.receipt(ctx, r)
}
func (p *runtimeControlProvider) StartCandidate(ctx context.Context, r bootstrap.ControlActionRequest) (bootstrap.ControlReceipt, error) {
	return p.receipt(ctx, r)
}
func (p *runtimeControlProvider) SyncCandidate(ctx context.Context, r bootstrap.ControlActionRequest) (bootstrap.ControlReceipt, error) {
	return p.receipt(ctx, r)
}
func (p *runtimeControlProvider) PromoteGlobalR3(ctx context.Context, r bootstrap.ControlActionRequest) (bootstrap.ControlReceipt, error) {
	return p.receipt(ctx, r)
}
func (p *runtimeControlProvider) RevokeBootstrapAuthority(ctx context.Context, r bootstrap.ControlActionRequest) (bootstrap.ControlReceipt, error) {
	return p.receipt(ctx, r)
}
func (p *runtimeControlProvider) RemoteManageRegion(ctx context.Context, r bootstrap.ControlActionRequest) (bootstrap.ControlReceipt, error) {
	return p.receipt(ctx, r)
}
func (p *runtimeControlProvider) StartRegionalR3(ctx context.Context, r bootstrap.ControlActionRequest) (bootstrap.ControlReceipt, error) {
	return p.receipt(ctx, r)
}
func (p *runtimeControlProvider) VerifyCandidate(ctx context.Context, r bootstrap.ControlActionRequest) (bootstrap.CandidateEvidence, error) {
	evidence, err := p.execute(ctx, r)
	if err != nil {
		return bootstrap.CandidateEvidence{}, err
	}
	candidate := bootstrap.CandidateEvidence{Region: r.Action.Region, IdentityDigest: evidence.IdentityDigest, StorageDigest: evidence.StorageDigest, HealthDigest: evidence.HealthDigest, CaughtUp: true, IdentityReady: true, StorageReady: true, HealthReady: true}
	if p.candidates == nil {
		p.candidates = make(map[string]bootstrap.CandidateEvidence)
	}
	p.candidates[r.Action.Region] = candidate
	return candidate, nil
}
func (p *runtimeControlProvider) VerifyGlobalR3(ctx context.Context, r bootstrap.ControlActionRequest) error {
	_, err := p.execute(ctx, r)
	return err
}
