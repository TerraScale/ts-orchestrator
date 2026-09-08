package vmqualbootstrap

import (
	"bytes"
	"context"
	"errors"

	"terrascale.tech/orchestrator/src/orchestrator/controltransition"
	"terrascale.tech/orchestrator/src/orchestrator/storageplan"
)

// PrepareStorageTransition binds the three exact grants issued by this run to
// actual preliminary evidence. The first signed plan is durable before delivery;
// subsequent calls validate and return its original bytes without resigning.
func (i *Issuer) PrepareStorageTransition(ctx context.Context, plan controltransition.Plan, scope []byte, receipts [][]byte) ([]byte, error) {
	if ctx == nil {
		return nil, errors.New("vmqual: storage transition context required")
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.signer == nil || i.persistent == nil || plan.Validate() != nil {
		return nil, errors.New("vmqual: durable finite transition issuer required")
	}
	source, ok := i.grants[plan.Source.NodeID]
	if !ok {
		return nil, errors.New("vmqual: source grant not issued in this run")
	}
	evidence := storageplan.Evidence{Source: bytes.Clone(source.SignedGrant), PreliminaryScope: bytes.Clone(scope), CandidateReceipts: receipts}
	for _, destination := range plan.Destinations {
		grant, ok := i.grants[destination.NodeID]
		if !ok {
			return nil, errors.New("vmqual: destination grant not issued in this run")
		}
		evidence.Destinations = append(evidence.Destinations, bytes.Clone(grant.SignedGrant))
	}
	signed, err := i.persistent.store.LoadOrCreate("storage-plan-"+plan.TransitionID+".json", controltransition.MaximumPlanBytes, func() ([]byte, error) { return storageplan.Prepare(ctx, plan, evidence, i.public, i.signer) }, func(raw []byte) error { _, err := storageplan.Verify(ctx, plan, evidence, i.public, raw); return err })
	if err != nil {
		return nil, err
	}
	return signed, nil
}
