package provider

import (
	"context"
	"encoding/json"
	"errors"

	"terrascale.tech/orchestrator/src/orchestrator/errs"
)

const maximumCreateNodeConsumptionBytes = 256 << 10

// CASCreateNodeJournal persists the exact one-shot OCI invocation record in
// the same durable CAS store used by provider ownership and mutation journals.
type CASCreateNodeJournal struct {
	store OwnershipCASStore
}

func NewCASCreateNodeJournal(store OwnershipCASStore) (*CASCreateNodeJournal, error) {
	if store == nil {
		return nil, &errs.Argument{Param: "store", Message: "create-node CAS store is required"}
	}
	return &CASCreateNodeJournal{store: store}, nil
}

func (j *CASCreateNodeJournal) AuthoritativeDurable() bool {
	return j != nil && j.store != nil
}

func createNodeConsumptionKey(capability CreateNodeAuthoritativeInvocationCapability, binding CreateNodeReceiptBinding) string {
	return "provider.create-node.consumption." + digestCanonical(
		"create-node-consumption-key-v1", capability.OperationId, capability.BindingDigest,
		capability.JournalVersion, capability.Nonce, binding.Digest(),
	)
}

func validateCreateNodeConsumptionBinding(capability CreateNodeAuthoritativeInvocationCapability, binding CreateNodeReceiptBinding, consumption CreateNodeInvocationConsumption) error {
	if capability.OperationId != binding.OperationId || capability.BindingDigest != binding.Digest() ||
		consumption.BindingDigest != binding.Digest() || consumption.CapabilityDigest != invocationCapabilityDigest(capability) ||
		consumption.OperationId != binding.OperationId || consumption.CreateKey != binding.CreateKey ||
		consumption.CellId != binding.CellId || consumption.CompartmentId != binding.CompartmentId ||
		consumption.Generation != binding.Generation || !consumption.ProviderRequest.structurallyValid(binding) ||
		consumption.ConsumedAt.IsZero() || consumption.SubmissionCommittedAt.IsZero() ||
		consumption.ReceiptIssuedAt.IsZero() || consumption.ReceiptExpiresAt.IsZero() ||
		consumption.CapabilityIssuedAt.IsZero() || consumption.CapabilityExpiresAt.IsZero() || consumption.LeaseExpiresAt.IsZero() {
		return &InvalidDataError{Message: "create-node invocation consumption is invalid"}
	}
	return nil
}

func encodeCreateNodeConsumption(consumption CreateNodeInvocationConsumption) ([]byte, error) {
	raw, err := json.Marshal(consumption)
	if err != nil || len(raw) == 0 || len(raw) > maximumCreateNodeConsumptionBytes {
		return nil, &InvalidDataError{Message: "create-node invocation consumption cannot be persisted"}
	}
	return raw, nil
}

func decodeCreateNodeConsumption(raw []byte, capability CreateNodeAuthoritativeInvocationCapability, binding CreateNodeReceiptBinding) (CreateNodeInvocationConsumption, error) {
	if len(raw) == 0 || len(raw) > maximumCreateNodeConsumptionBytes {
		return CreateNodeInvocationConsumption{}, &InvalidDataError{Message: "create-node invocation consumption is malformed"}
	}
	var consumption CreateNodeInvocationConsumption
	if json.Unmarshal(raw, &consumption) != nil || validateCreateNodeConsumptionBinding(capability, binding, consumption) != nil {
		return CreateNodeInvocationConsumption{}, &InvalidDataError{Message: "create-node invocation consumption is malformed"}
	}
	consumption.ProviderRequest = consumption.ProviderRequest.clone()
	return consumption, nil
}

func (j *CASCreateNodeJournal) ConsumeInvocationCapability(ctx context.Context, capability CreateNodeAuthoritativeInvocationCapability, binding CreateNodeReceiptBinding, consumption CreateNodeInvocationConsumption) error {
	if j == nil || j.store == nil {
		return &InvalidOperationError{Message: "create-node journal is unavailable"}
	}
	if ctx == nil {
		return &errs.Argument{Param: "ctx", Message: "provider context is required"}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := validateCreateNodeConsumptionBinding(capability, binding, consumption); err != nil {
		return err
	}
	raw, err := encodeCreateNodeConsumption(consumption)
	if err != nil {
		return err
	}
	key := createNodeConsumptionKey(capability, binding)
	for attempt := 0; attempt < 6; attempt++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		existing, version, err := j.store.Get(ctx, key)
		if err != nil {
			return err
		}
		if len(existing) != 0 {
			return &InvalidOperationError{Message: "create-node invocation capability is already consumed"}
		}
		if err := j.store.CompareAndSwap(ctx, key, version, raw); err == nil {
			return nil
		} else {
			var conflict OwnershipCASConflict
			var conflictPointer *OwnershipCASConflict
			if !errors.As(err, &conflict) && !errors.As(err, &conflictPointer) {
				return err
			}
		}
	}
	return OwnershipCASConflict{}
}

func (j *CASCreateNodeJournal) InvocationCapabilityConsumption(ctx context.Context, capability CreateNodeAuthoritativeInvocationCapability, binding CreateNodeReceiptBinding) (CreateNodeInvocationConsumption, bool, error) {
	if j == nil || j.store == nil {
		return CreateNodeInvocationConsumption{}, false, &InvalidOperationError{Message: "create-node journal is unavailable"}
	}
	if ctx == nil {
		return CreateNodeInvocationConsumption{}, false, &errs.Argument{Param: "ctx", Message: "provider context is required"}
	}
	if err := ctx.Err(); err != nil {
		return CreateNodeInvocationConsumption{}, false, err
	}
	raw, _, err := j.store.Get(ctx, createNodeConsumptionKey(capability, binding))
	if err != nil {
		return CreateNodeInvocationConsumption{}, false, err
	}
	if len(raw) == 0 {
		return CreateNodeInvocationConsumption{}, false, nil
	}
	consumption, err := decodeCreateNodeConsumption(raw, capability, binding)
	return consumption, err == nil, err
}

var _ CreateNodeJournal = (*CASCreateNodeJournal)(nil)
