package provider

import (
	"context"
	"sync"

	"terrascale.tech/orchestrator/src/orchestrator/errs"
)

// ProviderActuator is the only execution seam a regional control runtime needs.
// Implementations must accept only intents produced by Authorize and return
// call evidence suitable for durable reconciliation.
type ProviderActuator interface {
	Execute(context.Context, ProviderIntent) (ProviderCallEvidence, error)
}

// OwnershipJournal is a typed, region-scoped ownership record store. It is
// intentionally independent of the control package so both command and
// reconciliation runtimes can use it without an import cycle.
type OwnershipJournal interface {
	Record(context.Context, ProviderOwnershipRecord) error
	Lookup(context.Context, ProviderResourceId) (ProviderOwnershipRecord, bool, error)
}

// DurableOwnershipJournal is the stronger boundary required before a
// provider lifecycle decision may use an existing resource identity. A
// process-local journal is useful for tests, but cannot authorize adoption or
// destructive work after a crash or leadership change.
type DurableOwnershipEvidence interface {
	OwnershipJournal
	AuthoritativeDurable() bool
}

// AuthorizeWithOwnership loads the target's ownership from the durable
// journal immediately before authorization. Tags and caller-supplied records
// are treated only as consistency evidence; they cannot establish ownership.
func AuthorizeWithOwnership(ctx context.Context, request ProviderAuthorizationRequest, journal DurableOwnershipEvidence) ProviderAuthorizationDecision {
	if ctx == nil || journal == nil || !journal.AuthoritativeDurable() {
		return ProviderAuthorizationDecision{Trace: []ProviderDecisionReason{{Code: DecisionOwnershipMatches, Outcome: DecisionRejected}}}
	}
	target, existing := request.Context.Target.(ExistingProviderResource)
	if existing {
		if err := ctx.Err(); err != nil {
			return ProviderAuthorizationDecision{Trace: []ProviderDecisionReason{{Code: DecisionOwnershipMatches, Outcome: DecisionHeld}}}
		}
		record, ok, err := journal.Lookup(ctx, target.Id)
		if err != nil || !ok {
			return ProviderAuthorizationDecision{Trace: []ProviderDecisionReason{{Code: DecisionOwnershipMatches, Outcome: DecisionHeld}}}
		}
		request.OwnershipRecords = []ProviderOwnershipRecord{record}
	}
	return Authorize(request)
}

// MemoryOwnershipJournal is a bounded, concurrency-safe implementation useful
// for tests and process-local composition. Durable deployments should provide
// their own journal implementation.
type MemoryOwnershipJournal struct {
	mu      sync.RWMutex
	records map[string]ProviderOwnershipRecord
	max     int
}

func NewMemoryOwnershipJournal(max int) (*MemoryOwnershipJournal, error) {
	if max < 1 || max > MaximumOperationEvidenceCount {
		return nil, &errs.ArgumentOutOfRangeError{Param: "max"}
	}
	return &MemoryOwnershipJournal{records: make(map[string]ProviderOwnershipRecord), max: max}, nil
}

func (j *MemoryOwnershipJournal) Record(ctx context.Context, record ProviderOwnershipRecord) error {
	if ctx == nil {
		return &errs.Argument{Param: "ctx", Message: "provider context is required"}
	}
	if j == nil {
		return &InvalidOperationError{Message: "ownership journal is unavailable"}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if record.ResourceId.Value == "" || record.CellId.Value == "" || record.CompartmentId.Value == "" || record.Generation.Value == 0 {
		return &errs.Argument{Message: "ownership record is incomplete"}
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if _, exists := j.records[record.ResourceId.Value]; !exists && len(j.records) >= j.max {
		return &InvalidDataError{Message: "ownership journal capacity exceeded"}
	}
	j.records[record.ResourceId.Value] = record
	return nil
}

func (j *MemoryOwnershipJournal) Lookup(ctx context.Context, id ProviderResourceId) (ProviderOwnershipRecord, bool, error) {
	if ctx == nil {
		return ProviderOwnershipRecord{}, false, &errs.Argument{Param: "ctx", Message: "provider context is required"}
	}
	if j == nil {
		return ProviderOwnershipRecord{}, false, &InvalidOperationError{Message: "ownership journal is unavailable"}
	}
	if err := ctx.Err(); err != nil {
		return ProviderOwnershipRecord{}, false, err
	}
	j.mu.RLock()
	record, ok := j.records[id.Value]
	j.mu.RUnlock()
	return record, ok, nil
}
