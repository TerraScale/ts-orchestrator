package provider

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
)

// OwnershipCASStore is the persistence seam for the ownership journal. A
// revision of zero means that the key does not exist. Implementations must
// return ErrOwnershipCASConflict when the expected revision is stale.
type OwnershipCASStore interface {
	Get(context.Context, string) ([]byte, uint64, error)
	CompareAndSwap(context.Context, string, uint64, []byte) error
}

// OwnershipCASConflict is returned by a store when another writer changed a
// key after it was read. It is deliberately exported so stores can use the
// same error without importing any provider implementation details.
type OwnershipCASConflict struct{}

func (OwnershipCASConflict) Error() string { return "ownership journal compare-and-swap conflict" }

type DurableOwnershipJournal struct {
	store OwnershipCASStore
	max   int
}

func NewDurableOwnershipJournal(store OwnershipCASStore, max int) (*DurableOwnershipJournal, error) {
	if store == nil {
		return nil, &ArgumentError{Param: "store", Message: "ownership CAS store is required"}
	}
	if max < 1 || max > MaximumOperationEvidenceCount {
		return nil, &ArgumentOutOfRangeError{Param: "max"}
	}
	return &DurableOwnershipJournal{store: store, max: max}, nil
}

func (j *DurableOwnershipJournal) AuthoritativeDurable() bool { return j != nil && j.store != nil }

func ownershipJournalKey(id ProviderResourceId) string {
	h := sha256.Sum256([]byte(id.Value))
	return "provider.ownership." + hex.EncodeToString(h[:])
}

func validateOwnershipRecord(ctx context.Context, record ProviderOwnershipRecord) error {
	if ctx == nil {
		return &ArgumentError{Param: "ctx", Message: "provider context is required"}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if record.ResourceId.Value == "" || record.CellId.Value == "" || record.CompartmentId.Value == "" || record.Generation.Value == 0 {
		return &ArgumentError{Message: "ownership record is incomplete"}
	}
	if strings.ContainsAny(record.ResourceId.Value+record.CellId.Value+record.CompartmentId.Value, "\r\n") {
		return &ArgumentError{Message: "ownership record identity is invalid"}
	}
	return nil
}

func (j *DurableOwnershipJournal) Record(ctx context.Context, record ProviderOwnershipRecord) error {
	if j == nil || j.store == nil {
		return &InvalidOperationError{Message: "ownership journal is unavailable"}
	}
	if err := validateOwnershipRecord(ctx, record); err != nil {
		return err
	}
	b, err := json.Marshal(record)
	if err != nil || len(b) > 16*1024 {
		return &InvalidDataError{Message: "ownership record cannot be persisted"}
	}
	// A bounded retry handles concurrent leadership/reconciliation writers. A
	// stale generation is never allowed to move ownership backwards.
	for attempt := 0; attempt != 6; attempt++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		old, revision, err := j.store.Get(ctx, ownershipJournalKey(record.ResourceId))
		if err != nil {
			return err
		}
		if len(old) != 0 {
			var prior ProviderOwnershipRecord
			if json.Unmarshal(old, &prior) != nil || prior.ResourceId != record.ResourceId {
				return &InvalidDataError{Message: "ownership journal contains malformed data"}
			}
			if prior.Generation.Value > record.Generation.Value {
				return &InvalidOperationError{Message: "ownership record generation is stale"}
			}
			if prior.Generation == record.Generation {
				if prior != record {
					return &InvalidOperationError{Message: "ownership record conflicts at the same generation"}
				}
				return nil
			}
		}
		if err := j.store.CompareAndSwap(ctx, ownershipJournalKey(record.ResourceId), revision, b); err == nil {
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

func (j *DurableOwnershipJournal) Lookup(ctx context.Context, id ProviderResourceId) (ProviderOwnershipRecord, bool, error) {
	if j == nil || j.store == nil {
		return ProviderOwnershipRecord{}, false, &InvalidOperationError{Message: "ownership journal is unavailable"}
	}
	if ctx == nil {
		return ProviderOwnershipRecord{}, false, &ArgumentError{Param: "ctx", Message: "provider context is required"}
	}
	if err := ctx.Err(); err != nil {
		return ProviderOwnershipRecord{}, false, err
	}
	if id.Value == "" || strings.ContainsAny(id.Value, "\r\n") {
		return ProviderOwnershipRecord{}, false, &ArgumentError{Message: "ownership resource identity is invalid"}
	}
	b, _, err := j.store.Get(ctx, ownershipJournalKey(id))
	if err != nil {
		return ProviderOwnershipRecord{}, false, err
	}
	if len(b) == 0 {
		return ProviderOwnershipRecord{}, false, nil
	}
	var record ProviderOwnershipRecord
	if json.Unmarshal(b, &record) != nil || record.ResourceId != id || record.CellId.Value == "" || record.CompartmentId.Value == "" || record.Generation.Value == 0 {
		return ProviderOwnershipRecord{}, false, &InvalidDataError{Message: "ownership journal contains malformed data"}
	}
	return record, true, nil
}

var _ OwnershipJournal = (*DurableOwnershipJournal)(nil)
