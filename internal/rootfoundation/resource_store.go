package rootfoundation

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"reflect"
	"slices"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/ociresource"
	"github.com/TerraScale/ts-orchestrator/internal/region"
	"github.com/TerraScale/ts-orchestrator/internal/rootoci"
)

// ResourceAuthority is derived inside root from exact accepted config and a
// current root-signed amendment. Digests alone do not confer authority.
type ResourceAuthority struct {
	Source     ociresource.ResourceSource
	Specs      map[string]string
	PruneKinds map[string]bool
}

// ResourceStore keeps amendment operations in the existing protected own-cell
// object. It never projects foundation resources into amendment ownership.
type ResourceStore struct {
	backend      *Backend
	call         rootoci.Call
	receipt      rootoci.FoundationReceipt
	authority    ResourceAuthority
	store        region.FoundationStore
	observations interface {
		PutStatus(context.Context, ociresource.Status) error
		GetStatus(context.Context, ociresource.Key) (ociresource.Status, bool, error)
	}
}

func (b *Backend) OpenResourceStore(ctx context.Context, call rootoci.Call, receipt rootoci.FoundationReceipt,
	authority ResourceAuthority, observations *ociresource.KVStore,
) (*ResourceStore, error) {
	if b == nil || receipt.Cell != b.cell || receipt.Stage != "reconciled" || receipt.Epoch == 0 ||
		receipt.Generation == 0 || receipt.OperationID == "" || receipt.GrantDigest != authority.Source.GrantSHA256 || observations == nil {
		return nil, ErrScope
	}
	if err := authority.Source.Validate(); err != nil {
		return nil, err
	}
	resolver, err := b.current(ctx, call)
	if err != nil {
		return nil, err
	}
	authority.Specs, authority.PruneKinds = maps.Clone(authority.Specs), maps.Clone(authority.PruneKinds)
	s := &ResourceStore{backend: b, call: call, receipt: receipt, authority: authority, store: resolver.Store, observations: observations}
	record, etag, err := s.load(ctx)
	if err != nil {
		return nil, err
	}
	if record.OCIResources == nil || record.OCIResources.Source != authority.Source {
		if _, err := s.commit(ctx, record, etag, ociresource.Key{}, nil); err != nil {
			return nil, err
		}
	}
	return s, nil
}

func (s *ResourceStore) load(ctx context.Context) (region.FoundationRecord, string, error) {
	if err := s.backend.guard(ctx, s.call); err != nil {
		return region.FoundationRecord{}, "", err
	}
	if err := checkCall(ctx, s.call, rootoci.OperationReconcileFoundation, rootoci.Expectations{Cell: s.receipt.Cell,
		GrantSHA256: s.receipt.GrantDigest, OperationID: s.receipt.OperationID, Epoch: s.receipt.Epoch}); err != nil {
		return region.FoundationRecord{}, "", err
	}
	resolver, err := s.backend.current(ctx, s.call)
	if err != nil {
		return region.FoundationRecord{}, "", err
	}
	footprint, err := resolver.Footprint.AuthorizedRegions(ctx)
	if err != nil || footprint.GrantSHA256 != s.receipt.GrantDigest {
		return region.FoundationRecord{}, "", errors.Join(ErrScope, err)
	}
	record, etag, err := s.store.Load(ctx, s.receipt.Cell)
	if err != nil {
		return region.FoundationRecord{}, "", err
	}
	if record.LeaseID != "" && time.Now().Before(record.ExpiresAt) {
		return region.FoundationRecord{}, "", region.ErrFoundationBusy
	}
	if record.Stage != "reconciled" || record.LeaseID != "" || record.Generation != s.receipt.Generation ||
		record.GrantSHA256 != s.receipt.GrantDigest || record.Epoch != s.receipt.Epoch || record.OperationID != s.receipt.OperationID {
		return region.FoundationRecord{}, "", ErrScope
	}
	found := false
	for _, intent := range footprint.Regions {
		if intent.Plan["cell"] != record.Cell {
			continue
		}
		digest, err := region.FoundationIntentDigest(intent)
		if err != nil || digest != record.IntentDigest || intent.Generation != record.Generation {
			return region.FoundationRecord{}, "", errors.Join(ErrScope, err)
		}
		found = true
	}
	if !found {
		return region.FoundationRecord{}, "", ErrScope
	}
	if journal := record.OCIResources; journal != nil {
		previous, current := journal.Source, s.authority.Source
		if previous.ControllerConfigSHA256 == current.ControllerConfigSHA256 &&
			(current.CellSpecGeneration < previous.CellSpecGeneration || current.CellSpecGeneration == previous.CellSpecGeneration && current.CellSpecSHA256 != previous.CellSpecSHA256) {
			return region.FoundationRecord{}, "", errors.New("OCI signed source rolls back or removes its protected accepted spec floor")
		}
	}
	return record, etag, nil
}

func resourceEntry(record region.FoundationRecord, key ociresource.Key) (ociresource.ProtectedResource, error) {
	if err := key.Validate(); err != nil {
		return ociresource.ProtectedResource{}, err
	}
	if key.Region != record.Cell {
		return ociresource.ProtectedResource{}, ErrScope
	}
	if record.OCIResources == nil {
		return ociresource.ProtectedResource{}, ociresource.ErrNotFound
	}
	entry, ok := record.OCIResources.Resources[key.String()]
	if !ok {
		return ociresource.ProtectedResource{}, ociresource.ErrNotFound
	}
	entry.Desired.Revision = entry.Revision
	return entry, nil
}

func (s *ResourceStore) Get(ctx context.Context, key ociresource.Key) (ociresource.Desired, error) {
	record, _, err := s.load(ctx)
	if err != nil {
		return ociresource.Desired{}, err
	}
	entry, err := resourceEntry(record, key)
	return entry.Desired, err
}

func (s *ResourceStore) List(ctx context.Context, cell, kind string) ([]ociresource.Desired, error) {
	if err := (ociresource.Key{Region: cell, Kind: kind, Name: "x"}).Validate(); err != nil {
		return nil, err
	}
	if cell != s.receipt.Cell {
		return nil, ErrScope
	}
	record, _, err := s.load(ctx)
	if err != nil || record.OCIResources == nil {
		return nil, err
	}
	var out []ociresource.Desired
	for _, key := range slices.Sorted(maps.Keys(record.OCIResources.Resources)) {
		entry := record.OCIResources.Resources[key]
		if entry.Desired.Key.Kind == kind {
			entry.Desired.Revision = entry.Revision
			out = append(out, entry.Desired)
		}
	}
	return out, nil
}

func (s *ResourceStore) commit(ctx context.Context, record region.FoundationRecord, etag string,
	key ociresource.Key, entry *ociresource.ProtectedResource,
) (ociresource.Desired, error) {
	if err := s.backend.guard(ctx, s.call); err != nil {
		return ociresource.Desired{}, err
	}
	journal := ociresource.ProtectedJournal{Revision: 1, Source: s.authority.Source, Resources: map[string]ociresource.ProtectedResource{}}
	if record.OCIResources != nil {
		journal.Revision = record.OCIResources.Revision + 1
		journal.Resources = maps.Clone(record.OCIResources.Resources)
		if journal.Revision == 0 {
			return ociresource.Desired{}, errors.New("protected OCI journal revision exhausted")
		}
	}
	var desired ociresource.Desired
	if entry == nil {
		if key.Name != "" {
			delete(journal.Resources, key.String())
		}
	} else {
		entry.Revision = journal.Revision
		entry.Desired.Revision = journal.Revision
		journal.Resources[key.String()] = *entry
		desired = entry.Desired
	}
	record.OCIResources = &journal
	// The ETag covers every original field, including IAM and create history.
	// An ambiguous result is reread next pass; this CAS is never retried here.
	// The journal's own non-retrying conditional write cannot recursively
	// journal itself or invoke the amended resource's SaveOperation fence.
	ctx = ociclient.WithAuthority(ctx, func(ctx context.Context) error { return s.backend.guard(ctx, s.call) })
	ctx = ociclient.WithWireAttempt(ctx, func(*http.Request) (func(*http.Response, error, bool) error, error) {
		return func(*http.Response, error, bool) error { return nil }, nil
	})
	if _, err := s.store.CompareAndSwap(ctx, record, etag); err != nil {
		if errors.Is(err, region.ErrFoundationConflict) {
			return ociresource.Desired{}, errors.Join(ociresource.ErrConflict, err)
		}
		return ociresource.Desired{}, err
	}
	return desired, nil
}

func (s *ResourceStore) Put(ctx context.Context, desired ociresource.Desired) (ociresource.Desired, error) {
	if desired.Key.Region != s.receipt.Cell || s.authority.Specs[desired.Key.String()] != desired.SpecDigest || desired.Tombstone != nil {
		return ociresource.Desired{}, ErrScope
	}
	desired.Operation = nil
	if err := desired.Validate(); err != nil {
		return ociresource.Desired{}, err
	}
	record, etag, err := s.load(ctx)
	if err != nil {
		return ociresource.Desired{}, err
	}
	previous, err := resourceEntry(record, desired.Key)
	if err != nil && !errors.Is(err, ociresource.ErrNotFound) {
		return ociresource.Desired{}, err
	}
	if err == nil && (desired.Generation <= previous.Desired.Generation || previous.Desired.Tombstone != nil ||
		previous.Desired.Operation != nil && previous.Desired.Operation.CompletedAt.IsZero()) {
		return ociresource.Desired{}, ociresource.ErrConflict
	}
	return s.commit(ctx, record, etag, desired.Key, &ociresource.ProtectedResource{Desired: desired, Source: s.authority.Source})
}

func (s *ResourceStore) deleting(desired ociresource.Desired) bool {
	return s.authority.PruneKinds[desired.Key.Kind] && s.authority.Specs[desired.Key.String()] == ""
}

func (s *ResourceStore) MarkDeleted(ctx context.Context, key ociresource.Key, requestedAt, notBefore time.Time) (ociresource.Desired, error) {
	record, etag, err := s.load(ctx)
	if err != nil {
		return ociresource.Desired{}, err
	}
	entry, err := resourceEntry(record, key)
	if err != nil {
		return ociresource.Desired{}, err
	}
	if !s.deleting(entry.Desired) {
		return ociresource.Desired{}, ErrScope
	}
	if entry.Desired.Tombstone != nil {
		return entry.Desired, nil
	}
	if entry.Desired.Operation != nil && entry.Desired.Operation.CompletedAt.IsZero() {
		return ociresource.Desired{}, ociresource.ErrConflict
	}
	entry.Desired.Operation = nil
	entry.Desired.Tombstone = &ociresource.Tombstone{RequestedAt: requestedAt.UTC(), NotBefore: notBefore.UTC()}
	entry.RemovalSource = new(s.authority.Source)
	if err := entry.Desired.Validate(); err != nil {
		return ociresource.Desired{}, err
	}
	return s.commit(ctx, record, etag, key, &entry)
}

func (s *ResourceStore) SaveOperation(ctx context.Context, desired ociresource.Desired, epoch uint64, now time.Time, complete bool) (ociresource.Desired, error) {
	if epoch != s.receipt.Epoch {
		return ociresource.Desired{}, ociresource.ErrFenced
	}
	record, etag, err := s.load(ctx)
	if err != nil {
		return ociresource.Desired{}, err
	}
	entry, err := resourceEntry(record, desired.Key)
	if err != nil {
		return ociresource.Desired{}, err
	}
	if desired.Revision == 0 || entry.Revision != desired.Revision {
		return ociresource.Desired{}, ociresource.ErrConflict
	}
	actual, expected := desired, entry.Desired
	actual.Operation, expected.Operation = nil, nil
	if !reflect.DeepEqual(actual, expected) {
		return ociresource.Desired{}, ErrScope
	}
	if desired.Tombstone != nil {
		if entry.RemovalSource == nil || !complete && !s.deleting(desired) {
			return ociresource.Desired{}, ErrScope
		}
	} else if !complete && s.authority.Specs[desired.Key.String()] != desired.SpecDigest {
		return ociresource.Desired{}, ErrScope
	}
	previous := entry.Desired.Operation
	if complete && (previous == nil || !previous.CompletedAt.IsZero() || desired.Operation == nil || previous.ID != desired.Operation.ID) {
		return ociresource.Desired{}, errors.New("only an original protected OCI operation may be confirmed by observation")
	}
	if previous != nil && previous.CompletedAt.IsZero() {
		if desired.Operation == nil {
			if previous.AppliedAt.IsZero() || len(previous.WorkRequests) != 0 {
				return ociresource.Desired{}, errors.New("original OCI operation still has an uncertain outcome")
			}
			for _, request := range previous.Requests {
				if request.Uncertain() {
					return ociresource.Desired{}, errors.New("original OCI request outcome still needs observation")
				}
			}
		} else if desired.Operation.ID != previous.ID || desired.Operation.StartedAt != previous.StartedAt {
			return ociresource.Desired{}, errors.New("original OCI operation identity changed")
		} else if err := originalRequests(*previous, *desired.Operation); err != nil {
			return ociresource.Desired{}, err
		}
	}
	entry.Desired, err = ociresource.OperationRecord(desired, epoch, now, complete)
	if err != nil {
		return ociresource.Desired{}, err
	}
	return s.commit(ctx, record, etag, desired.Key, &entry)
}

func originalRequests(previous, next ociresource.Operation) error {
	if len(next.Requests) < len(previous.Requests) {
		return errors.New("original OCI request history was removed")
	}
	for i, request := range previous.Requests {
		current := next.Requests[i]
		if request.Method != current.Method || request.URL != current.URL || !slices.Equal(request.Body, current.Body) ||
			request.IfMatch != current.IfMatch || request.RetryToken != current.RetryToken || !request.StartedAt.Equal(current.StartedAt) || !request.Deadline.Equal(current.Deadline) {
			return errors.New("original OCI request bytes, token or deadline changed")
		}
	}
	return nil
}

func (s *ResourceStore) Purge(ctx context.Context, desired ociresource.Desired) error {
	record, etag, err := s.load(ctx)
	if err != nil {
		return err
	}
	entry, err := resourceEntry(record, desired.Key)
	if err != nil {
		return err
	}
	if desired.Tombstone == nil || desired.Revision == 0 || entry.Revision != desired.Revision ||
		!reflect.DeepEqual(desired, entry.Desired) || !s.deleting(desired) || time.Now().Before(desired.Tombstone.NotBefore) {
		return ociresource.ErrConflict
	}
	_, err = s.commit(ctx, record, etag, desired.Key, nil)
	return err
}

func (s *ResourceStore) PutStatus(ctx context.Context, status ociresource.Status) error {
	if status.Key.Region != s.receipt.Cell {
		return ErrScope
	}
	return s.observations.PutStatus(ctx, status)
}

func (s *ResourceStore) GetStatus(ctx context.Context, key ociresource.Key) (ociresource.Status, bool, error) {
	if key.Region != s.receipt.Cell {
		return ociresource.Status{}, false, fmt.Errorf("%w: OCI status cell", ErrScope)
	}
	return s.observations.GetStatus(ctx, key)
}

var _ ociresource.Store = (*ResourceStore)(nil)
