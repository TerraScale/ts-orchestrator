package ociresource

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"
)

// Validator is a spec that can check itself before it is published.
type Validator interface{ Validate() error }

// Publish writes spec as the next generation of key when its digest or policy
// changed, and reports whether it wrote. A tombstoned record is never
// revived: its deletion must complete first.
func Publish(ctx context.Context, store Store, key Key, policy DriftPolicy, spec Validator) (bool, error) {
	if err := key.Validate(); err != nil {
		return false, err
	}
	if err := spec.Validate(); err != nil {
		return false, fmt.Errorf("%s: %w", key, err)
	}
	generation := uint64(1)
	current, err := store.Get(ctx, key)
	switch {
	case errors.Is(err, ErrNotFound):
	case err != nil:
		return false, err
	default:
		if current.Tombstone != nil {
			return false, fmt.Errorf("%s: desired record is being deleted", key)
		}
		generation = current.Generation + 1
	}
	desired, err := NewDesired(key, generation, policy, spec)
	if err != nil {
		return false, err
	}
	if generation > 1 && desired.SpecDigest == current.SpecDigest && policy == current.Policy {
		return false, nil
	}
	if _, err := store.Put(ctx, desired); err != nil {
		return false, err
	}
	return true, nil
}

// Entry is one desired resource of a published set.
type Entry struct {
	Name   string
	Policy DriftPolicy
	Spec   Validator
}

// SetResult counts what PublishSet changed.
type SetResult struct {
	Published, Unchanged, Tombstoned int
}

// PublishSet makes the desired records of one kind in one region equal to
// entries. Every entry is validated before anything is written, so a bad
// entry never leaves a half-published set. With prune set, a record of the
// kind that is no longer listed is tombstoned to be released at
// now+pruneDelay; without it, unlisted records are left alone.
func PublishSet(ctx context.Context, store Store, region, kind string, entries []Entry, prune bool,
	now time.Time, pruneDelay time.Duration, guard func(context.Context) error,
) (SetResult, error) {
	var result SetResult
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		key := Key{Region: region, Kind: kind, Name: entry.Name}
		if err := key.Validate(); err != nil {
			return result, err
		}
		if !entry.Policy.valid() {
			return result, fmt.Errorf("%s: drift policy %q is unsupported", key, entry.Policy)
		}
		if entry.Spec == nil {
			return result, fmt.Errorf("%s: spec is missing", key)
		}
		if err := entry.Spec.Validate(); err != nil {
			return result, fmt.Errorf("%s: %w", key, err)
		}
		if slices.Contains(names, entry.Name) {
			return result, fmt.Errorf("%s: listed twice", key)
		}
		names = append(names, entry.Name)
	}
	// One entry that cannot be written (for example a name whose earlier
	// record is still being deleted) does not hold back the others.
	var failures []error
	fence := func() error {
		if guard == nil {
			return nil
		}
		if err := guard(ctx); err != nil {
			return fmt.Errorf("%w: %w", ErrFenced, err)
		}
		return nil
	}
	for _, entry := range entries {
		// Re-check authority before every write, so a controller that loses
		// leadership mid-set never publishes stale desired state.
		if err := fence(); err != nil {
			return result, err
		}
		wrote, err := Publish(ctx, store, Key{Region: region, Kind: kind, Name: entry.Name}, entry.Policy, entry.Spec)
		switch {
		case err != nil:
			if ctx.Err() != nil {
				return result, err
			}
			failures = append(failures, err)
		case wrote:
			result.Published++
		default:
			result.Unchanged++
		}
	}
	if !prune || len(failures) > 0 {
		return result, errors.Join(failures...)
	}
	if pruneDelay < 0 {
		return result, errors.New("OCI desired prune delay must not be negative")
	}
	records, err := store.List(ctx, region, kind)
	if err != nil {
		return result, err
	}
	for _, record := range records {
		if record.Tombstone != nil || slices.Contains(names, record.Key.Name) {
			continue
		}
		if err := fence(); err != nil {
			return result, err
		}
		if _, err := store.MarkDeleted(ctx, record.Key, now, now.Add(pruneDelay)); err != nil {
			return result, fmt.Errorf("%s: tombstone unlisted record: %w", record.Key, err)
		}
		result.Tombstoned++
	}
	return result, nil
}
