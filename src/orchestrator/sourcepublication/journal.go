package sourcepublication

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"

	"terrascale.tech/orchestrator/src/orchestrator/provider"
)

const maximumJournalKeys = 4096
const maximumJournalValueBytes = 16 << 10

// OwnershipKey matches the provider ownership journal's resource key.
func OwnershipKey(resourceID string) string {
	sum := sha256.Sum256([]byte(resourceID))
	return "provider.ownership." + hex.EncodeToString(sum[:])
}

// MutationKey matches the provider mutation journal's scope key.
func MutationKey(scope string) string {
	sum := sha256.Sum256([]byte(scope))
	return "provider.intent." + hex.EncodeToString(sum[:])
}

type journalCAS struct {
	store provider.OwnershipCASStore
	keys  map[string]struct{}
	guard func(context.Context) error
}

// NewJournalCAS restricts provider journal access to an immutable finite set of
// keys. The guard must authorize the operation both before and after storage
// access. A failed post-write guard reports failure but cannot undo the CAS.
func NewJournalCAS(store provider.OwnershipCASStore, allowedKeys []string, guard func(context.Context) error) (provider.OwnershipCASStore, error) {
	if store == nil || guard == nil || len(allowedKeys) == 0 || len(allowedKeys) > maximumJournalKeys {
		return nil, errors.New("sourcepublication: journal store, guard and bounded keys required")
	}
	keys := make(map[string]struct{}, len(allowedKeys))
	for _, key := range allowedKeys {
		var digest string
		switch {
		case strings.HasPrefix(key, "provider.ownership."):
			digest = strings.TrimPrefix(key, "provider.ownership.")
		case strings.HasPrefix(key, "provider.intent."):
			digest = strings.TrimPrefix(key, "provider.intent.")
		default:
			return nil, errors.New("sourcepublication: noncanonical journal key")
		}
		raw, err := hex.DecodeString(digest)
		if err != nil || len(raw) != sha256.Size || hex.EncodeToString(raw) != digest {
			return nil, errors.New("sourcepublication: noncanonical journal key")
		}
		if _, exists := keys[key]; exists {
			return nil, errors.New("sourcepublication: duplicate journal key")
		}
		keys[key] = struct{}{}
	}
	return &journalCAS{store: store, keys: keys, guard: guard}, nil
}

func (s *journalCAS) check(ctx context.Context, key string) error {
	if ctx == nil {
		return errors.New("sourcepublication: journal context required")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if _, ok := s.keys[key]; !ok {
		return errors.New("sourcepublication: journal key is not admitted")
	}
	return s.guard(ctx)
}

func (s *journalCAS) Get(ctx context.Context, key string) ([]byte, uint64, error) {
	if err := s.check(ctx, key); err != nil {
		return nil, 0, err
	}
	value, revision, err := s.store.Get(ctx, key)
	after := s.check(ctx, key)
	if len(value) > maximumJournalValueBytes {
		after = errors.Join(after, errors.New("sourcepublication: journal value exceeds bound"))
	}
	if after != nil {
		return nil, 0, errors.Join(err, after)
	}
	return value, revision, err
}

func (s *journalCAS) CompareAndSwap(ctx context.Context, key string, revision uint64, value []byte) error {
	if len(value) > maximumJournalValueBytes {
		return errors.New("sourcepublication: journal value exceeds bound")
	}
	if err := s.check(ctx, key); err != nil {
		return err
	}
	err := s.store.CompareAndSwap(ctx, key, revision, value)
	if after := s.check(ctx, key); after != nil {
		return errors.Join(err, after)
	}
	return err
}
