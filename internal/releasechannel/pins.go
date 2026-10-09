package releasechannel

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/nats-io/nats.go/jetstream"
)

// PinRefreshInterval keeps inventories current; MaxPinAge bounds how long
// pruning can use one when collection or publication stops succeeding.
const (
	PinRefreshInterval = 30 * time.Second
	MaxPinAge          = 2 * time.Minute
)

// PinRefreshDue also corrects timestamps beyond the clock allowance.
func PinRefreshDue(updatedAt, now time.Time) bool {
	age := now.Sub(updatedAt)
	return updatedAt.IsZero() || age >= PinRefreshInterval || age < -PinRefreshInterval
}

// ValidateFresh requires recent, complete inventories before pruning.
func (pins *ReleasePins) ValidateFresh(updatedAt, now time.Time) error {
	if err := pins.Validate(); err != nil {
		return err
	}
	age := now.Sub(updatedAt)
	if updatedAt.IsZero() || age > MaxPinAge || age < -PinRefreshInterval {
		return fmt.Errorf("%w: release pin inventory timestamp %s is missing, stale, or ahead of the clock", ErrInvalid, updatedAt)
	}
	return nil
}

// PinKeys refuses a partial inventory: only the watcher's nil entry proves
// that all initial keys arrived before CI can use them to prune releases.
func PinKeys(ctx context.Context, kv jetstream.KeyValue, filter string) ([]string, error) {
	watcher, err := kv.WatchFiltered(ctx, []string{filter}, jetstream.MetaOnly(), jetstream.IgnoreDeletes())
	if err != nil {
		return nil, err
	}
	defer watcher.Stop()
	var keys []string
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case entry, open := <-watcher.Updates():
			if !open {
				return nil, errors.New("release pin watcher closed before inventory completed")
			}
			if entry == nil {
				if err := ctx.Err(); err != nil {
					return nil, err
				}
				return keys, nil
			}
			keys = append(keys, entry.Key())
		}
	}
}
