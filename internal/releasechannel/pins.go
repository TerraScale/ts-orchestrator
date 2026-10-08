package releasechannel

import (
	"context"
	"errors"

	"github.com/nats-io/nats.go/jetstream"
)

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
