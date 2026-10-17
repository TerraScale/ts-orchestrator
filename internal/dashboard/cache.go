package dashboard

import (
	"context"
	"sync"
	"time"
)

// keyedCache memoizes a few provider answers by key for a short TTL, so
// every open page stream shares one cross-region decision query or one
// summary per window instead of issuing its own every tick.
type keyedCache[V any] struct {
	ttl     time.Duration
	limit   int
	mu      sync.Mutex
	entries map[string]cacheEntry[V]
	pending map[string]chan struct{}
}

type cacheEntry[V any] struct {
	at    time.Time
	value V
	err   error
}

func newKeyedCache[V any](ttl time.Duration, limit int) *keyedCache[V] {
	return &keyedCache[V]{ttl: ttl, limit: limit, entries: map[string]cacheEntry[V]{}, pending: map[string]chan struct{}{}}
}

// get returns the cached value for key or loads it. Loads for different keys
// run concurrently; callers of the same cold key wait for its active load.
func (cache *keyedCache[V]) get(ctx context.Context, key string, load func(context.Context) (V, error)) (V, error) {
	for {
		if err := ctx.Err(); err != nil {
			var value V
			return value, err
		}
		now := time.Now()
		cache.mu.Lock()
		if entry, ok := cache.entries[key]; ok && now.Sub(entry.at) < cache.ttl {
			cache.mu.Unlock()
			return entry.value, entry.err
		}
		if done, ok := cache.pending[key]; ok {
			cache.mu.Unlock()
			select {
			case <-ctx.Done():
				var value V
				return value, ctx.Err()
			case <-done:
				continue
			}
		}
		done := make(chan struct{})
		cache.pending[key] = done
		cache.mu.Unlock()
		defer func() {
			cache.mu.Lock()
			delete(cache.pending, key)
			close(done)
			cache.mu.Unlock()
		}()
		value, err := load(ctx)
		if ctx.Err() != nil {
			return value, err
		}
		cache.mu.Lock()
		defer cache.mu.Unlock()
		if len(cache.entries) >= cache.limit {
			for name, old := range cache.entries {
				if now.Sub(old.at) >= cache.ttl || len(cache.entries) >= cache.limit {
					delete(cache.entries, name)
				}
			}
		}
		cache.entries[key] = cacheEntry[V]{at: time.Now(), value: value, err: err}
		return value, err
	}
}
