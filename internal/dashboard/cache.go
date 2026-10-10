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
}

type cacheEntry[V any] struct {
	at    time.Time
	value V
	err   error
}

func newKeyedCache[V any](ttl time.Duration, limit int) *keyedCache[V] {
	return &keyedCache[V]{ttl: ttl, limit: limit, entries: map[string]cacheEntry[V]{}}
}

// get returns the cached value for key or loads it. Loads for different keys
// run concurrently; two callers of the same cold key may both load, which is
// harmless for read-only providers.
func (cache *keyedCache[V]) get(ctx context.Context, key string, load func(context.Context) (V, error)) (V, error) {
	now := time.Now()
	cache.mu.Lock()
	entry, ok := cache.entries[key]
	cache.mu.Unlock()
	if ok && now.Sub(entry.at) < cache.ttl {
		return entry.value, entry.err
	}
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
