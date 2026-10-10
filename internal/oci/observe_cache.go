package oci

import (
	"context"
	"sync"
	"time"
)

// observeVerificationTTL bounds how long a storage and network
// verification may be reused by placement's periodic Observe.
const observeVerificationTTL = 60 * time.Second

type observeOnlyKey struct{}

// observeOnly marks a context as the read-only placement Observe sweep. Only
// that sweep may reuse a cached verification; every path that precedes a
// mutation verifies afresh.
func observeOnly(ctx context.Context) context.Context {
	return context.WithValue(ctx, observeOnlyKey{}, true)
}

// WithCachedVerification opts one Observe call into reusing a cached
// storage and network verification. Only placement's periodic read sweep
// passes it; admission paths (host enrollment, registration verification)
// call Observe with a plain context and always verify afresh.
func WithCachedVerification(ctx context.Context) context.Context { return observeOnly(ctx) }

func isObserveOnly(ctx context.Context) bool {
	marked, _ := ctx.Value(observeOnlyKey{}).(bool)
	return marked
}

type cachedVerification struct {
	etag      string
	privateIP string
	at        time.Time
}

// verificationCache remembers a successful boot volume, VNIC, subnet and NSG
// verification per instance ETag. Each Observe tick otherwise issues four
// extra OCI reads per member host (ListBootVolumeAttachments, GetBootVolume,
// ListVnicAttachments, GetVnic). An instance ETag change, a verification
// failure, or the TTL expiring forces a fresh verification.
//
// The cache trades detection latency of out-of-band VNIC or boot volume
// changes (up to one minute) for OCI read volume. Admission and mutation
// paths always verify afresh.
type verificationCache struct {
	now func() time.Time

	mu      sync.Mutex
	entries map[string]cachedVerification
}

func newVerificationCache() *verificationCache {
	return &verificationCache{now: time.Now, entries: map[string]cachedVerification{}}
}

func (c *verificationCache) lookup(ctx context.Context, id, etag string) (string, bool) {
	if c == nil || etag == "" || !isObserveOnly(ctx) {
		return "", false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.entries[id]
	if !ok || entry.etag != etag || c.now().Sub(entry.at) >= observeVerificationTTL {
		return "", false
	}
	return entry.privateIP, true
}

func (c *verificationCache) store(id, etag, privateIP string) {
	if c == nil || etag == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	for key, entry := range c.entries {
		if now.Sub(entry.at) >= observeVerificationTTL {
			delete(c.entries, key)
		}
	}
	if len(c.entries) >= maxFleetInstances {
		return
	}
	c.entries[id] = cachedVerification{etag: etag, privateIP: privateIP, at: now}
}

func (c *verificationCache) forget(id string) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.entries, id)
}
