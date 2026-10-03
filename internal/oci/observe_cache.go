package oci

import (
	"context"
	"errors"
	"sync"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
)

// MaxObserveVerificationTTL bounds how long a storage and network
// verification may be reused by placement's periodic Observe.
const MaxObserveVerificationTTL = 60 * time.Second

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
// changes (up to the TTL) for OCI read volume, so it is off unless the signed
// controller configuration enables it.
type verificationCache struct {
	ttl time.Duration
	now func() time.Time

	mu      sync.Mutex
	entries map[string]cachedVerification
}

func newVerificationCache(ttl time.Duration) (*verificationCache, error) {
	if ttl < 0 || ttl > MaxObserveVerificationTTL {
		return nil, errors.New("OCI observe verification cache TTL is out of bounds")
	}
	if ttl == 0 {
		return nil, nil
	}
	return &verificationCache{ttl: ttl, now: time.Now, entries: map[string]cachedVerification{}}, nil
}

func (c *verificationCache) lookup(ctx context.Context, id, etag string) (string, bool) {
	if c == nil || etag == "" || !isObserveOnly(ctx) {
		return "", false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.entries[id]
	if !ok || entry.etag != etag || c.now().Sub(entry.at) >= c.ttl {
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
		if now.Sub(entry.at) >= c.ttl {
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

// InstancePrincipalFleetFactory returns NewInstancePrincipalFleetWithImageVerifier
// with an Observe verification cache of ttl. A zero ttl keeps the previous
// behavior of verifying every instance on every Observe.
func InstancePrincipalFleetFactory(ttl time.Duration) func(RegionConfig, RegionIntent, Journal, authority.Fencer,
	DrainRequester, WriterStopVerifier, ImageQualificationVerifier, map[string]string) (Fleet, error) {
	return func(config RegionConfig, intent RegionIntent, journal Journal, fencer authority.Fencer,
		drainRequester DrainRequester, writerStop WriterStopVerifier, imageVerifier ImageQualificationVerifier,
		hostMetadata map[string]string,
	) (Fleet, error) {
		if err := config.Validate(intent); err != nil {
			return nil, err
		}
		cache, err := newVerificationCache(ttl)
		if err != nil {
			return nil, err
		}
		provider, err := newSDKProvider(config, hostMetadata)
		if err != nil {
			return nil, err
		}
		provider.verified = cache
		return NewFleetWithImageVerifier(config, intent, provider, journal, fencer, drainRequester, writerStop, imageVerifier)
	}
}
