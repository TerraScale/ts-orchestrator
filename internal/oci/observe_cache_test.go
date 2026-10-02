package oci

import (
	"testing"
	"time"
)

func TestVerificationCacheIsObserveOnlyETagBoundAndExpires(t *testing.T) {
	if cache, err := newVerificationCache(0); err != nil || cache != nil {
		t.Fatalf("zero TTL must disable the cache: %v %v", cache, err)
	}
	for _, ttl := range []time.Duration{-time.Second, MaxObserveVerificationTTL + time.Second} {
		if _, err := newVerificationCache(ttl); err == nil {
			t.Fatalf("accepted TTL %v", ttl)
		}
	}
	var disabled *verificationCache
	disabled.store("i", "e", "10.0.0.1")
	disabled.forget("i")
	if _, ok := disabled.lookup(observeOnly(t.Context()), "i", "e"); ok {
		t.Fatal("nil cache returned an entry")
	}

	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	cache, err := newVerificationCache(10 * time.Second)
	if err != nil {
		t.Fatal(err)
	}
	cache.now = func() time.Time { return now }
	cache.store("i", "e1", "10.0.0.1")
	observe := observeOnly(t.Context())

	if ip, ok := cache.lookup(observe, "i", "e1"); !ok || ip != "10.0.0.1" {
		t.Fatalf("ip=%q ok=%v", ip, ok)
	}
	if _, ok := cache.lookup(t.Context(), "i", "e1"); ok {
		t.Fatal("a mutation path reused a cached verification")
	}
	if _, ok := cache.lookup(observe, "i", "e2"); ok {
		t.Fatal("a changed ETag reused a cached verification")
	}
	if _, ok := cache.lookup(observe, "i", ""); ok {
		t.Fatal("an empty ETag reused a cached verification")
	}
	now = now.Add(10 * time.Second)
	if _, ok := cache.lookup(observe, "i", "e1"); ok {
		t.Fatal("an expired verification was reused")
	}
	cache.store("i", "e1", "10.0.0.1")
	cache.forget("i")
	if _, ok := cache.lookup(observe, "i", "e1"); ok {
		t.Fatal("a forgotten verification was reused")
	}
	// Expired entries are pruned on store, keeping the cache bounded.
	cache.store("old", "e", "10.0.0.2")
	now = now.Add(time.Minute)
	cache.store("new", "e", "10.0.0.3")
	if _, ok := cache.entries["old"]; ok || len(cache.entries) != 1 {
		t.Fatalf("entries=%v", cache.entries)
	}
}
