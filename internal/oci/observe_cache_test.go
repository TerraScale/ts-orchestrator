package oci

import (
	"testing"
	"time"
)

func TestVerificationCacheIsObserveOnlyETagBoundAndExpires(t *testing.T) {
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	cache := newVerificationCache()
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
	now = now.Add(time.Minute)
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
