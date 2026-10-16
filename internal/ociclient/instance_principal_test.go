package ociclient

import (
	"sync"
	"testing"
	"time"

	"github.com/oracle/oci-go-sdk/v65/common"

	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
)

func TestInstancePrincipalSerializesFetchesButNotCachedRegions(t *testing.T) {
	provider := testProvider(t)
	slow, cached := catalog.OCIRegion("GRU"), catalog.OCIRegion("FRA")
	release := make(chan struct{})
	original := newInstancePrincipalProvider
	sharedMu.Lock()
	saved := sharedPrincipal
	sharedPrincipal = map[string]*Factory{}
	sharedMu.Unlock()
	t.Cleanup(func() {
		newInstancePrincipalProvider = original
		sharedMu.Lock()
		sharedPrincipal = saved
		sharedMu.Unlock()
	})
	// The SDK writes package-level state on every provider it builds; this
	// fake does the same, so -race fails if two fetches ever overlap.
	var sdkGlobal string
	newInstancePrincipalProvider = func(region common.Region,
		_ func(common.HTTPRequestDispatcher) (common.HTTPRequestDispatcher, error),
	) (common.ConfigurationProvider, error) {
		sdkGlobal = string(region)
		if string(region) == slow {
			<-release
		}
		return provider, nil
	}
	if _, err := InstancePrincipal(cached); err != nil {
		t.Fatal(err)
	}
	var wait sync.WaitGroup
	results := make([]*Factory, 2)
	for index := range results {
		wait.Go(func() {
			factory, err := InstancePrincipal(slow)
			if err != nil {
				t.Error(err)
			}
			results[index] = factory
		})
	}
	// A cached region never waits for another region's fetch.
	done := make(chan error, 1)
	go func() {
		_, err := InstancePrincipal(cached)
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("a slow region's provider fetch blocked a cached region")
	}
	close(release)
	wait.Wait()
	if results[0] == nil || results[0] != results[1] {
		t.Fatal("concurrent creators did not converge on one shared factory")
	}
	_ = sdkGlobal
}
