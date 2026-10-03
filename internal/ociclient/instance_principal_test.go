package ociclient

import (
	"sync"
	"testing"
	"time"

	"github.com/oracle/oci-go-sdk/v65/common"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociregion/catalog"
)

func TestInstancePrincipalFetchesOutsideTheSharedLock(t *testing.T) {
	provider := testProvider(t)
	slow, fast := catalog.OCIRegion("GRU"), catalog.OCIRegion("FRA")
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
	newInstancePrincipalProvider = func(region common.Region) (common.ConfigurationProvider, error) {
		if string(region) == slow {
			<-release
		}
		return provider, nil
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
	// A hung metadata fetch for one region must not block another region.
	done := make(chan error, 1)
	go func() {
		_, err := InstancePrincipal(fast)
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("a slow region's provider fetch blocked another region")
	}
	close(release)
	wait.Wait()
	if results[0] == nil || results[0] != results[1] {
		t.Fatal("concurrent creators did not converge on one shared factory")
	}
}
