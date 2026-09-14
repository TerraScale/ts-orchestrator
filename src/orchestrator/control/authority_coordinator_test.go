package authority

import (
	"sync"
	"testing"
)

func TestRegionalAuthorityCoordinatorDisposeIsConcurrentSafe(t *testing.T) {
	coordinator := &RegionalAuthorityCoordinator{
		stopping: func() {},
		loopDone: make(chan struct{}),
	}
	close(coordinator.loopDone)

	var wait sync.WaitGroup
	for index := 0; index < 32; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			coordinator.Dispose()
		}()
	}
	wait.Wait()
}
