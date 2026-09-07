package authority

import (
	"sync"
	"testing"
	"time"
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

func TestRegionalAuthorityCoordinatorUnavailableSnapshotIsNotReady(t *testing.T) {
	coordinator := &RegionalAuthorityCoordinator{}
	coordinator.publishSnapshot("leader", true, AuthorityObservation{
		AuthorityId: "gru-regional",
		KvRevision:  2,
		Epoch:       1,
		Lease:       &AuthorityLease{CandidateId: "candidate", LeaseId: "lease", ServerIssuedAt: time.Now().UTC(), Duration: time.Minute},
	}, nil, time.Now().UTC())
	if !coordinator.Snapshot().Ready() {
		t.Fatal("seed leader snapshot was not ready")
	}
	coordinator.publish("unavailable", false, AuthorityObservation{AuthorityId: "gru-regional"}, "regional-authority-unverified", time.Now().UTC())
	snapshot := coordinator.Snapshot()
	if snapshot.Ready() || snapshot.IsLeader || snapshot.Error == nil || *snapshot.Error != "regional-authority-unverified" || snapshot.LeaseExpiresAt != nil {
		t.Fatalf("unavailable snapshot retained authority: %+v", snapshot)
	}
}
