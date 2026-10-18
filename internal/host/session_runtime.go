package host

import (
	"context"
	"sync"
)

// RunSession owns the existing authenticated host transport while SwarmKit
// owns workloads. It never recovers or reconciles the native process runner.
func (a *Agent) RunSession(ctx context.Context) error {
	work, cancel := context.WithCancel(ctx)
	defer cancel()
	if err := a.checkClock(); err != nil {
		return err
	}
	if err := a.waitForSession(work); err != nil {
		return err
	}
	lost := make(chan error, 1)
	var workers sync.WaitGroup
	defer func() {
		cancel()
		workers.Wait()
	}()
	workers.Go(func() {
		a.maintainSessionLease(work, func(reason error) {
			a.sessionFailOnce.Do(func() {
				a.sessionLost.Store(true)
				cancel()
				lost <- reason
			})
		})
	})
	workers.Go(func() { a.publishLoad(work) })
	workers.Go(func() { a.publishLogs(work) })
	if a.cfg.FollowRollouts != nil {
		workers.Go(func() { a.cfg.FollowRollouts(work, a) })
	}
	if a.cfg.FollowNetBird != nil {
		workers.Go(func() { a.cfg.FollowNetBird(work, a) })
	}
	if a.cfg.Initialized != nil {
		a.cfg.Initialized()
	}
	select {
	case reason := <-lost:
		return reason
	case <-work.Done():
		if a.sessionLost.Load() {
			return <-lost
		}
		return work.Err()
	}
}
