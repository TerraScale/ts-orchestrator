package host

import "context"

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
	monitorDone := make(chan struct{})
	go func() {
		defer close(monitorDone)
		a.maintainSessionLease(work, func(reason error) {
			a.sessionFailOnce.Do(func() {
				a.sessionLost.Store(true)
				cancel()
				lost <- reason
			})
		})
	}()
	defer func() { cancel(); <-monitorDone }()
	go a.publishLoad(work)
	go a.publishLogs(work)
	if a.cfg.FollowRollouts != nil {
		go a.cfg.FollowRollouts(work, a)
	}
	if a.cfg.FollowNetBird != nil {
		go a.cfg.FollowNetBird(work, a)
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
