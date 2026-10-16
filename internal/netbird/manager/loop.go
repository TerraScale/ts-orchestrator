package manager

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/observability"
)

// Loop lets the cell's leading controller keep the manager reconciled. It
// never returns an error and recovers from panics: NetBird trouble is logged
// and retried with backoff, and never affects the controller.
type Loop struct {
	// Authority is the GRU account authority. Each cycle pins its owner and epoch.
	Authority authority.Fencer
	// Leader reports whether this controller currently holds cell authority.
	// Older callers use Leader until their authority wiring is migrated.
	Leader func() bool
	// Token reads the current admin PAT; the loop clears it after use.
	Token         func(context.Context) ([]byte, error)
	ManagementURL string
	Desired       Desired
	Interval      time.Duration // default 5m, jittered by up to +-20%
	OfflineFor    time.Duration // default DefaultOfflineFor
	Logf          func(format string, args ...any)
	// Test seams.
	newAPI       func(managementURL, token string) (*API, error)
	initialDelay time.Duration
}

const (
	defaultLoopInterval    = 5 * time.Minute
	firstRetry             = 30 * time.Second
	maxRetry               = 30 * time.Minute
	cycleTimeout           = 3 * time.Minute
	authorityCheckInterval = 100 * time.Millisecond
)

var errAuthorityLost = errors.New("NetBird management authority lost")

func (l Loop) withDefaults() Loop {
	if l.Interval <= 0 {
		l.Interval = defaultLoopInterval
	}
	if l.ManagementURL == "" {
		l.ManagementURL = DefaultManagementURL
	}
	if l.newAPI == nil {
		l.newAPI = NewAPI
	}
	// A loop without a leadership check must never mutate the manager, so a
	// nil Leader means "not the leader" rather than "always lead": every
	// controller of a cell would otherwise reconcile concurrently.
	if l.Leader == nil {
		l.Leader = func() bool { return false }
	}
	if l.Logf == nil {
		l.Logf = func(string, ...any) {}
	}
	return l
}

// Run reconciles until ctx ends.
func (l Loop) Run(ctx context.Context) {
	l = l.withDefaults()
	// Let the controller settle before the first cycle.
	delay := l.initialDelay
	if delay <= 0 {
		delay = jitter(30 * time.Second)
	}
	retry := firstRetry
	warned := map[string]bool{}
	for {
		ctx := observability.StartTrace(ctx)
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		if !l.leading() {
			delay, retry = jitter(l.Interval), firstRetry
			continue
		}
		if err := l.cycle(ctx, warned); err != nil {
			if ctx.Err() != nil {
				return
			}
			l.Logf("NetBird management failed, retrying in %s: %v", retry, err)
			delay, retry = jitter(retry), min(retry*2, maxRetry)
			continue
		}
		delay, retry = jitter(l.Interval), firstRetry
	}
}

func (l Loop) cycle(parent context.Context, warned map[string]bool) (err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("NetBird management panicked: %v", recovered)
		}
	}()
	ctx, cancel := context.WithTimeout(parent, cycleTimeout)
	defer cancel()
	ctx, cancelAuthority := context.WithCancelCause(ctx)
	expected := authority.Snapshot{}
	if l.Authority != nil {
		expected = l.Authority.Current()
	}
	checkAuthority := func() error {
		if !l.sameAuthority(expected) {
			cancelAuthority(errAuthorityLost)
		}
		return context.Cause(ctx)
	}
	if err := checkAuthority(); err != nil {
		cancelAuthority(nil)
		return err
	}
	watchDone := make(chan struct{})
	go func() {
		defer func() {
			if recovered := recover(); recovered != nil {
				cancelAuthority(fmt.Errorf("NetBird management panicked: %v", recovered))
			}
			close(watchDone)
		}()
		ticks := time.Tick(authorityCheckInterval)
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticks:
				if checkAuthority() != nil {
					return
				}
			}
		}
	}()
	defer func() {
		cancelAuthority(nil)
		<-watchDone
	}()
	token, err := l.Token(ctx)
	if err != nil {
		return err
	}
	api, err := l.newAPI(l.ManagementURL, string(token))
	clear(token)
	if err != nil {
		return err
	}
	defer api.Close()
	api.beforeWrite = func() error {
		if err := checkAuthority(); err != nil {
			return err
		}
		if l.Authority != nil {
			if err := l.Authority.Guard(ctx, expected.Epoch); err != nil {
				cancelAuthority(errors.Join(errAuthorityLost, err))
			}
		}
		return checkAuthority()
	}
	report, syncErr := Sync(ctx, api, l.Desired, true)
	l.log("sync", report, warned)
	// Peer hygiene only needs the servers group, so a sync refusal (for
	// example a routing-peer mismatch) must not freeze it. Leadership may
	// have moved during sync.
	if err := checkAuthority(); err != nil {
		return errors.Join(syncErr, err)
	}
	report, pruneErr := Prune(ctx, api, l.Desired, PruneOptions{OfflineFor: l.OfflineFor}, true)
	l.log("peer hygiene", report, warned)
	return errors.Join(syncErr, pruneErr)
}

func (l Loop) leading() bool {
	if l.Authority != nil {
		snapshot := l.Authority.Current()
		return snapshot.Scope == "gru" && snapshot.CanMutate()
	}
	return l.Leader()
}

func (l Loop) sameAuthority(expected authority.Snapshot) bool {
	if l.Authority == nil {
		return l.Leader()
	}
	current := l.Authority.Current()
	return expected.Scope == "gru" && current.CanMutate() && current.Scope == expected.Scope &&
		current.DeploymentID == expected.DeploymentID && current.CandidateID == expected.CandidateID &&
		current.OwnerID == expected.OwnerID && current.Epoch == expected.Epoch
}

// log reports every applied change and each distinct warning once.
func (l Loop) log(what string, report Report, warned map[string]bool) {
	for _, change := range report.Changes {
		l.Logf("NetBird %s applied: %s", what, change)
	}
	for _, warning := range report.Warnings {
		if !warned[warning] {
			warned[warning] = true
			l.Logf("NetBird %s warning: %s", what, warning)
		}
	}
}

func jitter(d time.Duration) time.Duration {
	spread := int64(d) / 5
	if spread <= 0 {
		return d
	}
	return d + time.Duration(rand.Int64N(2*spread+1)-spread)
}
