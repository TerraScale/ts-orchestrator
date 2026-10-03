package manager

import (
	"context"
	"fmt"
	"math/rand/v2"
	"time"
)

// Loop lets the cell's leading controller keep the manager reconciled. It
// never returns an error and recovers from panics: NetBird trouble is logged
// and retried with backoff, and never affects the controller.
type Loop struct {
	// Leader reports whether this controller currently holds cell authority.
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
	defaultLoopInterval = 5 * time.Minute
	firstRetry          = 30 * time.Second
	maxRetry            = 30 * time.Minute
	cycleTimeout        = 3 * time.Minute
)

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
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		if !l.Leader() {
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
	report, err := Sync(ctx, api, l.Desired, true)
	l.log("sync", report, warned)
	if err != nil {
		return err
	}
	// Leadership may have moved during sync.
	if !l.Leader() {
		return nil
	}
	report, err = Prune(ctx, api, l.Desired, PruneOptions{OfflineFor: l.OfflineFor}, true)
	l.log("peer hygiene", report, warned)
	return err
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
