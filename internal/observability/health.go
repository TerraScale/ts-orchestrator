package observability

import (
	"context"
	"sync"
	"time"
)

// Check is one readiness condition. It must be cheap and must not block on
// the network for longer than the caller's context allows.
type Check struct {
	Name string
	// Run returns an empty detail when healthy. A failing detail is a short
	// fixed phrase, never upstream error text, because /readyz is
	// unauthenticated on loopback.
	Run func(context.Context) (ok bool, detail string)
}

// Health aggregates readiness checks. Liveness is the process answering at
// all; readiness is every registered check passing.
type Health struct {
	mu     sync.RWMutex
	checks []Check
}

// Add registers a readiness check.
func (health *Health) Add(check Check) {
	if health == nil || check.Name == "" || check.Run == nil {
		return
	}
	health.mu.Lock()
	defer health.mu.Unlock()
	health.checks = append(health.checks, check)
}

// Evaluate runs every check with a bounded deadline and reports overall
// readiness. A process with no checks registered is not ready: it has not
// finished wiring its runtime yet.
func (health *Health) Evaluate(ctx context.Context) (bool, []CheckResult) {
	if health == nil {
		return false, nil
	}
	health.mu.RLock()
	checks := append([]Check(nil), health.checks...)
	health.mu.RUnlock()
	if len(checks) == 0 {
		return false, []CheckResult{{Name: "startup", Detail: "runtime checks are not registered"}}
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	ready := true
	results := make([]CheckResult, 0, len(checks))
	for _, check := range checks {
		ok, detail := check.Run(ctx)
		ready = ready && ok
		results = append(results, CheckResult{Name: check.Name, OK: ok, Detail: detail})
	}
	return ready, results
}
