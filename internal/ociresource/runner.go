package ociresource

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/oracle/oci-go-sdk/v65/common"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/observability"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
)

const (
	Interval          = time.Minute
	MaxChangesPerTick = 16
)

type Out struct {
	Same    io.Writer
	Changed io.Writer
}

type Pass struct {
	Kind string
	Run  func(ctx context.Context, out Out) error
}

type KindStatus struct {
	Kind         string        `json:"kind"`
	Result       string        `json:"result"`
	LastRun      time.Time     `json:"last_run"`
	LastSuccess  time.Time     `json:"last_success"`
	Duration     time.Duration `json:"duration"`
	Changes      int           `json:"changes"`
	ChangesTotal int           `json:"changes_total"`
	Errors       int           `json:"errors"`
	Running      bool          `json:"running"`
	Stopped      bool          `json:"stopped"`
}

type Runner struct {
	Region    string
	Authority authority.Fencer
	Passes    []Pass

	mu     sync.Mutex
	leader bool
	kinds  map[string]*KindStatus
}

var runners sync.Map

func (r *Runner) Run(ctx context.Context) {
	runners.Store(r.Region, r)
	defer runners.CompareAndDelete(r.Region, r)
	tick := time.NewTicker(Interval)
	defer tick.Stop()
	for {
		r.tick(ctx)
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

func (r *Runner) tick(ctx context.Context) {
	snapshot := r.Authority.Current()
	r.mu.Lock()
	defer r.mu.Unlock()
	r.leader = snapshot.Leader && snapshot.Ready && snapshot.Epoch != 0
	if !r.leader {
		return
	}
	for _, pass := range r.Passes {
		status := r.status(pass.Kind)
		if status.Running || status.Stopped {
			continue
		}
		status.Running = true
		go r.run(ctx, pass, snapshot.Epoch)
	}
}

func (r *Runner) status(kind string) *KindStatus {
	if r.kinds == nil {
		r.kinds = map[string]*KindStatus{}
	}
	status, ok := r.kinds[kind]
	if !ok {
		status = &KindStatus{Kind: kind, Result: "not run"}
		r.kinds[kind] = status
	}
	return status
}

func (r *Runner) run(ctx context.Context, pass Pass, epoch uint64) {
	var changes atomic.Int64
	var fenced, limited atomic.Bool
	guard := func(ctx context.Context) error {
		if err := r.Authority.Guard(ctx, epoch); err != nil {
			fenced.Store(true)
			return fmt.Errorf("%w: %w", ErrFenced, err)
		}
		if changes.Load() >= MaxChangesPerTick {
			limited.Store(true)
			return fmt.Errorf("%s %s wants more than %d OCI changes in one tick", r.Region, pass.Kind, MaxChangesPerTick)
		}
		changes.Add(1)
		return nil
	}
	started := time.Now()
	err := pass.Run(ociclient.WithAuthority(ctx, guard), Out{Same: io.Discard, Changed: changeLog{ctx: ctx, region: r.Region, kind: pass.Kind}})
	finished := time.Now()
	r.mu.Lock()
	defer r.mu.Unlock()
	status := r.status(pass.Kind)
	status.Running = false
	status.LastRun, status.Duration = started, finished.Sub(started)
	status.Changes = int(changes.Load())
	status.ChangesTotal += status.Changes
	log := slog.With("region", r.Region, "kind", pass.Kind, "changes", status.Changes, "duration", status.Duration.Round(time.Millisecond))
	var service common.ServiceError
	switch {
	case err == nil:
		status.Result, status.LastSuccess = "ok", finished
		log.DebugContext(ctx, "OCI reconcile pass in sync")
	case limited.Load():
		status.Errors++
		status.Stopped = true
		status.Result = fmt.Sprintf("stopped: more than %d changes in one tick", MaxChangesPerTick)
		log.ErrorContext(ctx, "OCI reconcile kind stopped at its change limit; it stays stopped until this leader restarts", "error", err)
	case fenced.Load() || ctx.Err() != nil:
		status.Result = "fenced: leadership lost"
		log.WarnContext(ctx, "OCI reconcile pass lost leadership", "error", err)
	case errors.As(err, &service) && (service.GetHTTPStatusCode() == http.StatusTooManyRequests || service.GetHTTPStatusCode() >= 500):
		status.Errors++
		status.Result = fmt.Sprintf("backed off until the next tick: OCI %d", service.GetHTTPStatusCode())
		log.WarnContext(ctx, "OCI throttled or failed the reconcile pass; the kind waits for the next tick", "status", service.GetHTTPStatusCode(), "error", err)
	default:
		status.Errors++
		status.Result = "failed: " + err.Error()
		log.WarnContext(ctx, "OCI reconcile pass failed", "error", err)
	}
}

func (r *Runner) Leading() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.leader
}

func (r *Runner) Status() []KindStatus {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []KindStatus
	for _, pass := range r.Passes {
		out = append(out, *r.status(pass.Kind))
	}
	return out
}

func WriteMetrics(w io.Writer) {
	runners.Range(func(_, value any) bool {
		r := value.(*Runner)
		observability.WriteGauge(w, observability.Series("ts_orch_oci_reconcile_leader", "region", r.Region), observability.Bool(r.Leading()))
		for _, s := range r.Status() {
			series := func(name string) string { return observability.Series(name, "region", r.Region, "kind", s.Kind) }
			if !s.LastRun.IsZero() {
				observability.WriteGauge(w, series("ts_orch_oci_reconcile_last_run_timestamp_seconds"), float64(s.LastRun.Unix()))
				observability.WriteGauge(w, series("ts_orch_oci_reconcile_duration_seconds"), s.Duration.Seconds())
			}
			if !s.LastSuccess.IsZero() {
				observability.WriteGauge(w, series("ts_orch_oci_reconcile_last_success_timestamp_seconds"), float64(s.LastSuccess.Unix()))
			}
			observability.WriteCounter(w, series("ts_orch_oci_reconcile_changes_total"), float64(s.ChangesTotal))
			observability.WriteCounter(w, series("ts_orch_oci_reconcile_errors_total"), float64(s.Errors))
			observability.WriteGauge(w, series("ts_orch_oci_reconcile_stopped"), observability.Bool(s.Stopped))
		}
		return true
	})
}

type changeLog struct {
	ctx          context.Context
	region, kind string
}

func (l changeLog) Write(p []byte) (int, error) {
	for line := range strings.SplitSeq(strings.TrimSpace(string(p)), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			slog.InfoContext(l.ctx, "OCI change", "region", l.region, "kind", l.kind, "change", line)
		}
	}
	return len(p), nil
}
