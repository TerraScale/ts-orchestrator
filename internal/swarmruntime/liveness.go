package swarmruntime

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/netip"
	"sync/atomic"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/memberstatus"
	"github.com/TerraScale/ts-orchestrator/internal/observability"
	"github.com/TerraScale/ts-orchestrator/internal/storage/execution"
	"github.com/VictoriaMetrics/metrics"
)

const (
	readinessInterval   = 10 * time.Second
	readinessDeadline   = 15 * time.Second
	readinessWindow     = 5 * time.Minute
	readinessStartGrace = time.Minute
	readinessBackoffMax = 15 * time.Minute
	readinessResetAfter = 30 * time.Minute
)

var errTaskUnresponsive = fmt.Errorf("task unresponsive throughout consecutive readiness probes for %s", readinessWindow)

var ReadinessMetrics = metrics.NewSet()

type readinessHistory struct {
	failures int
	task     string
	failed   time.Time
}

type readinessWatch struct {
	next       time.Time
	lastProbe  time.Time
	hungSince  time.Time
	readySince time.Time
	reported   bool
	hungUnix   atomic.Int64
	metric     string
}

func (c *controller) ownsData() bool {
	return c.stateful != nil || execution.Stateful(c.task) || len(c.spec.Mounts) != 0 ||
		c.task.ServiceAnnotations.Labels[LabelServiceSpec] == "terrabase" ||
		c.task.ServiceAnnotations.Labels[LabelRole] == "terrabase" ||
		c.task.Annotations.Labels[LabelRole] == "terrabase"
}

func (c *controller) readinessWatch() *readinessWatch {
	w := &readinessWatch{next: time.Now().Add(readinessStartGrace)}
	if c.ownsData() {
		w.metric = observability.Series(observability.MetricPrefix+"task_unresponsive_seconds", "task", c.task.ID, "service", c.task.ServiceID)
		ReadinessMetrics.NewGauge(w.metric, func() float64 {
			if since := w.hungUnix.Load(); since != 0 {
				return max(time.Since(time.Unix(0, since)).Seconds(), 0)
			}
			return 0
		})
	}
	return w
}

func (w *readinessWatch) close() {
	if w.metric != "" {
		ReadinessMetrics.UnregisterMetric(w.metric)
	}
}

func (s *statefulController) observeReadiness(ctx context.Context) func() {
	ctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		watch := s.readinessWatch()
		defer watch.close()
		ticker := time.NewTicker(readinessInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if time.Now().Before(watch.next) {
					continue
				}
				probeCtx, stop := context.WithTimeout(ctx, readinessDeadline)
				err := s.source.ObserveReadiness(probeCtx, s.task)
				stop()
				s.readinessFailed(ctx, watch, err)
			}
		}
	}()
	return func() { cancel(); <-done }
}

func (w *readinessWatch) observe(now time.Time, err error) bool {
	if !w.lastProbe.IsZero() && now.Sub(w.lastProbe) > readinessDeadline+2*readinessInterval {
		w.hungSince = time.Time{}
		w.readySince = time.Time{}
	}
	w.lastProbe = now
	w.next = now.Add(readinessInterval)
	if err == nil {
		w.hungSince = time.Time{}
		if w.readySince.IsZero() {
			w.readySince = now
		}
		return false
	}
	w.readySince = time.Time{}
	if !errors.Is(err, memberstatus.ErrUnresponsive) {
		w.hungSince = time.Time{}
		return false
	}
	if w.hungSince.IsZero() {
		w.hungSince = now.Add(-readinessDeadline)
	}
	return now.Sub(w.hungSince) >= readinessWindow
}

func readinessBackoff(n int) time.Duration {
	return min(time.Minute<<min(max(n-1, 0), 4), readinessBackoffMax)
}

func (c *controller) recordReadinessFailure() {
	if c.ownsData() {
		return
	}
	e := c.executor
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.readiness == nil {
		e.readiness = make(map[string]readinessHistory)
	}
	h := e.readiness[restartKey(c.task)]
	if h.task == c.task.ID {
		return
	}
	h.failures++
	h.task, h.failed = c.task.ID, time.Now()
	e.readiness[restartKey(c.task)] = h
}

func (c *controller) readinessFailed(ctx context.Context, w *readinessWatch, err error) bool {
	expired := w.observe(time.Now(), err)
	if c.ownsData() {
		if w.hungSince.IsZero() {
			w.hungUnix.Store(0)
			if w.reported {
				slog.InfoContext(ctx, "task readiness unresponsive window cleared", "task", c.task.ID, "error", err)
				w.reported = false
			}
		} else {
			w.hungUnix.Store(w.hungSince.UnixNano())
			if expired && !w.reported {
				slog.WarnContext(ctx, "data-owning task unresponsive for five minutes; operator action required", "task", c.task.ID)
				w.reported = true
			}
		}
		return false
	}
	if !expired {
		if !w.readySince.IsZero() && time.Since(w.readySince) >= readinessResetAfter {
			c.executor.mu.Lock()
			delete(c.executor.readiness, restartKey(c.task))
			c.executor.mu.Unlock()
		}
		return false
	}
	return ctx.Err() == nil
}

func probeLiveness(ctx context.Context, task *controller, port uint16) error {
	ctx, cancel := context.WithTimeout(ctx, readinessDeadline)
	defer cancel()
	var sent, answered atomic.Bool
	trace := &httptrace.ClientTrace{
		WroteRequest:         func(info httptrace.WroteRequestInfo) { sent.Store(info.Err == nil) },
		GotFirstResponseByte: func() { answered.Store(true) },
	}
	transport := &http.Transport{DialContext: (&net.Dialer{Timeout: time.Second}).DialContext, DisableKeepAlives: true, MaxResponseHeaderBytes: 8 << 10}
	defer transport.CloseIdleConnections()
	endpoint := netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), port)
	request, err := http.NewRequestWithContext(httptrace.WithClientTrace(ctx, trace), http.MethodGet, "http://"+endpoint.String()+ReadyPath(task.spec), nil)
	if err != nil {
		return err
	}
	response, err := (&http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}).Do(request)
	if err != nil {
		if sent.Load() && !answered.Load() && errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return memberstatus.ErrUnresponsive
		}
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("task readiness HTTP %d", response.StatusCode)
	}
	return nil
}
