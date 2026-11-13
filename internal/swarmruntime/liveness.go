package swarmruntime

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptrace"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/memberstatus"
	"github.com/TerraScale/ts-orchestrator/internal/observability"
	"github.com/VictoriaMetrics/metrics"
)

const (
	readinessLookupDeadline = 5 * time.Second
	readinessInterval       = 10 * time.Second
	readinessDeadline       = 15 * time.Second
	readinessWindow         = 4 * time.Minute
)

var ReadinessMetrics = metrics.NewSet()

type readinessHost struct {
	mu      sync.Mutex
	watches map[*readinessWatch]struct{}
	cancel  context.CancelFunc
}

type readinessWatch struct {
	controller       *controller
	ctx              context.Context
	hungSince        time.Time
	reported         bool
	hungAt           atomic.Pointer[time.Time]
	others           atomic.Bool
	metric           string
	peersMetric      string
	unobservedMetric string
}

type readinessResult struct {
	watch   *readinessWatch
	started time.Time
	err     error
}

func (c *controller) readinessWatch(ctx context.Context) *readinessWatch {
	w := &readinessWatch{controller: c, ctx: ctx}
	service := c.task.ServiceAnnotations.Labels[LabelServiceSpec]
	if service == "" {
		service = c.task.ServiceAnnotations.Labels[LabelRole]
	}
	if service == "" {
		service = c.task.ServiceAnnotations.Name
	}
	w.metric = observability.Series(observability.MetricPrefix+"task_unresponsive_seconds", "task", c.task.ID, "service", service)
	w.peersMetric = observability.Series(observability.MetricPrefix+"task_readiness_others_answered", "task", c.task.ID, "service", service)
	w.unobservedMetric = observability.Series(observability.MetricPrefix+"task_readiness_unobserved_total", "task", c.task.ID, "service", service)
	h := &c.executor.liveness
	h.mu.Lock()
	defer h.mu.Unlock()
	ReadinessMetrics.NewGauge(w.metric, func() float64 {
		if since := w.hungAt.Load(); since != nil {
			return max(time.Since(*since).Seconds(), 0)
		}
		return 0
	})
	ReadinessMetrics.NewGauge(w.peersMetric, func() float64 {
		if w.others.Load() {
			return 1
		}
		return 0
	})
	ReadinessMetrics.GetOrCreateCounter(w.unobservedMetric)
	if len(h.watches) == 0 {
		h.watches = make(map[*readinessWatch]struct{})
		observerCtx, cancel := context.WithCancel(context.Background())
		h.cancel = cancel
		go c.executor.observeReadiness(observerCtx)
	}
	h.watches[w] = struct{}{}
	return w
}

func (w *readinessWatch) close() {
	h := &w.controller.executor.liveness
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.watches, w)
	if len(h.watches) == 0 {
		h.cancel()
	}
	ReadinessMetrics.UnregisterMetric(w.metric)
	ReadinessMetrics.UnregisterMetric(w.peersMetric)
	ReadinessMetrics.UnregisterMetric(w.unobservedMetric)
}

func (s *statefulController) observeReadiness(ctx context.Context) func() {
	watch := s.readinessWatch(ctx)
	return watch.close
}

func (c *controller) readinessObservation(ctx context.Context) (time.Time, error) {
	if c.stateful != nil {
		started := time.Now()
		return started, c.stateful.source.ObserveReadiness(ctx, c.task)
	}
	lookupCtx, cancel := context.WithTimeout(ctx, readinessLookupDeadline)
	defer cancel()
	port, err := hostPort(c.task)
	if err != nil {
		return time.Time{}, errors.Join(memberstatus.ErrReadinessUnobserved, err)
	}
	if usesTaskPort(c.spec.Env) {
		ctr, err := c.executor.client.LoadContainer(runtimeContext(lookupCtx), c.id)
		if err != nil {
			return time.Time{}, errors.Join(memberstatus.ErrReadinessUnobserved, err)
		}
		labels, err := ctr.Labels(runtimeContext(lookupCtx))
		if err != nil {
			return time.Time{}, errors.Join(memberstatus.ErrReadinessUnobserved, err)
		}
		if labels["terrascale.task"] != c.task.ID || labels["terrascale.service"] != c.task.ServiceID || labels["terrascale.spec"] != c.fingerprint {
			return time.Time{}, memberstatus.ErrReadinessUnobserved
		}
		ownPort, err := strconv.ParseUint(labels[portsLabel], 10, 16)
		if err != nil || ownPort == 0 {
			return time.Time{}, errors.Join(memberstatus.ErrReadinessUnobserved, err)
		}
		port = uint16(ownPort)
	}
	if err := lookupCtx.Err(); err != nil {
		return time.Time{}, errors.Join(memberstatus.ErrReadinessUnobserved, err)
	}
	started := time.Now()
	return started, probeLiveness(ctx, net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port))), ReadyPath(c.spec))
}

func (e *Executor) observeReadiness(ctx context.Context) {
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			e.readinessRound(ctx)
			timer.Reset(readinessInterval)
		}
	}
}

func (e *Executor) readinessRound(ctx context.Context) {
	h := &e.liveness
	h.mu.Lock()
	var watches []*readinessWatch
	for w := range h.watches {
		if w.ctx.Err() == nil {
			watches = append(watches, w)
		}
	}
	h.mu.Unlock()
	results := make([]readinessResult, len(watches))
	var probes sync.WaitGroup
	for i, w := range watches {
		probes.Go(func() {
			probeCtx, cancel := context.WithCancel(w.ctx)
			defer cancel()
			stop := context.AfterFunc(ctx, cancel)
			defer stop()
			started, err := w.controller.readinessObservation(probeCtx)
			results[i] = readinessResult{watch: w, started: started, err: err}
		})
	}
	probes.Wait()
	h.mu.Lock()
	defer h.mu.Unlock()
	if ctx.Err() != nil {
		return
	}
	answered := 0
	for _, result := range results {
		if _, active := h.watches[result.watch]; active && result.watch.ctx.Err() == nil && readinessAnswered(result.err) {
			answered++
		}
	}
	for _, result := range results {
		w := result.watch
		if _, active := h.watches[w]; !active || w.ctx.Err() != nil {
			continue
		}
		others := answered
		if readinessAnswered(result.err) {
			others--
		}
		w.others.Store(others > 0)
		w.observe(result.started, result.err)
	}
}

func readinessAnswered(err error) bool {
	return err == nil || errors.Is(err, memberstatus.ErrReadinessAnswered)
}

func (w *readinessWatch) observe(started time.Time, err error) {
	if readinessAnswered(err) {
		w.hungSince = time.Time{}
		w.hungAt.Store(nil)
		if w.reported {
			slog.InfoContext(w.ctx, "task readiness unresponsive window cleared", "task", w.controller.task.ID)
			w.reported = false
		}
		return
	}
	if !errors.Is(err, memberstatus.ErrUnresponsive) {
		w.hungSince = time.Time{}
		w.hungAt.Store(nil)
		ReadinessMetrics.GetOrCreateCounter(w.unobservedMetric).Inc()
		return
	}
	if w.hungSince.IsZero() {
		w.hungSince = started
		w.hungAt.Store(&started)
	}
	if !w.reported && time.Since(w.hungSince) >= readinessWindow {
		slog.WarnContext(w.ctx, "task unresponsive", "task", w.controller.task.ID, "others_answered", w.others.Load())
		w.reported = true
	}
}

func probeLiveness(ctx context.Context, endpoint, path string) error {
	ctx, cancel := context.WithTimeout(ctx, readinessDeadline)
	defer cancel()
	var sent, answered atomic.Bool
	trace := &httptrace.ClientTrace{
		WroteRequest:         func(info httptrace.WroteRequestInfo) { sent.Store(info.Err == nil) },
		GotFirstResponseByte: func() { answered.Store(true) },
	}
	transport := &http.Transport{DialContext: (&net.Dialer{Timeout: time.Second}).DialContext, DisableKeepAlives: true, MaxResponseHeaderBytes: 8 << 10}
	defer transport.CloseIdleConnections()
	request, err := http.NewRequestWithContext(httptrace.WithClientTrace(ctx, trace), http.MethodGet, "http://"+endpoint+path, nil)
	if err != nil {
		return errors.Join(memberstatus.ErrReadinessUnobserved, err)
	}
	response, err := (&http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}).Do(request)
	if err != nil {
		if answered.Load() {
			return errors.Join(memberstatus.ErrReadinessAnswered, err)
		}
		if sent.Load() && errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return memberstatus.ErrUnresponsive
		}
		return errors.Join(memberstatus.ErrReadinessUnobserved, err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("%w: HTTP %d", memberstatus.ErrReadinessAnswered, response.StatusCode)
	}
	return nil
}
