package swarmruntime

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptrace"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/memberstatus"
	"github.com/TerraScale/ts-orchestrator/internal/observability"
	"github.com/TerraScale/ts-orchestrator/internal/storage/execution"
	"github.com/VictoriaMetrics/metrics"
	"github.com/gofrs/flock"
)

const (
	readinessLookupDeadline     = 5 * time.Second
	readinessCorrelationOverlap = time.Minute
	readinessInterval           = 10 * time.Second
	readinessDeadline           = 15 * time.Second
	readinessWindow             = 5 * time.Minute
	readinessStartGrace         = time.Minute
	readinessBackoffMax         = 15 * time.Minute
	readinessResetAfter         = 30 * time.Minute
	readinessHostBudget         = 15 * time.Minute
)

var errTaskUnresponsive = fmt.Errorf("task unresponsive throughout consecutive readiness probes for %s", readinessWindow)
var errReadinessUnobserved = errors.New("exact task readiness endpoint unavailable")
var ReadinessMetrics = metrics.NewSet()

type dataOwnership uint8

const (
	ownershipUnknown dataOwnership = iota
	dataOwner
	notDataOwner
)

type readinessHistory struct {
	failures int
	task     string
	failed   time.Time
}

type readinessHost struct {
	mu      sync.Mutex
	watches map[*readinessWatch]struct{}
	cancel  context.CancelFunc
}

type readinessWatch struct {
	controller      *controller
	ctx             context.Context
	failed          chan error
	next            time.Time
	lastRound       time.Time
	hungSince       time.Time
	failedFor       time.Duration
	witnessed       bool
	readySince      time.Time
	reported        string
	missingReported bool
	hungUnix        atomic.Int64
	metric          string
	evidence        []readinessSpan
	overlaps        map[string]time.Duration
}

type readinessSpan struct{ start, end time.Time }

type readinessResult struct {
	watch    *readinessWatch
	lookup   time.Time
	started  time.Time
	finished time.Time
	err      error
}

func (c *controller) ownsData() dataOwnership {
	if c == nil || c.task == nil || c.spec == nil {
		return ownershipUnknown
	}
	if c.stateful != nil || execution.Stateful(c.task) || len(c.spec.Mounts) != 0 ||
		c.task.ServiceAnnotations.Labels[LabelServiceSpec] == "terrabase" ||
		c.task.ServiceAnnotations.Labels[LabelRole] == "terrabase" ||
		c.task.Annotations.Labels[LabelRole] == "terrabase" {
		return dataOwner
	}
	for _, labels := range []map[string]string{c.task.Annotations.Labels, c.task.ServiceAnnotations.Labels} {
		if value, present := labels["terrascale.stateful"]; present && value != "false" {
			return ownershipUnknown
		}
	}
	spec, err := DecodeContainer(c.task)
	if err != nil {
		return ownershipUnknown
	}
	if _, err := execution.TaskSHA256(c.task); err != nil {
		return ownershipUnknown
	}
	if len(spec.Mounts) != 0 {
		return dataOwner
	}
	return notDataOwner
}

func (c *controller) readinessWatch(ctx context.Context) *readinessWatch {
	w := &readinessWatch{controller: c, ctx: ctx, failed: make(chan error, 1), next: time.Now().Add(readinessStartGrace)}
	w.metric = observability.Series(observability.MetricPrefix+"task_unresponsive_seconds", "task", c.task.ID, "service", c.task.ServiceID)
	ReadinessMetrics.NewGauge(w.metric, func() float64 {
		if since := w.hungUnix.Load(); since != 0 {
			return max(time.Since(time.Unix(0, since)).Seconds(), 0)
		}
		return 0
	})
	h := &c.executor.liveness
	h.mu.Lock()
	defer h.mu.Unlock()
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
		return time.Time{}, errors.Join(errReadinessUnobserved, err)
	}
	if usesTaskPort(c.spec.Env) {
		ctr, err := c.container(lookupCtx)
		if err != nil {
			return time.Time{}, errors.Join(errReadinessUnobserved, err)
		}
		labels, err := ctr.Labels(runtimeContext(lookupCtx))
		if err != nil {
			return time.Time{}, errors.Join(errReadinessUnobserved, err)
		}
		ownPort, err := strconv.ParseUint(labels[portsLabel], 10, 16)
		if err != nil || ownPort == 0 {
			return time.Time{}, errors.Join(errReadinessUnobserved, err)
		}
		port = uint16(ownPort)
	}
	if err := lookupCtx.Err(); err != nil {
		return time.Time{}, errors.Join(errReadinessUnobserved, err)
	}
	started := time.Now()
	return started, probeLiveness(ctx, net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port))), ReadyPath(c.spec))
}

func (e *Executor) observeReadiness(ctx context.Context) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	health := ""
	if err == nil {
		health = listener.Addr().String()
		server := &http.Server{ReadHeaderTimeout: readinessDeadline, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet || r.URL.Path != "/healthz" {
				http.NotFound(w, r)
				return
			}
			w.WriteHeader(http.StatusOK)
		})}
		defer server.Close()
		go func() { _ = server.Serve(listener) }()
	} else {
		slog.WarnContext(ctx, "local readiness witness unavailable", "error", err)
	}
	timer := time.NewTimer(readinessInterval)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			e.readinessRound(ctx, health)
			timer.Reset(readinessInterval)
		}
	}
}

func (e *Executor) readinessRound(ctx context.Context, health string) {
	h := &e.liveness
	h.mu.Lock()
	var watches []*readinessWatch
	for w := range h.watches {
		if w.ctx.Err() == nil && !time.Now().Before(w.next) {
			watches = append(watches, w)
		}
	}
	watched := len(h.watches)
	h.mu.Unlock()
	if len(watches) == 0 {
		return
	}
	results := make([]readinessResult, len(watches))
	var probes sync.WaitGroup
	for i, w := range watches {
		probes.Go(func() {
			probeCtx, cancel := context.WithCancel(w.ctx)
			defer cancel()
			stop := context.AfterFunc(ctx, cancel)
			defer stop()
			lookup := time.Now()
			started, err := w.controller.readinessObservation(probeCtx)
			results[i] = readinessResult{watch: w, lookup: lookup, started: started, finished: time.Now(), err: err}
		})
	}
	localAnswered := false
	if watched == 1 && health != "" {
		probes.Go(func() {
			localAnswered = probeLiveness(ctx, health, "/healthz") == nil
		})
	}
	probes.Wait()
	h.mu.Lock()
	defer h.mu.Unlock()
	if ctx.Err() != nil {
		return
	}
	now := time.Now()
	answered := 0
	for _, result := range results {
		if _, active := h.watches[result.watch]; active && result.watch.ctx.Err() == nil && readinessAnswered(result.err) {
			answered++
		}
	}
	witnesses := make(map[*readinessWatch]bool, len(results))
	for _, result := range results {
		w := result.watch
		if _, active := h.watches[w]; !active || w.ctx.Err() != nil {
			continue
		}
		others := answered
		if readinessAnswered(result.err) {
			others--
		}
		witness := others > 0 || watched == 1 && localAnswered
		witnesses[w] = witness
		w.observe(result.lookup, result.started, result.finished, result.err, witness)
	}
	for _, result := range results {
		w := result.watch
		if _, active := h.watches[w]; !active || w.ctx.Err() != nil || len(w.evidence) == 0 || !w.controller.replacementEligible() {
			continue
		}
		if w.overlaps == nil {
			w.overlaps = make(map[string]time.Duration)
		}
		for _, other := range results {
			v := other.watch
			if _, active := h.watches[v]; !active || v.ctx.Err() != nil || v == w || len(v.evidence) == 0 || !v.controller.replacementEligible() {
				continue
			}
			for _, left := range w.evidence {
				for _, right := range v.evidence {
					from, to := left.start, left.end
					if right.start.After(from) {
						from = right.start
					}
					if right.end.Before(to) {
						to = right.end
					}
					w.overlaps[v.controller.task.ID] += max(to.Sub(from), 0)
				}
			}
		}
	}
	for _, result := range results {
		w := result.watch
		if _, active := h.watches[w]; !active || w.ctx.Err() != nil {
			continue
		}
		w.decide(now, result.err, witnesses[w])
	}
}

func readinessAnswered(err error) bool {
	return err == nil || errors.Is(err, memberstatus.ErrReadinessAnswered)
}

func (w *readinessWatch) observe(lookup, started, now time.Time, err error, witness bool) {
	w.next = now.Add(readinessInterval)
	w.evidence = nil
	if errors.Is(err, errReadinessUnobserved) {
		w.readySince = time.Time{}
		w.witnessed = false
		ReadinessMetrics.GetOrCreateCounter(observability.Series(observability.MetricPrefix+"task_readiness_unobserved_total", "task", w.controller.task.ID, "service", w.controller.task.ServiceID)).Inc()
		if !w.missingReported {
			slog.WarnContext(w.ctx, "task readiness not observed: exact task endpoint unavailable", "task", w.controller.task.ID, "error", err)
			w.missingReported = true
		}
		return
	}
	if readinessAnswered(err) {
		w.hungSince = time.Time{}
		w.failedFor = 0
		w.overlaps = nil
		w.hungUnix.Store(0)
		if w.reported != "" {
			slog.InfoContext(w.ctx, "task readiness unresponsive window cleared", "task", w.controller.task.ID, "reason", w.reported)
			w.reported = ""
		}
	}
	if errors.Is(err, memberstatus.ErrUnresponsive) && w.hungSince.IsZero() {
		w.hungSince = started
	}
	if !witness {
		w.readySince = time.Time{}
		w.witnessed = false
		return
	}
	if errors.Is(err, memberstatus.ErrUnresponsive) {
		w.readySince = time.Time{}
		w.evidence = []readinessSpan{{started, now}}
		if w.witnessed && lookup.Sub(w.lastRound) <= 2*readinessInterval {
			w.evidence = append(w.evidence, readinessSpan{w.lastRound, lookup})
		}
		for _, span := range w.evidence {
			w.failedFor += max(span.end.Sub(span.start), 0)
		}
		w.witnessed = true
	} else {
		w.failedFor = 0
		w.overlaps = nil
		w.witnessed = false
		if err == nil {
			if w.readySince.IsZero() {
				w.readySince = now
			}
		} else {
			w.readySince = time.Time{}
		}
	}
	w.lastRound = now
}

func (c *controller) replacementEligible() bool {
	return c.ownsData() == notDataOwner && c.task.ServiceAnnotations.Labels[LabelReplaceWhenUnresponsive] == "true"
}

func (w *readinessWatch) report(reason string) {
	w.hungUnix.Store(w.hungSince.UnixNano())
	if w.reported == "" {
		slog.WarnContext(w.ctx, "task unresponsive; "+reason, "task", w.controller.task.ID)
		w.reported = reason
	}
}

func (w *readinessWatch) decide(now time.Time, err error, witness bool) {
	c := w.controller
	if w.hungSince.IsZero() {
		if !w.readySince.IsZero() && now.Sub(w.readySince) >= readinessResetAfter {
			c.executor.mu.Lock()
			delete(c.executor.readiness, restartKey(c.task))
			c.executor.mu.Unlock()
		}
		return
	}
	if now.Sub(w.hungSince) < readinessWindow {
		return
	}
	switch c.ownsData() {
	case dataOwner:
		w.report("not replaced: data owner")
		return
	case ownershipUnknown:
		w.report("not replaced: ownership unknown")
		return
	}
	if !c.replacementEligible() {
		w.report("not replaced: service has not requested replacement")
		return
	}
	if !witness {
		w.report("not replaced: no witness answered")
		return
	}
	failing := 0
	for _, overlap := range w.overlaps {
		if overlap >= readinessCorrelationOverlap {
			failing++
		}
	}
	if failing > 0 {
		w.report(fmt.Sprintf("not replaced: correlated with %d other tasks", failing))
		return
	}
	if errors.Is(err, errReadinessUnobserved) || w.failedFor < readinessWindow {
		return
	}
	if err := c.executor.reserveReadinessReplacement(now); err != nil {
		w.report("not replaced: host replacement budget unavailable")
		return
	}
	select {
	case w.failed <- errors.Join(errTaskUnresponsive, err):
		w.next = now.Add(readinessHostBudget)
	default:
	}
}

func (e *Executor) reserveReadinessReplacement(now time.Time) error {
	lock := flock.New(e.socket + ".readiness.lock")
	locked, err := lock.TryLock()
	if err != nil || !locked {
		return errors.New("host replacement budget locked")
	}
	defer lock.Unlock()
	path := filepath.Join(filepath.Dir(e.logRoot), "readiness-replacement")
	data, err := os.ReadFile(path)
	if err == nil {
		last, err := time.Parse(time.RFC3339Nano, string(data))
		if err != nil {
			return err
		}
		if now.Sub(last) < readinessHostBudget {
			return errors.New("host replacement budget used")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	_, writeErr := file.WriteString(now.UTC().Format(time.RFC3339Nano))
	syncErr := file.Sync()
	return errors.Join(writeErr, syncErr, file.Close())
}

func readinessBackoff(n int) time.Duration {
	return min(time.Minute<<min(max(n-1, 0), 4), readinessBackoffMax)
}

func (c *controller) recordReadinessFailure() {
	if c.ownsData() != notDataOwner {
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
		return err
	}
	response, err := (&http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}).Do(request)
	if err != nil {
		if sent.Load() && !answered.Load() && errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return memberstatus.ErrUnresponsive
		}
		if answered.Load() {
			return errors.Join(memberstatus.ErrReadinessAnswered, err)
		}
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("%w: HTTP %d", memberstatus.ErrReadinessAnswered, response.StatusCode)
	}
	return nil
}
