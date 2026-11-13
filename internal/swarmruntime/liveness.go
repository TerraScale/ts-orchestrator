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

	"github.com/TerraScale/ts-orchestrator/internal/handoff"
	"github.com/TerraScale/ts-orchestrator/internal/memberstatus"
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

type readinessHistory struct {
	failures int
	task     string
	failed   time.Time
}

type readinessWatch struct {
	next       time.Time
	hungSince  time.Time
	readySince time.Time
	suppressed uint64
}

func (c *controller) readinessWatch() readinessWatch {
	return readinessWatch{next: time.Now().Add(readinessStartGrace)}
}

func (w *readinessWatch) observe(now time.Time, err error) bool {
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
	if !w.observe(time.Now(), err) {
		if !w.readySince.IsZero() && time.Since(w.readySince) >= readinessResetAfter {
			c.executor.mu.Lock()
			delete(c.executor.readiness, restartKey(c.task))
			c.executor.mu.Unlock()
		}
		return false
	}
	if c.stateful != nil || c.regionalTerraBase() || len(c.spec.Mounts) != 0 {
		peerCtx, cancel := context.WithTimeout(ctx, readinessDeadline)
		err := handoff.TaskPeerReady(peerCtx, c.task.ID)
		cancel()
		if err != nil {
			w.suppressed++
			slog.WarnContext(ctx, "hung task retained without a ready regional peer", "task", c.task.ID, "suppressed", w.suppressed, "error", err)
			return false
		}
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
