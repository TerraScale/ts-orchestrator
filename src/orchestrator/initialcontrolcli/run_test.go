package initialcontrolcli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"

	"terrascale.tech/orchestrator/src/orchestrator/initialcontrol"
)

type statusRuntime struct {
	mu     sync.Mutex
	status initialcontrol.PreliminaryCaptureStatus
	done   chan struct{}
}

func (r *statusRuntime) Completion() <-chan struct{} { return r.done }
func (r *statusRuntime) PreliminaryCapture() initialcontrol.PreliminaryCaptureStatus {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.status
}

type statusWriter struct {
	bytes.Buffer
	next func()
}

func (w *statusWriter) Write(raw []byte) (int, error) {
	n, err := w.Buffer.Write(raw)
	if w.next != nil {
		next := w.next
		w.next = nil
		next()
	}
	return n, err
}

func TestInitialCLIReportsChangedCaptureAndFinalStatus(t *testing.T) {
	r := &statusRuntime{status: initialcontrol.PreliminaryCaptureStatus{State: "idle"}, done: make(chan struct{})}
	w := &statusWriter{}
	w.next = func() {
		r.mu.Lock()
		r.status = initialcontrol.PreliminaryCaptureStatus{State: "complete", CapturedStreams: 14, TotalStreams: 14, ReceiptSHA256: strings.Repeat("a", 64)}
		r.mu.Unlock()
		close(r.done)
	}
	if err := reportCapture(context.Background(), r, w); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(w.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("status output %s", w.String())
	}
	for i, state := range []string{"idle", "complete"} {
		var event struct {
			PreliminaryCapture initialcontrol.PreliminaryCaptureStatus `json:"preliminaryCapture"`
		}
		if err := json.Unmarshal([]byte(lines[i]), &event); err != nil || event.PreliminaryCapture.State != state {
			t.Fatalf("bad status %s", lines[i])
		}
	}
	if strings.Contains(w.String(), "ready") {
		t.Fatal("capture status asserted readiness")
	}
}
func TestInitialCLIReportsUnchangedStatusOnce(t *testing.T) {
	r := &statusRuntime{status: initialcontrol.PreliminaryCaptureStatus{State: "disabled"}, done: make(chan struct{})}
	close(r.done)
	var out bytes.Buffer
	if err := reportCapture(context.Background(), r, &out); err != nil {
		t.Fatal(err)
	}
	if strings.Count(out.String(), "\n") != 1 {
		t.Fatal("unchanged status repeated")
	}
}

type failedWriter struct{}

func (failedWriter) Write([]byte) (int, error) { return 0, errors.New("SECRET_OUTPUT_FAILURE") }
func TestInitialCLIStatusOutputFailureIsBounded(t *testing.T) {
	r := &statusRuntime{status: initialcontrol.PreliminaryCaptureStatus{State: "idle"}, done: make(chan struct{})}
	err := reportCapture(context.Background(), r, failedWriter{})
	if err == nil || strings.Contains(err.Error(), "SECRET") {
		t.Fatalf("unsafe output error %v", err)
	}
}
