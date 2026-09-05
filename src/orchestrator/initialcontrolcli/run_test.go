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
	mu          sync.Mutex
	status      initialcontrol.PreliminaryCaptureStatus
	publication initialcontrol.PreliminaryPublicationStatus
	done        chan struct{}
}

func (r *statusRuntime) Completion() <-chan struct{} { return r.done }
func (r *statusRuntime) PreliminaryCapture() initialcontrol.PreliminaryCaptureStatus {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.status
}

func (r *statusRuntime) PreliminaryPublication() initialcontrol.PreliminaryPublicationStatus {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.publication
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
	if err := reportPreliminary(context.Background(), r, w); err != nil {
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
	if err := reportPreliminary(context.Background(), r, &out); err != nil {
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
	err := reportPreliminary(context.Background(), r, failedWriter{})
	if err == nil || strings.Contains(err.Error(), "SECRET") {
		t.Fatalf("unsafe output error %v", err)
	}
}

func TestInitialCLIReportsPublicationWithoutCaptureChange(t *testing.T) {
	r := &statusRuntime{status: initialcontrol.PreliminaryCaptureStatus{State: "complete"}, publication: initialcontrol.PreliminaryPublicationStatus{State: "publishing", ScopeSHA256: strings.Repeat("a", 64)}, done: make(chan struct{})}
	w := &statusWriter{}
	w.next = func() {
		r.mu.Lock()
		r.publication.State = "complete"
		r.publication.ReceiptSHA256 = strings.Repeat("b", 64)
		r.mu.Unlock()
		close(r.done)
	}
	if err := reportPreliminary(context.Background(), r, w); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(w.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("status output %s", w.String())
	}
	for i, state := range []string{"publishing", "complete"} {
		var event struct {
			PreliminaryPublication initialcontrol.PreliminaryPublicationStatus `json:"preliminaryPublication"`
		}
		if err := json.Unmarshal([]byte(lines[i]), &event); err != nil || event.PreliminaryPublication.State != state {
			t.Fatalf("bad publication status %s", lines[i])
		}
		if i == 1 && event.PreliminaryPublication.ReceiptSHA256 != strings.Repeat("b", 64) {
			t.Fatal("missing final receipt digest")
		}
	}
	if strings.Contains(w.String(), "ready") {
		t.Fatal("publication asserted readiness")
	}
}

func TestInitialCLIStatusRedactsWorkerErrors(t *testing.T) {
	r := &statusRuntime{status: initialcontrol.PreliminaryCaptureStatus{State: "failed", Error: "SECRET_CAPTURE /private/key"}, publication: initialcontrol.PreliminaryPublicationStatus{State: "failed", Error: "SECRET_PROVIDER /private/credential"}, done: make(chan struct{})}
	close(r.done)
	var out bytes.Buffer
	if err := reportPreliminary(context.Background(), r, &out); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "SECRET") || strings.Contains(out.String(), "private") {
		t.Fatalf("unsafe status %s", out.String())
	}
	if !strings.Contains(out.String(), "preliminary publication refused or incomplete") {
		t.Fatal("missing bounded publication failure")
	}
}
