package host

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/logs"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
)

const journalWarning = `{"_SYSTEMD_UNIT":"terrascale-orchestrator-host.service","_COMM":"terrascale-orch","_PID":"976","PRIORITY":"4","MESSAGE":"rollout step 3 relay failed"}`

type sentWindow struct {
	subject string
	window  logs.Window
}

// capturePublish decodes each published window, so a test checks what a
// controller would read.
func capturePublish(t *testing.T, sent *[]sentWindow) func(string, []byte) error {
	return func(subject string, data []byte) error {
		var window logs.Window
		if err := json.Unmarshal(data, &window); err != nil {
			t.Errorf("published %s: %v", data, err)
		}
		*sent = append(*sent, sentWindow{subject, window})
		return nil
	}
}

func journalOf(lines string) func(context.Context) (io.ReadCloser, error) {
	return func(context.Context) (io.ReadCloser, error) {
		return io.NopCloser(strings.NewReader(lines)), nil
	}
}

func TestFollowLogsPublishesEachMinuteOfJournalLines(t *testing.T) {
	start := time.Date(2026, 10, 9, 19, 31, 0, 0, time.UTC)
	a := &Agent{cfg: AgentConfig{Cell: "gru", Node: "node-a", NATSUserPublicKey: testNATSUserKey("node-a")},
		wallNow: func() time.Time { return start.Add(10 * time.Second) }}
	var sent []sentWindow
	windows := &logWindows{
		counter: logs.NewCounter("gru", "node-a"),
		subject: protocol.AgentObservation("gru", testNATSUserKey("node-a"), "logs"),
		minute:  start,
		publish: capturePublish(t, &sent),
	}
	var retry logRetry

	err := a.followLogs(t.Context(), journalOf(journalWarning+"\n[104,105]\n"), windows, &retry)
	if err == nil || err.Error() != "journalctl exited" {
		t.Fatalf("followLogs = %v, want the journal to have exited", err)
	}
	windows.observe(t.Context(), start.Add(10*time.Second), nil, true)
	windows.roll(t.Context(), start.Add(2*time.Minute+time.Second))

	if len(sent) != 2 {
		t.Fatalf("published %d windows, want the finished minute and the silent one after it", len(sent))
	}
	first, silent := sent[0], sent[1]
	if first.subject != "ts.orch.v1.gru.agent."+testNATSUserKey("node-a")+".observation.logs" || first.window.Region != "gru" || first.window.Node != "node-a" || !first.window.Minute.Equal(start) || first.window.Seq != 0 {
		t.Fatalf("first window %+v on %s", first.window, first.subject)
	}
	// Equal counts and levels sort by component, so the empty one comes first.
	wantFirst := []logs.Class{
		{Service: "ts-orchestrator", Level: logs.LevelWarn, Message: "rollout step N relay failed", Count: 1, Example: "rollout step 3 relay failed"},
		{Service: "ts-orchestrator", Level: logs.LevelWarn, Component: "logs", Message: "oversized journal line", Count: 1},
	}
	if !slices.Equal(first.window.Classes, wantFirst) {
		t.Fatalf("classes = %+v", first.window.Classes)
	}
	if silent.window.Seq != 1 || len(silent.window.Classes) != 0 || !silent.window.Minute.Equal(start.Add(time.Minute)) {
		t.Fatalf("silent window = %+v, want an empty next minute", silent.window)
	}
}

func TestReadLogLinesSkipsAnOversizedLineButKeepsTheNext(t *testing.T) {
	long := strings.Repeat("x", logLineLimit+10) + "\n"
	var oversized []bool
	err := readLogLines(strings.NewReader(long+"ok\n"), func(_ []byte, over bool) {
		oversized = append(oversized, over)
	})
	if err != io.EOF {
		t.Fatalf("readLogLines = %v", err)
	}
	if len(oversized) != 2 || !oversized[0] || oversized[1] {
		t.Fatalf("lines oversized = %v, want the long line then the short one", oversized)
	}
}

func TestFollowLogsReturnsAFailedStart(t *testing.T) {
	a := &Agent{}
	wantErr := errors.New("journalctl: not found")
	err := a.followLogs(t.Context(), func(context.Context) (io.ReadCloser, error) { return nil, wantErr }, &logWindows{}, &logRetry{})
	if !errors.Is(err, wantErr) {
		t.Fatalf("followLogs = %v", err)
	}
}

func TestLogRetryDoublesToAMinuteAndStartsOverAfterAHealthyRun(t *testing.T) {
	r := logRetry{wait: logMinBackoff}
	var waits []time.Duration
	for range 8 {
		waits = append(waits, r.failed(t.Context(), errors.New("exit status 1"), 0))
	}
	want := []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second, 16 * time.Second, 32 * time.Second, time.Minute, time.Minute}
	for i := range want {
		if waits[i] != want[i] {
			t.Fatalf("waits = %v, want %v", waits, want)
		}
	}
	if wait := r.failed(t.Context(), errors.New("exit status 1"), logMaxBackoff); wait != time.Second {
		t.Fatalf("after a healthy minute the wait is %v, want 1s", wait)
	}
}

// blockingJournal is a journalctl with no records to read: it stays open until ctx ends.
func blockingJournal(ctx context.Context) io.ReadCloser {
	r, w := io.Pipe()
	go func() {
		<-ctx.Done()
		w.Close()
	}()
	return r
}

func TestPublishLogsRestartsJournalAfterAFailedStartAndPublishesItsMinutes(t *testing.T) {
	start := time.Date(2026, 10, 9, 19, 31, 0, 0, time.UTC)
	var clock atomic.Int64
	clock.Store(start.Unix())
	starts := make(chan int, 2)
	published := make(chan sentWindow, 4)
	calls := 0
	ticks := make(chan time.Time)
	a := &Agent{
		cfg:     AgentConfig{Cell: "gru", Node: "node-a", NATSUserPublicKey: testNATSUserKey("node-a")},
		wallNow: func() time.Time { return time.Unix(clock.Load(), 0).UTC() },
		logsCommand: func(ctx context.Context) (io.ReadCloser, error) {
			calls++
			starts <- calls
			if calls == 1 {
				return nil, errors.New("journalctl: not found")
			}
			return blockingJournal(ctx), nil
		},
		logsTick: ticks,
		logsPublish: func(subject string, data []byte) error {
			var window logs.Window
			if err := json.Unmarshal(data, &window); err != nil {
				return err
			}
			published <- sentWindow{subject, window}
			return nil
		},
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		a.publishLogs(ctx)
		close(done)
	}()
	for want := 1; want <= 2; want++ {
		select {
		case got := <-starts:
			if got != want {
				t.Fatalf("start %d, want %d", got, want)
			}
		case <-time.After(10 * time.Second):
			t.Fatalf("journalctl start %d never ran", want)
		}
	}
	clock.Store(start.Add(time.Minute).Unix())
	ticks <- time.Time{}
	select {
	case got := <-published:
		if got.subject != "ts.orch.v1.gru.agent."+testNATSUserKey("node-a")+".observation.logs" || got.window.Node != "node-a" || !got.window.Minute.Equal(start) {
			t.Fatalf("published %+v on %s", got.window, got.subject)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the finished minute was never published")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("publishLogs kept running after its context ended")
	}
}
