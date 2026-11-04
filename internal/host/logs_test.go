package host

import (
	"context"
	"encoding/json"

	"io"
	"slices"
	"strings"

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

// blockingJournal is a journalctl with no records to read: it stays open until ctx ends.
func blockingJournal(ctx context.Context) io.ReadCloser {
	r, w := io.Pipe()
	go func() {
		<-ctx.Done()
		w.Close()
	}()
	return r
}
