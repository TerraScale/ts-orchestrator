package host

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"log/slog"
	"strings"
	"testing"
	"time"
)

func TestSessionTraceOnlyRecordsVerifiedAcceptedLeases(t *testing.T) {
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })
	controller, conn, _, _, responseKey := testController(t)
	hostKey := registerTestHost(t, controller)
	controllerCtx, stopController := context.WithCancel(t.Context())
	defer stopController()
	controllerDone := make(chan error, 1)
	go func() { controllerDone <- controller.Run(controllerCtx) }()
	select {
	case <-controller.Ready():
	case <-t.Context().Done():
		t.Fatal(t.Context().Err())
	}
	agent, err := NewAgent(AgentConfig{ClockCheck: func() error { return nil }, WorkloadIdentity: testAgentIdentity(), Cell: "gru", Node: "node-a", Environment: "production", Roles: []string{"terrabase"},
		Conn: conn, Identity: hostKey, ControllerPublicKey: responseKey.Public().(ed25519.PublicKey),
		Runner: &sessionTraceRunner{memoryRunner: &memoryRunner{observed: make(map[string]Observation)}}, InstallRoot: testAgentInstallRoot(t),
		StateRoot: testAgentStateRoot(t), SessionTrace: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := agent.acquire(t.Context()); err != nil {
		t.Fatal(err)
	}
	agent.mu.RLock()
	acquired := agent.session
	agent.mu.RUnlock()
	monitorCtx, stopMonitor := context.WithCancel(t.Context())
	monitorDone := make(chan struct{})
	lost := make(chan error, 1)
	go func() {
		agent.maintainSession(monitorCtx, stopMonitor, lost)
		close(monitorDone)
	}()
	deadline := time.NewTimer(4 * time.Second)
	defer deadline.Stop()
	var renewed session
	for {
		agent.mu.RLock()
		renewed = agent.session
		agent.mu.RUnlock()
		if renewed.ExpiresAt.After(acquired.ExpiresAt) {
			break
		}
		select {
		case err := <-lost:
			t.Fatalf("host lost session before verified renewal: %v", err)
		case <-deadline.C:
			t.Fatal("verified session did not renew")
		case <-time.After(20 * time.Millisecond):
		}
	}
	stopMonitor()
	<-monitorDone

	// A reply signed by an untrusted controller key cannot produce another
	// accepted renewal event, even though the broker delivered it to the host.
	wrongPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	agent.cfg.ControllerPublicKey = wrongPublic
	failedCtx, stopFailed := context.WithCancel(t.Context())
	failedDone := make(chan struct{})
	go func() {
		agent.maintainSession(failedCtx, stopFailed, lost)
		close(failedDone)
	}()
	select {
	case err := <-lost:
		if err == nil {
			t.Fatal("untrusted controller response was accepted")
		}
	case <-time.After(4 * time.Second):
		stopFailed()
		t.Fatal("untrusted controller response did not fail session")
	}
	<-failedDone
	stopController()
	<-controllerDone

	var events []map[string]any
	var fenced map[string]any
	fenceIndex, closeIndex := -1, -1
	lineIndex := 0
	for line := range strings.SplitSeq(strings.TrimSpace(logs.String()), "\n") {
		var event map[string]any
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			t.Fatalf("decode session log: %v", err)
		}
		if event["msg"] == "host session accepted" {
			events = append(events, event)
		}
		if event["msg"] == "host session fenced" {
			if fenced != nil {
				t.Fatal("host emitted more than one fence event")
			}
			fenced, fenceIndex = event, lineIndex
		}
		if event["msg"] == "test native close" {
			closeIndex = lineIndex
		}
		lineIndex++
	}
	if len(events) != 2 || events[0]["phase"] != "acquire" || events[1]["phase"] != "renew" {
		t.Fatalf("verified accepted events = %v; want acquire and one renew", events)
	}
	hash := sha256.Sum256([]byte(acquired.SessionID))
	wantHash := hex.EncodeToString(hash[:16])
	for index, accepted := range []session{acquired, renewed} {
		event := events[index]
		if event["session_id_hash"] != wantHash || event["expires_at"] != accepted.ExpiresAt.UTC().Format(time.RFC3339Nano) ||
			event["epoch"] != float64(accepted.Epoch) {
			t.Fatalf("accepted event %d does not match verified lease: %v", index, event)
		}
	}
	if strings.Contains(logs.String(), acquired.SessionID) {
		t.Fatal("session trace disclosed raw session ID")
	}
	if fenced == nil || fenceIndex < 0 || closeIndex <= fenceIndex ||
		fenced["session_id_hash"] != wantHash || fenced["epoch"] != float64(renewed.Epoch) ||
		fenced["expires_at"] != renewed.ExpiresAt.UTC().Format(time.RFC3339Nano) ||
		fenced["cause_class"] != "renewal_failed" {
		t.Fatalf("fence event did not precede native close or bind to the last verified lease: %v", fenced)
	}
}

type sessionTraceRunner struct{ *memoryRunner }

func (r *sessionTraceRunner) Close(ctx context.Context) error {
	slog.Info("test native close")
	return r.memoryRunner.Close(ctx)
}
