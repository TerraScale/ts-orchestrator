package vmqual

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"terrascale.tech/orchestrator/src/orchestrator/vmnet"
)

func TestCollectFailureDiagnosticsReturnsStructuredBoundedArtifacts(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	consolePath := filepath.Join(root, "firecracker.log")
	metricsPath := filepath.Join(root, "firecracker.metrics")
	console := bytes.Repeat([]byte("console-frame\n"), 500)
	metrics := []byte(`{"utc_timestamp_ms":1,"api_server":{"sync_response_fails":1}}` + "\n")
	if err := os.WriteFile(consolePath, console, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(metricsPath, metrics, 0600); err != nil {
		t.Fatal(err)
	}
	stack := &Stack{journal: &Journal{VMs: []JournalVM{{
		ID: "gru-member-1", Region: string(vmnet.GRU), StateDir: root, LogPath: consolePath, MetricsPath: metricsPath,
	}}}}
	report, err := stack.CollectFailureDiagnostics(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(report) != 1 || report[0].VMID != "gru-member-1" || report[0].Region != vmnet.GRU || report[0].CapturedAt.IsZero() {
		t.Fatalf("diagnostic identity = %+v", report)
	}
	gotConsole := report[0].Console
	consoleDigest := sha256.Sum256(console)
	if !gotConsole.Present || gotConsole.SourceBytes != int64(len(console)) || gotConsole.CapturedBytes > maximumFailureDiagnosticExcerptBytes || !gotConsole.Truncated || gotConsole.SHA256 != hex.EncodeToString(consoleDigest[:]) {
		t.Fatalf("console diagnostic = %+v", gotConsole)
	}
	if !strings.HasSuffix(string(console), gotConsole.Tail) {
		t.Fatalf("console tail is not the observed suffix")
	}
	gotMetrics := report[0].Metrics
	if !gotMetrics.Present || gotMetrics.SourceBytes != int64(len(metrics)) || gotMetrics.CapturedBytes != len(metrics) || gotMetrics.Truncated || gotMetrics.Tail != string(metrics) {
		t.Fatalf("metrics diagnostic = %+v", gotMetrics)
	}
	payload, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if len(payload) > 2*maximumFailureDiagnosticExcerptBytes+2048 {
		t.Fatalf("encoded diagnostic is unexpectedly unbounded: %d bytes", len(payload))
	}
}

func TestCollectFailureDiagnosticsObservesMissingArtifacts(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	stack := &Stack{journal: &Journal{VMs: []JournalVM{{
		ID: "gru-member-1", Region: string(vmnet.GRU), StateDir: root,
		LogPath: filepath.Join(root, "firecracker.log"), MetricsPath: filepath.Join(root, "firecracker.metrics"),
	}}}}
	report, err := stack.CollectFailureDiagnostics(context.Background())
	if err == nil || len(report) != 1 {
		t.Fatalf("missing diagnostic report = %+v, error = %v", report, err)
	}
	if report[0].Console.Present || report[0].Console.Observation != "file was not created" || report[0].Metrics.Present || report[0].Metrics.Observation != "file was not created" {
		t.Fatalf("missing artifact observations = %+v", report[0])
	}
}

func TestFailureDiagnosticRejectsUnsafeSources(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte("secret"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "firecracker.log")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	artifact, err := captureFailureDiagnosticArtifact(root, link)
	if err == nil || artifact.Present || artifact.Tail != "" || artifact.Observation == "" {
		t.Fatalf("symlink artifact = %+v, error = %v", artifact, err)
	}

	unsafe := filepath.Join(root, "firecracker.metrics")
	if err := os.WriteFile(unsafe, []byte("metric"), 0644); err != nil {
		t.Fatal(err)
	}
	artifact, err = captureFailureDiagnosticArtifact(root, unsafe)
	if err == nil || artifact.Present || artifact.Tail != "" || artifact.Observation == "" {
		t.Fatalf("unsafe-mode artifact = %+v, error = %v", artifact, err)
	}
}

func TestFailureDiagnosticRejectsPathOutsideVMState(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	outsideRoot := t.TempDir()
	outside := filepath.Join(outsideRoot, "firecracker.log")
	if err := os.WriteFile(outside, []byte("secret"), 0600); err != nil {
		t.Fatal(err)
	}
	artifact, err := captureFailureDiagnosticArtifact(root, outside)
	if err == nil || artifact.Present || artifact.Tail != "" || !strings.Contains(artifact.Observation, "outside") {
		t.Fatalf("outside artifact = %+v, error = %v", artifact, err)
	}
}

func TestFailureDiagnosticUTF8AndObservationBounds(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	path := filepath.Join(root, "firecracker.log")
	invalid := bytes.Repeat([]byte{0xff}, maximumFailureDiagnosticExcerptBytes)
	if err := os.WriteFile(path, invalid, 0600); err != nil {
		t.Fatal(err)
	}
	artifact, err := captureFailureDiagnosticArtifact(root, path)
	if err != nil {
		t.Fatal(err)
	}
	if !utf8.ValidString(artifact.Tail) || artifact.CapturedBytes > maximumFailureDiagnosticExcerptBytes {
		t.Fatalf("invalid bounded UTF-8 capture: %d bytes", artifact.CapturedBytes)
	}
	observation := boundedDiagnosticObservation(&longDiagnosticError{text: strings.Repeat("x", 1024)})
	if len(observation) != 256 || !strings.HasSuffix(observation, "...[truncated]") {
		t.Fatalf("bounded observation = %q (%d bytes)", observation, len(observation))
	}
}

type longDiagnosticError struct{ text string }

func (e *longDiagnosticError) Error() string { return e.text }

func TestFailureDiagnosticCaptureHonorsCancelledContext(t *testing.T) {
	t.Parallel()
	stack := &Stack{journal: &Journal{VMs: []JournalVM{{ID: "gru-member-1", StateDir: t.TempDir()}}}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	started := time.Now()
	if _, err := stack.CollectFailureDiagnostics(ctx); err == nil || time.Since(started) > time.Second {
		t.Fatalf("cancelled capture error = %v", err)
	}
}
