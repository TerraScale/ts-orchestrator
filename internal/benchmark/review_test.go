package benchmark

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
)

func measuredStage(t *testing.T, w Workload, clients []string) Stage {
	t.Helper()
	from := time.Now().UTC().Add(-time.Minute)
	stage := Stage{From: from, To: from.Add(time.Duration(w.Warmup+1+w.Duration) * time.Second), Duration: w.Duration, MeasurementFrom: map[string]time.Time{}}
	stage.Usage, _ = usageFixture(t.Context(), "gru", stage.From, stage.To)
	for _, client := range clients {
		stage.MeasurementFrom[client] = from.Add(time.Duration(w.Warmup+1) * time.Second)
		perOp := map[string]json.RawMessage{}
		for _, op := range w.Mix {
			perOp[op.Op] = json.RawMessage(`{}`)
			for second := range w.Duration {
				stage.Samples = append(stage.Samples, Sample{TS: stage.MeasurementFrom[client].Add(time.Duration(second) * time.Second), Client: client, SDK: client, SDKVersion: "test", Region: "gru", Op: op.Op, Count: 100, P99: 30, Max: 30})
			}
		}
		stage.Samples = append(stage.Samples, Sample{Type: "summary", Client: client, Region: "gru", Workload: w.Name, OpsPerS: 100 * float64(len(w.Mix)), PerOp: perOp})
	}
	return stage
}

type resultRepository struct {
	memoryRepository
	save func(context.Context, Sample) error
}

func (r *resultRepository) SaveResult(ctx context.Context, _ string, _ int, sample Sample) error {
	return r.save(ctx, sample)
}

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(data []byte) (int, error) { return f(data) }

func TestSafetyCancellationPrecedesStorageAndOutput(t *testing.T) {
	for _, mode := range []string{"storage failure"} {
		t.Run(mode, func(t *testing.T) {
			w := workload(t)
			now := time.Now().UTC()
			stopped := make(chan struct{})
			var stageCtx context.Context
			g := generatorFunc(func(ctx context.Context, _ string, _ Workload, _ []string, emit func(Sample) error) error {
				stageCtx = ctx
				go func() { <-ctx.Done(); close(stopped) }()
				if err := emit(Sample{Type: "measurement_start", Client: "go", Region: "gru", TS: now}); err != nil {
					return err
				}
				now = now.Add(time.Second)
				sample := Sample{TS: now, Client: "go", SDK: "go", SDKVersion: "test", Region: "gru", Op: "doc.get", Count: 100, Errors: 2}
				if mode == "latency" {
					sample.Errors = 0
					sample.P99, sample.Max = w.Targets.P99*2001, w.Targets.P99*2001
				}
				if err := emit(sample); err != nil {
					return err
				}
				return ctx.Err()
			})
			repo := &resultRepository{}
			repo.save = func(ctx context.Context, sample Sample) error {
				select {
				case <-stopped:
				case <-time.After(time.Second):
					t.Fatal("storage blocked while load was still running")
				}
				deadline, bounded := ctx.Deadline()
				if ctx.Err() != nil || !bounded || time.Until(deadline) > 30*time.Second {
					t.Fatalf("triggering sample save is canceled or unbounded: %v %v", ctx.Err(), deadline)
				}
				if mode == "storage failure" {
					return context.Canceled
				}
				repo.results = append(repo.results, sample)
				return nil
			}
			output := writerFunc(func(data []byte) (int, error) {
				if stageCtx.Err() != context.Canceled {
					t.Fatal("output blocked while load was still running")
				}
				if mode == "output failure" {
					return 0, context.Canceled
				}
				return len(data), nil
			})
			run, err := (Runner{Now: func() time.Time { return now }, Generator: g, Repository: repo, Usage: usageFixture}).Execute(t.Context(), "gru", w, []string{"go"}, output)
			failed := mode == "storage failure" || mode == "output failure"
			if failed {
				if !errors.Is(err, context.Canceled) || run.Status != "failed" || run.Verdict.Scale != "unknown" {
					t.Fatalf("I/O failure hidden by safety stop: %+v %v", run, err)
				}
			} else if err != nil || run.Status != "completed" || len(repo.results) != 1 || run.Verdict.Scale != "up" {
				t.Fatalf("safety stop did not retain triggering result: %+v %v", run, err)
			}
		})
	}
}

func installHelper(t *testing.T, name, test string) {
	t.Helper()
	dir := t.TempDir()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	script := "#!/bin/sh\nexec '" + strings.ReplaceAll(exe, "'", "'\\''") + "' -test.run=^" + test + "$ -- \"$@\"\n"
	if err := os.WriteFile(filepath.Join(dir, name), []byte(script), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("GORACE", "atexit_sleep_ms=0")
}

func TestSSHCancelAndStreamFailuresWaitForRemoteCleanup(t *testing.T) {
	for _, mode := range []string{"complete", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			installHelper(t, "ssh", "TestSSHWorkerHelper")
			installHelper(t, "podman", "TestPodmanHelper")
			state := t.TempDir()
			t.Setenv("TS_761_PODMAN_STATE", state)
			t.Setenv("TS_761_PODMAN_MODE", "stream")
			t.Setenv("TS_761_SSH_MODE", mode)
			job := Job{ID: entityid.New(), Region: "gru", Workload: workload(t), Clients: []string{"go"}, Images: map[string]string{"go": "test"}}
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			emitErr := errors.New("storage failed")
			err := (SSHGenerator{User: "test", Address: "127.0.0.1", WorkerPath: "/test"}).runWorker(ctx, job, func(Sample) error {
				if mode == "emit-error" {
					return emitErr
				}
				if mode != "complete" {
					cancel()
				}
				return nil
			})
			switch mode {
			case "complete":
				if err != nil {
					t.Fatalf("normal completion was not acknowledged: %v", err)
				}
			case "cancel":
				if err != context.Canceled {
					t.Fatalf("clean cancellation was not acknowledged: %v", err)
				}
			case "oversized":
				if !errors.Is(err, bufio.ErrBufferFull) {
					t.Fatalf("scanner error lost: %v", err)
				}
			case "emit-error":
				if !errors.Is(err, emitErr) {
					t.Fatalf("emit error lost: %v", err)
				}
			case "missing-fields":
				if err == nil || !strings.Contains(err.Error(), "worker returned invalid JSONL") {
					t.Fatalf("missing latency evidence was accepted: %v", err)
				}
			default:
				if err == nil || err == context.Canceled || !strings.Contains(err.Error(), "cleanup was not acknowledged") {
					t.Fatalf("missing cleanup acknowledgement was hidden: %v", err)
				}
			}
			entries, readErr := os.ReadDir(state)
			if readErr != nil || len(entries) != 0 {
				t.Fatalf("returned before remote cleanup: %v %v", entries, readErr)
			}
		})
	}
}

func TestSSHWorkerHelper(t *testing.T) {
	mode := os.Getenv("TS_761_SSH_MODE")
	if mode == "" {
		return
	}
	err := workerSession(context.Background(), os.Stdin, os.Stdout, func(ctx context.Context, job Job, out io.Writer) error {
		if mode == "complete" {
			at := time.Now().UTC()
			if err := json.NewEncoder(out).Encode(workerControl{Type: "measurement_start", JobID: job.ID, Client: "go", MeasurementFrom: at.Add(time.Duration(job.Workload.Warmup) * time.Second)}); err != nil {
				return err
			}
			return json.NewEncoder(out).Encode(Sample{TS: at, Client: "go", SDK: "go", SDKVersion: "test", Region: "gru", Op: "doc.get", Count: 100, P99: 30, Max: 40})
		}
		if mode == "oversized" {
			_, _ = io.WriteString(out, strings.Repeat("x", 300<<10)+"\n")
			<-ctx.Done()
			return ctx.Err()
		}
		if mode == "missing-fields" {
			_ = json.NewEncoder(out).Encode(map[string]any{"ts": time.Now().UTC(), "client": "go", "sdk": "go", "sdk_version": "test", "region": "gru", "op": "doc.get", "count": 100, "errors": 0})
			<-ctx.Done()
			return ctx.Err()
		}
		err := runContainers(ctx, job, map[string]string{"TS_BENCH_CLIENT_ID": "test-client", "TS_BENCH_CLIENT_SECRET": "private-test-value"}, out)
		if mode == "cleanup-error" {
			return errors.Join(err, &containerCleanupError{errors.New("cleanup failed")})
		}
		if mode == "no-ack" {
			os.Exit(0)
		}
		return err
	})
	if err != nil {
		os.Exit(1)
	}
	os.Exit(0)
}
