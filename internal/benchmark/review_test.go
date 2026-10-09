package benchmark

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func measuredStage(t *testing.T, w Workload, clients []string) Stage {
	t.Helper()
	from := time.Now().UTC().Add(-time.Minute)
	stage := Stage{From: from, To: from.Add(30 * time.Second), Duration: 30, MeasurementFrom: map[string]time.Time{}}
	stage.Usage, _ = usageFixture(t.Context(), "gru", stage.From, stage.To)
	for _, client := range clients {
		stage.MeasurementFrom[client] = from.Add(time.Duration(w.Warmup+1) * time.Second)
		perOp := map[string]json.RawMessage{}
		for _, op := range w.Mix {
			perOp[op.Op] = json.RawMessage(`{}`)
			for second := range 30 {
				stage.Samples = append(stage.Samples, Sample{TS: from.Add(time.Duration(second+1) * time.Second), Client: client, SDK: client, SDKVersion: "test", Region: "gru", Op: op.Op, Count: 100, P99: 30, Max: 30})
			}
		}
		stage.Samples = append(stage.Samples, Sample{Type: "summary", Client: client, Region: "gru", Workload: w.Name, OpsPerS: 100 * float64(len(w.Mix)), PerOp: perOp})
	}
	return stage
}

func TestQualificationRequiresEveryClientAndOperation(t *testing.T) {
	w := workload(t)
	w.Mix = append(w.Mix, w.Mix[0])
	w.Mix[1].Op = "doc.update"
	clients := []string{"go", "rust"}
	for _, missing := range []string{"none", "samples", "summary", "extra-summary"} {
		t.Run(missing, func(t *testing.T) {
			stage := measuredStage(t, w, clients)
			var samples []Sample
			for _, sample := range stage.Samples {
				if sample.Client == "rust" {
					if missing == "samples" && sample.Op == "doc.update" {
						continue
					}
					if sample.Type == "summary" {
						switch missing {
						case "samples":
							sample.OpsPerS = 100
						case "summary":
							delete(sample.PerOp, "doc.update")
						case "extra-summary":
							sample.PerOp["doc.delete"] = json.RawMessage(`{}`)
						}
					}
				}
				samples = append(samples, sample)
			}
			stage.Samples = samples
			v := capacityVerdict(w, []Stage{stage}, clients)
			if v.Qualified != (missing == "none") || v.Scale == "down" && missing != "none" {
				t.Fatalf("operation coverage %s produced %+v", missing, v)
			}
		})
	}
}

func TestFinalLatencyFailurePreservesMaximumWithoutScaleDown(t *testing.T) {
	w := workload(t)
	w.Name = "ramp"
	first, last := measuredStage(t, w, []string{"go"}), measuredStage(t, w, []string{"go"})
	for i := range last.Samples {
		if last.Samples[i].Type == "" {
			last.Samples[i].P99 = w.Targets.P99 * 1500
			last.Samples[i].Max = last.Samples[i].P99
		}
	}
	v := capacityVerdict(w, []Stage{first, last}, []string{"go"})
	if !v.Qualified || v.MaxSustainedOps != 100 || v.Scale != "up" || v.Bottleneck != "latency/errors" {
		t.Fatalf("earlier success masked final failure: %+v", v)
	}
}

func TestIncompleteEvidenceCannotRecommendScaling(t *testing.T) {
	w := workload(t)
	clients := []string{"go"}
	for _, reason := range []string{"short", "missing operation", "gap", "throughput disagreement", "missing summary", "short with cpu pressure", "short with latency pressure"} {
		t.Run(reason, func(t *testing.T) {
			first, last := measuredStage(t, w, clients), measuredStage(t, w, clients)
			switch reason {
			case "short", "short with cpu pressure", "short with latency pressure":
				last.Samples = append(last.Samples[:20], last.Samples[30:]...)
				if reason == "short with cpu pressure" {
					last.Usage.Replicas[0].CPU.Headroom.Min = 0.01
				}
				if reason == "short with latency pressure" {
					last.Samples[0].P99 = w.Targets.P99 * 1500
				}
			case "missing operation":
				for i := range last.Samples {
					last.Samples[i].Count = 0
					last.Samples[i].OpsPerS = 0
				}
			case "gap":
				for i := 15; i < 30; i++ {
					last.Samples[i].TS = last.Samples[i].TS.Add(3 * time.Second)
				}
				last.To = last.To.Add(3 * time.Second)
			case "throughput disagreement":
				last.Samples[30].OpsPerS = 50
			case "missing summary":
				last.Samples = last.Samples[:30]
			}
			for _, stages := range [][]Stage{{last}, {first, last}} {
				v := capacityVerdict(w, stages, clients)
				if v.Scale != "unknown" || v.Bottleneck != "unknown" || v.CPUHeadroom == nil || v.MemoryHeadroom == nil {
					t.Fatalf("incomplete evidence %s recommended scaling: %+v", reason, v)
				}
				if v.Qualified != (len(stages) == 2) || len(stages) == 2 && v.MaxSustainedOps != 100 {
					t.Fatalf("earlier qualified maximum lost: %+v", v)
				}
			}
		})
	}
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
	for _, mode := range []string{"errors", "latency", "storage failure", "output failure"} {
		t.Run(mode, func(t *testing.T) {
			w := workload(t)
			now := time.Now().UTC()
			stopped := make(chan struct{})
			var stageCtx context.Context
			g := generatorFunc(func(ctx context.Context, _ string, _ Workload, _ []string, emit func(Sample) error) error {
				stageCtx = ctx
				go func() { <-ctx.Done(); close(stopped) }()
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

func TestCleanupStopsAllOwnedContainersConcurrently(t *testing.T) {
	for _, mode := range []string{"cleanup-barrier", "cleanup-failures"} {
		t.Run(mode, func(t *testing.T) {
			installHelper(t, "podman", "TestPodmanHelper")
			state := t.TempDir()
			t.Setenv("TS_761_PODMAN_STATE", state)
			t.Setenv("TS_761_PODMAN_MODE", mode)
			jobID := newID()
			names := []string{"bench-" + jobID + "-go", "bench-" + jobID + "-dotnet", "bench-" + jobID + "-rust"}
			for _, name := range names {
				if err := os.WriteFile(filepath.Join(state, name), []byte(jobID), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(filepath.Join(state, "foreign"), []byte("another-job"), 0600); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(t.Context())
			cancel()
			err := cleanupContainers(ctx, jobID, append(names, "foreign"))
			var cleanupErr *containerCleanupError
			if !errors.As(err, &cleanupErr) || !strings.Contains(err.Error(), "foreign container") {
				t.Fatalf("foreign ownership or cleanup error lost: %v", err)
			}
			if mode == "cleanup-barrier" && strings.Contains(err.Error(), "stop failed") {
				t.Fatalf("clients did not receive concurrent stop requests: %v", err)
			}
			if mode == "cleanup-failures" && (!strings.Contains(err.Error(), "stop failed") || !strings.Contains(err.Error(), "cleanup failed")) {
				t.Fatalf("joined cleanup errors lost: %v", err)
			}
			for _, name := range names {
				_, err := os.Stat(filepath.Join(state, name))
				if mode == "cleanup-failures" && strings.HasSuffix(name, "-go") {
					if err != nil {
						t.Fatal("failed removal fixture unexpectedly disappeared")
					}
				} else if !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("owned container remained after cleanup: %s %v", name, err)
				}
			}
			if _, err := os.Stat(filepath.Join(state, "foreign")); err != nil {
				t.Fatal("foreign container was removed")
			}
		})
	}
}

func TestSafetyStopCannotHideCleanupFailure(t *testing.T) {
	w := workload(t)
	now := time.Now().UTC()
	cleanupErr := errors.New("remote cleanup failed")
	g := generatorFunc(func(ctx context.Context, _ string, w Workload, _ []string, emit func(Sample) error) error {
		now = now.Add(time.Second)
		if err := emit(Sample{TS: now, Client: "go", SDK: "go", SDKVersion: "test", Region: "gru", Op: "doc.get", Count: 100, Errors: 2}); err != nil {
			return err
		}
		return errors.Join(ctx.Err(), cleanupErr)
	})
	run, err := (Runner{Now: func() time.Time { return now }, Generator: g, Repository: new(memoryRepository), Usage: usageFixture}).Execute(t.Context(), "gru", w, []string{"go"}, io.Discard)
	if !errors.Is(err, cleanupErr) || run.Status != "failed" || run.Verdict.Qualified || run.Verdict.Scale != "unknown" {
		t.Fatalf("cleanup failure was concealed: %+v %v", run, err)
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

func TestOversizedClientLineCancelsBeforeWaitingAndCleansUp(t *testing.T) {
	installHelper(t, "podman", "TestPodmanHelper")
	state := t.TempDir()
	t.Setenv("TS_761_PODMAN_STATE", state)
	t.Setenv("TS_761_PODMAN_MODE", "oversized")
	job := Job{ID: newID(), Region: "gru", Workload: workload(t), Clients: []string{"go"}, Images: map[string]string{"go": "test"}}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	err := runContainers(ctx, job, map[string]string{"TS_BENCH_CLIENT_ID": "test-client", "TS_BENCH_CLIENT_SECRET": "private-test-value"}, io.Discard)
	if !errors.Is(err, bufio.ErrTooLong) || ctx.Err() != nil {
		t.Fatalf("oversized output did not terminate promptly: %v ctx=%v", err, ctx.Err())
	}
	entries, err := os.ReadDir(state)
	if err != nil || len(entries) != 0 {
		t.Fatalf("oversized output leaked containers: %v %v", entries, err)
	}
}

func TestSSHCancelAndStreamFailuresWaitForRemoteCleanup(t *testing.T) {
	for _, mode := range []string{"complete", "cancel", "oversized", "emit-error", "cleanup-error", "no-ack", "missing-fields"} {
		t.Run(mode, func(t *testing.T) {
			installHelper(t, "ssh", "TestSSHWorkerHelper")
			installHelper(t, "podman", "TestPodmanHelper")
			state := t.TempDir()
			t.Setenv("TS_761_PODMAN_STATE", state)
			t.Setenv("TS_761_PODMAN_MODE", "stream")
			t.Setenv("TS_761_SSH_MODE", mode)
			job := Job{ID: newID(), Region: "gru", Workload: workload(t), Clients: []string{"go"}, Images: map[string]string{"go": "test"}}
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

func TestWorkerDisconnectCancelsBeforeAcknowledging(t *testing.T) {
	job := Job{ID: newID()}
	var input, output bytes.Buffer
	_ = json.NewEncoder(&input).Encode(job)
	err := workerSession(t.Context(), &input, &output, func(ctx context.Context, _ Job, _ io.Writer) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(3 * time.Second):
			t.Fatal("stdin EOF left the remote worker running")
			return nil
		}
	})
	var ack workerControl
	if !errors.Is(err, context.Canceled) || json.Unmarshal(output.Bytes(), &ack) != nil || !ack.Clean || ack.JobID != job.ID {
		t.Fatalf("disconnect failed to acknowledge cleanup: %s %v", output.Bytes(), err)
	}
}
