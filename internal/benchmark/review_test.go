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
	stage := Stage{From: from, To: from.Add(30 * time.Second), Duration: 30}
	stage.Usage, _ = usageFixture(t.Context(), "gru", stage.From, stage.To)
	for _, client := range clients {
		perOp := map[string]json.RawMessage{}
		for _, op := range w.Mix {
			perOp[op.Op] = json.RawMessage(`{}`)
			for second := range 30 {
				stage.Samples = append(stage.Samples, Sample{TS: from.Add(time.Duration(second+1) * time.Second), Client: client, Op: op.Op, Count: 100, P99: 30})
			}
		}
		stage.Samples = append(stage.Samples, Sample{Type: "summary", Client: client, OpsPerS: 100 * float64(len(w.Mix)), PerOp: perOp})
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
		}
	}
	v := capacityVerdict(w, []Stage{first, last}, []string{"go"})
	if !v.Qualified || v.MaxSustainedOps != 100 || v.Scale != "up" || v.Bottleneck != "latency/errors" {
		t.Fatalf("earlier success masked final failure: %+v", v)
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
	for _, mode := range []string{"complete", "cancel", "oversized", "emit-error", "cleanup-error", "no-ack"} {
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
			return json.NewEncoder(out).Encode(Sample{TS: time.Now().UTC(), Client: "go", SDK: "go", SDKVersion: "test", Region: "gru", Op: "doc.get", Count: 100, P99: 30, Max: 40})
		}
		if mode == "oversized" {
			_, _ = io.WriteString(out, strings.Repeat("x", 300<<10)+"\n")
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
