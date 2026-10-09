package benchmark

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
	"time"
)

func TestWorkerMeasurementMarkersExcludeWarmupAfterStartup(t *testing.T) {
	installHelper(t, "ssh", "TestSSHWorkerHelper")
	installHelper(t, "podman", "TestPodmanHelper")
	state := t.TempDir()
	t.Setenv("TS_761_PODMAN_STATE", state)
	t.Setenv("TS_761_PODMAN_MODE", "warmup")
	t.Setenv("TS_761_SSH_MODE", "warmup")
	w := workload(t)
	w.Warmup = 30
	now := time.Now().UTC().Add(-90 * time.Second)
	clients := []string{"go", "rust"}
	g := generatorFunc(func(ctx context.Context, _ string, w Workload, clients []string, emit func(Sample) error) error {
		job := Job{ID: newID(), Region: "gru", Workload: w, Clients: clients, Images: map[string]string{"go": "test-go", "rust": "test-rust"}}
		return (SSHGenerator{User: "test", Address: "127.0.0.1", WorkerPath: "/test"}).runWorker(ctx, job, func(sample Sample) error {
			at := sample.TS
			if sample.Type == "measurement_start" {
				at = at.Add(-time.Duration(w.Warmup) * time.Second)
			}
			now = maxTime(now, at)
			return emit(sample)
		})
	})
	repo := new(memoryRepository)
	var out bytes.Buffer
	run, err := (Runner{Now: func() time.Time { return now }, Generator: g, Repository: repo, Usage: usageFixture}).Execute(t.Context(), "gru", w, clients, &out)
	if err != nil || !run.Verdict.Qualified || run.Verdict.MaxSustainedOps != 200 || run.Verdict.Scale != "down" {
		t.Fatalf("startup shifted warmup into measurements: %+v %v", run, err)
	}
	stage := run.Stages[0]
	if len(stage.MeasurementFrom) != 2 || stage.MeasurementFrom["go"].Before(stage.From.Add(45*time.Second)) || stage.MeasurementFrom["go"].Equal(stage.MeasurementFrom["rust"]) {
		t.Fatalf("per-client measurement boundaries were lost: %+v", stage.MeasurementFrom)
	}
	if len(repo.results) != 122 || bytes.Contains(out.Bytes(), []byte(`"type":"measurement_start"`)) {
		t.Fatal("private timing controls leaked into shared JSONL results")
	}
	entries, err := os.ReadDir(state)
	if err != nil || len(entries) != 0 {
		t.Fatalf("warmup run leaked owned containers: %v %v", entries, err)
	}
}

func TestInitialRunSaveFailureProducesFailedLocalReport(t *testing.T) {
	w := workload(t)
	now := time.Now().UTC()
	repo := &memoryRepository{firstErr: errors.New("initial save unavailable")}
	g := generatorFunc(func(context.Context, string, Workload, []string, func(Sample) error) error {
		t.Fatal("load started after initial persistence failed")
		return nil
	})
	run, err := (Runner{Now: func() time.Time { return now }, Generator: g, Repository: repo, Usage: usageFixture}).Execute(t.Context(), "gru", w, []string{"go"}, io.Discard)
	if !errors.Is(err, repo.firstErr) || !idPattern.MatchString(run.ID) || run.Status != "failed" || run.Ended.IsZero() || run.Verdict.Qualified || run.Verdict.Scale != "unknown" || run.Verdict.Bottleneck != "unknown" || run.Verdict.P99TargetMS != w.Targets.P99 {
		t.Fatalf("initial save failure returned an unfinished run: %+v %v", run, err)
	}
	path, err := writeReport(t.TempDir(), run)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil || !bytes.Contains(data, []byte(`"status":"failed"`)) || bytes.Contains(data, []byte(`"status":"running"`)) || !bytes.Contains(data, []byte(`"scale":"unknown"`)) {
		t.Fatalf("local report left a terminated run running: %s %v", data, err)
	}
}

func TestMeasurementMarkerCannotBeRepeatedOrContradictClientClock(t *testing.T) {
	for _, mode := range []string{"duplicate", "contradictory"} {
		t.Run(mode, func(t *testing.T) {
			w := workload(t)
			now := time.Now().UTC()
			g := generatorFunc(func(_ context.Context, _ string, _ Workload, _ []string, emit func(Sample) error) error {
				marker := Sample{Type: "measurement_start", Client: "go", Region: "gru", TS: now.Add(time.Second)}
				if err := emit(marker); err != nil {
					return err
				}
				if mode == "duplicate" {
					return emit(marker)
				}
				return emit(Sample{TS: now, Client: "go", SDK: "go", SDKVersion: "test", Region: "gru", Op: "doc.get", Count: 100})
			})
			run, err := (Runner{Now: func() time.Time { return now }, Generator: g, Repository: new(memoryRepository), Usage: usageFixture}).Execute(t.Context(), "gru", w, []string{"go"}, io.Discard)
			if err == nil || !strings.Contains(err.Error(), "measurement") || run.Status != "failed" || run.Verdict.Scale != "unknown" {
				t.Fatalf("invalid measurement timing was accepted: %+v %v", run, err)
			}
		})
	}
}

func maxTime(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}
