package benchmark

import (
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

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/capacity"
)

func TestBlockedResultIODoesNotDelayLaterSafetySample(t *testing.T) {
	for _, mode := range []string{"storage", "output"} {
		t.Run(mode, func(t *testing.T) {
			w := workload(t)
			now := time.Now().UTC()
			blocked, release := make(chan struct{}), make(chan struct{})
			block := func() error {
				close(blocked)
				select {
				case <-release:
					return nil
				case <-time.After(time.Second):
					return errors.New("blocked I/O prevented safety inspection")
				}
			}
			repo := &resultRepository{}
			repo.save = func(_ context.Context, sample Sample) error {
				if mode == "storage" && len(repo.results) == 0 {
					if err := block(); err != nil {
						return err
					}
				}
				repo.results = append(repo.results, sample)
				return nil
			}
			writes := 0
			out := writerFunc(func(data []byte) (int, error) {
				if mode == "output" && writes == 0 {
					if err := block(); err != nil {
						return 0, err
					}
				}
				writes++
				return len(data), nil
			})
			g := generatorFunc(func(ctx context.Context, _ string, _ Workload, _ []string, emit func(Sample) error) error {
				defer close(release)
				sample := Sample{TS: now, Client: "go", SDK: "go", SDKVersion: "test", Region: "gru", Op: "doc.get", Count: 100}
				if err := emit(sample); err != nil {
					return err
				}
				<-blocked
				now = now.Add(time.Second)
				sample.TS, sample.Errors = now, 2
				if err := emit(sample); err != nil {
					return err
				}
				if ctx.Err() != context.Canceled {
					return errors.New("unsafe sample did not cancel load")
				}
				return ctx.Err()
			})
			run, err := (Runner{Now: func() time.Time { return now }, Generator: g, Repository: repo, Usage: usageFixture}).Execute(t.Context(), "gru", w, []string{"go"}, out)
			if err != nil || run.Status != "completed" || run.Stages[0].Stopped == "" || len(repo.results) != 2 || writes != 2 {
				t.Fatalf("blocked %s delayed safety or lost queued results: %+v %v saved=%d writes=%d", mode, run, err, len(repo.results), writes)
			}
		})
	}
}

func TestResultQueueOverflowCancelsAndFailsRun(t *testing.T) {
	w := workload(t)
	w.Duration = 300
	now := time.Now().UTC()
	blocked, release := make(chan struct{}), make(chan struct{})
	repo := &resultRepository{}
	repo.save = func(ctx context.Context, sample Sample) error {
		if len(repo.results) == 0 {
			close(blocked)
			select {
			case <-release:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		repo.results = append(repo.results, sample)
		return nil
	}
	g := generatorFunc(func(ctx context.Context, _ string, _ Workload, _ []string, emit func(Sample) error) error {
		defer close(release)
		for second := range resultQueueSize + 2 {
			sample := Sample{TS: now, Client: "go", SDK: "go", SDKVersion: "test", Region: "gru", Op: "doc.get", Count: 100}
			if err := emit(sample); err != nil {
				if ctx.Err() != context.Canceled {
					t.Error("queue overflow left load running")
				}
				return err
			}
			if second == 0 {
				<-blocked
			}
			now = now.Add(time.Second)
		}
		return nil
	})
	run, err := (Runner{Now: func() time.Time { return now }, Generator: g, Repository: repo, Usage: usageFixture}).Execute(t.Context(), "gru", w, []string{"go"}, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "queue overflow") || run.Status != "failed" || run.Verdict.Qualified || run.Verdict.Scale != "unknown" || len(repo.results) != resultQueueSize+1 {
		t.Fatalf("overflow did not fail and drain accepted results: %+v %v saved=%d", run, err, len(repo.results))
	}
}

func TestResultConsumerFailureCancelsActiveLoad(t *testing.T) {
	for _, mode := range []string{"storage", "output"} {
		t.Run(mode, func(t *testing.T) {
			w := workload(t)
			now := time.Now().UTC()
			failure := errors.New(mode + " unavailable")
			repo := &resultRepository{save: func(context.Context, Sample) error {
				if mode == "storage" {
					return failure
				}
				return nil
			}}
			out := writerFunc(func(data []byte) (int, error) { return 0, failure })
			g := generatorFunc(func(ctx context.Context, _ string, _ Workload, _ []string, emit func(Sample) error) error {
				if err := emit(Sample{TS: now, Client: "go", SDK: "go", SDKVersion: "test", Region: "gru", Op: "doc.get", Count: 100}); err != nil {
					return err
				}
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-time.After(time.Second):
					return errors.New("persistence failure left load running")
				}
			})
			run, err := (Runner{Now: func() time.Time { return now }, Generator: g, Repository: repo, Usage: usageFixture}).Execute(t.Context(), "gru", w, []string{"go"}, out)
			if !errors.Is(err, failure) || !errors.Is(err, context.Canceled) || run.Status != "failed" || run.Verdict.Qualified || run.Verdict.Scale != "unknown" {
				t.Fatalf("consumer failure did not cancel and fail load: %+v %v", run, err)
			}
		})
	}
}

func TestPendingResultsDrainInOrderBeforeUsageAndFinalRun(t *testing.T) {
	w := workload(t)
	now := time.Now().UTC()
	generated := make(chan struct{})
	repo := &resultRepository{}
	repo.save = func(ctx context.Context, sample Sample) error {
		select {
		case <-generated:
		case <-ctx.Done():
			return ctx.Err()
		}
		repo.results = append(repo.results, sample)
		return nil
	}
	g := generatorFunc(func(_ context.Context, _ string, _ Workload, _ []string, emit func(Sample) error) error {
		defer close(generated)
		for range 3 {
			if err := emit(Sample{TS: now, Client: "go", SDK: "go", SDKVersion: "test", Region: "gru", Op: "doc.get", Count: 100}); err != nil {
				return err
			}
			now = now.Add(time.Second)
		}
		return emit(Sample{Type: "summary", Client: "go", Region: "gru", Workload: w.Name, OpsPerS: 100, PerOp: map[string]json.RawMessage{"doc.get": json.RawMessage(`{}`)}})
	})
	usage := func(ctx context.Context, region string, from, to time.Time) (capacity.Usage, error) {
		if len(repo.results) != 4 {
			t.Fatalf("usage started before pending saves drained: %d", len(repo.results))
		}
		return usageFixture(ctx, region, from, to)
	}
	var out bytes.Buffer
	run, err := (Runner{Now: func() time.Time { return now }, Generator: g, Repository: repo, Usage: usage}).Execute(t.Context(), "gru", w, []string{"go"}, &out)
	if err != nil || run.Status != "completed" || len(repo.runs) != 2 || len(repo.results) != 4 || bytes.Count(out.Bytes(), []byte{'\n'}) != 4 {
		t.Fatalf("pending saves did not drain before completion: %+v %v", run, err)
	}
	for i, sample := range repo.results[:3] {
		if !sample.TS.Equal(repo.results[0].TS.Add(time.Duration(i) * time.Second)) {
			t.Fatal("persistence reordered samples")
		}
	}
}

func TestFailedResultOutputRetainsReportWithoutRetryingWriter(t *testing.T) {
	for _, failure := range []error{errResultOutput, errResultDrainTimeout} {
		t.Run(failure.Error(), func(t *testing.T) {
			root := t.TempDir()
			run := Run{ID: newID(), Region: "gru", Workload: workload(t), Started: time.Now().UTC(), Status: "failed", Verdict: Verdict{Scale: "unknown"}}
			out := writerFunc(func([]byte) (int, error) {
				t.Error("reporting retried the unavailable result writer")
				return 0, errors.New("output unavailable")
			})
			err := finishRun(root, out, run, errors.Join(context.Canceled, failure))
			if !errors.Is(err, failure) || !errors.Is(err, context.Canceled) {
				t.Fatalf("output failure lost: %v", err)
			}
			path := filepath.Join(root, run.Region, run.Started.Format("2006-01-02")+"-"+run.Workload.Name+".md")
			data, err := os.ReadFile(path)
			if err != nil || !bytes.Contains(data, []byte(run.ID)) || !bytes.Contains(data, []byte(`"status":"failed"`)) {
				t.Fatalf("failed-run report was lost: %s %v", data, err)
			}
		})
	}
}
