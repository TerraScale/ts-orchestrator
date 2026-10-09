package benchmark

import (
	"context"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/capacity"
)

func TestQualificationNeedsIntervalsForEveryOperation(t *testing.T) {
	w := workload(t)
	w.Mix = append(w.Mix, w.Mix[0])
	w.Mix[1].Op = "doc.update"
	clients := []string{"go", "rust"}
	for _, mode := range []string{"complete", "one update", "update gap", "explicit zero intervals"} {
		t.Run(mode, func(t *testing.T) {
			stage := measuredStage(t, w, clients)
			var samples []Sample
			counts := map[string]uint64{}
			for _, sample := range stage.Samples {
				second := sample.TS.Sub(stage.MeasurementFrom[sample.Client]) / time.Second
				if sample.Op == "doc.update" && second != 0 {
					switch mode {
					case "one update":
						continue
					case "update gap":
						if second >= 10 && second <= 15 {
							continue
						}
					case "explicit zero intervals":
						sample.Count = 0
					}
				}
				if sample.Type == "summary" {
					sample.OpsPerS = float64(counts[sample.Client]) / float64(w.Duration)
				} else {
					counts[sample.Client] += sample.Count
				}
				samples = append(samples, sample)
			}
			stage.Samples = samples
			v := capacityVerdict(w, []Stage{stage}, clients)
			want := mode == "complete" || mode == "explicit zero intervals"
			if v.Qualified != want || want && v.Scale != "down" || !want && (v.Scale != "unknown" || v.MaxSustainedOps != 0) {
				t.Fatalf("operation interval coverage %q: %+v", mode, v)
			}
		})
	}
}

func TestDuplicateMeasurementIntervalsCannotInflateCapacity(t *testing.T) {
	w := workload(t)
	stage := measuredStage(t, w, []string{"go"})
	var samples []Sample
	for _, sample := range stage.Samples {
		if sample.Type == "summary" {
			sample.OpsPerS = 200
		}
		samples = append(samples, sample)
		if sample.Type == "" {
			sample.TS = sample.TS.Add(100 * time.Millisecond)
			samples = append(samples, sample)
		}
	}
	stage.Samples = samples
	if v := capacityVerdict(w, []Stage{stage}, []string{"go"}); v.Qualified || v.Scale != "unknown" || v.MaxSustainedOps != 0 {
		t.Fatalf("duplicate sub-second intervals inflated capacity: %+v", v)
	}
	now := stage.From
	cleaned := false
	g := generatorFunc(func(_ context.Context, _ string, _ Workload, _ []string, emit func(Sample) error) error {
		defer func() { cleaned = true }()
		for _, sample := range stage.Samples {
			if sample.Type == "" {
				now = sample.TS
			}
			if err := emit(sample); err != nil {
				return err
			}
		}
		return nil
	})
	repo := new(memoryRepository)
	run, err := (Runner{Now: func() time.Time { return now }, Generator: g, Repository: repo, Usage: usageFixture}).Execute(t.Context(), "gru", w, []string{"go"}, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "sample interval") || !cleaned || len(repo.results) != 1 || run.Status != "failed" || run.Verdict.Qualified || run.Verdict.Scale != "unknown" {
		t.Fatalf("runner accepted or persisted overlapping intervals: %+v %v cleaned=%t", run, err, cleaned)
	}
}

type usageRepository struct {
	memoryRepository
	usages []capacity.Usage
}

func (r *usageRepository) SaveUsage(_ context.Context, _ string, _ int, usage capacity.Usage) error {
	r.usages = append(r.usages, usage)
	return nil
}

func TestUsageAlignsWithCommonClientMeasurementWindow(t *testing.T) {
	for _, offset := range []int{4, 35} {
		t.Run((time.Duration(offset) * time.Second).String(), func(t *testing.T) {
			w := workload(t)
			w.Warmup = 5
			base := time.Now().UTC().Add(-2 * time.Minute)
			now := base
			queried := false
			clients := []string{"go", "rust"}
			g := generatorFunc(func(_ context.Context, _ string, _ Workload, _ []string, emit func(Sample) error) error {
				stage := measuredStage(t, w, clients)
				for _, client := range clients {
					start := base.Add(25 * time.Second)
					if client == "rust" {
						start = start.Add(time.Duration(offset) * time.Second)
					}
					now = maxTime(now, start.Add(-5*time.Second))
					if err := emit(Sample{Type: "measurement_start", Client: client, Region: "gru", TS: start}); err != nil {
						return err
					}
					for _, sample := range stage.Samples {
						if sample.Client != client {
							continue
						}
						if sample.Type == "" {
							sample.TS = start.Add(sample.TS.Sub(stage.MeasurementFrom[client]))
							now = maxTime(now, sample.TS)
						}
						if err := emit(sample); err != nil {
							return err
						}
					}
				}
				now = base.Add(110 * time.Second)
				return nil
			})
			usage := func(ctx context.Context, region string, from, to time.Time) (capacity.Usage, error) {
				queried = true
				if !from.Equal(base.Add(29*time.Second)) || !to.Equal(base.Add(55*time.Second)) {
					t.Fatalf("usage included startup, warmup or cleanup: %s..%s", from.Sub(base), to.Sub(base))
				}
				return usageFixture(ctx, region, from, to)
			}
			repo := new(usageRepository)
			run, err := (Runner{Now: func() time.Time { return now }, Generator: g, Repository: repo, Usage: usage}).Execute(t.Context(), "gru", w, clients, io.Discard)
			if err != nil || len(repo.usages) != 1 || queried != (offset == 4) || run.Verdict.Qualified != queried {
				t.Fatalf("measurement usage failed: %+v %v queried=%t", run, err, queried)
			}
			if queried && (run.Verdict.Scale != "down" || !repo.usages[0].From.Equal(base.Add(29*time.Second)) || !repo.usages[0].To.Equal(base.Add(55*time.Second))) || !queried && (run.Verdict.Scale != "unknown" || repo.usages[0].Complete) {
				t.Fatalf("wrong usage or scale verdict: %+v", run)
			}
		})
	}
}

func TestSafetyStopTruncatesUsageBeforePersistenceAndCleanup(t *testing.T) {
	w := workload(t)
	w.Warmup = 5
	base := time.Now().UTC().Add(-time.Minute)
	now := base
	var clockMu sync.Mutex
	clock := func() time.Time {
		clockMu.Lock()
		defer clockMu.Unlock()
		return now
	}
	setNow := func(at time.Time) {
		clockMu.Lock()
		defer clockMu.Unlock()
		now = at
	}
	g := generatorFunc(func(ctx context.Context, _ string, _ Workload, _ []string, emit func(Sample) error) error {
		setNow(base.Add(5 * time.Second))
		if err := emit(Sample{Type: "measurement_start", Client: "go", Region: "gru", TS: base.Add(10 * time.Second)}); err != nil {
			return err
		}
		for second := 10; second <= 12; second++ {
			setNow(base.Add(time.Duration(second) * time.Second))
			sample := Sample{TS: clock(), Client: "go", SDK: "go", SDKVersion: "test", Region: "gru", Op: "doc.get", Count: 100}
			if second == 12 {
				sample.Errors = 2
			}
			if err := emit(sample); err != nil {
				return err
			}
		}
		setNow(base.Add(72 * time.Second))
		return ctx.Err()
	})
	repo := &resultRepository{save: func(_ context.Context, sample Sample) error {
		if sample.Errors > 0 {
			clockMu.Lock()
			now = now.Add(30 * time.Second)
			clockMu.Unlock()
		}
		return nil
	}}
	usage := func(ctx context.Context, region string, from, to time.Time) (capacity.Usage, error) {
		if !from.Equal(base.Add(10*time.Second)) || !to.Equal(base.Add(12*time.Second)) {
			t.Fatalf("safety usage included warmup, blocking persistence or cleanup: %s..%s", from.Sub(base), to.Sub(base))
		}
		return usageFixture(ctx, region, from, to)
	}
	run, err := (Runner{Now: clock, Generator: g, Repository: repo, Usage: usage}).Execute(t.Context(), "gru", w, []string{"go"}, io.Discard)
	if err != nil || !run.Stages[0].StoppedAt.Equal(base.Add(12*time.Second)) || run.Verdict.Qualified || run.Verdict.Scale != "up" {
		t.Fatalf("safety stop did not retain truncated usage and measured pressure: %+v %v", run, err)
	}
}

func TestSafetyStopBeforeMeasurementLeavesUsageUnknown(t *testing.T) {
	w := workload(t)
	w.Warmup = 5
	now := time.Now().UTC()
	g := generatorFunc(func(ctx context.Context, _ string, _ Workload, _ []string, emit func(Sample) error) error {
		if err := emit(Sample{TS: now, Client: "go", SDK: "go", SDKVersion: "test", Region: "gru", Op: "doc.get", Count: 100, Errors: 2}); err != nil {
			return err
		}
		now = now.Add(time.Minute)
		return ctx.Err()
	})
	usage := func(context.Context, string, time.Time, time.Time) (capacity.Usage, error) {
		t.Fatal("usage queried an unmeasured or inverted window")
		return capacity.Usage{}, nil
	}
	repo := new(usageRepository)
	run, err := (Runner{Now: func() time.Time { return now }, Generator: g, Repository: repo, Usage: usage}).Execute(t.Context(), "gru", w, []string{"go"}, io.Discard)
	if err != nil || len(repo.usages) != 1 || repo.usages[0].Complete || !repo.usages[0].From.IsZero() || !repo.usages[0].To.IsZero() || run.Verdict.Qualified || run.Verdict.Scale != "unknown" {
		t.Fatalf("warmup-only safety stop invented measured usage: %+v %v", run, err)
	}
}
