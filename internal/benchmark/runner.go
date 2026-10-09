package benchmark

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/capacity"
)

type Verdict struct {
	MaxSustainedOps float64  `json:"max_sustained_ops_per_s"`
	P99TargetMS     float64  `json:"p99_target_ms"`
	CPUHeadroom     *float64 `json:"cpu_headroom_cores"`
	MemoryHeadroom  *float64 `json:"memory_headroom_bytes"`
	Bottleneck      string   `json:"bottleneck"`
	Scale           string   `json:"scale"`
	Qualified       bool     `json:"qualified"`
}

type Stage struct {
	Concurrency int            `json:"concurrency"`
	Duration    int            `json:"duration_s"`
	From        time.Time      `json:"from"`
	To          time.Time      `json:"to"`
	Samples     []Sample       `json:"samples"`
	Usage       capacity.Usage `json:"usage"`
	Stopped     string         `json:"stopped,omitempty"`
}

type Run struct {
	ID       string    `json:"id"`
	Region   string    `json:"region"`
	Workload Workload  `json:"workload"`
	Clients  []string  `json:"clients"`
	Started  time.Time `json:"started"`
	Ended    time.Time `json:"ended"`
	Stages   []Stage   `json:"stages"`
	Verdict  Verdict   `json:"verdict"`
	Status   string    `json:"status"`
	// Existing generator hosts incur no temporary-instance charge.
	TemporaryInstanceUSD float64 `json:"temporary_instance_usd"`
}

type Generator interface {
	Execute(context.Context, string, Workload, []string, func(Sample) error) error
}
type Repository interface {
	SaveRun(context.Context, Run) error
	SaveResult(context.Context, string, int, Sample) error
	SaveUsage(context.Context, string, int, capacity.Usage) error
}
type Runner struct {
	Now        func() time.Time
	Generator  Generator
	Repository Repository
	Usage      func(context.Context, string, time.Time, time.Time) (capacity.Usage, error)
}

func (r Runner) Execute(ctx context.Context, region string, w Workload, clients []string, out io.Writer) (run Run, resultErr error) {
	if r.Now == nil {
		r.Now = time.Now
	}
	if err := w.Validate(); err != nil {
		return run, err
	}
	if region != "gru" && region != "sfo" || len(clients) == 0 || len(clients) > 3 || r.Generator == nil || r.Repository == nil || r.Usage == nil {
		return run, errors.New("benchmark requires region, clients, generator, SDK storage and usage")
	}
	for i, client := range clients {
		if !contains(languages, client) || contains(clients[:i], client) {
			return run, errors.New("clients must be distinct go,dotnet,rust")
		}
	}
	ctx, cancel := context.WithTimeout(ctx, MaxRun)
	defer cancel()
	levels := []int{w.Concurrency}
	if w.Name == "ramp" {
		levels = nil
		for n := 1; n < w.Concurrency; n *= 2 {
			levels = append(levels, n)
		}
		levels = append(levels, w.Concurrency)
		if w.Duration < 30*len(levels) || w.Duration+w.Warmup*len(levels) > workloadBudgetSeconds {
			return run, fmt.Errorf("ramp needs at least 30 measurement seconds per concurrency step and must fit warmups within %d seconds", workloadBudgetSeconds)
		}
	}
	run = Run{ID: newID(), Region: region, Workload: w, Clients: clients, Started: r.Now().UTC(), Status: "running", Stages: []Stage{}}
	if err := r.Repository.SaveRun(ctx, run); err != nil {
		return run, err
	}
	defer func() {
		run.Ended = r.Now().UTC()
		run.Status = "completed"
		if resultErr != nil {
			run.Status = "failed"
		}
		run.Verdict = capacityVerdict(w, run.Stages, clients)
		if resultErr != nil {
			run.Verdict.Qualified = false
			run.Verdict.Scale = "unknown"
		}
		finish, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Minute)
		defer cancel()
		if err := r.Repository.SaveRun(finish, run); err != nil {
			resultErr = errors.Join(resultErr, err)
			run.Status = "failed"
			run.Verdict.Qualified = false
			run.Verdict.Scale = "unknown"
		}
	}()
	for stageIndex, level := range levels {
		workload := w
		workload.Concurrency = level
		if w.Name == "ramp" {
			workload.Duration = w.Duration / len(levels)
			if stageIndex == 0 {
				workload.Duration += w.Duration % len(levels)
			}
		}
		stage := Stage{Concurrency: level, Duration: workload.Duration, From: r.Now().UTC(), Samples: []Sample{}}
		stageCtx, stop := context.WithCancel(ctx)
		seen := map[string]time.Time{}
		summaries := map[string]bool{}
		err := r.Generator.Execute(stageCtx, run.ID, workload, clients, func(sample Sample) error {
			if err := sample.validate(sample.Client, region, w.Name, r.Now()); err != nil {
				return err
			}
			if !contains(clients, sample.Client) || summaries[sample.Client] {
				return errors.New("unexpected client or result after summary")
			}
			if sample.Type == "summary" {
				if !summaryMatchesMix(sample, w) {
					return errors.New("summary operations must match workload mix")
				}
				summaries[sample.Client] = true
			} else {
				if sample.TS.Before(stage.From.Add(-2 * time.Second)) {
					return errors.New("sample predates benchmark stage")
				}
				validOp := false
				for _, op := range w.Mix {
					if op.Op == sample.Op {
						validOp = true
					}
				}
				if !validOp {
					return errors.New("sample operation is outside workload mix")
				}
				key := sample.Client + "/" + sample.Op
				if !seen[key].IsZero() && !sample.TS.After(seen[key]) {
					return errors.New("duplicate or out-of-order sample")
				}
				seen[key] = sample.TS
			}
			if len(stage.Samples) >= 20000 {
				return errors.New("benchmark result bound reached")
			}
			stage.Samples = append(stage.Samples, sample)
			saveCtx := stageCtx
			if sample.Type == "" && (sample.Count > 0 && float64(sample.Errors)/float64(sample.Count) > 0.01 || sample.P99 > w.Targets.P99*2000) {
				stage.Stopped = "error rate >1% or p99 >2x target"
				stop()
				var saveCancel context.CancelFunc
				saveCtx, saveCancel = context.WithTimeout(context.WithoutCancel(stageCtx), 30*time.Second)
				defer saveCancel()
			}
			if err := r.Repository.SaveResult(saveCtx, run.ID, stageIndex, sample); err != nil {
				return fmt.Errorf("save benchmark result: %w", err)
			}
			if err := json.NewEncoder(out).Encode(sample); err != nil {
				return fmt.Errorf("stream benchmark result: %w", err)
			}
			return nil
		})
		stop()
		stage.To = r.Now().UTC()
		usageCtx, usageCancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		stage.Usage, resultErr = r.Usage(usageCtx, region, stage.From, stage.To)
		if resultErr == nil {
			resultErr = r.Repository.SaveUsage(usageCtx, run.ID, stageIndex, stage.Usage)
		}
		usageCancel()
		run.Stages = append(run.Stages, stage)
		if stage.Stopped != "" && err == context.Canceled {
			// Only a clean cancellation may complete a safety-stopped run.
			err = nil
		}
		if err != nil || resultErr != nil {
			return run, errors.Join(err, resultErr)
		}
		if stage.Stopped != "" {
			return run, nil
		}
		if len(summaries) != len(clients) {
			return run, errors.New("client exited without its summary")
		}
	}
	return run, nil
}

func contains(values []string, value string) bool {
	for _, v := range values {
		if v == value {
			return true
		}
	}
	return false
}

func capacityVerdict(w Workload, stages []Stage, clients []string) Verdict {
	v := Verdict{P99TargetMS: w.Targets.P99, Bottleneck: "unknown", Scale: "unknown"}
	finalQualified := false
	finalEvidenceComplete := false
	finalSLOViolation := false
	for _, stage := range stages {
		evidenceComplete := true
		sloViolation := stage.Stopped != ""
		summaries := map[string]bool{}
		perClient := map[string]map[int64]uint64{}
		perOperation := map[string]bool{}
		summaryRates := map[string]float64{}
		ops := 0.0
		start := stage.From.Add(time.Duration(w.Warmup) * time.Second)
		for _, sample := range stage.Samples {
			if sample.Type == "summary" {
				summaries[sample.Client] = true
				ops += sample.OpsPerS
				summaryRates[sample.Client] = sample.OpsPerS
				if sample.ErrorRate > 0.01 {
					sloViolation = true
				}
				if !summaryMatchesMix(sample, w) {
					evidenceComplete = false
				}
				continue
			}
			if sample.TS.Before(start) {
				continue
			}
			if sample.Count > 0 && (sample.P99 > w.Targets.P99*1000 || float64(sample.Errors)/float64(sample.Count) > 0.01) {
				sloViolation = true
			}
			seconds := perClient[sample.Client]
			if seconds == nil {
				seconds = map[int64]uint64{}
				perClient[sample.Client] = seconds
			}
			seconds[sample.TS.Unix()] += sample.Count
			if sample.Count > sample.Errors {
				perOperation[sample.Client+"/"+sample.Op] = true
			}
		}
		if len(summaries) != len(clients) {
			evidenceComplete = false
		}
		for _, client := range clients {
			for _, op := range w.Mix {
				if !perOperation[client+"/"+op.Op] {
					evidenceComplete = false
				}
			}
			seconds := perClient[client]
			duration := stage.Duration
			if duration == 0 {
				duration = w.Duration
			}
			if len(seconds) < max(30, duration-2) {
				evidenceComplete = false
				continue
			}
			var times []int64
			var count uint64
			for at := range seconds {
				times = append(times, at)
				count += seconds[at]
			}
			observed := float64(count) / float64(len(seconds))
			if observed == 0 || summaryRates[client] < observed*0.95 || summaryRates[client] > observed*1.05 {
				evidenceComplete = false
			}
			slices.Sort(times)
			for i := 1; i < len(times); i++ {
				if times[i]-times[i-1] > 2 {
					evidenceComplete = false
				}
			}
		}
		qualified := evidenceComplete && !sloViolation && stage.Usage.Complete
		if qualified && ops > v.MaxSustainedOps {
			v.MaxSustainedOps = ops
			v.Qualified = true
		}
		finalQualified = qualified
		finalEvidenceComplete = evidenceComplete
		finalSLOViolation = sloViolation
	}
	if len(stages) == 0 {
		return v
	}
	last := stages[len(stages)-1]
	if !last.Usage.Complete {
		v.Qualified = false
		return v
	}
	cpu, memory, cpuRatio, memoryRatio := 0.0, 0.0, 1.0, 1.0
	for _, node := range last.Usage.Nodes {
		if node.CPU.Headroom == nil || node.CPU.Limit == nil || node.Memory.Headroom == nil || node.Memory.Limit == nil {
			return v
		}
		cpu += node.CPU.Headroom.Min
		memory += node.Memory.Headroom.Min
		if node.CPU.Limit.Max > 0 {
			cpuRatio = min(cpuRatio, node.CPU.Headroom.Min/node.CPU.Limit.Max)
		}
		if node.Memory.Limit.Max > 0 {
			memoryRatio = min(memoryRatio, node.Memory.Headroom.Min/node.Memory.Limit.Max)
		}
	}
	// A service can hit its cgroup cap while its node still has spare capacity.
	for _, replica := range last.Usage.Replicas {
		if replica.CPU.Headroom == nil || replica.CPU.Limit == nil || replica.Memory.Headroom == nil || replica.Memory.Limit == nil {
			v.Qualified = false
			return v
		}
		if replica.CPU.Limit.Max > 0 {
			cpuRatio = min(cpuRatio, replica.CPU.Headroom.Min/replica.CPU.Limit.Max)
		}
		if replica.Memory.Limit.Max > 0 {
			memoryRatio = min(memoryRatio, replica.Memory.Headroom.Min/replica.Memory.Limit.Max)
		}
	}
	v.CPUHeadroom = &cpu
	v.MemoryHeadroom = &memory
	// A safety stop is measured pressure even though it truncates the evidence.
	if !finalEvidenceComplete && last.Stopped == "" {
		return v
	}
	v.Scale = "ok"
	switch {
	case cpuRatio < 0.2:
		v.Bottleneck = "cpu"
		v.Scale = "up"
	case memoryRatio < 0.2:
		v.Bottleneck = "memory"
		v.Scale = "up"
	case finalSLOViolation:
		v.Bottleneck = "latency/errors"
		v.Scale = "up"
	case finalQualified && cpuRatio > 0.6 && memoryRatio > 0.6:
		v.Bottleneck = "none"
		v.Scale = "down"
	default:
		v.Bottleneck = "none"
	}
	return v
}

func summaryMatchesMix(sample Sample, w Workload) bool {
	if len(sample.PerOp) != len(w.Mix) {
		return false
	}
	for _, op := range w.Mix {
		if _, ok := sample.PerOp[op.Op]; !ok {
			return false
		}
	}
	return true
}

func WriteVerdict(out io.Writer, run Run) error {
	_, err := fmt.Fprintf(out, "run %s: max sustained %.2f ops/s at p99 %.2f ms; qualified=%t; bottleneck=%s; scale=%s; temporary instance $%.6f\n", run.ID, run.Verdict.MaxSustainedOps, run.Verdict.P99TargetMS, run.Verdict.Qualified, run.Verdict.Bottleneck, run.Verdict.Scale, run.TemporaryInstanceUSD)
	if err != nil {
		return err
	}
	if run.Verdict.CPUHeadroom != nil && run.Verdict.MemoryHeadroom != nil {
		_, err = fmt.Fprintf(out, "headroom: %.2f CPU cores, %.2f MiB memory\n", *run.Verdict.CPUHeadroom, *run.Verdict.MemoryHeadroom/(1<<20))
	}
	return err
}
