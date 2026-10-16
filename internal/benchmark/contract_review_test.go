package benchmark

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"io"
	"os"
	"strings"
	"testing"
	"time"
)

func TestJSONLRejectsMissingAndNullFieldsButAcceptsExplicitZero(t *testing.T) {
	for _, sample := range []Sample{
		{TS: time.Now().UTC(), Client: "go", SDK: "go", SDKVersion: "test", Region: "gru", Op: "doc.get"},
		{Type: "summary", Client: "go", Region: "gru", Workload: "point-reads", PerOp: map[string]json.RawMessage{"doc.get": json.RawMessage(`{}`)}},
	} {
		data, err := json.Marshal(sample)
		if err != nil {
			t.Fatal(err)
		}
		var parsed Sample
		if err := json.Unmarshal(data, &parsed); err != nil {
			t.Fatal(err)
		}
		if err := parsed.Validate("go", "gru", "point-reads"); err != nil {
			t.Fatalf("explicit zeroes rejected: %s %v", data, err)
		}
		var original map[string]json.RawMessage
		if err := json.Unmarshal(data, &original); err != nil {
			t.Fatal(err)
		}
		for key := range original {
			for _, mode := range []string{"missing", "null"} {
				t.Run(sample.Type+"/"+key+"/"+mode, func(t *testing.T) {
					var fields map[string]json.RawMessage
					_ = json.Unmarshal(data, &fields)
					if mode == "missing" {
						delete(fields, key)
					} else {
						fields[key] = json.RawMessage(`null`)
					}
					invalid, err := json.Marshal(fields)
					if err != nil {
						t.Fatal(err)
					}
					if err := json.Unmarshal(invalid, &parsed); err == nil {
						t.Fatalf("missing evidence accepted: %s", invalid)
					}
				})
			}
		}
	}
}

func TestWorkerRejectsMissingLatencyEvidenceAndCleansUp(t *testing.T) {
	installHelper(t, "podman", "TestPodmanHelper")
	state := t.TempDir()
	t.Setenv("TS_761_PODMAN_STATE", state)
	t.Setenv("TS_761_PODMAN_MODE", "missing-fields")
	job := Job{ID: entityid.New(), Region: "gru", Workload: workload(t), Clients: []string{"go"}, Images: map[string]string{"go": "test"}}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	var out bytes.Buffer
	err := runContainers(ctx, job, map[string]string{"TS_BENCH_CLIENT_ID": "test-client", "TS_BENCH_CLIENT_SECRET": "private-test-value"}, &out)
	if err == nil || out.Len() != 0 || ctx.Err() != nil {
		t.Fatalf("worker accepted missing evidence: %s %v", out.Bytes(), err)
	}
	entries, err := os.ReadDir(state)
	if err != nil || len(entries) != 0 {
		t.Fatalf("invalid evidence leaked containers: %v %v", entries, err)
	}
}

func TestFinalPersistenceFailureInvalidatesReturnedVerdictAndReport(t *testing.T) {
	w := workload(t)
	stage := measuredStage(t, w, []string{"go"})
	for _, fail := range []bool{false, true} {
		t.Run(map[bool]string{false: "saved", true: "failed"}[fail], func(t *testing.T) {
			now := stage.From
			repo := new(memoryRepository)
			if fail {
				repo.finalErr = errors.New("final storage write failed")
			}
			g := generatorFunc(func(_ context.Context, _ string, _ Workload, _ []string, emit func(Sample) error) error {
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
			run, err := (Runner{Now: func() time.Time { return now }, Generator: g, Repository: repo, Usage: usageFixture}).Execute(t.Context(), "gru", w, []string{"go"}, io.Discard)
			if !fail {
				if err != nil || run.Status != "completed" || !run.Verdict.Qualified || run.Verdict.Scale != "down" {
					t.Fatalf("successful control run did not qualify: %+v %v", run, err)
				}
				return
			}
			if !errors.Is(err, repo.finalErr) || run.Status != "failed" || run.Verdict.Qualified || run.Verdict.Scale != "unknown" {
				t.Fatalf("final save failure looked successful: %+v %v", run, err)
			}
			var verdict bytes.Buffer
			if err := WriteVerdict(&verdict, run); err != nil {
				t.Fatal(err)
			}
			path, err := writeReport(t.TempDir(), run)
			if err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(verdict.String(), "qualified=false") || !strings.Contains(verdict.String(), "scale=unknown") || !bytes.Contains(data, []byte(`"status":"failed"`)) || bytes.Contains(data, []byte(`"qualified":true`)) {
				t.Fatalf("CLI/report retained a qualified success: %s %s", verdict.Bytes(), data)
			}
		})
	}
}

func TestWorkloadReservesClientLifecycleTime(t *testing.T) {
	for _, test := range []struct {
		duration, warmup int
		valid            bool
	}{{780, 0, true}, {480, 300, true}, {781, 0, false}, {481, 300, false}, {840, 0, false}} {
		w := workload(t)
		w.Duration, w.Warmup = test.duration, test.warmup
		if err := w.Validate(); (err == nil) != test.valid {
			t.Fatalf("duration=%d warmup=%d valid=%t err=%v", test.duration, test.warmup, test.valid, err)
		}
	}
	if clientLifetime != 840*time.Second || clientLifetime-time.Duration(workloadBudgetSeconds)*time.Second < time.Minute || clientLifetime >= MaxRun {
		t.Fatal("no lifecycle reserve within the overall deadline")
	}
	w := workload(t)
	w.Name, w.Duration, w.Warmup = "ramp", 120, 221
	repo := new(memoryRepository)
	g := generatorFunc(func(context.Context, string, Workload, []string, func(Sample) error) error {
		t.Fatal("oversized ramp started load")
		return nil
	})
	run, err := (Runner{Generator: g, Repository: repo, Usage: usageFixture}).Execute(t.Context(), "gru", w, []string{"go"}, io.Discard)
	if err == nil || run.ID != "" || len(repo.runs) != 0 || !strings.Contains(err.Error(), "780") {
		t.Fatalf("ramp did not reserve lifecycle time: %+v %v", run, err)
	}
}
