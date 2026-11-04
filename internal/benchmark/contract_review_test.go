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
