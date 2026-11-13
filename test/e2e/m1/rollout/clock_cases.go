package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/regionhealth"
	"github.com/TerraScale/ts-orchestrator/internal/rollout"
	"github.com/fsnotify/fsnotify"
	"github.com/nats-io/nats.go"
)

func clockCases(ctx context.Context, root string) {
	var group sync.WaitGroup
	failures := make(chan error, 5)
	for _, scenario := range []string{"healthy-forward", "failure-forward", "backward-bound", "future-first", "process-discontinuity"} {
		directory := filepath.Join(root, scenario)
		must(os.MkdirAll(directory, 0700))
		group.Go(func() {
			output, err := exec.CommandContext(ctx, os.Args[0], "clock", directory, scenario).CombinedOutput()
			if err != nil {
				failures <- fmt.Errorf("%s: %w: %s", scenario, err, output)
			} else {
				fmt.Print(string(output))
			}
		})
	}
	group.Wait()
	close(failures)
	var failure error
	for err := range failures {
		failure = errors.Join(failure, err)
	}
	must(failure)
}

func clockCase(ctx context.Context, root, scenario string) {
	started := time.Now()
	first := rollout.BakeVerdict{}
	switch scenario {
	case "backward-bound":
		first.FirstSample = started.Add(-rollout.MaxBakeWindow + 6*time.Second).UTC()
	case "future-first":
		first.FirstSample = started.Add(time.Hour).UTC()
	case "process-discontinuity":
		first.FirstSample = started.Add(-time.Minute).UTC()
		must(os.WriteFile(filepath.Join(root, "clock-offset"), []byte(fmt.Sprint(int64(-31*time.Second))), 0600))
	}
	samples := 0
	var saved rollout.BakeVerdict
	verdict, err := rollout.RunBake(ctx, first, func(context.Context) (map[string]string, error) {
		samples++
		offset := time.Duration(0)
		switch {
		case scenario == "healthy-forward" && samples == 2:
			offset = 31 * time.Second
		case scenario == "failure-forward" && samples == 4:
			offset = 31 * time.Second
		case scenario == "backward-bound" && samples == 2:
			offset = -31 * time.Second
		}
		if offset != 0 {
			must(os.WriteFile(filepath.Join(root, "clock-offset"), []byte(fmt.Sprint(int64(offset))), 0600))
		}
		if scenario == "failure-forward" {
			return map[string]string{"candidate": "unready"}, errors.New("candidate unready")
		}
		return map[string]string{"candidate": "ok"}, nil
	}, func(v rollout.BakeVerdict) error {
		data, err := json.Marshal(v)
		must(err)
		must(json.Unmarshal(data, &saved))
		must(os.WriteFile(filepath.Join(root, "verdict.json"), data, 0600))
		return nil
	})
	elapsed := time.Since(started)
	require(!saved.Finished.IsZero() && saved.Finished.Equal(verdict.Finished), "terminal verdict was not finished and saved")
	switch scenario {
	case "healthy-forward":
		require(err == nil && verdict.Reason == "" && elapsed >= rollout.BakeWindow, "forward wall step passed a healthy bake early")
	case "failure-forward":
		require(err != nil && strings.Contains(verdict.Reason, "15 seconds") && elapsed >= rollout.BakeFailureDuration, "forward wall step shortened the real failure streak")
	case "backward-bound":
		require(err != nil && strings.Contains(verdict.Reason, "total observation bound") && elapsed < 10*time.Second, "backward wall step extended or lost the total-bound failure")
	case "future-first", "process-discontinuity":
		data, failure := json.Marshal(verdict)
		must(failure)
		var fields map[string]any
		must(json.Unmarshal(data, &fields))
		require(err == nil && elapsed >= rollout.BakeWindow && !verdict.FirstSample.After(verdict.Started) && fields["interruption"] != nil, "future first sample was trusted instead of restarting the window")
	}
	logStep(fmt.Sprintf("clock %s finished and saved after %s", scenario, elapsed.Round(time.Millisecond)))
}

func assertWaiting(ctx context.Context, conn *nats.Conn, region, service string, generation int64) {
	since := time.Now()
	observe(ctx, conn, func(s map[string]state) bool {
		observation, present := s[region].Serving[service]
		if !present || !observation.At.After(since) {
			return false
		}
		require(observation.Generation < generation && s[region].Ready[service] < generation, "downstream region admitted while an earlier region lacked current passing evidence")
		return true
	})
}

func hostSamplerCase(ctx context.Context, root string) {
	watcher, err := fsnotify.NewWatcher()
	must(err)
	defer watcher.Close()
	must(watcher.Add(root))
	fmt.Println("READY")
	for {
		if _, err := os.Stat(filepath.Join(root, "sample")); err == nil {
			break
		}
		select {
		case <-watcher.Events:
		case <-ctx.Done():
			panic(ctx.Err())
		}
	}
	for range 20 {
		check, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
		report := regionhealth.Check(check, root)
		cancel()
		require(report.State != regionhealth.StateOK, "blocked host observation passed health")
	}
	stacks := make([]byte, 1<<20)
	stacks = stacks[:runtime.Stack(stacks, true)]
	require(bytes.Count(stacks, []byte("observability.ReadSystem(")) == 1, "blocked host reads accumulated per health request")
	logStep("twenty health requests share one blocked host sampler and fail health")
}
