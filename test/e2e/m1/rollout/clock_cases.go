package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/TerraScale/ts-orchestrator/internal/natscell/mesh"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/regionhealth"
	"github.com/TerraScale/ts-orchestrator/internal/rollout"
	"github.com/fsnotify/fsnotify"
	"github.com/nats-io/nats.go"
)

func clockCases(ctx context.Context, root string) {
	var group sync.WaitGroup
	failures := make(chan error, 5)
	for _, scenario := range []string{"healthy-forward", "failure-forward", "healthy-backward", "failure-backward", "process-discontinuity"} {
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
	if scenario == "process-discontinuity" {
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
		case (scenario == "failure-forward" || scenario == "failure-backward") && samples == 4:
			offset = 31 * time.Second
			if scenario == "failure-backward" {
				offset = -offset
			}
		case scenario == "healthy-backward" && samples == 2:
			offset = -31 * time.Second
		}
		if offset != 0 {
			must(os.WriteFile(filepath.Join(root, "clock-offset"), []byte(fmt.Sprint(int64(offset))), 0600))
		}
		if strings.HasPrefix(scenario, "failure-") {
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
	if strings.HasPrefix(scenario, "failure-") {
		require(err != nil && strings.Contains(verdict.Reason, "15 seconds") && elapsed >= rollout.BakeFailureDuration && elapsed < rollout.BakeFailureDuration+4*time.Second, "wall step shortened the real failure streak")
	} else {
		require(err == nil && verdict.Reason == "" && elapsed >= rollout.BakeWindow && elapsed < rollout.BakeWindow+4*time.Second, "wall step changed the healthy bake window")
	}
	logStep(fmt.Sprintf("clock %s finished and saved after %s", scenario, elapsed.Round(time.Millisecond)))
}

func assertWaiting(ctx context.Context, conn *nats.Conn, region, service string, generation int64, earlier, missing string) {
	since := time.Now()
	observe(ctx, conn, func(s map[string]state) bool {
		decision := s[region].Admission[service]
		if decision.Generation != generation || !decision.At.After(since) {
			return false
		}
		require(decision.Earlier == earlier && decision.Evidence == missing, fmt.Sprintf("wrong admission decision: %+v", decision))
		require(s[region].Ready[service] != generation, "downstream region admitted without required evidence")
		return true
	})
	regions := mesh.Regions()
	order := append(append([]string{}, regions[1:]...), regions[0])
	seat := []string{"first", "second", "third"}[slices.Index(order, region)]
	assertRuntimeBefore(ctx, "c21-"+seat, os.Args[3], filepath.Join(os.Args[2], seat), service, generation)

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
	check, cancel := context.WithTimeout(ctx, 6*time.Second)
	report := regionhealth.Check(check, root)
	cancel()
	require(report.State != regionhealth.StateOK, "blocked host observation passed health")
	must(os.WriteFile(filepath.Join(root, "blocked"), nil, 0600))
	for {
		if _, err := os.Stat(filepath.Join(root, "unblocked")); err == nil {
			break
		}
		select {
		case <-watcher.Events:
		case <-ctx.Done():
			panic(ctx.Err())
		}
	}
	check, cancel = context.WithTimeout(ctx, 5*time.Second)
	err = regionhealth.Serving(check, root, "")
	cancel()
	require(err == nil, fmt.Sprintf("host observation did not recover: %v", err))
	logStep("blocked host observation expires; a fresh read recovers without process restart")
	must(syscall.Mount("tmpfs", "/var/lib", "tmpfs", 0, "size=1m"))
	check, cancel = context.WithTimeout(ctx, 5*time.Second)
	err = regionhealth.Serving(check, root+"/.", "")
	cancel()
	require(err != nil && strings.Contains(err.Error(), "disk /var/lib/containerd unreadable"), fmt.Sprintf("unreadable required filesystem passed health: %v", err))
	logStep("an unreadable required filesystem fails serving health")

}
