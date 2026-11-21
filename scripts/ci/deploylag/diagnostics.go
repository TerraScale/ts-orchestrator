package main

import (
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/pullrelease"
	"github.com/TerraScale/ts-orchestrator/internal/releasepush"
	"github.com/TerraScale/ts-orchestrator/internal/secretpreflight"
)

func printDeploymentDiagnostics(region string, report releasepush.DeploymentObservation, observeErr error) {
	if observeErr != nil {
		fmt.Printf("DEPLOY diagnostic region=%q error=%q\n", region, secretpreflight.Scrub(observeErr.Error()))
	}
	var binary pullrelease.Status
	if json.Unmarshal(report.Pull, &binary) == nil {
		if binary.Target != nil {
			fmt.Printf("DEPLOY diagnostic region=%q host=%q revision=%q release=%q phase=%q passed_at=%q reason=%q\n", region, report.Host, binary.Target.SHA, binary.Target.Tag(), binary.Phase, timestamp(binary.Passed), secretpreflight.Scrub(binary.Reason))
			for _, host := range binary.Hosts {
				fmt.Printf("DEPLOY diagnostic region=%q host=%q revision=%q phase=%q ready_at=%q error=%q\n", region, host.Host, host.Version, host.State, timestamp(host.Ready), secretpreflight.Scrub(host.Error))
			}
		}
		if hold := binary.Candidate; hold != nil {
			fmt.Printf("DEPLOY diagnostic region=%q host=%q candidate_revision=%q candidate_release=%q candidate_seq=%d reason=%q\n", region, report.Host, hold.Revision, hold.Tag, hold.Seq, secretpreflight.Scrub(hold.Reason))
		}
	}
	for _, service := range slices.Sorted(maps.Keys(report.Apps)) {
		app := report.Apps[service]
		var generation int64
		if app.Placement != nil {
			generation = app.Placement.Generation
		}
		fmt.Printf("DEPLOY diagnostic region=%q host=%q service=%q generation=%d passed_at=%q replicas=%d tasks=%d error=%q reason=%q\n", region, app.Host, service, generation, timestamp(app.PassedAt), app.Replicas, len(app.Tasks), secretpreflight.Scrub(app.Error), secretpreflight.Scrub(app.Reason))
		if hold := app.Admission; hold != nil {
			fmt.Printf("DEPLOY diagnostic region=%q host=%q service=%q candidate_generation=%d candidate_revision=%q candidate_image=%q earlier=%q reason=%q\n", region, app.Host, service, hold.Generation, hold.Revision, hold.Image, hold.Earlier, secretpreflight.Scrub(hold.Reason))
		}
		for _, task := range app.Tasks {
			printTaskDiagnostic(region, service, "current", task)
		}
		for _, task := range app.FailedTasks {
			printTaskDiagnostic(region, service, "failed", task)
		}
	}
}

func printTaskDiagnostic(region, service, history string, task releasepush.DeploymentTask) {
	fmt.Printf("DEPLOY diagnostic region=%q service=%q task=%q history=%q host=%q revision=%q image=%q generation=%d state=%q status_at=%q status_age_seconds=%d error=%q reason=%q\n", region, service, task.ID, history, task.Host, task.Revision, task.Image, task.Generation, task.State, timestamp(task.StatusAt), task.StatusAgeSeconds, secretpreflight.Scrub(task.Error), secretpreflight.Scrub(task.Reason))
}

func timestamp(at time.Time) string {
	if at.IsZero() {
		return ""
	}
	return at.UTC().Format(time.RFC3339Nano)
}
