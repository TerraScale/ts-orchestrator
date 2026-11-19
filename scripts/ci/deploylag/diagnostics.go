package main

import (
	"fmt"
	"maps"
	"slices"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/releasepush"
	"github.com/TerraScale/ts-orchestrator/internal/secretpreflight"
)

func printDeploymentDiagnostics(region string, report releasepush.DeploymentObservation, observeErr error) {
	if observeErr != nil {
		fmt.Printf("DEPLOY diagnostic region=%q error=%q\n", region, secretpreflight.Scrub(observeErr.Error()))
	}
	for _, service := range slices.Sorted(maps.Keys(report.Apps)) {
		app := report.Apps[service]
		fmt.Printf("DEPLOY diagnostic region=%q service=%q replicas=%d tasks=%d error=%q reason=%q\n", region, service, app.Replicas, len(app.Tasks), secretpreflight.Scrub(app.Error), secretpreflight.Scrub(app.Reason))
		for _, task := range app.Tasks {
			printTaskDiagnostic(region, service, "current", task)
		}
		for _, task := range app.FailedTasks {
			printTaskDiagnostic(region, service, "failed", task)
		}
	}
}

func printTaskDiagnostic(region, service, history string, task releasepush.DeploymentTask) {
	statusAt := ""
	if !task.StatusAt.IsZero() {
		statusAt = task.StatusAt.UTC().Format(time.RFC3339Nano)
	}
	fmt.Printf("DEPLOY diagnostic region=%q service=%q task=%q history=%q host=%q state=%q status_at=%q status_age_seconds=%d error=%q reason=%q\n", region, service, task.ID, history, task.Host, task.State, statusAt, task.StatusAgeSeconds, secretpreflight.Scrub(task.Error), secretpreflight.Scrub(task.Reason))
}
