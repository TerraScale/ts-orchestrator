package main

import (
	"fmt"
	"maps"
	"slices"

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
			fmt.Printf("DEPLOY diagnostic region=%q service=%q host=%q state=%q reason=%q\n", region, service, task.Host, task.State, secretpreflight.Scrub(task.Reason))
		}
	}
}
