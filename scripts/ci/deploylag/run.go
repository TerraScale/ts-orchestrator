package main

import (
	"cmp"
	"context"
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/fleet"
	"github.com/TerraScale/ts-orchestrator/internal/releasepush"
)

func run(ctx context.Context, a *api, now time.Time) bool {
	regions, err := releasepush.LoadRegions("deploy/m1/regions.json")
	rows, red, unknown := map[string][]string{}, map[string]bool{}, map[string]bool{}
	if err != nil {
		line := "cannot observe regions: " + err.Error()
		fmt.Println(line)
		for _, x := range artifacts {
			rows[x.name] = []string{line}
			unknown[x.name] = true
		}
	}
	reports := map[string]releasepush.DeploymentObservation{}
	observationErrors := map[string]error{}
	targets := map[string]releasepush.DeploymentTarget{}
	for _, region := range regions {
		report, observeErr := a.region(ctx, region.Region)
		printDeploymentDiagnostics(region.Region, report, observeErr)
		reports[region.Region], observationErrors[region.Region] = report, observeErr
		if observeErr != nil {
			continue
		}
		for _, x := range artifacts {
			target := report.Targets[x.name]
			candidate, parseErr := strconv.ParseUint(target.RunID, 10, 64)
			selected, _ := strconv.ParseUint(targets[x.name].RunID, 10, 64)
			if x.name == "ts-orchestrator" {
				candidate, selected = target.Seq, targets[x.name].Seq
			}
			if _, exists := targets[x.name]; !exists {
				targets[x.name] = target
			}
			if target.Error == "" && parseErr == nil && (candidate > selected || candidate == selected && target.Attempt > targets[x.name].Attempt) {
				targets[x.name] = target
			}
			current := targets[x.name]
			if target.Error == "" && parseErr == nil && candidate == selected && target.Attempt == current.Attempt && (target.Revision != current.Revision || target.Image != current.Image) {
				current.Error = "regions report conflicting signed release selections"
				targets[x.name] = current
			}
		}
	}
	placements := agreedPlacements(regions, reports, observationErrors)
	for _, region := range regions {
		report, observeErr := reports[region.Region], observationErrors[region.Region]
		if observeErr != nil {
			line := fmt.Sprintf("cannot observe %s: %s", region.Region, observeErr)
			fmt.Println(line)
			for _, x := range artifacts {
				unknown[x.name] = true
				rows[x.name] = append(rows[x.name], line)
				if report.Region != region.Region {
					continue
				}
				if failures := reportedFailures(x, report); len(failures) > 0 {
					failure := fmt.Sprintf("%s %s: state=red %s", x.name, region.Region, strings.Join(failures, "; "))
					fmt.Println(failure)
					rows[x.name] = append(rows[x.name], failure)
					red[x.name] = true
				}
			}
			continue
		}
		report.Targets = targets
		for _, x := range artifacts {
			result := a.verdict(ctx, x, region.Region, report, placements[x.name], now)
			fmt.Println(result.line)
			rows[x.name] = append(rows[x.name], result.line)
			red[x.name] = red[x.name] || result.red
			unknown[x.name] = unknown[x.name] || result.unknown
		}
	}
	var affected, healthy []string
	complete := true
	for _, x := range artifacts {
		if unknown[x.name] {
			complete = false
		}
		if red[x.name] {
			affected = append(affected, x.name)
		} else if !unknown[x.name] {
			healthy = append(healthy, x.name)
		}
	}
	if os.Getenv("GITHUB_REF") == "refs/heads/main" {
		pages, err := a.issues(ctx, rows, red, unknown, time.Now())
		if err != nil {
			fmt.Println("issue delivery failed:", err)
			complete = false
		}
		if len(pages) > 0 {
			if err := a.page(ctx, pages); err != nil {
				fmt.Println("paging failed:", err)
				complete = false
			}
		}
	}
	staging := fleet.Embedded().Staging.Label
	report, observeErr := a.region(ctx, staging)
	printDeploymentDiagnostics(staging, report, observeErr)
	if len(affected) > 0 {
		fmt.Println("DEPLOY red", strings.Join(affected, ","))
		return false
	}
	fmt.Println("DEPLOY ok", cmp.Or(strings.Join(healthy, ","), "-"))
	return complete
}

func agreedPlacements(regions []releasepush.Region, reports map[string]releasepush.DeploymentObservation, observationErrors map[string]error) map[string]*releasepush.Placement {
	agreed := map[string]*releasepush.Placement{}
	for _, x := range artifacts {
		var placement *releasepush.Placement
		for i, region := range regions {
			app, ok := reports[region.Region].Apps[x.name]
			if observationErrors[region.Region] != nil || !ok || app.Placement == nil || i > 0 && !samePlacement(*app.Placement, *placement) {
				placement = nil
				break
			}
			placement = app.Placement
		}
		if placement != nil {
			agreed[x.name] = placement
		}
	}
	return agreed
}

func samePlacement(a, b releasepush.Placement) bool {
	return a.Generation == b.Generation && a.RollbackOf == b.RollbackOf && slices.Equal(a.Regions, b.Regions)
}
