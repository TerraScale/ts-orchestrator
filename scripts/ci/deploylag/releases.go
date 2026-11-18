package main

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/releasepush"
)

type applicationRelease struct {
	published       time.Time
	waiting, failed bool
	detail          string
}

func (a *api) applicationRelease(ctx context.Context, x artifact, target releasepush.DeploymentTarget) (applicationRelease, error) {
	key := x.name + "/" + target.RunID + "/" + strconv.FormatUint(target.Attempt, 10)
	if release, ok := a.releases[key]; ok {
		return release, nil
	}
	jobName := "main-auth"
	if x.name == "ts-dashboard" {
		jobName = "Publish and release"
	}
	var result struct {
		Total int `json:"total_count"`
		Jobs  []struct {
			Name  string `json:"name"`
			URL   string `json:"html_url"`
			Steps []struct {
				Name        string    `json:"name"`
				Status      string    `json:"status"`
				Conclusion  string    `json:"conclusion"`
				CompletedAt time.Time `json:"completed_at"`
			} `json:"steps"`
		} `json:"jobs"`
	}
	url := fmt.Sprintf("%s%s/actions/runs/%s/attempts/%d/jobs?per_page=100", forge, x.repo, target.RunID, target.Attempt)
	if err := a.request(ctx, "GET", url, a.readToken, nil, &result); err != nil {
		return applicationRelease{}, err
	}
	if result.Total > len(result.Jobs) {
		return applicationRelease{}, errors.New("selected publisher job inventory is incomplete")
	}
	for _, job := range result.Jobs {
		if job.Name != jobName {
			continue
		}
		release := applicationRelease{}
		selected, waited := false, false
		for _, step := range job.Steps {
			switch step.Name {
			case "Publish and verify the same image and bundles in every OCIR region":
				if step.Conclusion == "success" {
					release.published = step.CompletedAt
				}
			case "Select the signed release", "Wait for rollout":
				if step.Name == "Select the signed release" {
					selected = true
				} else {
					waited = true
				}
				status := cmp.Or(step.Conclusion, step.Status)
				release.detail += fmt.Sprintf("%s %s=%s (%s); ", jobName, step.Name, status, job.URL)
				switch status {
				case "success":
				case "failure", "cancelled", "timed_out":
					release.failed = true
				case "in_progress", "queued", "pending":
					release.waiting = true
				case "skipped":
					if !release.failed {
						return applicationRelease{}, errors.New("selected release step was skipped")
					}
				default:
					return applicationRelease{}, fmt.Errorf("selected release step %s has an unknown status", step.Name)
				}
			}
		}
		if release.published.IsZero() || !selected || !waited {
			return applicationRelease{}, errors.New("selected publisher lacks publication, Select the signed release or Wait for rollout evidence")
		}
		release.detail = "publish=" + release.published.UTC().Format(time.RFC3339) + "; " + release.detail
		a.releases[key] = release
		return release, nil
	}
	return applicationRelease{}, fmt.Errorf("selected publishing run %s attempt %d has no %s job", target.RunID, target.Attempt, jobName)
}
