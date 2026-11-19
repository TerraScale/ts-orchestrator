package main

import (
	"cmp"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"slices"

	"github.com/TerraScale/ts-orchestrator/internal/pullrelease"
	"github.com/TerraScale/ts-orchestrator/internal/releasepush"
)

type finding struct {
	line         string
	red, unknown bool
}

func hostFailure(host releasepush.HostVersion) string {
	if host.Error == "" && !host.Down && host.Refusal == nil && host.RolledBack == "" {
		return ""
	}
	reason := cmp.Or(host.Error, host.State, "host down or release rolled back")
	if host.Refusal != nil {
		reason = cmp.Or(host.Refusal.Reason, host.Refusal.Kind)
	}
	return host.Host + ": " + reason
}

type pullRollout struct {
	Target *struct {
		SHA string `json:"sha"`
	} `json:"target"`
	Phase  string         `json:"phase"`
	Reason string         `json:"reason"`
	Hosts  jsontext.Value `json:"hosts"`
}

func parsePullRollout(raw []byte) *pullRollout {
	var rollout pullRollout
	if err := json.Unmarshal(raw, &rollout); err != nil {
		return nil
	}
	return &rollout
}

func (p pullRollout) matches(revision string) bool {
	return p.Target == nil || p.Target.SHA == revision
}

func (p pullRollout) pending(revision string) bool {
	return p.Target != nil && p.Target.SHA == revision && !slices.Contains([]string{pullrelease.PhaseIdle, pullrelease.PhaseComplete, pullrelease.PhaseNewer}, p.Phase)
}

func (p pullRollout) failed(revision string) bool {
	return p.matches(revision) && slices.Contains([]string{pullrelease.PhaseRefused, pullrelease.PhaseRolledBack, pullrelease.PhaseStalled}, p.Phase)
}

func reportedFailures(x artifact, report releasepush.DeploymentObservation, rollout *pullRollout) []string {
	var reasons []string
	if x.name != "ts-orchestrator" {
		app := report.Apps[x.name]
		if app.Failed {
			reasons = append(reasons, app.Host+": "+cmp.Or(app.Reason, "host reports deployment failure"))
			for _, task := range app.Tasks {
				if task.Reason != "" {
					reasons = append(reasons, task.Host+": "+task.Reason)
				}
			}
		}
		return reasons
	}
	for _, host := range report.Hosts {
		if reason := hostFailure(host); reason != "" {
			reasons = append(reasons, reason)
		}
	}
	if rollout != nil && rollout.failed(report.Targets[x.name].Revision) {
		reasons = append(reasons, report.Host+": "+cmp.Or(rollout.Reason, rollout.Phase))
	}
	return reasons
}
