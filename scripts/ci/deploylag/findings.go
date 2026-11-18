package main

import (
	"cmp"
	"encoding/json/v2"
	"slices"

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

func reportedFailures(x artifact, report releasepush.DeploymentObservation) []string {
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
	var pull struct {
		Target *struct {
			SHA string `json:"sha"`
		} `json:"target"`
		Phase  string `json:"phase"`
		Reason string `json:"reason"`
	}
	if json.Unmarshal(report.Pull, &pull) == nil && (pull.Target == nil || pull.Target.SHA == report.Targets[x.name].Revision) && slices.Contains([]string{"refused", "rolled_back", "rollback_stalled"}, pull.Phase) {
		reasons = append(reasons, report.Host+": "+cmp.Or(pull.Reason, pull.Phase))
	}
	return reasons
}
