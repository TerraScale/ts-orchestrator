package fleet

import (
	"errors"
	"fmt"
)

type QuorumObservation struct {
	Nodes []SwarmNode `json:"nodes"`
	Error string      `json:"error,omitempty"`
}

func QuorumCheck(region Region, observation QuorumObservation, eligible map[string]string) Check {
	check := Check{Kind: "swarm quorum", State: Missing}
	if observation.Error != "" {
		check.Details = []string{observation.Error}
		return check
	}
	ids, instances, hosts := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, node := range observation.Nodes {
		if !node.Manager || !node.ManagerReady || !node.Ready || node.Region != region.OCIRegion ||
			node.ID == "" || node.InstanceID == "" || node.Hostname == "" || eligible[node.InstanceID] != node.Hostname ||
			ids[node.ID] || instances[node.InstanceID] || hosts[node.Hostname] {
			continue
		}
		ids[node.ID], instances[node.InstanceID], hosts[node.Hostname] = true, true, true
		check.Details = append(check.Details, fmt.Sprintf("manager %s %s %s ready and Raft-reachable", node.Hostname, node.ID, node.InstanceID))
	}
	check.Details = append([]string{fmt.Sprintf("%d/%d distinct ready, Raft-reachable managers on verified regional OCI hosts", len(instances), MinNodes)}, check.Details...)
	if len(instances) >= MinNodes {
		check.State = Ok
	}
	return check
}

func RequireQuorum(reports []Report) error {
	var failures []error
	for _, report := range reports {
		for _, check := range report.Checks {
			if check.Kind == "swarm quorum" && check.State != Ok {
				failures = append(failures, fmt.Errorf("%s is not quorum-ready: %s", report.Name, check.Details[0]))
			}
		}
	}
	return errors.Join(failures...)
}
