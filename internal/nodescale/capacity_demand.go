package nodescale

import (
	"context"
	"errors"
	"math"

	"github.com/moby/swarmkit/v2/api"
)

// CapacityDemand comes only from current signed function intents and their
// exact unassigned DesiredRunning SwarmKit tasks, never desired replica counts.
type CapacityDemand struct {
	Architecture string
	Slots        uint64
}

func (s *Scaler) functionDemand(ctx context.Context, t *tick) (*CapacityDemand, error) {
	if s.FunctionDemand == nil || t.record.Action != nil {
		return nil, nil
	}
	demands, err := s.FunctionDemand(ctx)
	if err != nil {
		return nil, err
	}
	wanted := map[string]uint64{}
	for _, demand := range demands {
		if demand.Architecture != "arm64" && demand.Architecture != "amd64" || math.MaxUint64-wanted[demand.Architecture] < demand.Slots {
			return nil, errors.New("function demand has invalid architecture or slot count")
		}
		wanted[demand.Architecture] += demand.Slots
	}
	if wanted["arm64"] == 0 && wanted["amd64"] == 0 {
		return nil, nil
	}
	for _, provisioning := range t.pool.ProvisioningFunctions {
		if provisioning.Architecture != "arm64" && provisioning.Architecture != "amd64" {
			return nil, errors.New("provisioning function pool lacks an admitted architecture")
		}
		wanted[provisioning.Architecture] -= min(wanted[provisioning.Architecture], provisioning.Slots)
	}
	tasks, err := s.Control.ListTasks(ctx, &api.ListTasksRequest{})
	if err != nil {
		return nil, err
	}
	if tasks == nil {
		return nil, errors.New("current worker slot occupancy is unavailable")
	}
	byInstance := nodesByInstance(t.hosts)
	for _, instance := range t.pool.Instances {
		if instance.Capacity.Role != RoleWasm || absent(instance.State) {
			continue
		}
		architecture := instance.Capacity.Architecture
		if instance.Capacity.Validate() != nil {
			return nil, errors.New("observed function host lacks exact capacity identity")
		}
		if instance.State != "PROVISIONING" && instance.State != "STARTING" && instance.State != "RUNNING" {
			return nil, errors.New("function host provisioning outcome is unknown")
		}
		node, seen := byInstance[instance.ID]
		if seen && node == nil {
			return nil, errors.New("function host has ambiguous admitted worker identity")
		}
		available := !seen // An actual provisioning host already accounts for one pending slot.
		if seen {
			if !s.admitted(node, api.NodeRoleWorker) || node.Spec.Annotations.Labels["terrascale.host-role"] != RoleWasm || node.Spec.Annotations.Labels["terrascale.execution-scope"] != "tenant" {
				return nil, errors.New("function host differs from its admitted isolation identity")
			}
			if node.Description == nil || node.Description.Platform == nil || node.Description.Platform.Architecture != architecture || node.Description.Resources == nil {
				return nil, errors.New("function worker slot geometry is unavailable")
			}
			slot := false
			for _, resource := range node.Description.Resources.Generic {
				if discrete := resource.GetDiscreteResourceSpec(); discrete != nil && discrete.Kind == "terrascale.function-worker-slot" {
					if slot || discrete.Value != 1 {
						return nil, errors.New("function host worker slot geometry is ambiguous")
					}
					slot = true
				}
			}
			// CORE reserves this single generic slot and host port 8080 per worker.
			if !slot {
				return nil, errors.New("function host lacks the qualified single worker slot")
			}
			available = node.Status.State == api.NodeStatus_READY && node.Spec.Availability == api.NodeAvailabilityActive
			for _, task := range tasks.Tasks {
				if task == nil {
					return nil, errors.New("function worker task occupancy is incomplete")
				}
				if task.NodeID == node.ID && (task.DesiredState <= api.TaskStateRunning || task.Status.State < api.TaskStateCompleted || task.Status.State == api.TaskStateOrphaned) {
					available = false
				}
			}
		}
		if available && wanted[architecture] > 0 {
			wanted[architecture]--
		}
	}
	for _, architecture := range []string{"arm64", "amd64"} {
		if wanted[architecture] > 0 {
			return &CapacityDemand{Architecture: architecture, Slots: wanted[architecture]}, nil
		}
	}
	return nil, nil
}

func containerSample(t *tick) (Sample, int) {
	wasm := map[string]bool{}
	count := 0
	for _, instance := range t.pool.Instances {
		if instance.Capacity.Role == RoleWasm && !absent(instance.State) {
			wasm[instance.Name] = true
			count++
		}
	}
	loads := []NodeLoad{}
	for _, load := range t.loads {
		if !wasm[load.Node] {
			loads = append(loads, load)
		}
	}
	return Measure(t.obs.nodes-count, loads, t.now), count
}
