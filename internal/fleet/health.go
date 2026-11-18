package fleet

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/core"
	"github.com/oracle/oci-go-sdk/v65/networkloadbalancer"
)

func backendHealth(ctx context.Context, pass nlbPass, balancers []networkloadbalancer.NetworkLoadBalancerSummary, instances []core.Instance, attachments []core.VnicAttachment) (Check, error) {
	region := pass.region
	wanted := []nlbBackend{}
	check := Check{Kind: "serving backends", State: Missing}
	nodes := 0
	for _, instance := range instances {
		if !gone(string(instance.LifecycleState)) && region.owns("instance", "node", instance.FreeformTags) {
			nodes++
			for _, attachment := range attachments {
				if deref(attachment.InstanceId) != deref(instance.Id) || attachment.LifecycleState != core.VnicAttachmentLifecycleStateAttached {
					continue
				}
				vnic, err := pass.network.GetVnic(ctx, core.GetVnicRequest{VnicId: attachment.VnicId})
				if err != nil {
					return check, fmt.Errorf("node health address %s: %w", deref(instance.DisplayName), err)
				}
				if vnic.IsPrimary != nil && *vnic.IsPrimary {
					wanted = append(wanted, nlbBackend{deref(instance.DisplayName), deref(vnic.PrivateIp)})
				}
			}
		}
	}
	for _, balancer := range balancers {
		if gone(string(balancer.LifecycleState)) || !region.owns("network-load-balancer", "nlb", balancer.FreeformTags) {
			continue
		}
		if check.State == Missing {
			check.State = Ok
		}
		configuration, err := pass.balancers.GetNetworkLoadBalancer(ctx, networkloadbalancer.GetNetworkLoadBalancerRequest{NetworkLoadBalancerId: balancer.Id})
		if err != nil {
			return check, err
		}
		for _, port := range nlbPorts {
			name := backendSetName(port)
			health, err := pass.balancers.GetBackendSetHealth(ctx, networkloadbalancer.GetBackendSetHealthRequest{NetworkLoadBalancerId: balancer.Id, BackendSetName: common.String(name)})
			if err != nil {
				return check, fmt.Errorf("backend health %s %s: %w", deref(balancer.DisplayName), name, err)
			}
			have := addresses(configuration.BackendSets[name].Backends)
			want := addresses(backendSet(wanted, port).Backends)
			if !slices.Equal(have, want) || len(wanted) != nodes {
				check.State = Differs
				check.Details = append(check.Details, fmt.Sprintf("%s members %v; node backends %v", name, have, want))
			}
			count := deref(health.TotalBackendCount)
			if health.Status != networkloadbalancer.BackendSetHealthStatusOk || count != nodes || nodes < region.Nodes.Min {
				check.State = Differs
			}
			check.Details = append(check.Details, fmt.Sprintf("%s %s %s: %d backends, %d nodes", deref(balancer.DisplayName), name, health.Status, count, nodes))
			for _, state := range []struct {
				name  string
				names []string
			}{{"critical", health.CriticalStateBackendNames}, {"warning", health.WarningStateBackendNames}, {"unknown", health.UnknownStateBackendNames}} {
				if len(state.names) > 0 {
					check.State = Differs
					check.Details = append(check.Details, name+" "+state.name+": "+strings.Join(state.names, ", "))
				}
			}
		}
	}
	return check, nil
}
