package fleet

import (
	"context"
	"fmt"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/nlbhealth"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/networkloadbalancer"
)

func WithdrawalWindow(ctx context.Context, label string) (time.Duration, error) {
	region, err := Embedded().Region(label)
	if err != nil {
		return nlbhealth.UnverifiedDrainWindow, err
	}
	factory, err := LoopFactory(ctx, region)
	if err != nil {
		return nlbhealth.UnverifiedDrainWindow, err
	}
	client, err := factory.NetworkLoadBalancer()
	if err != nil {
		return nlbhealth.UnverifiedDrainWindow, err
	}
	balancers, err := list("withdrawal nlb", func(page *string) ([]networkloadbalancer.NetworkLoadBalancerSummary, *string, error) {
		response, err := client.ListNetworkLoadBalancers(ctx, networkloadbalancer.ListNetworkLoadBalancersRequest{
			CompartmentId: common.String(region.CompartmentID), Page: page})
		return response.Items, response.OpcNextPage, err
	})
	if err != nil {
		return nlbhealth.UnverifiedDrainWindow, err
	}
	var owned []networkloadbalancer.NetworkLoadBalancerSummary
	for _, balancer := range balancers {
		if !gone(string(balancer.LifecycleState)) && region.owns("network-load-balancer", "nlb", balancer.FreeformTags) {
			owned = append(owned, balancer)
		}
	}
	if len(owned) != 1 {
		return nlbhealth.UnverifiedDrainWindow, fmt.Errorf("%s has %d owned NLBs", label, len(owned))
	}
	response, err := client.GetNetworkLoadBalancer(ctx, networkloadbalancer.GetNetworkLoadBalancerRequest{NetworkLoadBalancerId: owned[0].Id})
	if err != nil {
		return nlbhealth.UnverifiedDrainWindow, err
	}
	want := healthChecker()
	for _, port := range nlbPorts {
		set, ok := response.BackendSets[backendSetName(port)]
		have := set.HealthChecker
		if !ok || have == nil || have.Protocol != want.Protocol || deref(have.Port) != deref(want.Port) ||
			deref(have.UrlPath) != deref(want.UrlPath) || deref(have.ReturnCode) != deref(want.ReturnCode) ||
			deref(have.IntervalInMillis) != deref(want.IntervalInMillis) || deref(have.TimeoutInMillis) != deref(want.TimeoutInMillis) ||
			deref(have.Retries) != deref(want.Retries) || set.Policy != nlbPolicy ||
			deref(set.IsInstantFailoverEnabled) || deref(set.AreOperationallyActiveBackendsPreferred) {
			return nlbhealth.UnverifiedDrainWindow, fmt.Errorf("%s %s withdrawal policy differs", label, backendSetName(port))
		}
	}
	return nlbhealth.DrainWindow, nil
}
