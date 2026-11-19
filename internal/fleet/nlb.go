package fleet

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/nlbhealth"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/ociresource"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/core"
	"github.com/oracle/oci-go-sdk/v65/networkloadbalancer"
)

var nlbPorts = []int{80, 443, 5432}

const (
	nlbHealthPort = 80
	nlbHealthPath = "/readyz"
	nlbPolicy     = networkloadbalancer.NetworkLoadBalancingPolicyFiveTuple
)

func (r Region) ownedTags(kind, name string) map[string]string {
	return map[string]string{
		"terrascale-managed-by":   "ts-orchestrator",
		"terrascale-owner":        Owner,
		"terrascale-resource-key": r.Key(kind, name).String(),
	}
}

func (r Region) owns(kind, name string, tags map[string]string) bool {
	return ociresource.Ownership{Owner: Owner}.Owns(r.Key(kind, name), ociresource.Tags{Freeform: tags})
}

type nlbBackend struct {
	name, address string
}

type nlbPass struct {
	region    Region
	network   core.VirtualNetworkClient
	compute   core.ComputeClient
	balancers networkloadbalancer.NetworkLoadBalancerClient
	out       ociresource.Out
}

func applyNLB(ctx context.Context, _ Fleet, region Region, f *ociclient.Factory, _ Cluster, out ociresource.Out) error {
	var err error
	p := nlbPass{region: region, out: out}
	if p.network, err = f.Network(); err != nil {
		return err
	}
	if p.compute, err = f.Compute(); err != nil {
		return err
	}
	if p.balancers, err = f.NetworkLoadBalancer(); err != nil {
		return err
	}
	return p.apply(ctx)
}

func (p nlbPass) say(format string, args ...any) error {
	_, err := fmt.Fprintf(p.out.Changed, "%s nlb: %s\n", p.region.Label, fmt.Sprintf(format, args...))
	return err
}

func (p nlbPass) same(format string, args ...any) {
	fmt.Fprintf(p.out.Same, "%s nlb: %s\n", p.region.Label, fmt.Sprintf(format, args...))
}

func (p nlbPass) apply(ctx context.Context) error {
	compartment := common.String(p.region.CompartmentID)
	subnets, err := list("subnet", func(page *string) ([]core.Subnet, *string, error) {
		r, err := p.network.ListSubnets(ctx, core.ListSubnetsRequest{CompartmentId: compartment, Page: page})
		return r.Items, r.OpcNextPage, err
	})
	if err != nil {
		return err
	}
	public, vcn := "", ""
	for _, s := range subnets {
		if !gone(string(s.LifecycleState)) && p.region.owns("subnet", "host-subnet", s.FreeformTags) {
			public, vcn = deref(s.Id), deref(s.VcnId)
		}
	}
	nsgs, err := list("nsg", func(page *string) ([]core.NetworkSecurityGroup, *string, error) {
		r, err := p.network.ListNetworkSecurityGroups(ctx, core.ListNetworkSecurityGroupsRequest{CompartmentId: compartment, Page: page})
		return r.Items, r.OpcNextPage, err
	})
	if err != nil {
		return err
	}
	var groups []string
	for _, name := range []string{"edge-nsg", "host-nsg"} {
		for _, g := range nsgs {
			if !gone(string(g.LifecycleState)) && deref(g.VcnId) == vcn && p.region.owns("nsg", name, g.FreeformTags) {
				groups = append(groups, deref(g.Id))
			}
		}
	}
	if public == "" || len(groups) != 2 {
		return fmt.Errorf("%s: the document-made public subnet and the edge and host NSGs must exist before the nlb", p.region.Label)
	}
	backends, err := p.backends(ctx, subnets, vcn)
	if err != nil {
		return err
	}
	address, err := p.reservedAddress(ctx)
	if err != nil || address.Id == nil {
		return err
	}
	return p.balancer(ctx, public, groups, address, backends)
}

func (p nlbPass) backends(ctx context.Context, subnets []core.Subnet, vcn string) ([]nlbBackend, error) {
	compartment := common.String(p.region.CompartmentID)
	inVCN := map[string]bool{}
	for _, s := range subnets {
		inVCN[deref(s.Id)] = deref(s.VcnId) == vcn
	}
	instances, err := list("instance", func(page *string) ([]core.Instance, *string, error) {
		r, err := p.compute.ListInstances(ctx, core.ListInstancesRequest{CompartmentId: compartment, LifecycleState: core.InstanceLifecycleStateRunning, Page: page})
		return r.Items, r.OpcNextPage, err
	})
	if err != nil {
		return nil, err
	}
	attachments, err := list("vnic attachment", func(page *string) ([]core.VnicAttachment, *string, error) {
		r, err := p.compute.ListVnicAttachments(ctx, core.ListVnicAttachmentsRequest{CompartmentId: compartment, Page: page})
		return r.Items, r.OpcNextPage, err
	})
	if err != nil {
		return nil, err
	}
	var backends []nlbBackend
	for _, in := range instances {
		for _, a := range attachments {
			if deref(a.InstanceId) != deref(in.Id) || a.LifecycleState != core.VnicAttachmentLifecycleStateAttached || !inVCN[deref(a.SubnetId)] {
				continue
			}
			vnic, err := p.network.GetVnic(ctx, core.GetVnicRequest{VnicId: a.VnicId})
			if err != nil {
				return nil, fmt.Errorf("vnic of %s: %w", deref(in.DisplayName), err)
			}
			if vnic.IsPrimary != nil && *vnic.IsPrimary && deref(vnic.PrivateIp) != "" {
				backends = append(backends, nlbBackend{deref(in.DisplayName), deref(vnic.PrivateIp)})
			}
		}
	}
	if len(backends) == 0 {
		return nil, fmt.Errorf("%s: no running node in the region's network to balance to", p.region.Label)
	}
	slices.SortFunc(backends, func(a, b nlbBackend) int { return strings.Compare(a.address, b.address) })
	return backends, nil
}

func (p nlbPass) reservedAddress(ctx context.Context) (core.PublicIp, error) {
	compartment := common.String(p.region.CompartmentID)
	reserved, err := list("reserved address", func(page *string) ([]core.PublicIp, *string, error) {
		r, err := p.network.ListPublicIps(ctx, core.ListPublicIpsRequest{Scope: core.ListPublicIpsScopeRegion, Lifetime: core.ListPublicIpsLifetimeReserved, CompartmentId: compartment, Page: page})
		return r.Items, r.OpcNextPage, err
	})
	if err != nil {
		return core.PublicIp{}, err
	}
	for _, ip := range reserved {
		if !gone(string(ip.LifecycleState)) && p.region.owns("public-ip", "nlb", ip.FreeformTags) {
			p.same("ok reserved address %s %s", deref(ip.DisplayName), deref(ip.IpAddress))
			return ip, nil
		}
	}
	if err := p.say("create reserved address %s-1-nlb-ip", p.region.Label); err != nil || !p.out.Apply {
		return core.PublicIp{}, err
	}
	created, err := p.network.CreatePublicIp(ctx, core.CreatePublicIpRequest{CreatePublicIpDetails: core.CreatePublicIpDetails{
		CompartmentId: compartment, Lifetime: core.CreatePublicIpDetailsLifetimeReserved,
		DisplayName: common.String(p.region.Label + "-1-nlb-ip"), FreeformTags: p.region.ownedTags("public-ip", "nlb"),
	}})
	if err != nil {
		return core.PublicIp{}, fmt.Errorf("create reserved address: %w", err)
	}
	ip := created.PublicIp
	return core.PublicIp{}, wait(ctx, "reserved address "+deref(ip.IpAddress), func() (bool, error) {
		r, err := p.network.GetPublicIp(ctx, core.GetPublicIpRequest{PublicIpId: ip.Id})
		return r.LifecycleState == core.PublicIpLifecycleStateAvailable, err
	})
}

func healthChecker() networkloadbalancer.HealthCheckerDetails {
	return networkloadbalancer.HealthCheckerDetails{
		Protocol: networkloadbalancer.HealthCheckProtocolsHttp, Port: common.Int(nlbHealthPort), UrlPath: common.String(nlbHealthPath),
		ReturnCode: common.Int(200), IntervalInMillis: common.Int(int(nlbhealth.Interval / time.Millisecond)),
		TimeoutInMillis: common.Int(int(nlbhealth.Timeout / time.Millisecond)), Retries: common.Int(nlbhealth.Retries),
	}
}

func backendSetName(port int) string { return fmt.Sprintf("tcp-%d", port) }

func backendDetails(backends []nlbBackend, port int) []networkloadbalancer.BackendDetails {
	var details []networkloadbalancer.BackendDetails
	for _, b := range backends {
		details = append(details, networkloadbalancer.BackendDetails{Name: common.String(fmt.Sprintf("%s:%d", b.address, port)), IpAddress: common.String(b.address), Port: common.Int(port), Weight: common.Int(1)})
	}
	return details
}

func backendSet(backends []nlbBackend, port int) networkloadbalancer.BackendSetDetails {
	health := healthChecker()
	set := networkloadbalancer.BackendSetDetails{
		Policy: nlbPolicy, IsPreserveSource: common.Bool(true), IsFailOpen: common.Bool(true), IsInstantFailoverEnabled: common.Bool(false),
		HealthChecker: &networkloadbalancer.HealthChecker{Protocol: health.Protocol, Port: health.Port, UrlPath: health.UrlPath, ReturnCode: health.ReturnCode,
			IntervalInMillis: health.IntervalInMillis, TimeoutInMillis: health.TimeoutInMillis, Retries: health.Retries},
	}
	for _, d := range backendDetails(backends, port) {
		set.Backends = append(set.Backends, networkloadbalancer.Backend{Name: d.Name, IpAddress: d.IpAddress, Port: d.Port, Weight: d.Weight})
	}
	return set
}

func listener(port int) networkloadbalancer.ListenerDetails {
	return networkloadbalancer.ListenerDetails{Name: common.String(backendSetName(port)), DefaultBackendSetName: common.String(backendSetName(port)),
		Port: common.Int(port), Protocol: networkloadbalancer.ListenerProtocolsTcp}
}

func addresses(backends []networkloadbalancer.Backend) []string {
	var all []string
	for _, b := range backends {
		all = append(all, fmt.Sprintf("%s:%d", deref(b.IpAddress), deref(b.Port)))
	}
	slices.Sort(all)
	return all
}

func sameSet(have networkloadbalancer.BackendSet, want networkloadbalancer.BackendSetDetails) bool {
	h, w := have.HealthChecker, want.HealthChecker
	return h != nil && h.Protocol == w.Protocol && deref(h.UrlPath) == deref(w.UrlPath) && deref(h.Port) == deref(w.Port) && deref(h.ReturnCode) == deref(w.ReturnCode) &&
		deref(h.IntervalInMillis) == deref(w.IntervalInMillis) && deref(h.TimeoutInMillis) == deref(w.TimeoutInMillis) && deref(h.Retries) == deref(w.Retries) &&
		have.Policy == want.Policy && deref(have.IsPreserveSource) && deref(have.IsFailOpen) && !deref(have.IsInstantFailoverEnabled) &&
		slices.Equal(addresses(have.Backends), addresses(want.Backends))
}

func (p nlbPass) balancer(ctx context.Context, subnet string, groups []string, address core.PublicIp, backends []nlbBackend) error {
	compartment := common.String(p.region.CompartmentID)
	summaries, err := list("nlb", func(page *string) ([]networkloadbalancer.NetworkLoadBalancerSummary, *string, error) {
		r, err := p.balancers.ListNetworkLoadBalancers(ctx, networkloadbalancer.ListNetworkLoadBalancersRequest{CompartmentId: compartment, Page: page})
		return r.Items, r.OpcNextPage, err
	})
	if err != nil {
		return err
	}
	var names []string
	for _, b := range backends {
		names = append(names, b.name+" "+b.address)
	}
	for _, s := range summaries {
		if gone(string(s.LifecycleState)) || !p.region.owns("network-load-balancer", "nlb", s.FreeformTags) {
			continue
		}
		got, err := p.balancers.GetNetworkLoadBalancer(ctx, networkloadbalancer.GetNetworkLoadBalancerRequest{NetworkLoadBalancerId: s.Id})
		if err != nil {
			return err
		}
		return p.converge(ctx, got.NetworkLoadBalancer, subnet, groups, address, backends, strings.Join(names, ", "))
	}
	sets, listeners := map[string]networkloadbalancer.BackendSetDetails{}, map[string]networkloadbalancer.ListenerDetails{}
	for _, port := range nlbPorts {
		sets[backendSetName(port)] = backendSet(backends, port)
		listeners[backendSetName(port)] = listener(port)
	}
	if err := p.say("create %s-1-nlb %s, backends %s", p.region.Label, deref(address.IpAddress), strings.Join(names, ", ")); err != nil {
		return err
	}
	for _, port := range nlbPorts {
		if err := p.say("create backend set %s: %s", backendSetName(port), strings.Join(names, ", ")); err != nil {
			return err
		}
		if err := p.say("create listener %s", backendSetName(port)); err != nil {
			return err
		}
	}
	if !p.out.Apply {
		return nil
	}
	created, err := p.balancers.CreateNetworkLoadBalancer(ctx, networkloadbalancer.CreateNetworkLoadBalancerRequest{CreateNetworkLoadBalancerDetails: networkloadbalancer.CreateNetworkLoadBalancerDetails{
		CompartmentId: compartment, DisplayName: common.String(p.region.Label + "-1-nlb"), SubnetId: common.String(subnet), IsPrivate: common.Bool(false),
		IsPreserveSourceDestination: common.Bool(false), NlbIpVersion: networkloadbalancer.NlbIpVersionIpv4, NetworkSecurityGroupIds: groups,
		ReservedIps: []networkloadbalancer.ReservedIp{{Id: address.Id}}, BackendSets: sets, Listeners: listeners,
		FreeformTags: p.region.ownedTags("network-load-balancer", "nlb"),
	}})
	if err != nil {
		return fmt.Errorf("create nlb: %w", err)
	}
	return p.work(ctx, "create nlb", created.OpcWorkRequestId)
}

func (p nlbPass) converge(ctx context.Context, nlb networkloadbalancer.NetworkLoadBalancer, subnet string, groups []string, address core.PublicIp, backends []nlbBackend, names string) error {
	id := nlb.Id
	reserved := slices.ContainsFunc(nlb.IpAddresses, func(ip networkloadbalancer.IpAddress) bool {
		return ip.ReservedIp != nil && deref(ip.ReservedIp.Id) == deref(address.Id)
	})
	if deref(nlb.SubnetId) != subnet || !reserved || deref(nlb.IsPrivate) || deref(nlb.IsPreserveSourceDestination) {
		return fmt.Errorf("%s nlb %s differs in subnet, address or source mode, which OCI cannot change in place; delete it and apply again (docs/oci-reconcile.md)", p.region.Label, deref(nlb.DisplayName))
	}
	changed := false
	if have := slices.Sorted(slices.Values(nlb.NetworkSecurityGroupIds)); !slices.Equal(have, slices.Sorted(slices.Values(groups))) {
		if err := p.write(ctx, "update nsgs", func() (*string, error) {
			r, err := p.balancers.UpdateNetworkSecurityGroups(ctx, networkloadbalancer.UpdateNetworkSecurityGroupsRequest{NetworkLoadBalancerId: id,
				UpdateNetworkSecurityGroupsDetails: networkloadbalancer.UpdateNetworkSecurityGroupsDetails{NetworkSecurityGroupIds: groups}})
			return r.OpcWorkRequestId, err
		}); err != nil {
			return err
		}
		changed = true
	}
	for _, port := range nlbPorts {
		name, want := backendSetName(port), backendSet(backends, port)
		have, ok := nlb.BackendSets[name]
		switch {
		case !ok:
			if err := p.write(ctx, fmt.Sprintf("create backend set %s: %s", name, names), func() (*string, error) {
				r, err := p.balancers.CreateBackendSet(ctx, networkloadbalancer.CreateBackendSetRequest{NetworkLoadBalancerId: id, CreateBackendSetDetails: networkloadbalancer.CreateBackendSetDetails{
					Name: common.String(name), Policy: want.Policy, IsPreserveSource: want.IsPreserveSource, IsFailOpen: want.IsFailOpen,
					IsInstantFailoverEnabled: want.IsInstantFailoverEnabled, HealthChecker: new(healthChecker()), Backends: backendDetails(backends, port)}})
				return r.OpcWorkRequestId, err
			}); err != nil {
				return err
			}
			changed = true
		case !sameSet(have, want):
			if err := p.write(ctx, fmt.Sprintf("update backend set %s: %s -> %s", name, strings.Join(addresses(have.Backends), " "), names), func() (*string, error) {
				r, err := p.balancers.UpdateBackendSet(ctx, networkloadbalancer.UpdateBackendSetRequest{NetworkLoadBalancerId: id, BackendSetName: common.String(name),
					UpdateBackendSetDetails: networkloadbalancer.UpdateBackendSetDetails{Policy: common.String(string(want.Policy)), IsPreserveSource: want.IsPreserveSource,
						IsFailOpen: want.IsFailOpen, IsInstantFailoverEnabled: want.IsInstantFailoverEnabled, HealthChecker: new(healthChecker()), Backends: backendDetails(backends, port)}})
				return r.OpcWorkRequestId, err
			}); err != nil {
				return err
			}
			changed = true
		}
		l, ok := nlb.Listeners[name]
		switch want := listener(port); {
		case !ok:
			if err := p.write(ctx, "create listener "+name, func() (*string, error) {
				r, err := p.balancers.CreateListener(ctx, networkloadbalancer.CreateListenerRequest{NetworkLoadBalancerId: id, CreateListenerDetails: networkloadbalancer.CreateListenerDetails{
					Name: want.Name, DefaultBackendSetName: want.DefaultBackendSetName, Port: want.Port, Protocol: want.Protocol}})
				return r.OpcWorkRequestId, err
			}); err != nil {
				return err
			}
			changed = true
		case deref(l.Port) != port || l.Protocol != want.Protocol || deref(l.DefaultBackendSetName) != name:
			if err := p.write(ctx, "update listener "+name, func() (*string, error) {
				r, err := p.balancers.UpdateListener(ctx, networkloadbalancer.UpdateListenerRequest{NetworkLoadBalancerId: id, ListenerName: common.String(name),
					UpdateListenerDetails: networkloadbalancer.UpdateListenerDetails{DefaultBackendSetName: want.DefaultBackendSetName, Port: want.Port, Protocol: want.Protocol}})
				return r.OpcWorkRequestId, err
			}); err != nil {
				return err
			}
			changed = true
		}
	}
	if !changed {
		p.same("ok %s %s tcp %v, backends %s", deref(nlb.DisplayName), deref(address.IpAddress), nlbPorts, names)
	}
	return nil
}

func (p nlbPass) write(ctx context.Context, what string, call func() (*string, error)) error {
	if err := p.say("%s", what); err != nil || !p.out.Apply {
		return err
	}
	id, err := call()
	return p.work(ctx, what, id, err)
}

func (p nlbPass) work(ctx context.Context, what string, id *string, errs ...error) error {
	if err := errors.Join(errs...); err != nil {
		return fmt.Errorf("%s: %w", what, err)
	}
	return wait(ctx, what, func() (bool, error) {
		r, err := p.balancers.GetWorkRequest(ctx, networkloadbalancer.GetWorkRequestRequest{WorkRequestId: id})
		switch {
		case err != nil:
			return false, err
		case r.Status == networkloadbalancer.OperationStatusSucceeded:
			return true, nil
		case r.Status == networkloadbalancer.OperationStatusAccepted || r.Status == networkloadbalancer.OperationStatusInProgress:
			return false, nil
		}
		return false, fmt.Errorf("work request %s ended %s", deref(id), r.Status)
	})
}

func wait(ctx context.Context, what string, done func() (bool, error)) error {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Minute)
	defer cancel()
	for delay := 2 * time.Second; ; delay = min(delay*2, 30*time.Second) {
		ok, err := done()
		if err != nil {
			return fmt.Errorf("%s: %w", what, err)
		}
		if ok {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("%s did not finish: %w", what, ctx.Err())
		case <-time.After(delay):
		}
	}
}
