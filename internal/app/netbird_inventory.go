package app

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/host"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/oci"
)

// Admit only live registrations whose exact OCI binding is positively owned.
func (n *netbirdRollout) refreshManaged(ctx context.Context) error {
	if time.Since(n.observed) < 30*time.Second {
		return nil
	}
	hosts, err := n.fence.hosts.ListHosts(ctx)
	if err != nil {
		return err
	}
	now := time.Now()
	candidates := make([]host.HostStatus, 0, len(hosts))
	for _, h := range hosts {
		if h.Registration.ManagedOCI != nil && now.Before(h.SessionExpiresAt) {
			candidates = append(candidates, h)
		}
	}
	addresses := map[string]string{}
	if len(candidates) != 0 && n.fleet != nil {
		instances, err := n.observeManaged(ctx, candidates)
		if err != nil {
			return err
		}
		for _, h := range candidates {
			if address, err := netbirdManagedAddress(h.Registration, instances); err == nil {
				addresses[h.Registration.Node] = address
			}
		}
	}
	n.managedAddresses, n.observed = addresses, now
	return nil
}

// Recovery verifies only its recorded node; unrelated retired hosts cannot
// prevent returning an already drained node. Required mesh/quorum gates remain.
func (n *netbirdRollout) refreshRecoveryNode(ctx context.Context, node string) error {
	_, adopted := n.fence.spec()
	if address := adopted[node]; address != "" {
		if err := netbirdOCIAddress(address); err != nil {
			return err
		}
		n.managedAddresses, n.observed = nil, time.Time{}
		return nil
	}
	hosts, err := n.fence.hosts.ListHosts(ctx)
	if err != nil {
		return err
	}
	index := slices.IndexFunc(hosts, func(h host.HostStatus) bool { return h.Registration.Node == node })
	if index < 0 || hosts[index].Registration.ManagedOCI == nil || n.fleet == nil {
		return fmt.Errorf("NetBird recovery node %s has no adopted grant or verified OCI binding", node)
	}
	instances, err := n.observeManaged(ctx, hosts[index:index+1])
	if err != nil {
		return err
	}
	address, err := netbirdManagedAddress(hosts[index].Registration, instances)
	if err != nil {
		return err
	}
	n.managedAddresses, n.observed = map[string]string{node: address}, time.Time{}
	return nil
}

func (n *netbirdRollout) observeManaged(ctx context.Context, hosts []host.HostStatus) ([]oci.Instance, error) {
	if observer, ok := n.fleet.(oci.SelectiveObserver); ok {
		return observer.ObserveSelected(ctx, func(id, node string) bool {
			return slices.ContainsFunc(hosts, func(h host.HostStatus) bool {
				return id == h.Registration.ManagedOCI.InstanceID || node == h.Registration.Node
			})
		})
	}
	return n.fleet.Observe(ctx)
}

func netbirdManagedAddress(registration host.Registration, instances []oci.Instance) (string, error) {
	binding := registration.ManagedOCI
	if binding == nil || registration.Node == "" || binding.InstanceID == "" || binding.Owner == "" || binding.CreateKey == "" || binding.Region == "" || binding.FleetGeneration == 0 {
		return "", errors.New("NetBird host has no complete OCI identity binding")
	}
	var match *oci.Instance
	for index := range instances {
		instance := &instances[index]
		if instance.ID != binding.InstanceID && instance.Node != registration.Node {
			continue
		}
		if match != nil {
			return "", errors.New("NetBird OCI host identity is ambiguous")
		}
		match = instance
	}
	if match == nil || match.ID != binding.InstanceID || match.Node != registration.Node || match.Owner != binding.Owner ||
		match.CreateKey != binding.CreateKey || match.Generation != binding.FleetGeneration || string(match.Region) != binding.Region || match.State != "RUNNING" {
		return "", fmt.Errorf("managed NetBird node %s is not positively observed", registration.Node)
	}
	if err := netbirdOCIAddress(match.PrivateIP); err != nil {
		return "", err
	}
	return match.PrivateIP, nil
}

func netbirdOCIAddress(address string) error {
	ip, err := netip.ParseAddr(address)
	if err != nil || !ip.Is4() || !ip.IsPrivate() || ip.IsLoopback() || netbirdClientRange.Contains(ip) {
		return errors.New("NetBird node has no independent OCI private IPv4 address")
	}
	return nil
}
