package hostnetwork

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/oracle/oci-go-sdk/v65/core"
)

// network converges the resources inside one VCN. A nil ID is a resource a
// dry run would create first.
type network struct {
	*reconciler
	vcn *string
}

// nsg converges one role NSG and its rules, adding before removing.
func (n network) nsg(g nsg) (*string, error) {
	ctx := n.ctx
	key := strings.TrimPrefix(g.name, n.s.cell+"-")
	list, err := n.net.ListNetworkSecurityGroups(ctx, core.ListNetworkSecurityGroupsRequest{CompartmentId: &n.compartment, VcnId: n.vcn, DisplayName: &g.name})
	if err != nil {
		return nil, err
	}
	live, err := one(list.Items, g.name, func(s core.NetworkSecurityGroup) (string, string) {
		return deref(s.DisplayName), string(s.LifecycleState)
	})
	if err != nil {
		return nil, err
	}
	var id *string
	var rules []core.SecurityRule
	if live == nil {
		if err := n.step("create NSG "+g.name, func() error {
			t, _ := n.tags("nsg", key, nil)
			c, err := n.net.CreateNetworkSecurityGroup(ctx, core.CreateNetworkSecurityGroupRequest{CreateNetworkSecurityGroupDetails: core.CreateNetworkSecurityGroupDetails{
				CompartmentId: &n.compartment, VcnId: n.vcn, DisplayName: &g.name, FreeformTags: t}})
			id = c.Id
			return errors.Join(err, n.await(func() (string, error) {
				s, err := n.net.GetNetworkSecurityGroup(ctx, core.GetNetworkSecurityGroupRequest{NetworkSecurityGroupId: c.Id})
				return string(s.LifecycleState), err
			}))
		}); err != nil {
			return nil, err
		}
	} else {
		id = live.Id
		t, err := n.tags("nsg", key, live.FreeformTags)
		if err != nil {
			return nil, err
		}
		if t != nil {
			if err := n.step("tag NSG "+g.name, func() error {
				_, err := n.net.UpdateNetworkSecurityGroup(ctx, core.UpdateNetworkSecurityGroupRequest{NetworkSecurityGroupId: id,
					UpdateNetworkSecurityGroupDetails: core.UpdateNetworkSecurityGroupDetails{FreeformTags: t}})
				return err
			}); err != nil {
				return nil, err
			}
		}
		for page := (*string)(nil); ; {
			r, err := n.net.ListNetworkSecurityGroupSecurityRules(ctx, core.ListNetworkSecurityGroupSecurityRulesRequest{NetworkSecurityGroupId: id, Page: page})
			if err != nil {
				return nil, err
			}
			rules = append(rules, r.Items...)
			if page = r.OpcNextPage; page == nil {
				break
			}
		}
	}
	add, remove := diff(rules, g.rules)
	if len(add) > 0 {
		details := make([]core.AddSecurityRuleDetails, len(add))
		for i, r := range add {
			details[i] = r.add()
		}
		if err := n.step(fmt.Sprintf("add %d rules to NSG %s", len(add), g.name), func() error {
			_, err := n.net.AddNetworkSecurityGroupSecurityRules(ctx, core.AddNetworkSecurityGroupSecurityRulesRequest{NetworkSecurityGroupId: id,
				AddNetworkSecurityGroupSecurityRulesDetails: core.AddNetworkSecurityGroupSecurityRulesDetails{SecurityRules: details}})
			return err
		}); err != nil {
			return nil, err
		}
	}
	if len(remove) > 0 {
		if err := n.step(fmt.Sprintf("remove %d rules from NSG %s", len(remove), g.name), func() error {
			_, err := n.net.RemoveNetworkSecurityGroupSecurityRules(ctx, core.RemoveNetworkSecurityGroupSecurityRulesRequest{NetworkSecurityGroupId: id,
				RemoveNetworkSecurityGroupSecurityRulesDetails: core.RemoveNetworkSecurityGroupSecurityRulesDetails{SecurityRuleIds: remove}})
			return err
		}); err != nil {
			return nil, err
		}
	}
	return id, nil
}

// vnic sets the host's primary VNIC NSGs to exactly the role NSGs.
func (n network) vnic(nsgs []string) error {
	ctx := n.ctx
	// The host is named by its controller slot (gru-1-ctl-1) or as node 1
	// (ts-sjc-1).
	var host *core.Instance
	for _, name := range []string{n.s.host, n.s.node} {
		list, err := n.compute.ListInstances(ctx, core.ListInstancesRequest{CompartmentId: &n.compartment, DisplayName: &name})
		if err != nil {
			return err
		}
		found, err := one(list.Items, name, func(i core.Instance) (string, string) { return deref(i.DisplayName), string(i.LifecycleState) })
		if err != nil {
			return err
		}
		if found != nil && host != nil {
			return fmt.Errorf("both %s and %s are live", n.s.host, n.s.node)
		}
		if found != nil {
			host = found
		}
	}
	if host == nil {
		// A new cell launches its host into the subnet created below, with
		// these NSGs; the next run attaches them if it did not.
		_, err := fmt.Fprintf(n.out, "skip: no host %s or %s yet\n", n.s.host, n.s.node)
		return err
	}
	attachments, err := n.compute.ListVnicAttachments(ctx, core.ListVnicAttachmentsRequest{CompartmentId: &n.compartment, InstanceId: host.Id})
	if err != nil {
		return err
	}
	for _, a := range attachments.Items {
		if a.LifecycleState != core.VnicAttachmentLifecycleStateAttached {
			continue
		}
		v, err := n.net.GetVnic(ctx, core.GetVnicRequest{VnicId: a.VnicId})
		if err != nil {
			return err
		}
		if !deref(v.IsPrimary) {
			continue
		}
		if slices.Equal(slices.Sorted(slices.Values(v.NsgIds)), slices.Sorted(slices.Values(nsgs))) {
			return nil
		}
		return n.step(fmt.Sprintf("set %s VNIC NSGs to %d role NSGs", n.s.host, len(nsgs)), func() error {
			_, err := n.net.UpdateVnic(ctx, core.UpdateVnicRequest{VnicId: v.Id, UpdateVnicDetails: core.UpdateVnicDetails{NsgIds: nsgs}})
			return err
		})
	}
	return fmt.Errorf("host %s has no attached primary VNIC", n.s.host)
}
