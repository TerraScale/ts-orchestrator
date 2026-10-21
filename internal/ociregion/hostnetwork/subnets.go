package hostnetwork

import (
	"errors"
	"fmt"
	"slices"

	"github.com/oracle/oci-go-sdk/v65/core"
)

// securityList converges a subnet security list to no rules: the role NSGs
// carry every rule.
func (n network) securityList(key string, id *string, name string) (*string, error) {
	ctx := n.ctx
	var sl *core.SecurityList
	if id != nil {
		g, err := n.net.GetSecurityList(ctx, core.GetSecurityListRequest{SecurityListId: id})
		if err != nil {
			return nil, err
		}
		sl = &g.SecurityList
	} else {
		list, err := n.net.ListSecurityLists(ctx, core.ListSecurityListsRequest{CompartmentId: &n.compartment, VcnId: n.vcn, DisplayName: &name})
		if err != nil {
			return nil, err
		}
		if sl, err = one(list.Items, name, func(s core.SecurityList) (string, string) { return deref(s.DisplayName), string(s.LifecycleState) }); err != nil {
			return nil, err
		}
	}
	none := func() ([]core.IngressSecurityRule, []core.EgressSecurityRule) {
		return []core.IngressSecurityRule{}, []core.EgressSecurityRule{}
	}
	if sl == nil {
		var created *string
		return created, n.step("create security list "+name, func() error {
			t, _ := n.tags("security-list", key, nil)
			in, out := none()
			c, err := n.net.CreateSecurityList(ctx, core.CreateSecurityListRequest{CreateSecurityListDetails: core.CreateSecurityListDetails{
				CompartmentId: &n.compartment, VcnId: n.vcn, DisplayName: &name, IngressSecurityRules: in, EgressSecurityRules: out, FreeformTags: t}})
			created = c.Id
			return errors.Join(err, n.await(func() (string, error) {
				g, err := n.net.GetSecurityList(ctx, core.GetSecurityListRequest{SecurityListId: c.Id})
				return string(g.LifecycleState), err
			}))
		})
	}
	t, err := n.tags("security-list", key, sl.FreeformTags)
	if err != nil || t == nil && len(sl.IngressSecurityRules)+len(sl.EgressSecurityRules) == 0 {
		return sl.Id, err
	}
	return sl.Id, n.step(fmt.Sprintf("clear %d rules from security list %s", len(sl.IngressSecurityRules)+len(sl.EgressSecurityRules), deref(sl.DisplayName)), func() error {
		in, out := none()
		_, err := n.net.UpdateSecurityList(ctx, core.UpdateSecurityListRequest{SecurityListId: sl.Id, UpdateSecurityListDetails: core.UpdateSecurityListDetails{
			IngressSecurityRules: in, EgressSecurityRules: out, FreeformTags: t}})
		return err
	})
}

func (n network) subnet(key, name, dns, cidr string, private bool, routes, list *string) error {
	ctx := n.ctx
	all, err := n.net.ListSubnets(ctx, core.ListSubnetsRequest{CompartmentId: &n.compartment, VcnId: n.vcn, DisplayName: &name})
	if err != nil {
		return err
	}
	s, err := one(all.Items, name, func(s core.Subnet) (string, string) { return deref(s.DisplayName), string(s.LifecycleState) })
	if err != nil {
		return err
	}
	lists := []string{deref(list)}
	if s == nil {
		return n.step("create subnet "+name+" "+cidr, func() error {
			t, _ := n.tags("subnet", key, nil)
			_, err := n.net.CreateSubnet(ctx, core.CreateSubnetRequest{CreateSubnetDetails: core.CreateSubnetDetails{CompartmentId: &n.compartment,
				VcnId: n.vcn, CidrBlock: &cidr, DisplayName: &name, DnsLabel: &dns, ProhibitPublicIpOnVnic: &private,
				RouteTableId: routes, SecurityListIds: lists, FreeformTags: t}})
			return err
		})
	}
	if deref(s.CidrBlock) != cidr || deref(s.ProhibitPublicIpOnVnic) != private {
		return fmt.Errorf("subnet %s is %s (private %t), want %s (private %t); refusing to adopt", name, deref(s.CidrBlock), deref(s.ProhibitPublicIpOnVnic), cidr, private)
	}
	t, err := n.tags("subnet", key, s.FreeformTags)
	if err != nil || t == nil && deref(s.RouteTableId) == deref(routes) && slices.Equal(s.SecurityListIds, lists) {
		return err
	}
	return n.step("converge subnet "+name, func() error {
		_, err := n.net.UpdateSubnet(ctx, core.UpdateSubnetRequest{SubnetId: s.Id, UpdateSubnetDetails: core.UpdateSubnetDetails{
			RouteTableId: routes, SecurityListIds: lists, FreeformTags: t}})
		return err
	})
}
