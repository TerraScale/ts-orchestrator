package regionhost

import (
	"maps"
	"regexp"
	"slices"
	"strings"

	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"github.com/oracle/oci-go-sdk/v65/core"
	"github.com/oracle/oci-go-sdk/v65/identity"
)

// The one Vault for every region (the same identifiers internal/natscell/mesh
// reads) and the IAM that lets every host use it.
const (
	gruCompartment = "ocid1.compartment.oc1..aaaaaaaaypdff62jbchkojfli5i22ybzm3qnptwwsbg3aa2t5ali6te52nzq"
	gruVault       = "ocid1.vault.oc1.sa-saopaulo-1.ffvnrldqaaexa.abtxeljrlqoda2dl7r527hwngvx5k5j7lhfytswubkmx6rtg5f4mjtv4xzlq"
	gruVaultKey    = "ocid1.key.oc1.sa-saopaulo-1.ffvnrldqaaexa.abtxeljr2bdwyvlua7oi6gpg7gl72ln6t2l2fb63tl2cvhllvokc4l2afeeq"
	dynamicGroup   = "ts-orch-hosts"
	vaultPolicy    = "ts-orch-hosts-vault"
)

var (
	cellCompartment = regexp.MustCompile(`^([a-z]{3})-1-control$`)
	ruleCompartment = regexp.MustCompile(`instance\.compartment\.id = '([^']+)'`)
)

// matchingRule matches the instances of every compartment in ids.
func matchingRule(ids []string) string {
	terms := make([]string, len(ids))
	for i, id := range ids {
		terms[i] = "instance.compartment.id = '" + id + "'"
	}
	return "ANY {" + strings.Join(terms, ", ") + "}"
}

// sameRule reports whether live matches exactly the compartments in ids, in
// any order.
func sameRule(live string, ids []string) bool {
	var have []string
	for _, m := range ruleCompartment.FindAllStringSubmatch(live, -1) {
		have = append(have, m[1])
	}
	return live == matchingRule(have) && slices.Equal(slices.Sorted(slices.Values(have)), slices.Sorted(slices.Values(ids)))
}

// statements are the gru-vault statements (formerly oci-iam.sh) plus, per region, read
// and write of its in-region join secret ts-orch-join-<region> and of its
// operator dashboard token <region>-1-orch-dashboard-token (hostdashboard.SecretName),
// which the region's first host creates.
func statements(regions []string) []string {
	in := "in compartment id " + gruCompartment
	vault := "target.vault.id = '" + gruVault + "'"
	s := []string{
		"Allow dynamic-group " + dynamicGroup + " to read secret-bundles " + in + " where " + vault,
		"Allow dynamic-group " + dynamicGroup + " to read vaults " + in + " where " + vault,
		"Allow dynamic-group " + dynamicGroup + " to inspect secrets " + in,
		"Allow dynamic-group " + dynamicGroup + " to manage secret-family " + in + " where all {" + vault + ", target.secret.name = 'ts-orch-mesh-key'}",
		"Allow dynamic-group " + dynamicGroup + " to use vaults " + in + " where " + vault,
		"Allow dynamic-group " + dynamicGroup + " to use keys " + in + " where target.key.id = '" + gruVaultKey + "'",
	}
	for _, region := range slices.Sorted(slices.Values(regions)) {
		for _, secret := range []string{"ts-orch-join-" + region, dashboardSecret(region)} {
			s = append(s, "Allow dynamic-group "+dynamicGroup+" to manage secret-family "+in+" where all {"+vault+", target.secret.name = '"+secret+"'}")
		}
	}
	return s
}

// dashboardSecret is hostdashboard.SecretName without its dependencies.
func dashboardSecret(region string) string { return region + "-1-orch-dashboard-token" }

// hostCompartments maps each region code to its CELL-control compartment, for
// every cell compartment under TerraScale with a live instance.
func (r *run) hostCompartments() (map[string]string, error) {
	list, err := r.home.ListCompartments(r.ctx, identity.ListCompartmentsRequest{CompartmentId: &r.parent,
		LifecycleState: identity.CompartmentLifecycleStateActive, Limit: new(1000)})
	if err != nil {
		return nil, err
	}
	hosts := map[string]string{}
	for _, c := range list.Items {
		m := cellCompartment.FindStringSubmatch(deref(c.Name))
		if m == nil {
			continue
		}
		entry, ok := catalog.LookupName(m[1])
		if !ok {
			continue
		}
		f, err := ociclient.OperatorConfig(entry.OCIRegion)
		if err != nil {
			return nil, err
		}
		compute, err := f.Compute()
		if err != nil {
			return nil, err
		}
		items, err := compute.ListInstances(r.ctx, core.ListInstancesRequest{CompartmentId: c.Id})
		if err != nil {
			return nil, err
		}
		if len(live(items.Items)) > 0 {
			hosts[m[1]] = *c.Id
		}
	}
	return hosts, nil
}

// ensureIAM converges the dynamic group and the gru-vault policy to the
// regions that have a host.
func (r *run) ensureIAM() error {
	hosts, err := r.hostCompartments()
	if err != nil {
		return err
	}
	regions := slices.Sorted(maps.Keys(hosts))
	ids := make([]string, len(regions))
	for i, region := range regions {
		ids[i] = hosts[region]
	}
	groups, err := r.home.ListDynamicGroups(r.ctx, identity.ListDynamicGroupsRequest{CompartmentId: &r.tenancy, Name: new(dynamicGroup)})
	if err != nil {
		return err
	}
	rule := matchingRule(ids)
	if len(groups.Items) == 1 { // the list leaves the matching rule out
		g, err := r.home.GetDynamicGroup(r.ctx, identity.GetDynamicGroupRequest{DynamicGroupId: groups.Items[0].Id})
		if err != nil {
			return err
		}
		groups.Items[0] = g.DynamicGroup
	}
	switch {
	case len(groups.Items) == 0:
		id := "-"
		if !r.dry {
			g, err := r.home.CreateDynamicGroup(r.ctx, identity.CreateDynamicGroupRequest{CreateDynamicGroupDetails: identity.CreateDynamicGroupDetails{
				CompartmentId: &r.tenancy, Name: new(dynamicGroup), Description: new("ts-orch hosts of every region"), MatchingRule: &rule}})
			if err != nil {
				return err
			}
			id = *g.Id
		}
		err = r.report("created", "dynamic-group", dynamicGroup, id)
	case sameRule(deref(groups.Items[0].MatchingRule), ids):
		err = r.report("unchanged", "dynamic-group", dynamicGroup, *groups.Items[0].Id)
	default:
		if !r.dry {
			if _, err := r.home.UpdateDynamicGroup(r.ctx, identity.UpdateDynamicGroupRequest{DynamicGroupId: groups.Items[0].Id,
				UpdateDynamicGroupDetails: identity.UpdateDynamicGroupDetails{MatchingRule: &rule}}); err != nil {
				return err
			}
		}
		err = r.report("updated", "dynamic-group", dynamicGroup, *groups.Items[0].Id)
	}
	if err != nil {
		return err
	}
	policies, err := r.home.ListPolicies(r.ctx, identity.ListPoliciesRequest{CompartmentId: new(gruCompartment), Name: new(vaultPolicy)})
	if err != nil {
		return err
	}
	want := statements(regions)
	switch {
	case len(policies.Items) == 0:
		id := "-"
		if !r.dry {
			p, err := r.home.CreatePolicy(r.ctx, identity.CreatePolicyRequest{CreatePolicyDetails: identity.CreatePolicyDetails{
				CompartmentId: new(gruCompartment), Name: new(vaultPolicy), Description: new("ts-orch hosts read gru-vault"), Statements: want}})
			if err != nil {
				return err
			}
			id = *p.Id
		}
		return r.report("created", "policy", vaultPolicy, id)
	case slices.Equal(slices.Sorted(slices.Values(policies.Items[0].Statements)), slices.Sorted(slices.Values(want))):
		return r.report("unchanged", "policy", vaultPolicy, *policies.Items[0].Id)
	}
	if !r.dry {
		if _, err := r.home.UpdatePolicy(r.ctx, identity.UpdatePolicyRequest{PolicyId: policies.Items[0].Id,
			UpdatePolicyDetails: identity.UpdatePolicyDetails{Statements: want}}); err != nil {
			return err
		}
	}
	return r.report("updated", "policy", vaultPolicy, *policies.Items[0].Id)
}
