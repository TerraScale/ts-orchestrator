package regionhost

import (
	"encoding/json/v2"
	"errors"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"

	"github.com/TerraScale/ts-orchestrator/deploy/m1"
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

func statements(hosts map[string]string) ([]string, error) {
	in := "in compartment id " + gruCompartment
	vault := "target.vault.id = '" + gruVault + "'"
	s := []string{
		"Allow dynamic-group " + dynamicGroup + " to read vaults " + in + " where " + vault,
		"Allow dynamic-group " + dynamicGroup + " to inspect secrets " + in,
		"Allow dynamic-group " + dynamicGroup + " to use vaults " + in + " where " + vault,
		"Allow dynamic-group " + dynamicGroup + " to use keys " + in + " where target.key.id = '" + gruVaultKey + "'",
	}
	services, err := m1.Files.ReadDir("services")
	if err != nil {
		return nil, err
	}
	principals := map[string][]string{}
	for _, region := range slices.Sorted(maps.Keys(hosts)) {
		grants := map[string]string{}
		for _, secret := range []string{"ts-orch-mesh-key", "gru-1-terrabase-nats-token", "ts-orch-join-" + region, dashboardSecret(region)} {
			grants[secret] = "manage secret-family"
		}
		for _, secret := range []string{
			"gru-1-ghcr-pull-token", "gru-1-netbird-setup-key",
			"gru-1-terrabase-backup-access-key-id", "gru-1-terrabase-backup-secret-key",
			"gru-1-terrabase-files-access-key-id", "gru-1-terrabase-files-secret-key",
			"gru-1-terrabase-master-key", "gru-1-terrabase-peer-secret",
			"gru-1-terrabase-shapes-access-key-id", "gru-1-terrabase-shapes-secret-access-key",
			"gru-1-terrabase-shapes-cdn-api-token",
		} {
			grants[secret] = "read secret-bundles"
		}
		if region == "gru" {
			for _, secret := range []string{"gru-1-netbird-admin-pat", "gru-1-netbird-owner-password", "gru-1-netbird-operators-setup-key", "gru-1-netbird-relay-auth-secret", "gru-1-netbird-session-cookie-key", "gru-1-netbird-datastore-encryption-key", "gru-1-netbird-setup-key"} {
				grants[secret] = "manage secret-family"
			}
		}
		for _, service := range services {
			if !strings.HasSuffix(service.Name(), ".json") {
				continue
			}
			body, err := m1.Files.ReadFile("services/" + service.Name())
			if err != nil {
				return nil, err
			}
			var manifest struct {
				Regions []string `json:"regions"`
				Secrets map[string]struct {
					Vault string `json:"vault"`
					Name  string `json:"name"`
				} `json:"secrets"`
			}
			if err := json.Unmarshal(body, &manifest); err != nil {
				return nil, fmt.Errorf("service manifest %s: %w", service.Name(), err)
			}
			if len(manifest.Regions) > 0 && !slices.Contains(manifest.Regions, region) {
				continue
			}
			for _, ref := range manifest.Secrets {
				if ref.Vault != gruVault || ref.Name == "" {
					return nil, fmt.Errorf("service manifest %s has an unsupported secret reference", service.Name())
				}
				if _, exists := grants[ref.Name]; !exists {
					grants[ref.Name] = "read secret-bundles"
				}
			}
		}
		for _, secret := range slices.Sorted(maps.Keys(grants)) {
			key := grants[secret] + "|" + secret
			principals[key] = append(principals[key], "request.principal.compartment.id = '"+hosts[region]+"'")
		}
	}
	for _, key := range slices.Sorted(maps.Keys(principals)) {
		grant, secret, _ := strings.Cut(key, "|")
		scope := strings.Join(principals[key], ", ")
		if len(principals[key]) > 1 {
			scope = "any {" + scope + "}"
		}
		s = append(s, "Allow dynamic-group "+dynamicGroup+" to "+grant+" "+in+" where all {"+vault+", "+scope+", target.secret.name = '"+secret+"'}")
	}
	return s, nil
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
	want, err := statements(hosts)
	if err != nil {
		return err
	}
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
		return r.finishIAM("created", id, hosts)
	case slices.Equal(slices.Sorted(slices.Values(policies.Items[0].Statements)), slices.Sorted(slices.Values(want))):
		return r.finishIAM("unchanged", *policies.Items[0].Id, hosts)
	}
	if !r.dry {
		if _, err := r.home.UpdatePolicy(r.ctx, identity.UpdatePolicyRequest{PolicyId: policies.Items[0].Id,
			UpdatePolicyDetails: identity.UpdatePolicyDetails{Statements: want}}); err != nil {
			return err
		}
	}
	return r.finishIAM("updated", *policies.Items[0].Id, hosts)
}

func (r *run) finishIAM(verb, id string, hosts map[string]string) error {
	if err := r.report(verb, "policy", vaultPolicy, id); err != nil {
		return err
	}
	for _, name := range []string{"terrascale-gru-read-secrets", "terrascale-gru-netbird-secrets"} {
		policies, err := r.home.ListPolicies(r.ctx, identity.ListPoliciesRequest{CompartmentId: new(gruCompartment), Name: &name})
		if err != nil {
			return err
		}
		for _, policy := range policies.Items {
			groups, err := r.home.ListDynamicGroups(r.ctx, identity.ListDynamicGroupsRequest{CompartmentId: &r.tenancy, Name: new("terrascale-gru-instances")})
			if err != nil {
				return err
			}
			if len(groups.Items) != 1 || hosts["gru"] == "" {
				return errors.New("superseded credential policy has no matching host group")
			}
			group, err := r.home.GetDynamicGroup(r.ctx, identity.GetDynamicGroupRequest{DynamicGroupId: groups.Items[0].Id})
			if err != nil {
				return err
			}
			if !sameRule(strings.Replace(deref(group.MatchingRule), "ALL {", "ANY {", 1), []string{hosts["gru"]}) {
				return errors.New("superseded credential group differs from the scoped hosts")
			}
			for _, statement := range policy.Statements {
				if !strings.HasPrefix(statement, "Allow dynamic-group terrascale-gru-instances to ") {
					return fmt.Errorf("superseded policy %s contains another principal", name)
				}
			}
			if !r.dry {
				if _, err := r.home.DeletePolicy(r.ctx, identity.DeletePolicyRequest{PolicyId: policy.Id}); err != nil {
					return err
				}
			}
			if err := r.report("removed", "policy", name, *policy.Id); err != nil {
				return err
			}
		}
	}
	return nil
}
