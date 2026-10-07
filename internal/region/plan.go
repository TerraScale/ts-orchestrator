// Package region brings a new region up with one command (TS-663): it
// derives the region's plan from a reviewed plan of another region, runs
// every foundation, founding, edge and registration step in order with a
// resumable journal, and verifies that the region serves.
package region

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"strings"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/naming"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/networkplan"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociclient"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"github.com/oracle/oci-go-sdk/v65/core"
	"github.com/oracle/oci-go-sdk/v65/identity"
)

// Live is what a plan needs from the new OCI region itself: its first
// availability domain and its "All <key> Services" service gateway service.
type Live struct {
	AvailabilityDomain string
	ServiceID          string
	ServiceCIDR        string
}

// Lookup reads Live for an OCI region of the tenancy.
type Lookup func(ctx context.Context, tenancy, ociRegion string) (Live, error)

// Network is the initial /24 inside the cell's stable /16 reservation.
func Network(cell string) (string, error) {
	if !catalog.IsCell(cell) {
		return "", fmt.Errorf("cell %q is not in the region catalog", cell)
	}
	return networkplan.RegionNetwork(cell)
}

// Derive returns label's plan in ociRegion from a reviewed plan of another
// non-home region. The template's tenancy, shared compartments, Forgejo,
// origin-pull trust, host sizes and budget stay. Names, addresses, the
// region, its availability domain and its service gateway change, and
// every resource ID is unbound: ts-orch oci-region foundation binds them.
func Derive(template map[string]any, label, ociRegion string, live Live) (map[string]any, error) {
	entry, ok := catalog.LookupName(label)
	if !ok || entry.OCIRegion != ociRegion {
		return nil, fmt.Errorf("region %s in %s is not in the region catalog (internal/ociregion/catalog)", label, ociRegion)
	}
	if entry.Cell == catalog.Bootstrap {
		return nil, errors.New("the home region is founded by docs/region-bootstrap.md, not derived")
	}
	from, ok := catalog.Lookup(fmt.Sprint(template["cell"]))
	if !ok || from.Cell == entry.Cell || from.Cell == catalog.Bootstrap {
		return nil, errors.New("the template must be another non-home region's plan, such as deploy/oci-region/sfo-1-plan.json")
	}
	if template["operator_gateway"] != nil || template["netbird"] != nil {
		return nil, errors.New("the template declares the home region's operator gateway or NetBird routing")
	}
	sec, _ := template["network_security"].(map[string]any)
	fromNet, _ := template["network_cidr"].(string)
	fromLabel, _ := sec["service_gateway_cidr_block"].(string)
	if live.AvailabilityDomain == "" || live.ServiceID == "" || live.ServiceCIDR == "" || fromLabel == "" ||
		!strings.HasSuffix(fromNet, ".0.0/24") {
		return nil, errors.New("the template or the region lookup lacks the network, availability domain or service gateway")
	}
	toNet, err := Network(entry.Cell)
	if err != nil {
		return nil, err
	}
	fromCell, err := naming.RegionCell(from.Cell).Name()
	if err != nil {
		return nil, err
	}
	toCell, err := naming.RegionCell(entry.Cell).Name()
	if err != nil {
		return nil, err
	}
	// The template's own names and addresses carry these prefixes; OCIDs,
	// PEM blocks and shared names never do.
	replace := strings.NewReplacer(fromCell+"-", toCell+"-", "ts-"+from.Name()+"-", "ts-"+label+"-")
	fromPrefix, toPrefix := strings.TrimSuffix(fromNet, "0.0/24"), strings.TrimSuffix(toNet, "0.0/24")
	var rename func(v any) any
	rename = func(v any) any {
		switch v := v.(type) {
		case string:
			switch {
			case v == fromLabel:
				return live.ServiceCIDR
			case strings.HasPrefix(v, fromPrefix):
				return toPrefix + strings.TrimPrefix(v, fromPrefix)
			}
			return replace.Replace(v)
		case map[string]any:
			for k, x := range v {
				v[k] = rename(x)
			}
		case []any:
			for i, x := range v {
				v[i] = rename(x)
			}
		}
		return v
	}
	data, err := json.Marshal(template)
	if err != nil {
		return nil, err
	}
	var plan map[string]any
	if err := json.Unmarshal(data, &plan); err != nil {
		return nil, err
	}
	rename(plan)
	plan["cell"], plan["region"], plan["availability_domain"] = entry.Cell, ociRegion, live.AvailabilityDomain
	plan["purpose"] = toCell + " founding plan derived by ts-orch region plan from " + fromCell + "; ts-orch oci-region foundation binds the resource IDs"
	plan["network_security"].(map[string]any)["service_gateway_service_id"] = live.ServiceID
	var unbind func(v any) any
	unbind = func(v any) any {
		if m, ok := v.(map[string]any); ok {
			for k, x := range m {
				m[k] = unbind(x)
			}
			return m
		}
		return nil
	}
	plan["resource_ids"] = unbind(plan["resource_ids"])
	plan["host_credential_secret"] = unbind(plan["host_credential_secret"])
	plan["seed_a_create_identity"], plan["orchestrator_owner"], plan["bootstrap_object_prefix"] = nil, nil, ""
	return plan, nil
}

// LiveSDK reads Live with the operator's ~/.oci/config DEFAULT profile.
func LiveSDK(ctx context.Context, tenancy, ociRegion string) (Live, error) {
	factory, err := ociclient.OperatorConfig(ociRegion)
	if err != nil {
		return Live{}, err
	}
	ids, err := factory.Identity()
	if err != nil {
		return Live{}, err
	}
	ads, err := ids.ListAvailabilityDomains(ctx, identity.ListAvailabilityDomainsRequest{CompartmentId: &tenancy})
	if err != nil {
		return Live{}, fmt.Errorf("list %s availability domains: %w", ociRegion, err)
	}
	var live Live
	for _, ad := range ads.Items {
		if name := deref(ad.Name); live.AvailabilityDomain == "" || name < live.AvailabilityDomain {
			live.AvailabilityDomain = name
		}
	}
	network, err := factory.Network()
	if err != nil {
		return Live{}, err
	}
	services, err := network.ListServices(ctx, core.ListServicesRequest{})
	if err != nil {
		return Live{}, fmt.Errorf("list %s services: %w", ociRegion, err)
	}
	for _, service := range services.Items {
		if cidr := deref(service.CidrBlock); strings.HasPrefix(cidr, "all-") && strings.HasSuffix(cidr, "-services-in-oracle-services-network") {
			live.ServiceID, live.ServiceCIDR = deref(service.Id), cidr
		}
	}
	return live, nil
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
