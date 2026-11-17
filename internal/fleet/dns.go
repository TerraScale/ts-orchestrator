package fleet

import (
	"context"
	"errors"
	"fmt"

	"github.com/TerraScale/ts-orchestrator/internal/ociresource"

	"github.com/TerraScale/ts-orchestrator/internal/edge/geodns"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/core"
)

var errDNSNLB = errors.New("missing owned NLB address")

func dnsConfig(ctx context.Context, fleet Fleet, f *ociclient.Factory) (geodns.Config, error) {
	home, _ := fleet.DNSRegion()
	entry, _ := catalog.LookupName(home.Label)
	cfg := geodns.Config{Zone: fleet.DNS.Zone, CompartmentID: fleet.DNS.CompartmentID,
		Cell: entry.Cell, Owner: Owner, HealthPath: fleet.DNS.HealthCheckPath, Names: fleet.DNS.SteeredNames, TTL: fleet.DNS.SteeringTTLSeconds}
	for _, region := range fleet.Regions {
		rf, err := f.ForRegion(region.OCIRegion)
		if err != nil {
			return cfg, err
		}
		network, err := rf.Network()
		if err != nil {
			return cfg, err
		}
		addresses, err := list("reserved address", func(page *string) ([]core.PublicIp, *string, error) {
			r, err := network.ListPublicIps(ctx, core.ListPublicIpsRequest{CompartmentId: common.String(region.CompartmentID), Scope: core.ListPublicIpsScopeRegion, Lifetime: core.ListPublicIpsLifetimeReserved, Page: page})
			return r.Items, r.OpcNextPage, err
		})
		if err != nil {
			return cfg, err
		}
		var owned []core.PublicIp
		for _, address := range addresses {
			if !gone(string(address.LifecycleState)) && region.owns("public-ip", "nlb", address.FreeformTags) {
				owned = append(owned, address)
			}
		}
		if len(owned) != 1 || deref(owned[0].IpAddress) == "" {
			return cfg, fmt.Errorf("%w: %s requires exactly one owned %s reserved address; found %d", errDNSNLB, region.Label, region.Key("public-ip", "nlb"), len(owned))
		}
		entry, _ := catalog.LookupName(region.Label)
		cfg.Regions = append(cfg.Regions, geodns.Region{Label: region.Label, IP: deref(owned[0].IpAddress), APIName: region.APIName(fleet.DNS.Zone), Continents: region.GeoContinents, Latitude: entry.Latitude, Longitude: entry.Longitude})
	}
	return cfg, nil
}

func applyDNS(ctx context.Context, fleet Fleet, region Region, f *ociclient.Factory, _ Cluster, out ociresource.Out) error {
	home, _ := fleet.DNSRegion()
	if region.Label != home.Label {
		return fmt.Errorf("global dns pass belongs to %s, the fleet DNS compartment", home.Label)
	}
	cfg, err := dnsConfig(ctx, fleet, f)
	if err != nil {
		return err
	}
	client, err := geodns.New(f)
	if err != nil {
		return err
	}
	changes, err := client.Reconcile(ctx, cfg, out.Apply, func(change geodns.Change) error {
		_, err := fmt.Fprintf(out.Changed, "%s dns: %s %s %s\n", region.Label, change.Action, change.Kind, change.Name)
		return err
	})
	for _, change := range changes {
		if change.Action == "ok" {
			if _, writeErr := fmt.Fprintf(out.Same, "%s dns: ok %s %s %s\n", region.Label, change.Kind, change.Name, change.ID); writeErr != nil {
				return writeErr
			}
		}
	}
	return err
}
