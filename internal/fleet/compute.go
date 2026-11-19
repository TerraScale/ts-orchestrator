package fleet

import (
	"context"
	"encoding/base64"
	"fmt"
	"slices"
	"strings"

	m1 "github.com/TerraScale/ts-orchestrator/deploy/m1"
	"github.com/TerraScale/ts-orchestrator/internal/nodeinit"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/ociresource"
	"github.com/TerraScale/ts-orchestrator/internal/ociresource/compute"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/core"
	"github.com/oracle/oci-go-sdk/v65/identity"
)

const nodeNSG = "node-nsg"

func ApplyCompute(ctx context.Context, _ Fleet, region Region, f *ociclient.Factory, _ Cluster, out ociresource.Out) error {
	var err error
	clients := compute.Clients{}
	if clients.Compute, err = f.Compute(); err != nil {
		return err
	}
	if clients.Management, err = f.ComputeManagement(); err != nil {
		return err
	}
	if clients.Storage, err = f.Blockstorage(); err != nil {
		return err
	}
	network, err := f.Network()
	if err != nil {
		return err
	}
	ids, err := f.Identity()
	if err != nil {
		return err
	}
	compartment := common.String(region.CompartmentID)
	ownership := ociresource.Ownership{Owner: Owner}
	owned := func(kind, name string, tags map[string]string) bool {
		return ownership.Owns(region.Key(kind, name), ociresource.Tags{Freeform: tags})
	}
	subnets, err := list("subnet", func(page *string) ([]core.Subnet, *string, error) {
		r, err := network.ListSubnets(ctx, core.ListSubnetsRequest{CompartmentId: compartment, Page: page})
		return r.Items, r.OpcNextPage, err
	})
	if err != nil {
		return err
	}
	subnet := slices.IndexFunc(subnets, func(s core.Subnet) bool {
		return s.LifecycleState == core.SubnetLifecycleStateAvailable && owned("subnet", "private-subnet", s.FreeformTags) &&
			deref(s.CidrBlock) == region.PrivateSubnetCIDR && s.ProhibitPublicIpOnVnic != nil && *s.ProhibitPublicIpOnVnic
	})
	nsgs, err := list("nsg", func(page *string) ([]core.NetworkSecurityGroup, *string, error) {
		r, err := network.ListNetworkSecurityGroups(ctx, core.ListNetworkSecurityGroupsRequest{CompartmentId: compartment, Page: page})
		return r.Items, r.OpcNextPage, err
	})
	if err != nil {
		return err
	}
	nsg := slices.IndexFunc(nsgs, func(g core.NetworkSecurityGroup) bool {
		return g.LifecycleState == core.NetworkSecurityGroupLifecycleStateAvailable && owned("nsg", nodeNSG, g.FreeformTags)
	})
	if subnet < 0 || nsg < 0 {
		return fmt.Errorf("%s has no document-made private subnet %s or NSG %s; run ts-orch region apply %s network first",
			region.Label, region.Key("subnet", "private-subnet"), region.Key("nsg", nodeNSG), region.Label)
	}
	external, err := VerifyExternal(ctx, region, clients.Compute, clients.Management, network, deref(subnets[subnet].VcnId))
	if err != nil {
		return fmt.Errorf("refusing compute minimum %d: %w", region.Nodes.Min, err)
	}
	domains, err := ids.ListAvailabilityDomains(ctx, identity.ListAvailabilityDomainsRequest{CompartmentId: compartment})
	if err != nil {
		return fmt.Errorf("list availability domains: %w", err)
	}
	var places []compute.Place
	for _, domain := range domains.Items {
		faults, err := ids.ListFaultDomains(ctx, identity.ListFaultDomainsRequest{CompartmentId: compartment, AvailabilityDomain: domain.Name})
		if err != nil {
			return fmt.Errorf("list fault domains: %w", err)
		}
		place := compute.Place{AvailabilityDomain: deref(domain.Name)}
		for _, fault := range faults.Items {
			place.FaultDomains = append(place.FaultDomains, deref(fault.Name))
		}
		places = append(places, place)
	}
	nodes := region.Nodes
	return compute.Pass{Clients: clients, Ownership: ownership, Out: out, Nodes: compute.Nodes{
		Label: region.Label, Compartment: region.CompartmentID, Shape: nodes.Shape, OCPUs: nodes.OCPUs, MemoryGB: nodes.MemoryGB,
		BootGB: nodes.BootGB, DataGB: nodes.DataGB, DataVPUsPerGB: nodes.DataVPUsPerGB, Min: nodes.Min, Max: nodes.Max, External: external,
		SubnetID: deref(subnets[subnet].Id), NSGID: deref(nsgs[nsg].Id), Places: places, Key: region.Key,
		Launch: func(ctx context.Context) (compute.Launch, error) { return launch(ctx, clients.Compute, region) },
	}}.Run(ctx)
}

func launch(ctx context.Context, client core.ComputeClient, region Region) (compute.Launch, error) {
	arch := nodeinit.ShapeArch(region.Nodes.Shape)
	image := map[string]string{"amd64": "x86_64", "arm64": "aarch64"}[arch]
	release, err := newestNodeRelease(ctx)
	if err != nil {
		return compute.Launch{}, err
	}
	if err := release.knows(region); err != nil {
		return compute.Launch{}, fmt.Errorf("%w; refusing to launch %s nodes on it", err, region.Label)
	}
	binary, ok := release.attested.Binaries[arch]
	if !ok {
		return compute.Launch{}, fmt.Errorf("attested release %s has no %s binary", release.attested.Tag(), arch)
	}
	pinned, prebuilt, err := nodeinit.PinnedHostImage(region.Label, arch)
	if err != nil {
		return compute.Launch{}, err
	}
	if prebuilt {
		metadata, err := nodeinit.HostMetadata(binary.URL, binary.SHA256)
		return compute.Launch{ImageID: pinned.ImageID, Metadata: metadata}, err
	}
	images, err := client.ListImages(ctx, core.ListImagesRequest{CompartmentId: common.String(region.CompartmentID),
		OperatingSystem: common.String("Canonical Ubuntu"), OperatingSystemVersion: common.String("24.04"), Shape: common.String(region.Nodes.Shape),
		SortBy: core.ListImagesSortByTimecreated, SortOrder: core.ListImagesSortOrderDesc})
	if err != nil {
		return compute.Launch{}, fmt.Errorf("list images: %w", err)
	}
	chosen := slices.IndexFunc(images.Items, func(i core.Image) bool {
		name := deref(i.DisplayName)
		return strings.Contains(name, image) == (arch == "arm64") && !strings.Contains(name, "Minimal")
	})
	if chosen < 0 {
		return compute.Launch{}, fmt.Errorf("no Canonical Ubuntu 24.04 %s image for %s", arch, region.Nodes.Shape)
	}
	script, err := nodeinit.PoolCloudInit(m1.Files, binary.URL, binary.SHA256)
	if err != nil {
		return compute.Launch{}, err
	}
	return compute.Launch{ImageID: deref(images.Items[chosen].Id), Metadata: map[string]string{"user_data": base64.StdEncoding.EncodeToString([]byte(script))}}, nil
}
