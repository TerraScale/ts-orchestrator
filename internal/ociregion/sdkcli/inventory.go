package sdkcli

import (
	"context"
	"errors"
	"fmt"

	"github.com/oracle/oci-go-sdk/v65/core"
	"github.com/oracle/oci-go-sdk/v65/loadbalancer"
	"github.com/oracle/oci-go-sdk/v65/networkloadbalancer"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"
)

// The compartment-scoped lists inventory uses to price a region.
func init() {
	for path, h := range map[string]handler{
		"compute instance list": listIn(func(c *Client) (core.ComputeClient, error) { return c.compute() },
			func(ctx context.Context, client core.ComputeClient, compartment string, _ Command, page *string) ([]core.Instance, *string, error) {
				response, err := client.ListInstances(ctx, core.ListInstancesRequest{CompartmentId: &compartment, Page: page})
				return response.Items, response.OpcNextPage, err
			}),
		"bv volume list": listIn((*Client).blockstorage,
			func(ctx context.Context, client core.BlockstorageClient, compartment string, _ Command, page *string) ([]core.Volume, *string, error) {
				response, err := client.ListVolumes(ctx, core.ListVolumesRequest{CompartmentId: &compartment, Page: page})
				return response.Items, response.OpcNextPage, err
			}),
		"bv boot-volume list": listIn((*Client).blockstorage,
			func(ctx context.Context, client core.BlockstorageClient, compartment string, command Command, page *string) ([]core.BootVolume, *string, error) {
				response, err := client.ListBootVolumes(ctx, core.ListBootVolumesRequest{CompartmentId: &compartment,
					AvailabilityDomain: command.optional("availability-domain"), Page: page})
				return response.Items, response.OpcNextPage, err
			}),
		"bv backup list": listIn((*Client).blockstorage,
			func(ctx context.Context, client core.BlockstorageClient, compartment string, _ Command, page *string) ([]core.VolumeBackup, *string, error) {
				response, err := client.ListVolumeBackups(ctx, core.ListVolumeBackupsRequest{CompartmentId: &compartment, Page: page})
				return response.Items, response.OpcNextPage, err
			}),
		"bv boot-volume-backup list": listIn((*Client).blockstorage,
			func(ctx context.Context, client core.BlockstorageClient, compartment string, _ Command, page *string) ([]core.BootVolumeBackup, *string, error) {
				response, err := client.ListBootVolumeBackups(ctx, core.ListBootVolumeBackupsRequest{CompartmentId: &compartment, Page: page})
				return response.Items, response.OpcNextPage, err
			}),
		"network vcn list": listIn((*Client).network,
			func(ctx context.Context, client core.VirtualNetworkClient, compartment string, _ Command, page *string) ([]core.Vcn, *string, error) {
				response, err := client.ListVcns(ctx, core.ListVcnsRequest{CompartmentId: &compartment, Page: page})
				return response.Items, response.OpcNextPage, err
			}),
		"network subnet list": listIn((*Client).network,
			func(ctx context.Context, client core.VirtualNetworkClient, compartment string, command Command, page *string) ([]core.Subnet, *string, error) {
				response, err := client.ListSubnets(ctx, core.ListSubnetsRequest{CompartmentId: &compartment, VcnId: command.optional("vcn-id"), Page: page})
				return response.Items, response.OpcNextPage, err
			}),
		"network nsg list": listIn((*Client).network,
			func(ctx context.Context, client core.VirtualNetworkClient, compartment string, command Command, page *string) ([]core.NetworkSecurityGroup, *string, error) {
				response, err := client.ListNetworkSecurityGroups(ctx, core.ListNetworkSecurityGroupsRequest{CompartmentId: &compartment, VcnId: command.optional("vcn-id"), Page: page})
				return response.Items, response.OpcNextPage, err
			}),
		"network security-list list": listIn((*Client).network,
			func(ctx context.Context, client core.VirtualNetworkClient, compartment string, command Command, page *string) ([]core.SecurityList, *string, error) {
				response, err := client.ListSecurityLists(ctx, core.ListSecurityListsRequest{CompartmentId: &compartment, VcnId: command.optional("vcn-id"), Page: page})
				return response.Items, response.OpcNextPage, err
			}),
		"network route-table list": listIn((*Client).network,
			func(ctx context.Context, client core.VirtualNetworkClient, compartment string, command Command, page *string) ([]core.RouteTable, *string, error) {
				response, err := client.ListRouteTables(ctx, core.ListRouteTablesRequest{CompartmentId: &compartment, VcnId: command.optional("vcn-id"), Page: page})
				return response.Items, response.OpcNextPage, err
			}),
		"network service-gateway list": listIn((*Client).network,
			func(ctx context.Context, client core.VirtualNetworkClient, compartment string, command Command, page *string) ([]core.ServiceGateway, *string, error) {
				response, err := client.ListServiceGateways(ctx, core.ListServiceGatewaysRequest{CompartmentId: &compartment, VcnId: command.optional("vcn-id"), Page: page})
				return response.Items, response.OpcNextPage, err
			}),
		"network internet-gateway list": listIn((*Client).network,
			func(ctx context.Context, client core.VirtualNetworkClient, compartment string, command Command, page *string) ([]core.InternetGateway, *string, error) {
				response, err := client.ListInternetGateways(ctx, core.ListInternetGatewaysRequest{CompartmentId: &compartment, VcnId: command.optional("vcn-id"), Page: page})
				return response.Items, response.OpcNextPage, err
			}),
		"network local-peering-gateway list": listIn((*Client).network,
			func(ctx context.Context, client core.VirtualNetworkClient, compartment string, command Command, page *string) ([]core.LocalPeeringGateway, *string, error) {
				response, err := client.ListLocalPeeringGateways(ctx, core.ListLocalPeeringGatewaysRequest{CompartmentId: &compartment, VcnId: command.optional("vcn-id"), Page: page})
				return response.Items, response.OpcNextPage, err
			}),
		"network nat-gateway list": listIn((*Client).network,
			func(ctx context.Context, client core.VirtualNetworkClient, compartment string, command Command, page *string) ([]core.NatGateway, *string, error) {
				response, err := client.ListNatGateways(ctx, core.ListNatGatewaysRequest{CompartmentId: &compartment, VcnId: command.optional("vcn-id"), Page: page})
				return response.Items, response.OpcNextPage, err
			}),
		"network public-ip list": listIn((*Client).network,
			func(ctx context.Context, client core.VirtualNetworkClient, compartment string, command Command, page *string) ([]core.PublicIp, *string, error) {
				response, err := client.ListPublicIps(ctx, core.ListPublicIpsRequest{CompartmentId: &compartment,
					Scope: core.ListPublicIpsScopeEnum(command.value("scope")), Page: page})
				return response.Items, response.OpcNextPage, err
			}),
		"lb load-balancer list": listIn((*Client).loadBalancer,
			func(ctx context.Context, client loadbalancer.LoadBalancerClient, compartment string, _ Command, page *string) ([]loadbalancer.LoadBalancer, *string, error) {
				response, err := client.ListLoadBalancers(ctx, loadbalancer.ListLoadBalancersRequest{CompartmentId: &compartment, Page: page})
				return response.Items, response.OpcNextPage, err
			}),
		"nlb network-load-balancer list": nlbList,
		"os bucket list":                 osBucketList,
	} {
		handlers[path] = h
	}
}

// listIn adapts a compartment-scoped paginated list.
func listIn[S, T any](service func(*Client) (S, error),
	list func(context.Context, S, string, Command, *string) ([]T, *string, error),
) handler {
	return func(ctx context.Context, c *Client, command Command) (any, error) {
		compartment, err := command.flag("compartment-id")
		if err != nil {
			return nil, err
		}
		client, err := service(c)
		if err != nil {
			return nil, err
		}
		return pages(command.All, func(page *string) ([]T, *string, error) {
			return list(ctx, client, compartment, command, page)
		})
	}
}

func (c *Client) blockstorage() (core.BlockstorageClient, error) {
	client, err := c.factory.Blockstorage()
	c.pin(&client.BaseClient)
	return client, err
}

func (c *Client) loadBalancer() (loadbalancer.LoadBalancerClient, error) {
	client, err := c.factory.LoadBalancer()
	if err != nil {
		return client, err
	}
	c.pin(&client.BaseClient)
	return client, nil
}

// nlbList keeps the CLI's {"items": [...]} collection shape.
func nlbList(ctx context.Context, c *Client, command Command) (any, error) {
	compartment, err := command.flag("compartment-id")
	if err != nil {
		return nil, err
	}
	client, err := c.factory.NetworkLoadBalancer()
	if err != nil {
		return nil, err
	}
	c.pin(&client.BaseClient)
	items, err := pages(command.All, func(page *string) ([]networkloadbalancer.NetworkLoadBalancerSummary, *string, error) {
		response, err := client.ListNetworkLoadBalancers(ctx, networkloadbalancer.ListNetworkLoadBalancersRequest{
			CompartmentId: &compartment, Page: page})
		return response.Items, response.OpcNextPage, err
	})
	if err != nil {
		return nil, err
	}
	return map[string]any{"items": items}, nil
}

// osBucketList resolves the namespace as the CLI does when it is omitted.
func osBucketList(ctx context.Context, c *Client, command Command) (any, error) {
	compartment, err := command.flag("compartment-id")
	if err != nil {
		return nil, err
	}
	client, err := c.objects()
	if err != nil {
		return nil, err
	}
	namespace := command.value("namespace-name")
	if namespace == "" {
		response, err := client.GetNamespace(ctx, objectstorage.GetNamespaceRequest{})
		if err != nil {
			return nil, fmt.Errorf("resolve Object Storage namespace: %w", err)
		}
		if response.Value == nil {
			return nil, errors.New("OCI returned no Object Storage namespace")
		}
		namespace = *response.Value
	}
	return pages(command.All, func(page *string) ([]objectstorage.BucketSummary, *string, error) {
		response, err := client.ListBuckets(ctx, objectstorage.ListBucketsRequest{NamespaceName: &namespace,
			CompartmentId: &compartment, Page: page})
		return response.Items, response.OpcNextPage, err
	})
}
