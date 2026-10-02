package sdkcli

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/core"
	"github.com/oracle/oci-go-sdk/v65/identity"
	"github.com/oracle/oci-go-sdk/v65/keymanagement"
	"github.com/oracle/oci-go-sdk/v65/networkloadbalancer"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"
	"github.com/oracle/oci-go-sdk/v65/vault"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociclient"
)

type handler func(context.Context, *Client, Command) (any, error)

// handlers maps a CLI command path to its SDK implementation. Every entry is
// a read; this package never mutates OCI.
var handlers = map[string]handler{
	"iam compartment get":                           iamCompartmentGet,
	"iam compartment list":                          iamCompartmentList,
	"iam policy get":                                iamPolicyGet,
	"iam dynamic-group get":                         iamDynamicGroupGet,
	"iam region-subscription list":                  iamRegionSubscriptionList,
	"iam availability-domain list":                  iamAvailabilityDomainList,
	"network vcn get":                               networkVcnGet,
	"network subnet get":                            networkSubnetGet,
	"network nsg get":                               networkNsgGet,
	"network nsg rules list":                        networkNsgRulesList,
	"network security-list get":                     networkSecurityListGet,
	"network route-table get":                       networkRouteTableGet,
	"network service-gateway get":                   networkServiceGatewayGet,
	"network internet-gateway get":                  networkInternetGatewayGet,
	"network local-peering-gateway get":             networkLocalPeeringGatewayGet,
	"network drg get":                               networkDrgGet,
	"network drg-attachment get":                    networkDrgAttachmentGet,
	"network drg-attachment list":                   networkDrgAttachmentList,
	"network drg-route-distribution get":            networkDrgRouteDistributionGet,
	"network drg-route-distribution-statement list": networkDrgRouteDistributionStatementList,
	"network drg-route-rule list":                   networkDrgRouteRuleList,
	"network remote-peering-connection get":         networkRemotePeeringConnectionGet,
	"compute instance list-vnics":                   computeInstanceListVnics,
	"compute image list":                            computeImageList,
	"nlb network-load-balancer get":                 nlbGet,
	"vault secret get":                              vaultSecretGet,
	"kms management vault get":                      kmsVaultGet,
	"kms management key get":                        kmsKeyGet,
	"os ns get":                                     osNamespaceGet,
	"os bucket get":                                 osBucketGet,
	"os retention-rule list":                        osRetentionRuleList,
	"os object list":                                osObjectList,
	"os object list-object-versions":                osObjectVersionList,
	"os object head":                                osObjectHead,
}

func (c *Client) compute() (core.ComputeClient, error) {
	client, err := c.factory.Compute()
	c.pin(&client.BaseClient)
	return client, err
}

func (c *Client) network() (core.VirtualNetworkClient, error) {
	client, err := c.factory.Network()
	c.pin(&client.BaseClient)
	return client, err
}

func (c *Client) objects() (objectstorage.ObjectStorageClient, error) {
	client, err := c.factory.ObjectStorage()
	c.pin(&client.BaseClient)
	return client, err
}

func (c *Client) identity() (identity.IdentityClient, error) {
	client, err := identity.NewIdentityClientWithConfigurationProvider(c.factory.Provider())
	if err != nil {
		return client, fmt.Errorf("create OCI identity client: %w", err)
	}
	client.SetRegion(c.factory.Region())
	c.factory.Configure(&client.BaseClient, ociclient.ServiceIdentity)
	c.pin(&client.BaseClient)
	return client, nil
}

func iamCompartmentGet(ctx context.Context, c *Client, command Command) (any, error) {
	id, err := command.flag("compartment-id")
	if err != nil {
		return nil, err
	}
	client, err := c.identity()
	if err != nil {
		return nil, err
	}
	response, err := client.GetCompartment(ctx, identity.GetCompartmentRequest{CompartmentId: &id})
	return response.Compartment, err
}

func iamCompartmentList(ctx context.Context, c *Client, command Command) (any, error) {
	id, err := command.flag("compartment-id")
	if err != nil {
		return nil, err
	}
	client, err := c.identity()
	if err != nil {
		return nil, err
	}
	return pages(command.All, func(page *string) ([]identity.Compartment, *string, error) {
		response, err := client.ListCompartments(ctx, identity.ListCompartmentsRequest{CompartmentId: &id, Page: page})
		return response.Items, response.OpcNextPage, err
	})
}

func iamPolicyGet(ctx context.Context, c *Client, command Command) (any, error) {
	id, err := command.flag("policy-id")
	if err != nil {
		return nil, err
	}
	client, err := c.identity()
	if err != nil {
		return nil, err
	}
	response, err := client.GetPolicy(ctx, identity.GetPolicyRequest{PolicyId: &id})
	return response.Policy, err
}

func iamDynamicGroupGet(ctx context.Context, c *Client, command Command) (any, error) {
	id, err := command.flag("dynamic-group-id")
	if err != nil {
		return nil, err
	}
	client, err := c.identity()
	if err != nil {
		return nil, err
	}
	response, err := client.GetDynamicGroup(ctx, identity.GetDynamicGroupRequest{DynamicGroupId: &id})
	return response.DynamicGroup, err
}

func iamRegionSubscriptionList(ctx context.Context, c *Client, command Command) (any, error) {
	id, err := command.flag("tenancy-id")
	if err != nil {
		return nil, err
	}
	client, err := c.identity()
	if err != nil {
		return nil, err
	}
	response, err := client.ListRegionSubscriptions(ctx, identity.ListRegionSubscriptionsRequest{TenancyId: &id})
	if response.Items == nil {
		response.Items = []identity.RegionSubscription{}
	}
	return response.Items, err
}

func iamAvailabilityDomainList(ctx context.Context, c *Client, command Command) (any, error) {
	id, err := command.flag("compartment-id")
	if err != nil {
		return nil, err
	}
	client, err := c.identity()
	if err != nil {
		return nil, err
	}
	response, err := client.ListAvailabilityDomains(ctx, identity.ListAvailabilityDomainsRequest{CompartmentId: &id})
	if response.Items == nil {
		response.Items = []identity.AvailabilityDomain{}
	}
	return response.Items, err
}

// get wraps a single-ID network read.
func networkGet[T any](flag string, read func(context.Context, core.VirtualNetworkClient, string) (T, error)) handler {
	return func(ctx context.Context, c *Client, command Command) (any, error) {
		id, err := command.flag(flag)
		if err != nil {
			return nil, err
		}
		client, err := c.network()
		if err != nil {
			return nil, err
		}
		return read(ctx, client, id)
	}
}

var (
	networkVcnGet = networkGet("vcn-id", func(ctx context.Context, client core.VirtualNetworkClient, id string) (core.Vcn, error) {
		response, err := client.GetVcn(ctx, core.GetVcnRequest{VcnId: &id})
		return response.Vcn, err
	})
	networkSubnetGet = networkGet("subnet-id", func(ctx context.Context, client core.VirtualNetworkClient, id string) (core.Subnet, error) {
		response, err := client.GetSubnet(ctx, core.GetSubnetRequest{SubnetId: &id})
		return response.Subnet, err
	})
	networkNsgGet = networkGet("nsg-id", func(ctx context.Context, client core.VirtualNetworkClient, id string) (core.NetworkSecurityGroup, error) {
		response, err := client.GetNetworkSecurityGroup(ctx, core.GetNetworkSecurityGroupRequest{NetworkSecurityGroupId: &id})
		return response.NetworkSecurityGroup, err
	})
	networkSecurityListGet = networkGet("security-list-id", func(ctx context.Context, client core.VirtualNetworkClient, id string) (core.SecurityList, error) {
		response, err := client.GetSecurityList(ctx, core.GetSecurityListRequest{SecurityListId: &id})
		return response.SecurityList, err
	})
	networkRouteTableGet = networkGet("rt-id", func(ctx context.Context, client core.VirtualNetworkClient, id string) (core.RouteTable, error) {
		response, err := client.GetRouteTable(ctx, core.GetRouteTableRequest{RtId: &id})
		return response.RouteTable, err
	})
	networkServiceGatewayGet = networkGet("service-gateway-id", func(ctx context.Context, client core.VirtualNetworkClient, id string) (core.ServiceGateway, error) {
		response, err := client.GetServiceGateway(ctx, core.GetServiceGatewayRequest{ServiceGatewayId: &id})
		return response.ServiceGateway, err
	})
	networkInternetGatewayGet = networkGet("ig-id", func(ctx context.Context, client core.VirtualNetworkClient, id string) (core.InternetGateway, error) {
		response, err := client.GetInternetGateway(ctx, core.GetInternetGatewayRequest{IgId: &id})
		return response.InternetGateway, err
	})
	networkLocalPeeringGatewayGet = networkGet("local-peering-gateway-id", func(ctx context.Context, client core.VirtualNetworkClient, id string) (core.LocalPeeringGateway, error) {
		response, err := client.GetLocalPeeringGateway(ctx, core.GetLocalPeeringGatewayRequest{LocalPeeringGatewayId: &id})
		return response.LocalPeeringGateway, err
	})
	networkDrgGet = networkGet("drg-id", func(ctx context.Context, client core.VirtualNetworkClient, id string) (core.Drg, error) {
		response, err := client.GetDrg(ctx, core.GetDrgRequest{DrgId: &id})
		return response.Drg, err
	})
	networkDrgAttachmentGet = networkGet("drg-attachment-id", func(ctx context.Context, client core.VirtualNetworkClient, id string) (core.DrgAttachment, error) {
		response, err := client.GetDrgAttachment(ctx, core.GetDrgAttachmentRequest{DrgAttachmentId: &id})
		return response.DrgAttachment, err
	})
	networkDrgRouteDistributionGet = networkGet("route-distribution-id", func(ctx context.Context, client core.VirtualNetworkClient, id string) (core.DrgRouteDistribution, error) {
		response, err := client.GetDrgRouteDistribution(ctx, core.GetDrgRouteDistributionRequest{DrgRouteDistributionId: &id})
		return response.DrgRouteDistribution, err
	})
	networkRemotePeeringConnectionGet = networkGet("remote-peering-connection-id", func(ctx context.Context, client core.VirtualNetworkClient, id string) (core.RemotePeeringConnection, error) {
		response, err := client.GetRemotePeeringConnection(ctx, core.GetRemotePeeringConnectionRequest{RemotePeeringConnectionId: &id})
		return response.RemotePeeringConnection, err
	})
)

func networkNsgRulesList(ctx context.Context, c *Client, command Command) (any, error) {
	id, err := command.flag("nsg-id")
	if err != nil {
		return nil, err
	}
	client, err := c.network()
	if err != nil {
		return nil, err
	}
	// The CLI pages this list even without --all.
	return pages(true, func(page *string) ([]core.SecurityRule, *string, error) {
		response, err := client.ListNetworkSecurityGroupSecurityRules(ctx, core.ListNetworkSecurityGroupSecurityRulesRequest{
			NetworkSecurityGroupId: &id, Page: page})
		return response.Items, response.OpcNextPage, err
	})
}

func networkDrgAttachmentList(ctx context.Context, c *Client, command Command) (any, error) {
	compartment, err := command.flag("compartment-id")
	if err != nil {
		return nil, err
	}
	client, err := c.network()
	if err != nil {
		return nil, err
	}
	request := core.ListDrgAttachmentsRequest{CompartmentId: &compartment, DrgId: command.optional("drg-id")}
	if kind := command.value("attachment-type"); kind != "" {
		request.AttachmentType = core.ListDrgAttachmentsAttachmentTypeEnum(kind)
	}
	return pages(command.All, func(page *string) ([]core.DrgAttachment, *string, error) {
		request.Page = page
		response, err := client.ListDrgAttachments(ctx, request)
		return response.Items, response.OpcNextPage, err
	})
}

func networkDrgRouteDistributionStatementList(ctx context.Context, c *Client, command Command) (any, error) {
	id, err := command.flag("route-distribution-id")
	if err != nil {
		return nil, err
	}
	client, err := c.network()
	if err != nil {
		return nil, err
	}
	return pages(command.All, func(page *string) ([]core.DrgRouteDistributionStatement, *string, error) {
		response, err := client.ListDrgRouteDistributionStatements(ctx, core.ListDrgRouteDistributionStatementsRequest{
			DrgRouteDistributionId: &id, Page: page})
		return response.Items, response.OpcNextPage, err
	})
}

func networkDrgRouteRuleList(ctx context.Context, c *Client, command Command) (any, error) {
	id, err := command.flag("drg-route-table-id")
	if err != nil {
		return nil, err
	}
	client, err := c.network()
	if err != nil {
		return nil, err
	}
	return pages(command.All, func(page *string) ([]core.DrgRouteRule, *string, error) {
		response, err := client.ListDrgRouteRules(ctx, core.ListDrgRouteRulesRequest{DrgRouteTableId: &id, Page: page})
		return response.Items, response.OpcNextPage, err
	})
}

func computeInstanceListVnics(ctx context.Context, c *Client, command Command) (any, error) {
	instance, err := command.flag("instance-id")
	if err != nil {
		return nil, err
	}
	compartment, err := command.flag("compartment-id")
	if err != nil {
		return nil, err
	}
	compute, err := c.compute()
	if err != nil {
		return nil, err
	}
	network, err := c.network()
	if err != nil {
		return nil, err
	}
	attachments, err := pages(command.All, func(page *string) ([]core.VnicAttachment, *string, error) {
		response, err := compute.ListVnicAttachments(ctx, core.ListVnicAttachmentsRequest{CompartmentId: &compartment,
			InstanceId: &instance, Page: page})
		return response.Items, response.OpcNextPage, err
	})
	if err != nil {
		return nil, err
	}
	// The CLI's list-vnics resolves each attached VNIC.
	vnics := []core.Vnic{}
	for _, attachment := range attachments {
		if attachment.LifecycleState != core.VnicAttachmentLifecycleStateAttached || attachment.VnicId == nil {
			continue
		}
		response, err := network.GetVnic(ctx, core.GetVnicRequest{VnicId: attachment.VnicId})
		if err != nil {
			return nil, err
		}
		vnics = append(vnics, response.Vnic)
	}
	return vnics, nil
}

func computeImageList(ctx context.Context, c *Client, command Command) (any, error) {
	compartment, err := command.flag("compartment-id")
	if err != nil {
		return nil, err
	}
	client, err := c.compute()
	if err != nil {
		return nil, err
	}
	return pages(command.All, func(page *string) ([]core.Image, *string, error) {
		response, err := client.ListImages(ctx, core.ListImagesRequest{CompartmentId: &compartment,
			DisplayName: command.optional("display-name"), Page: page})
		return response.Items, response.OpcNextPage, err
	})
}

func nlbGet(ctx context.Context, c *Client, command Command) (any, error) {
	id, err := command.flag("network-load-balancer-id")
	if err != nil {
		return nil, err
	}
	client, err := c.factory.NetworkLoadBalancer()
	if err != nil {
		return nil, err
	}
	c.pin(&client.BaseClient)
	response, err := client.GetNetworkLoadBalancer(ctx, networkloadbalancer.GetNetworkLoadBalancerRequest{NetworkLoadBalancerId: &id})
	return response.NetworkLoadBalancer, err
}

func vaultSecretGet(ctx context.Context, c *Client, command Command) (any, error) {
	id, err := command.flag("secret-id")
	if err != nil {
		return nil, err
	}
	client, err := vault.NewVaultsClientWithConfigurationProvider(c.factory.Provider())
	if err != nil {
		return nil, fmt.Errorf("create OCI vaults client: %w", err)
	}
	client.SetRegion(c.factory.Region())
	c.factory.Configure(&client.BaseClient, ociclient.ServiceKMS)
	c.pin(&client.BaseClient)
	response, err := client.GetSecret(ctx, vault.GetSecretRequest{SecretId: &id})
	return response.Secret, err
}

func kmsVaultGet(ctx context.Context, c *Client, command Command) (any, error) {
	id, err := command.flag("vault-id")
	if err != nil {
		return nil, err
	}
	client, err := keymanagement.NewKmsVaultClientWithConfigurationProvider(c.factory.Provider())
	if err != nil {
		return nil, fmt.Errorf("create OCI KMS vault client: %w", err)
	}
	client.SetRegion(c.factory.Region())
	c.factory.Configure(&client.BaseClient, ociclient.ServiceKMS)
	c.pin(&client.BaseClient)
	response, err := client.GetVault(ctx, keymanagement.GetVaultRequest{VaultId: &id})
	return response.Vault, err
}

func kmsKeyGet(ctx context.Context, c *Client, command Command) (any, error) {
	id, err := command.flag("key-id")
	if err != nil {
		return nil, err
	}
	endpoint, err := command.flag("endpoint")
	if err != nil {
		return nil, err
	}
	if !kmsEndpointInRegion(endpoint, c.factory.Region()) {
		return nil, fmt.Errorf("KMS management endpoint %q is outside region %s", endpoint, c.factory.Region())
	}
	client, err := keymanagement.NewKmsManagementClientWithConfigurationProvider(c.factory.Provider(), endpoint)
	if err != nil {
		return nil, fmt.Errorf("create OCI KMS management client: %w", err)
	}
	c.factory.Configure(&client.BaseClient, ociclient.ServiceKMS)
	c.pin(&client.BaseClient)
	response, err := client.GetKey(ctx, keymanagement.GetKeyRequest{KeyId: &id})
	return response.Key, err
}

// kmsEndpointInRegion accepts only a bare https origin on the OCI KMS
// management domain of region, so signed requests never leave it.
func kmsEndpointInRegion(endpoint, region string) bool {
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Scheme != "https" || parsed.User != nil || parsed.Port() != "" ||
		(parsed.Path != "" && parsed.Path != "/") || parsed.RawQuery != "" || parsed.Fragment != "" {
		return false
	}
	host := parsed.Hostname()
	prefix, ok := strings.CutSuffix(host, ".kms."+region+".oraclecloud.com")
	return ok && prefix != "" && !strings.Contains(prefix, ".")
}

func osNamespaceGet(ctx context.Context, c *Client, _ Command) (any, error) {
	client, err := c.objects()
	if err != nil {
		return nil, err
	}
	response, err := client.GetNamespace(ctx, objectstorage.GetNamespaceRequest{})
	if err != nil {
		return nil, err
	}
	if response.Value == nil {
		return nil, fmt.Errorf("OCI returned no Object Storage namespace")
	}
	return *response.Value, nil
}

func bucketFlags(command Command) (string, string, error) {
	namespace, err := command.flag("namespace-name")
	if err != nil {
		return "", "", err
	}
	bucket, err := command.flag("bucket-name")
	return namespace, bucket, err
}

func osBucketGet(ctx context.Context, c *Client, command Command) (any, error) {
	namespace, bucket, err := bucketFlags(command)
	if err != nil {
		return nil, err
	}
	client, err := c.objects()
	if err != nil {
		return nil, err
	}
	response, err := client.GetBucket(ctx, objectstorage.GetBucketRequest{NamespaceName: &namespace, BucketName: &bucket})
	return response.Bucket, err
}

func osRetentionRuleList(ctx context.Context, c *Client, command Command) (any, error) {
	namespace, bucket, err := bucketFlags(command)
	if err != nil {
		return nil, err
	}
	client, err := c.objects()
	if err != nil {
		return nil, err
	}
	return pages(command.All, func(page *string) ([]objectstorage.RetentionRuleSummary, *string, error) {
		response, err := client.ListRetentionRules(ctx, objectstorage.ListRetentionRulesRequest{NamespaceName: &namespace,
			BucketName: &bucket, Page: page})
		return response.Items, response.OpcNextPage, err
	})
}

func osObjectList(ctx context.Context, c *Client, command Command) (any, error) {
	namespace, bucket, err := bucketFlags(command)
	if err != nil {
		return nil, err
	}
	client, err := c.objects()
	if err != nil {
		return nil, err
	}
	return pages(command.All, func(start *string) ([]objectstorage.ObjectSummary, *string, error) {
		response, err := client.ListObjects(ctx, objectstorage.ListObjectsRequest{NamespaceName: &namespace,
			BucketName: &bucket, Fields: command.optional("fields"), Start: start})
		return response.Objects, response.NextStartWith, err
	})
}

func osObjectVersionList(ctx context.Context, c *Client, command Command) (any, error) {
	namespace, bucket, err := bucketFlags(command)
	if err != nil {
		return nil, err
	}
	client, err := c.objects()
	if err != nil {
		return nil, err
	}
	// The SDK types ListObjectVersions fields as a single enum value and
	// rejects the comma-separated list the CLI and the API accept, so the
	// list is set on the query before the request is signed.
	if fields := command.value("fields"); fields != "" {
		setQuery(&client.BaseClient, "fields", fields)
	}
	return pages(command.All, func(page *string) ([]objectstorage.ObjectVersionSummary, *string, error) {
		response, err := client.ListObjectVersions(ctx, objectstorage.ListObjectVersionsRequest{NamespaceName: &namespace,
			BucketName: &bucket, Page: page})
		return response.Items, response.OpcNextPage, err
	})
}

// setQuery sets one query parameter on every request the client sends. The
// SDK runs the interceptor before signing, so the parameter is signed.
func setQuery(client *common.BaseClient, name, value string) {
	previous := client.Interceptor
	client.Interceptor = func(request *http.Request) error {
		if previous != nil {
			if err := previous(request); err != nil {
				return err
			}
		}
		query := request.URL.Query()
		query.Set(name, value)
		request.URL.RawQuery = query.Encode()
		return nil
	}
}

// osObjectHead returns the CLI's object head document: the lower-cased
// response headers, which contain no capitals for Render to rewrite.
func osObjectHead(ctx context.Context, c *Client, command Command) (any, error) {
	namespace, bucket, err := bucketFlags(command)
	if err != nil {
		return nil, err
	}
	name, err := command.flag("name")
	if err != nil {
		return nil, err
	}
	client, err := c.objects()
	if err != nil {
		return nil, err
	}
	response, err := client.HeadObject(ctx, objectstorage.HeadObjectRequest{NamespaceName: &namespace, BucketName: &bucket, ObjectName: &name})
	if err != nil {
		if serviceErr, ok := common.IsServiceError(err); ok && serviceErr.GetHTTPStatusCode() == http.StatusNotFound {
			return nil, fmt.Errorf("object %s does not exist", name)
		}
		return nil, err
	}
	headers := map[string]any{}
	if response.RawResponse != nil {
		for key, values := range response.RawResponse.Header {
			if len(values) > 0 {
				headers[strings.ToLower(key)] = values[0]
			}
		}
	}
	return headers, nil
}
