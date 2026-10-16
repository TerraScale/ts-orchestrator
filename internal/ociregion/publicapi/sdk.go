package publicapi

import (
	"cmp"
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/oracle/oci-go-sdk/v65/core"
	"github.com/oracle/oci-go-sdk/v65/loadbalancer"
	"github.com/oracle/oci-go-sdk/v65/secrets"
	"github.com/oracle/oci-go-sdk/v65/vault"

	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/command"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/sdkcli"
)

// SDKClient serves the provisioner's commands through the OCI Go SDK inside
// the binary: reads through sdkcli, and the handful of creates the public API
// path needs here. Unsupported commands fail before any subprocess can run.
type SDKClient struct {
	Region   string
	reader   *sdkcli.Client
	creators map[string]creator
	// Pause is injectable so state waits run without sleeping in tests.
	Pause func(context.Context, time.Duration) error
}

type creator func(context.Context, *SDKClient, sdkcli.Command) (any, error)

// NewSDKClient builds the client for one catalog OCI region.
func NewSDKClient(region string) (*SDKClient, error) {
	reader, err := sdkcli.ForRegion(region)
	if err != nil {
		return nil, err
	}
	return &SDKClient{Region: region, reader: reader, creators: creators}, nil
}

// NewClientWithFactory shares the caller's authenticated OCI provider and rate limits.
func NewClientWithFactory(factory *ociclient.Factory) *SDKClient {
	return &SDKClient{Region: factory.Region(), reader: sdkcli.NewClient(factory, ""), creators: creators}
}

var creators = map[string]creator{
	"network internet-gateway create": createInternetGateway,
	"network route-table create":      createRouteTable,
	"network security-list create":    createSecurityList,
	"network subnet create":           createSubnet,
	"network nsg create":              createNSG,
	"network nsg rules add":           addNSGRules,
	"network nsg rules remove":        removeNSGRules,
	"lb load-balancer create":         createLoadBalancer,
	"lb certificate create":           createLBCertificate,
	"lb load-balancer update-shape":   updateLBShape,
	"lb load-balancer update":         updateLBTags,
	"lb backend-set update":           updateBackendSet,
	"lb hostname update":              updateHostname,
	"lb listener update":              updateListener,
	"lb routing-policy create":        createRoutingPolicy,
	"vault secret create-base64":      createSecret,
	"vault secret update-base64":      updateSecret,
	"vault secret list":               listSecrets,
	"secrets secret-bundle get":       getSecretBundle,
	"iam compartment create":          createCompartment,
	"iam dynamic-group create":        createDynamicGroup,
	"iam policy create":               createPolicy,
	"network vcn create":              createVCN,
	"network service-gateway create":  createServiceGateway,
	"kms management vault create":     createVault,
	"kms management key create":       createKey,
	"os bucket create":                createBucket,
	"os retention-rule create":        createRetentionRule,
}

// createFlags lists every flag each in-binary creator consumes.
var createFlags = map[string][]string{
	"network internet-gateway create": {"freeform-tags", "compartment-id", "vcn-id", "display-name", "is-enabled", "wait-for-state"},
	"network route-table create":      {"freeform-tags", "compartment-id", "vcn-id", "display-name", "route-rules", "wait-for-state"},
	"network security-list create": {"freeform-tags", "compartment-id", "vcn-id", "display-name", "ingress-security-rules",
		"egress-security-rules", "wait-for-state"},
	"network subnet create": {"freeform-tags", "compartment-id", "vcn-id", "display-name", "cidr-block", "dns-label", "route-table-id",
		"security-list-ids", "prohibit-public-ip-on-vnic", "wait-for-state"},
	"network nsg create":       {"freeform-tags", "compartment-id", "vcn-id", "display-name", "wait-for-state"},
	"network nsg rules add":    {"nsg-id", "security-rules"},
	"network nsg rules remove": {"nsg-id", "security-rule-ids"},
	"lb load-balancer create": {"compartment-id", "display-name", "shape-name", "subnet-ids", "is-private",
		"network-security-group-ids", "shape-details", "certificates", "hostnames", "backend-sets", "listeners", "rule-sets"},
	"lb certificate create":          {"load-balancer-id", "certificate"},
	"lb load-balancer update-shape":  {"load-balancer-id", "shape-name", "shape-details"},
	"lb load-balancer update":        {"load-balancer-id", "freeform-tags"},
	"lb backend-set update":          {"load-balancer-id", "backend-set-name", "details"},
	"lb hostname update":             {"load-balancer-id", "name", "hostname"},
	"lb listener update":             {"load-balancer-id", "listener-name", "details"},
	"lb routing-policy create":       {"load-balancer-id", "name", "condition-language-version", "rules"},
	"vault secret create-base64":     {"compartment-id", "vault-id", "key-id", "secret-name", "description", "secret-content-content"},
	"vault secret update-base64":     {"secret-id", "secret-content-content"},
	"vault secret list":              {"compartment-id", "vault-id", "name"},
	"secrets secret-bundle get":      {"secret-id"},
	"iam compartment create":         {"freeform-tags", "compartment-id", "name", "description"},
	"iam dynamic-group create":       {"freeform-tags", "compartment-id", "name", "description", "matching-rule"},
	"iam policy create":              {"freeform-tags", "compartment-id", "name", "description", "statements"},
	"network vcn create":             {"freeform-tags", "compartment-id", "display-name", "cidr-block", "dns-label", "wait-for-state"},
	"network service-gateway create": {"freeform-tags", "compartment-id", "vcn-id", "display-name", "services", "wait-for-state"},
	"kms management vault create":    {"freeform-tags", "compartment-id", "display-name", "vault-type"},
	"kms management key create":      {"freeform-tags", "compartment-id", "display-name", "key-shape", "protection-mode", "endpoint"},
	"os bucket create": {"freeform-tags", "namespace-name", "compartment-id", "name", "kms-key-id", "versioning", "public-access-type",
		"storage-tier"},
	"os retention-rule create": {"namespace-name", "bucket-name", "display-name", "time-amount", "time-unit"},
}

// unacceptedCreateFlags returns, sorted, the flags of a create command that
// its creator does not consume.
func unacceptedCreateFlags(parsed sdkcli.Command) []string {
	accepted := createFlags[parsed.Path]
	var extra []string
	for name := range parsed.Flags {
		if !slices.Contains(accepted, name) {
			extra = append(extra, name)
		}
	}
	slices.Sort(extra)
	return extra
}

func (c *SDKClient) Call(ctx context.Context, args ...string) (map[string]any, error) {
	parsed, err := sdkcli.Parse(args)
	if err != nil {
		return nil, err
	}
	if create, ok := c.creators[parsed.Path]; ok {
		// Reject unconsumed mutation flags before any effect.
		if extra := unacceptedCreateFlags(parsed); len(extra) > 0 {
			return nil, fmt.Errorf("%w: %s with --%s", sdkcli.ErrUnsupported, parsed.Path, strings.Join(extra, ", --"))
		}
		value, err := create(ctx, c, parsed)
		if err != nil {
			return nil, fmt.Errorf("OCI %s failed: %w", parsed.Path, err)
		}
		return c.wrap(value)
	}
	data, _, err := c.reader.Call(ctx, args)
	if err != nil {
		return nil, err
	}
	var value any
	if err := json.Unmarshal(data, &value); err != nil {
		return nil, fmt.Errorf("decode OCI response: %w", err)
	}
	return map[string]any{"data": value}, nil
}

func (c *SDKClient) Head(ctx context.Context, args ...string) error {
	_, err := c.Call(ctx, args...)
	return err
}

func (c *SDKClient) wrap(value any) (map[string]any, error) {
	var etag *string
	if t, ok := value.(tagged); ok {
		value, etag = t.value, t.etag
	}
	data, err := sdkcli.Render(value)
	if err != nil {
		return nil, err
	}
	var decoded any
	if err := json.Unmarshal(data, &decoded); err != nil {
		return nil, err
	}
	if etag != nil {
		return map[string]any{"data": decoded, "etag": *etag}, nil
	}
	return map[string]any{"data": decoded}, nil
}

func flags(command sdkcli.Command, names ...string) ([]string, error) {
	values := make([]string, 0, len(names))
	for _, name := range names {
		value := command.Flags[name]
		if value == "" {
			return nil, fmt.Errorf("--%s is required", name)
		}
		values = append(values, value)
	}
	return values, nil
}

func jsonFlag(command sdkcli.Command, name string, target any) error {
	value := command.Flags[name]
	if value == "" {
		return fmt.Errorf("--%s is required", name)
	}
	if err := json.Unmarshal([]byte(value), target, json.RejectUnknownMembers(true)); err != nil {
		return fmt.Errorf("--%s: %w", name, err)
	}
	return nil
}

func optionalTags(command sdkcli.Command) (map[string]string, error) {
	var tags map[string]string
	if command.Flags["freeform-tags"] == "" {
		return nil, nil
	}
	err := jsonFlag(command, "freeform-tags", &tags)
	return tags, err
}

func boolFlag(command sdkcli.Command, name string) (*bool, error) {
	value := command.Flags[name]
	if value == "" {
		return nil, nil
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return nil, fmt.Errorf("--%s: %w", name, err)
	}
	return &parsed, nil
}

func (c *SDKClient) network() (core.VirtualNetworkClient, error) {
	return c.reader.Factory().Network()
}

// waitAvailable re-reads a created network resource until it is AVAILABLE,
// or a DRG attachment ATTACHED: the CLI's --wait-for-state.
func (c *SDKClient) waitAvailable(ctx context.Context, created sdkcli.Command, get func(context.Context) (any, string, error)) (any, error) {
	want := cmp.Or(created.Flags["wait-for-state"], "AVAILABLE")
	if want != "AVAILABLE" && want != "ATTACHED" {
		return nil, fmt.Errorf("--wait-for-state %s is unsupported", want)
	}
	pause := c.Pause
	if pause == nil {
		pause = command.Pause
	}
	delay := 2 * time.Second
	for range 60 {
		value, state, err := get(ctx)
		if err != nil {
			return nil, err
		}
		switch state {
		case want:
			return value, nil
		case "PROVISIONING", "CREATING", "ATTACHING":
		default:
			return nil, fmt.Errorf("resource entered %s", state)
		}
		if created.Flags["wait-for-state"] == "" {
			return value, nil
		}
		if err := pause(ctx, delay); err != nil {
			return nil, err
		}
		delay = min(delay*2, 15*time.Second)
	}
	return nil, fmt.Errorf("resource did not become %s", want)
}

func createInternetGateway(ctx context.Context, c *SDKClient, command sdkcli.Command) (any, error) {
	values, err := flags(command, "compartment-id", "vcn-id", "display-name")
	if err != nil {
		return nil, err
	}
	enabled, err := boolFlag(command, "is-enabled")
	if err != nil || enabled == nil {
		return nil, errors.Join(err, errors.New("--is-enabled is required"))
	}
	tags, err := optionalTags(command)
	if err != nil {
		return nil, err
	}
	client, err := c.network()
	if err != nil {
		return nil, err
	}
	response, err := client.CreateInternetGateway(ctx, core.CreateInternetGatewayRequest{CreateInternetGatewayDetails: core.CreateInternetGatewayDetails{FreeformTags: tags,
		CompartmentId: &values[0], VcnId: &values[1], DisplayName: &values[2], IsEnabled: enabled}})
	if err != nil {
		return nil, err
	}
	return c.waitAvailable(ctx, command, func(ctx context.Context) (any, string, error) {
		got, err := client.GetInternetGateway(ctx, core.GetInternetGatewayRequest{IgId: response.Id})
		return got.InternetGateway, string(got.LifecycleState), err
	})
}

func createRouteTable(ctx context.Context, c *SDKClient, command sdkcli.Command) (any, error) {
	values, err := flags(command, "compartment-id", "vcn-id", "display-name")
	if err != nil {
		return nil, err
	}
	var rules []core.RouteRule
	if err := jsonFlag(command, "route-rules", &rules); err != nil {
		return nil, err
	}
	tags, err := optionalTags(command)
	if err != nil {
		return nil, err
	}
	client, err := c.network()
	if err != nil {
		return nil, err
	}
	response, err := client.CreateRouteTable(ctx, core.CreateRouteTableRequest{OpcRetryToken: retryToken(), CreateRouteTableDetails: core.CreateRouteTableDetails{FreeformTags: tags,
		CompartmentId: &values[0], VcnId: &values[1], DisplayName: &values[2], RouteRules: rules}})
	if err != nil {
		return nil, err
	}
	return c.waitAvailable(ctx, command, func(ctx context.Context) (any, string, error) {
		got, err := client.GetRouteTable(ctx, core.GetRouteTableRequest{RtId: response.Id})
		return got.RouteTable, string(got.LifecycleState), err
	})
}

func createSecurityList(ctx context.Context, c *SDKClient, command sdkcli.Command) (any, error) {
	values, err := flags(command, "compartment-id", "vcn-id", "display-name")
	if err != nil {
		return nil, err
	}
	var ingress []core.IngressSecurityRule
	var egress []core.EgressSecurityRule
	if err := jsonFlag(command, "ingress-security-rules", &ingress); err != nil {
		return nil, err
	}
	if err := jsonFlag(command, "egress-security-rules", &egress); err != nil {
		return nil, err
	}
	tags, err := optionalTags(command)
	if err != nil {
		return nil, err
	}
	client, err := c.network()
	if err != nil {
		return nil, err
	}
	response, err := client.CreateSecurityList(ctx, core.CreateSecurityListRequest{OpcRetryToken: retryToken(), CreateSecurityListDetails: core.CreateSecurityListDetails{FreeformTags: tags,
		CompartmentId: &values[0], VcnId: &values[1], DisplayName: &values[2], IngressSecurityRules: ingress, EgressSecurityRules: egress}})
	if err != nil {
		return nil, err
	}
	return c.waitAvailable(ctx, command, func(ctx context.Context) (any, string, error) {
		got, err := client.GetSecurityList(ctx, core.GetSecurityListRequest{SecurityListId: response.Id})
		return got.SecurityList, string(got.LifecycleState), err
	})
}

func createSubnet(ctx context.Context, c *SDKClient, command sdkcli.Command) (any, error) {
	values, err := flags(command, "compartment-id", "vcn-id", "display-name", "cidr-block", "dns-label", "route-table-id")
	if err != nil {
		return nil, err
	}
	var securityLists []string
	if err := jsonFlag(command, "security-list-ids", &securityLists); err != nil {
		return nil, err
	}
	prohibitPublicIP, err := boolFlag(command, "prohibit-public-ip-on-vnic")
	if err != nil {
		return nil, err
	}
	tags, err := optionalTags(command)
	if err != nil {
		return nil, err
	}
	client, err := c.network()
	if err != nil {
		return nil, err
	}
	response, err := client.CreateSubnet(ctx, core.CreateSubnetRequest{OpcRetryToken: retryToken(), CreateSubnetDetails: core.CreateSubnetDetails{FreeformTags: tags,
		CompartmentId: &values[0], VcnId: &values[1], DisplayName: &values[2], CidrBlock: &values[3], DnsLabel: &values[4],
		RouteTableId: &values[5], SecurityListIds: securityLists, ProhibitPublicIpOnVnic: prohibitPublicIP}})
	if err != nil {
		return nil, err
	}
	return c.waitAvailable(ctx, command, func(ctx context.Context) (any, string, error) {
		got, err := client.GetSubnet(ctx, core.GetSubnetRequest{SubnetId: response.Id})
		return got.Subnet, string(got.LifecycleState), err
	})
}

func createNSG(ctx context.Context, c *SDKClient, command sdkcli.Command) (any, error) {
	values, err := flags(command, "compartment-id", "vcn-id", "display-name")
	if err != nil {
		return nil, err
	}
	tags, err := optionalTags(command)
	if err != nil {
		return nil, err
	}
	client, err := c.network()
	if err != nil {
		return nil, err
	}
	response, err := client.CreateNetworkSecurityGroup(ctx, core.CreateNetworkSecurityGroupRequest{OpcRetryToken: retryToken(),
		CreateNetworkSecurityGroupDetails: core.CreateNetworkSecurityGroupDetails{FreeformTags: tags, CompartmentId: &values[0], VcnId: &values[1], DisplayName: &values[2]}})
	if err != nil {
		return nil, err
	}
	return c.waitAvailable(ctx, command, func(ctx context.Context) (any, string, error) {
		got, err := client.GetNetworkSecurityGroup(ctx, core.GetNetworkSecurityGroupRequest{NetworkSecurityGroupId: response.Id})
		return got.NetworkSecurityGroup, string(got.LifecycleState), err
	})
}

func addNSGRules(ctx context.Context, c *SDKClient, command sdkcli.Command) (any, error) {
	values, err := flags(command, "nsg-id")
	if err != nil {
		return nil, err
	}
	var rules []core.AddSecurityRuleDetails
	if err := jsonFlag(command, "security-rules", &rules); err != nil {
		return nil, err
	}
	client, err := c.network()
	if err != nil {
		return nil, err
	}
	response, err := client.AddNetworkSecurityGroupSecurityRules(ctx, core.AddNetworkSecurityGroupSecurityRulesRequest{
		NetworkSecurityGroupId:                      &values[0],
		AddNetworkSecurityGroupSecurityRulesDetails: core.AddNetworkSecurityGroupSecurityRulesDetails{SecurityRules: rules}})
	if err != nil {
		return nil, err
	}
	return response.AddedNetworkSecurityGroupSecurityRules, nil
}

func removeNSGRules(ctx context.Context, c *SDKClient, command sdkcli.Command) (any, error) {
	values, err := flags(command, "nsg-id")
	if err != nil {
		return nil, err
	}
	var ids []string
	if err := jsonFlag(command, "security-rule-ids", &ids); err != nil {
		return nil, err
	}
	client, err := c.network()
	if err != nil {
		return nil, err
	}
	_, err = client.RemoveNetworkSecurityGroupSecurityRules(ctx, core.RemoveNetworkSecurityGroupSecurityRulesRequest{
		NetworkSecurityGroupId:                         &values[0],
		RemoveNetworkSecurityGroupSecurityRulesDetails: core.RemoveNetworkSecurityGroupSecurityRulesDetails{SecurityRuleIds: ids}})
	return map[string]any{}, err
}

func (c *SDKClient) loadBalancer() (loadbalancer.LoadBalancerClient, error) {
	return c.reader.Factory().LoadBalancer()
}

// decodeLoadBalancer reads lb load-balancer create's flags into the SDK's
// create details, rejecting unknown members.
func decodeLoadBalancer(command sdkcli.Command) (loadbalancer.CreateLoadBalancerDetails, error) {
	values, err := flags(command, "compartment-id", "display-name", "shape-name")
	if err != nil {
		return loadbalancer.CreateLoadBalancerDetails{}, err
	}
	isPrivate, err := boolFlag(command, "is-private")
	if err != nil {
		return loadbalancer.CreateLoadBalancerDetails{}, err
	}
	details := loadbalancer.CreateLoadBalancerDetails{CompartmentId: &values[0], DisplayName: &values[1], ShapeName: &values[2], IsPrivate: isPrivate}
	for name, target := range map[string]any{"subnet-ids": &details.SubnetIds, "network-security-group-ids": &details.NetworkSecurityGroupIds,
		"shape-details": &details.ShapeDetails, "certificates": &details.Certificates, "hostnames": &details.Hostnames,
		"backend-sets": &details.BackendSets, "listeners": &details.Listeners, "rule-sets": &details.RuleSets} {
		if err := jsonFlag(command, name, target); err != nil {
			return loadbalancer.CreateLoadBalancerDetails{}, err
		}
	}
	return details, nil
}

// createLoadBalancer submits the load balancer; it is created
// asynchronously, so the provisioner waits for it to list ACTIVE.
func createLoadBalancer(ctx context.Context, c *SDKClient, command sdkcli.Command) (any, error) {
	details, err := decodeLoadBalancer(command)
	if err != nil {
		return nil, err
	}
	client, err := c.loadBalancer()
	if err != nil {
		return nil, err
	}
	response, err := client.CreateLoadBalancer(ctx, loadbalancer.CreateLoadBalancerRequest{CreateLoadBalancerDetails: details})
	return map[string]any{"work-request-id": response.OpcWorkRequestId}, err
}

// createLBCertificate takes the bundle as one JSON flag: PEM begins with
// dashes, which the CLI-style argument parser reads as a flag.
func createLBCertificate(ctx context.Context, c *SDKClient, command sdkcli.Command) (any, error) {
	values, err := flags(command, "load-balancer-id")
	if err != nil {
		return nil, err
	}
	var details loadbalancer.CreateCertificateDetails
	if err := jsonFlag(command, "certificate", &details); err != nil {
		return nil, err
	}
	client, err := c.loadBalancer()
	if err != nil {
		return nil, err
	}
	response, err := client.CreateCertificate(ctx, loadbalancer.CreateCertificateRequest{LoadBalancerId: &values[0], CreateCertificateDetails: details})
	return map[string]any{"work-request-id": response.OpcWorkRequestId}, err
}

func updateLBShape(ctx context.Context, c *SDKClient, command sdkcli.Command) (any, error) {
	values, err := flags(command, "load-balancer-id", "shape-name")
	if err != nil {
		return nil, err
	}
	var shape loadbalancer.ShapeDetails
	if err := jsonFlag(command, "shape-details", &shape); err != nil {
		return nil, err
	}
	client, err := c.loadBalancer()
	if err != nil {
		return nil, err
	}
	response, err := client.UpdateLoadBalancerShape(ctx, loadbalancer.UpdateLoadBalancerShapeRequest{LoadBalancerId: &values[0],
		UpdateLoadBalancerShapeDetails: loadbalancer.UpdateLoadBalancerShapeDetails{ShapeName: &values[1], ShapeDetails: &shape}})
	return map[string]any{"work-request-id": response.OpcWorkRequestId}, err
}

// updateLBTags replaces the load balancer's freeform tags; its defined tags
// are left as they are.
func updateLBTags(ctx context.Context, c *SDKClient, command sdkcli.Command) (any, error) {
	values, err := flags(command, "load-balancer-id")
	if err != nil {
		return nil, err
	}
	var tags map[string]string
	if err := jsonFlag(command, "freeform-tags", &tags); err != nil {
		return nil, err
	}
	client, err := c.loadBalancer()
	if err != nil {
		return nil, err
	}
	response, err := client.UpdateLoadBalancer(ctx, loadbalancer.UpdateLoadBalancerRequest{LoadBalancerId: &values[0],
		UpdateLoadBalancerDetails: loadbalancer.UpdateLoadBalancerDetails{FreeformTags: tags}})
	if err != nil {
		return nil, err
	}
	return map[string]any{"work-request-id": response.OpcWorkRequestId}, nil
}

func updateBackendSet(ctx context.Context, c *SDKClient, command sdkcli.Command) (any, error) {
	values, err := flags(command, "load-balancer-id", "backend-set-name")
	if err != nil {
		return nil, err
	}
	var details loadbalancer.UpdateBackendSetDetails
	if err := jsonFlag(command, "details", &details); err != nil {
		return nil, err
	}
	client, err := c.loadBalancer()
	if err != nil {
		return nil, err
	}
	response, err := client.UpdateBackendSet(ctx, loadbalancer.UpdateBackendSetRequest{LoadBalancerId: &values[0], BackendSetName: &values[1],
		UpdateBackendSetDetails: details})
	return map[string]any{"work-request-id": response.OpcWorkRequestId}, err
}

func updateHostname(ctx context.Context, c *SDKClient, command sdkcli.Command) (any, error) {
	values, err := flags(command, "load-balancer-id", "name", "hostname")
	if err != nil {
		return nil, err
	}
	client, err := c.loadBalancer()
	if err != nil {
		return nil, err
	}
	response, err := client.UpdateHostname(ctx, loadbalancer.UpdateHostnameRequest{LoadBalancerId: &values[0], Name: &values[1],
		UpdateHostnameDetails: loadbalancer.UpdateHostnameDetails{Hostname: &values[2]}})
	return map[string]any{"work-request-id": response.OpcWorkRequestId}, err
}

func updateListener(ctx context.Context, c *SDKClient, command sdkcli.Command) (any, error) {
	values, err := flags(command, "load-balancer-id", "listener-name")
	if err != nil {
		return nil, err
	}
	var details loadbalancer.UpdateListenerDetails
	if err := jsonFlag(command, "details", &details); err != nil {
		return nil, err
	}
	client, err := c.loadBalancer()
	if err != nil {
		return nil, err
	}
	response, err := client.UpdateListener(ctx, loadbalancer.UpdateListenerRequest{LoadBalancerId: &values[0], ListenerName: &values[1],
		UpdateListenerDetails: details})
	return map[string]any{"work-request-id": response.OpcWorkRequestId}, err
}

func createRoutingPolicy(ctx context.Context, c *SDKClient, command sdkcli.Command) (any, error) {
	values, err := flags(command, "load-balancer-id", "name", "condition-language-version")
	if err != nil {
		return nil, err
	}
	details := loadbalancer.CreateRoutingPolicyDetails{Name: &values[1],
		ConditionLanguageVersion: loadbalancer.CreateRoutingPolicyDetailsConditionLanguageVersionEnum(values[2])}
	if err := jsonFlag(command, "rules", &details.Rules); err != nil {
		return nil, err
	}
	client, err := c.loadBalancer()
	if err != nil {
		return nil, err
	}
	response, err := client.CreateRoutingPolicy(ctx, loadbalancer.CreateRoutingPolicyRequest{LoadBalancerId: &values[0],
		CreateRoutingPolicyDetails: details})
	return map[string]any{"work-request-id": response.OpcWorkRequestId}, err
}

func (c *SDKClient) vaults() (vault.VaultsClient, error) {
	factory := c.reader.Factory()
	client, err := vault.NewVaultsClientWithConfigurationProvider(factory.Provider())
	if err != nil {
		return client, err
	}
	client.SetRegion(factory.Region())
	factory.Configure(&client.BaseClient, ociclient.ServiceKMS)
	return client, nil
}

func createSecret(ctx context.Context, c *SDKClient, command sdkcli.Command) (any, error) {
	values, err := flags(command, "compartment-id", "vault-id", "key-id", "secret-name", "description", "secret-content-content")
	if err != nil {
		return nil, err
	}
	client, err := c.vaults()
	if err != nil {
		return nil, err
	}
	response, err := client.CreateSecret(ctx, vault.CreateSecretRequest{CreateSecretDetails: vault.CreateSecretDetails{
		CompartmentId: &values[0], VaultId: &values[1], KeyId: &values[2], SecretName: &values[3], Description: &values[4],
		SecretContent: vault.Base64SecretContentDetails{Content: &values[5]}}})
	if err != nil {
		return nil, err
	}
	return response.Secret, nil
}

// updateSecret adds a new current version; earlier versions stay readable.
func updateSecret(ctx context.Context, c *SDKClient, command sdkcli.Command) (any, error) {
	values, err := flags(command, "secret-id", "secret-content-content")
	if err != nil {
		return nil, err
	}
	client, err := c.vaults()
	if err != nil {
		return nil, err
	}
	response, err := client.UpdateSecret(ctx, vault.UpdateSecretRequest{SecretId: &values[0], UpdateSecretDetails: vault.UpdateSecretDetails{
		SecretContent: vault.Base64SecretContentDetails{Content: &values[1]}}})
	if err != nil {
		return nil, err
	}
	return response.Secret, nil
}

func listSecrets(ctx context.Context, c *SDKClient, command sdkcli.Command) (any, error) {
	values, err := flags(command, "compartment-id", "vault-id", "name")
	if err != nil {
		return nil, err
	}
	client, err := c.vaults()
	if err != nil {
		return nil, err
	}
	var secrets []vault.SecretSummary
	for page := (*string)(nil); ; {
		response, err := client.ListSecrets(ctx, vault.ListSecretsRequest{CompartmentId: &values[0], VaultId: &values[1], Name: &values[2], Page: page})
		if err != nil {
			return nil, err
		}
		secrets = append(secrets, response.Items...)
		if page = response.OpcNextPage; page == nil {
			return secrets, nil
		}
	}
}

func getSecretBundle(ctx context.Context, c *SDKClient, command sdkcli.Command) (any, error) {
	values, err := flags(command, "secret-id")
	if err != nil {
		return nil, err
	}
	factory := c.reader.Factory()
	client, err := secrets.NewSecretsClientWithConfigurationProvider(factory.Provider())
	if err != nil {
		return nil, err
	}
	client.SetRegion(factory.Region())
	factory.Configure(&client.BaseClient, ociclient.ServiceKMS)
	response, err := client.GetSecretBundle(ctx, secrets.GetSecretBundleRequest{SecretId: &values[0]})
	if err != nil {
		return nil, err
	}
	return response.SecretBundle, nil
}
