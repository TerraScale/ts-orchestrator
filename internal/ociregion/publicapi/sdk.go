package publicapi

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/oracle/oci-go-sdk/v65/core"
	"github.com/oracle/oci-go-sdk/v65/networkloadbalancer"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociregion/command"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociregion/sdkcli"
)

// SDKClient serves the provisioner's commands through the OCI Go SDK inside
// the binary: reads through sdkcli, and the handful of creates the public API
// path needs here. With the auto backend, a command neither serves falls back
// to the Python CLI.
type SDKClient struct {
	Region   string
	Backend  sdkcli.Backend
	reader   *sdkcli.Client
	creators map[string]creator
	// Pause is injectable so state waits run without sleeping in tests.
	Pause func(context.Context, time.Duration) error
}

type creator func(context.Context, *SDKClient, sdkcli.Command) (any, error)

// NewSDKClient builds the client for one catalog OCI region.
func NewSDKClient(region string, backend sdkcli.Backend) (*SDKClient, error) {
	reader, err := sdkcli.ForRegion(region)
	if err != nil {
		return nil, err
	}
	return &SDKClient{Region: region, Backend: backend, reader: reader, creators: creators}, nil
}

var creators = map[string]creator{
	"network internet-gateway create":  createInternetGateway,
	"network route-table create":       createRouteTable,
	"network security-list create":     createSecurityList,
	"network subnet create":            createSubnet,
	"network nsg rules add":            addNSGRules,
	"nlb network-load-balancer create": createNLB,
}

// createFlags lists every flag each in-binary creator consumes.
var createFlags = map[string][]string{
	"network internet-gateway create": {"compartment-id", "vcn-id", "display-name", "is-enabled", "wait-for-state"},
	"network route-table create":      {"compartment-id", "vcn-id", "display-name", "route-rules", "wait-for-state"},
	"network security-list create": {"compartment-id", "vcn-id", "display-name", "ingress-security-rules",
		"egress-security-rules", "wait-for-state"},
	"network subnet create": {"compartment-id", "vcn-id", "display-name", "cidr-block", "dns-label", "route-table-id",
		"security-list-ids", "prohibit-public-ip-on-vnic", "wait-for-state"},
	"network nsg rules add": {"nsg-id", "security-rules"},
	"nlb network-load-balancer create": {"compartment-id", "display-name", "subnet-id", "is-private",
		"is-preserve-source-destination", "backend-sets", "listeners"},
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
		// A create is a mutation, so a flag it would not consume is caught
		// before any effect: under auto the oci CLI serves the command,
		// under sdk it fails instead of silently diverging.
		if extra := unacceptedCreateFlags(parsed); len(extra) > 0 {
			if c.Backend == sdkcli.BackendAuto {
				return command.CLI{Region: c.Region}.Call(ctx, args...)
			}
			return nil, fmt.Errorf("%w: %s with --%s", sdkcli.ErrUnsupported, parsed.Path, strings.Join(extra, ", --"))
		}
		value, err := create(ctx, c, parsed)
		if err != nil {
			return nil, fmt.Errorf("OCI %s failed: %w", parsed.Path, err)
		}
		return c.wrap(value)
	}
	data, handled, err := c.reader.Call(ctx, args)
	if !handled && c.Backend == sdkcli.BackendAuto && errors.Is(err, sdkcli.ErrUnsupported) {
		return command.CLI{Region: c.Region}.Call(ctx, args...)
	}
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
	data, err := sdkcli.Render(value)
	if err != nil {
		return nil, err
	}
	var decoded any
	if err := json.Unmarshal(data, &decoded); err != nil {
		return nil, err
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
// the CLI's --wait-for-state AVAILABLE.
func (c *SDKClient) waitAvailable(ctx context.Context, created sdkcli.Command, get func(context.Context) (any, string, error)) (any, error) {
	if state := created.Flags["wait-for-state"]; state != "" && state != "AVAILABLE" {
		return nil, fmt.Errorf("--wait-for-state %s is unsupported", state)
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
		case "AVAILABLE":
			return value, nil
		case "PROVISIONING", "CREATING":
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
	return nil, errors.New("resource did not become AVAILABLE")
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
	client, err := c.network()
	if err != nil {
		return nil, err
	}
	response, err := client.CreateInternetGateway(ctx, core.CreateInternetGatewayRequest{CreateInternetGatewayDetails: core.CreateInternetGatewayDetails{
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
	client, err := c.network()
	if err != nil {
		return nil, err
	}
	response, err := client.CreateRouteTable(ctx, core.CreateRouteTableRequest{CreateRouteTableDetails: core.CreateRouteTableDetails{
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
	client, err := c.network()
	if err != nil {
		return nil, err
	}
	response, err := client.CreateSecurityList(ctx, core.CreateSecurityListRequest{CreateSecurityListDetails: core.CreateSecurityListDetails{
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
	client, err := c.network()
	if err != nil {
		return nil, err
	}
	response, err := client.CreateSubnet(ctx, core.CreateSubnetRequest{CreateSubnetDetails: core.CreateSubnetDetails{
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

func createNLB(ctx context.Context, c *SDKClient, command sdkcli.Command) (any, error) {
	values, err := flags(command, "compartment-id", "display-name", "subnet-id")
	if err != nil {
		return nil, err
	}
	isPrivate, err := boolFlag(command, "is-private")
	if err != nil {
		return nil, err
	}
	preserve, err := boolFlag(command, "is-preserve-source-destination")
	if err != nil {
		return nil, err
	}
	var backendSets map[string]networkloadbalancer.BackendSetDetails
	var listeners map[string]networkloadbalancer.ListenerDetails
	if err := jsonFlag(command, "backend-sets", &backendSets); err != nil {
		return nil, err
	}
	if err := jsonFlag(command, "listeners", &listeners); err != nil {
		return nil, err
	}
	client, err := c.reader.Factory().NetworkLoadBalancer()
	if err != nil {
		return nil, err
	}
	response, err := client.CreateNetworkLoadBalancer(ctx, networkloadbalancer.CreateNetworkLoadBalancerRequest{
		CreateNetworkLoadBalancerDetails: networkloadbalancer.CreateNetworkLoadBalancerDetails{
			CompartmentId: &values[0], DisplayName: &values[1], SubnetId: &values[2], IsPrivate: isPrivate,
			IsPreserveSourceDestination: preserve, BackendSets: backendSets, Listeners: listeners}})
	if err != nil {
		return nil, err
	}
	return response.NetworkLoadBalancer, nil
}
