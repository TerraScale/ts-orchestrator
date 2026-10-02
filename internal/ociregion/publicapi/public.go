// Package publicapi exposes cell members through a TLS passthrough OCI network load balancer.
package publicapi

import (
	"context"
	"encoding/json/v2"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociregion/command"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociregion/sdkcli"
)

const Prefix = "terrascale-gru-public"

type Options struct {
	Plan, Members, WorkloadNSG, SubnetCIDR string
	ClientPort                             int
}

type Provisioner struct {
	Client       command.Client
	Pause        func(context.Context, time.Duration) error
	PollAttempts int
}

func Run(ctx context.Context, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("oci-region public-api", flag.ContinueOnError)
	fs.SetOutput(out)
	var o Options
	fs.StringVar(&o.Plan, "plan", "", "regional plan JSON")
	fs.StringVar(&o.Members, "members", "", "comma-separated member private IPs")
	fs.IntVar(&o.ClientPort, "client-port", 9465, "member client port")
	fs.StringVar(&o.WorkloadNSG, "workload-nsg", "", "workload NSG")
	fs.StringVar(&o.SubnetCIDR, "subnet-cidr", "10.251.0.128/26", "public subnet CIDR")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected arguments: %v", fs.Args())
	}
	client, err := newClient(o.Plan)
	if err != nil {
		return err
	}
	r, err := (Provisioner{Client: client}).Provision(ctx, o)
	if err != nil {
		return err
	}
	b, err := json.Marshal(r, json.Deterministic(true))
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(out, string(b))
	return err
}

// newClient selects the in-binary SDK client unless TS_OCI_BACKEND=cli. The
// SDK client is pinned to the plan's catalog region; the CLI used the
// profile's default region.
func newClient(planPath string) (command.Client, error) {
	backend, err := sdkcli.SelectedBackend()
	if err != nil {
		return nil, err
	}
	if backend == sdkcli.BackendCLI {
		return command.CLI{}, nil
	}
	if planPath == "" {
		return nil, errors.New("--plan is required")
	}
	b, err := os.ReadFile(planPath)
	if err != nil {
		return nil, err
	}
	var plan struct {
		Region string `json:"region"`
	}
	if err := json.Unmarshal(b, &plan); err != nil {
		return nil, err
	}
	if !catalog.IsOCIRegion(plan.Region) {
		return nil, fmt.Errorf("plan region %q is not a catalog OCI region", plan.Region)
	}
	return NewSDKClient(plan.Region, backend)
}

func Named(rows []map[string]any, name string) (map[string]any, error) {
	var found map[string]any
	for _, r := range rows {
		if r["display-name"] == name && !slices.Contains([]string{"TERMINATED", "TERMINATING", "DELETED", "DELETING"}, fmt.Sprint(r["lifecycle-state"])) {
			if found != nil {
				return nil, fmt.Errorf("more than one live resource is named %s", name)
			}
			found = r
		}
	}
	return found, nil
}

func (p Provisioner) data(ctx context.Context, args ...string) (map[string]any, error) {
	r, err := p.Client.Call(ctx, args...)
	if err != nil {
		return nil, err
	}
	return command.Object(r["data"])
}
func (p Provisioner) rows(ctx context.Context, args ...string) ([]map[string]any, error) {
	r, err := p.Client.Call(ctx, args...)
	if err != nil {
		return nil, err
	}
	return command.Rows(r["data"])
}
func (p Provisioner) pause(ctx context.Context, d time.Duration) error {
	if p.Pause != nil {
		return p.Pause(ctx, d)
	}
	return command.Pause(ctx, d)
}
func (p Provisioner) attempts() int {
	if p.PollAttempts > 0 {
		return p.PollAttempts
	}
	return 90
}

func (p Provisioner) WaitState(ctx context.Context, args []string, state string) (map[string]any, error) {
	for n := range p.attempts() {
		r, err := p.data(ctx, args...)
		if err != nil {
			return nil, err
		}
		if r["lifecycle-state"] == state {
			return r, nil
		}
		if slices.Contains([]string{"FAILED", "TERMINATED", "TERMINATING", "DELETED", "DELETING"}, fmt.Sprint(r["lifecycle-state"])) {
			return nil, fmt.Errorf("%v entered %v before reaching %s", args, r["lifecycle-state"], state)
		}
		if n+1 < p.attempts() {
			if err := p.pause(ctx, 10*time.Second); err != nil {
				return nil, err
			}
		}
	}
	return nil, fmt.Errorf("%v did not reach %s", args, state)
}

func (p Provisioner) ensureNetwork(ctx context.Context, kind, compartment, vcn string, extra ...string) (map[string]any, error) {
	rows, err := p.rows(ctx, "network", kind, "list", "--compartment-id", compartment, "--vcn-id", vcn, "--all")
	if err != nil {
		return nil, err
	}
	r, err := Named(rows, Prefix)
	if err != nil || r != nil {
		return r, err
	}
	args := []string{"network", kind, "create", "--compartment-id", compartment, "--vcn-id", vcn, "--display-name", Prefix, "--wait-for-state", "AVAILABLE"}
	return p.data(ctx, append(args, extra...)...)
}

func (p Provisioner) balancer(ctx context.Context, compartment string) (map[string]any, error) {
	r, err := p.data(ctx, "nlb", "network-load-balancer", "list", "--compartment-id", compartment, "--all")
	if err != nil {
		return nil, err
	}
	rows, err := command.Rows(r["items"])
	if err != nil {
		return nil, err
	}
	return Named(rows, Prefix)
}

func (p Provisioner) Provision(ctx context.Context, o Options) (map[string]any, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	for key, value := range map[string]string{"plan": o.Plan, "members": o.Members, "workload-nsg": o.WorkloadNSG, "subnet-cidr": o.SubnetCIDR} {
		if value == "" {
			return nil, fmt.Errorf("--%s is required", key)
		}
	}
	if o.ClientPort < 1 || o.ClientPort > 65535 {
		return nil, fmt.Errorf("client port must be between 1 and 65535")
	}
	if _, err := netip.ParsePrefix(o.SubnetCIDR); err != nil {
		return nil, fmt.Errorf("public subnet CIDR: %w", err)
	}
	members := []string{}
	for _, s := range strings.Split(o.Members, ",") {
		ip, err := netip.ParseAddr(s)
		if err != nil {
			return nil, fmt.Errorf("member IP: %w", err)
		}
		members = append(members, ip.String())
	}
	b, err := os.ReadFile(o.Plan)
	if err != nil {
		return nil, err
	}
	var plan struct {
		ResourceIDs struct {
			NetworkCompartment string `json:"network_compartment"`
			VCN                string `json:"vcn"`
		} `json:"resource_ids"`
		SubnetCIDR string `json:"subnet_cidr"`
	}
	if err := json.Unmarshal(b, &plan); err != nil {
		return nil, err
	}
	network, vcn := plan.ResourceIDs.NetworkCompartment, plan.ResourceIDs.VCN
	if network == "" || vcn == "" {
		return nil, fmt.Errorf("plan requires network_compartment and vcn resource IDs")
	}
	if _, err := netip.ParsePrefix(plan.SubnetCIDR); err != nil {
		return nil, fmt.Errorf("private subnet CIDR: %w", err)
	}
	gateway, err := p.ensureNetwork(ctx, "internet-gateway", network, vcn, "--is-enabled", "true")
	if err != nil {
		return nil, err
	}
	gatewayID, err := command.ID(gateway)
	if err != nil {
		return nil, err
	}
	routes, err := p.ensureNetwork(ctx, "route-table", network, vcn, "--route-rules", command.JSON([]any{map[string]any{"destination": "0.0.0.0/0", "destinationType": "CIDR_BLOCK", "networkEntityId": gatewayID}}))
	if err != nil {
		return nil, err
	}
	routesID, err := command.ID(routes)
	if err != nil {
		return nil, err
	}
	port := map[string]any{"destinationPortRange": map[string]any{"min": o.ClientPort, "max": o.ClientPort}}
	security, err := p.ensureNetwork(ctx, "security-list", network, vcn,
		"--ingress-security-rules", command.JSON([]any{map[string]any{"protocol": "6", "source": "0.0.0.0/0", "sourceType": "CIDR_BLOCK", "isStateless": false, "tcpOptions": map[string]any{"destinationPortRange": map[string]any{"min": 443, "max": 443}}}}),
		"--egress-security-rules", command.JSON([]any{map[string]any{"protocol": "6", "destination": plan.SubnetCIDR, "destinationType": "CIDR_BLOCK", "isStateless": false, "tcpOptions": port}}))
	if err != nil {
		return nil, err
	}
	securityID, err := command.ID(security)
	if err != nil {
		return nil, err
	}
	subnet, err := p.ensureNetwork(ctx, "subnet", network, vcn, "--cidr-block", o.SubnetCIDR, "--dns-label", "public", "--prohibit-public-ip-on-vnic", "false", "--route-table-id", routesID, "--security-list-ids", command.JSON([]string{securityID}))
	if err != nil {
		return nil, err
	}
	subnetID, err := command.ID(subnet)
	if err != nil {
		return nil, err
	}
	ruleRows, err := p.rows(ctx, "network", "nsg", "rules", "list", "--nsg-id", o.WorkloadNSG, "--all")
	if err != nil {
		return nil, err
	}
	hasRule := false
	for _, r := range ruleRows {
		tcp, _ := r["tcp-options"].(map[string]any)
		ports, _ := tcp["destination-port-range"].(map[string]any)
		if r["source"] == o.SubnetCIDR && r["direction"] == "INGRESS" && r["protocol"] == "6" && fmt.Sprint(ports["min"]) == strconv.Itoa(o.ClientPort) && fmt.Sprint(ports["max"]) == strconv.Itoa(o.ClientPort) {
			hasRule = true
		}
	}
	if !hasRule {
		_, err = p.Client.Call(ctx, "network", "nsg", "rules", "add", "--nsg-id", o.WorkloadNSG, "--security-rules", command.JSON([]any{map[string]any{"direction": "INGRESS", "protocol": "6", "source": o.SubnetCIDR, "sourceType": "CIDR_BLOCK", "isStateless": false, "description": "TerraBase HTTPS from the public load balancer", "tcpOptions": port}}))
		if err != nil {
			return nil, err
		}
	}
	balancer, err := p.balancer(ctx, network)
	if err != nil {
		return nil, err
	}
	if balancer == nil {
		backends := make([]map[string]any, 0, len(members))
		for _, ip := range members {
			backends = append(backends, map[string]any{"ipAddress": ip, "port": o.ClientPort, "weight": 1})
		}
		backendSet := map[string]any{"terrabase-https": map[string]any{"policy": "FIVE_TUPLE", "isPreserveSource": false, "healthChecker": map[string]any{"protocol": "TCP", "port": o.ClientPort, "intervalInMillis": 10000, "timeoutInMillis": 3000, "retries": 3}, "backends": backends}}
		listeners := map[string]any{"https": map[string]any{"name": "https", "defaultBackendSetName": "terrabase-https", "port": 443, "protocol": "TCP"}}
		_, err = p.Client.Call(ctx, "nlb", "network-load-balancer", "create", "--compartment-id", network, "--display-name", Prefix, "--subnet-id", subnetID, "--is-private", "false", "--is-preserve-source-destination", "false", "--backend-sets", command.JSON(backendSet), "--listeners", command.JSON(listeners))
		if err != nil {
			return nil, err
		}
		for n := range p.attempts() {
			balancer, err = p.balancer(ctx, network)
			if err != nil {
				return nil, err
			}
			if balancer != nil {
				break
			}
			if n+1 < p.attempts() {
				if err := p.pause(ctx, 5*time.Second); err != nil {
					return nil, err
				}
			}
		}
		if balancer == nil {
			return nil, fmt.Errorf("network load balancer did not appear")
		}
	}
	id, err := command.ID(balancer)
	if err != nil {
		return nil, err
	}
	balancer, err = p.WaitState(ctx, []string{"nlb", "network-load-balancer", "get", "--network-load-balancer-id", id}, "ACTIVE")
	if err != nil {
		return nil, err
	}
	addresses, err := command.Rows(balancer["ip-addresses"])
	if err != nil {
		return nil, err
	}
	var public any
	for _, address := range addresses {
		if address["is-public"] == true {
			public = address["ip-address"]
			break
		}
	}
	return map[string]any{"network_load_balancer": id, "public_ip": public, "subnet": subnetID, "members": members, "port": 443}, nil
}
