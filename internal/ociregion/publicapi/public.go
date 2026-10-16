// Package publicapi puts a cell's TerraBase and ts-auth APIs on the
// internet. Proxied Cloudflare DNS reaches an OCI flexible load balancer
// that admits only Cloudflare's ranges, verifies Cloudflare's origin-pull
// client certificate, serves a Cloudflare Origin CA certificate and routes
// by hostname to the members and controllers over the private subnet.
package publicapi

import (
	"context"
	_ "embed"
	"encoding/json/v2"
	"errors"
	"flag"
	"fmt"
	"io"
	"maps"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/naming"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/command"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/sdkcli"
	"github.com/TerraScale/ts-orchestrator/internal/ociresource"
	"github.com/TerraScale/ts-orchestrator/internal/ociresource/lb"
)

// PublishedOriginIPs are Cloudflare's current published IPv4 ranges.
func PublishedOriginIPs(ctx context.Context) ([]string, error) {
	return Cloudflare{BaseURL: cloudflareAPI}.OriginIPs(ctx)
}

// ParsePlan reads a regional plan's public API from its JSON.
func ParsePlan(wire []byte) (Desired, error) {
	var p planFile
	if err := json.Unmarshal(wire, &p); err != nil {
		return Desired{}, fmt.Errorf("plan: %w", err)
	}
	return p.desired()
}

const (
	tcp = "6"
	// AuthPort is ts-auth's port on every controller (TS-487).
	AuthPort = 8080
	// OrchPort is where every controller serves the Machines API
	// (cellspec.MachinesAPIPort), with its signed controller TLS certificate.
	OrchPort = 8444
	// HealthPath answers 200 on a ready TerraBase member (TS-483) and ts-auth.
	HealthPath = "/readyz"
	// OrchHealthPath answers 200 while a controller serves the Machines API.
	OrchHealthPath = "/healthz"
	// IdleTimeout outlasts Cloudflare's 100 s proxy timeout, so Cloudflare,
	// not the load balancer, ends a slow request; long-polls must return
	// within 100 s.
	IdleTimeout = 120
)

// originPullCA is Cloudflare's shared CA, retained only to reject it as
// customer-specific origin trust. It must never be installed on the edge.
//
//go:embed origin-pull-ca.pem
var originPullCA string

// The load balancer's certificate bundles.
const (
	originCertificate = "origin"
	memberCA          = "member-ca"
	// cellCA is the cell's controller CA, which the Machines API backends'
	// certificates chain to.
	cellCA = "cell-ca"
)

// TerraBase Management requests go to their own backend set, so an operator
// can pin catalog writes to the catalog primary while it moves (TS-578);
// otherwise it holds the same members as terrabase.
const (
	primarySet       = "terrabase-primary"
	managementRoutes = "terrabase_routes"
)

// managementRules is the terrabase listener's routing policy.
var managementRules = []any{map[string]any{"name": "management_to_primary", "condition": "any(http.request.url.path sw '/v1/management')",
	"actions": []any{map[string]any{"name": "FORWARD_TO_BACKENDSET", "backendSetName": primarySet}}}}

const usage = `Usage: ts-orch oci-region public-api <command> --plan PLAN [flags]

  preview     List every resource, certificate and record the edge uses; no calls
  cert        Create the Origin CA certificate into Vault and the load balancer (dry run unless --apply)
  apply       Create the missing network and load balancer: --member-ca FILE [--cell-ca FILE with public_api.orch]
  origin-ips  Sync the load balancer NSG to Cloudflare's published ranges (dry run unless --apply)
`

// Names are the static names of the cell's public API resources.
type Names struct {
	IGW, Routes, Security, Subnet, NSG, LB, Secret string
}

// Backend is one load balancer backend.
type Backend struct {
	Name string
	Addr netip.AddrPort
}

// Desired is a cell's public API as its plan describes it.
type Desired struct {
	Cell, Region                                      string
	Network, Control, VCN, ControllerNSG, WorkloadNSG string
	Vault, Key                                        string
	PrivateCIDR, PublicCIDR, APIHost, AuthHost        string
	ClientPort, MinMbps, MaxMbps                      int
	Names                                             Names
	// TerraBase seeds the terrabase backend set when apply creates the load
	// balancer; Members are every planned member, which the controller may
	// put in it afterwards (TS-571).
	TerraBase, Members, Auth []Backend
	OriginPull               OriginPull
	// Owner is the plan's orchestrator_owner. When it is set, apply stamps
	// the controller's ownership of Owned on the load balancer.
	Owner string
	// Owned is the controller's resource key for the terrabase backend set.
	Owned ociresource.Key
	// OrchHost and Orch are the Machines API's host and its controllers,
	// when the plan's public_api.orch serves it (cellspec machines_api).
	OrchHost string
	Orch     []Backend
}

// host is one HTTPS hostname and the backend set it routes to.
type host struct{ set, name string }

// hosts are the hostnames the load balancer serves, each to its own set.
func (d Desired) hosts() []host {
	hosts := []host{{"terrabase", d.APIHost}, {"ts-auth", d.AuthHost}}
	if d.OrchHost != "" {
		hosts = append(hosts, host{"ts-orch", d.OrchHost})
	}
	return hosts
}

// hostNames are the hostnames the origin certificate must name.
func (d Desired) hostNames() []string {
	var names []string
	for _, h := range d.hosts() {
		names = append(names, h.name)
	}
	return names
}

type planFile struct {
	Cell       string `json:"cell"`
	Region     string `json:"region"`
	SubnetCIDR string `json:"subnet_cidr"`
	Hosts      []struct {
		Slot      string `json:"slot"`
		PrivateIP string `json:"private_ip"`
	} `json:"hosts"`
	OrchestratorOwner string `json:"orchestrator_owner"`
	PublicAPI         *struct {
		SubnetCIDR   string `json:"subnet_cidr"`
		ListenerPort int    `json:"listener_port"`
		ClientPort   int    `json:"client_port"`
		MinMbps      int    `json:"min_mbps"`
		MaxMbps      int    `json:"max_mbps"`
		// TerraBaseMembers seeds the terrabase backend set when apply creates
		// the load balancer. The controller's oci_reconcile.public_lb owns
		// its backends afterwards; apply no longer converges them.
		//
		// ponytail: the plan lists gru-1-db-1 only. Members serve diverging
		// catalogs until TS-561 replicates them, so a new cell starts with one.
		TerraBaseMembers []string    `json:"terrabase_members"`
		OriginPull       *OriginPull `json:"origin_pull"`
		// Orch serves <region>.orch.terrascale.tech, the controllers'
		// Machines API.
		Orch bool `json:"orch"`
	} `json:"public_api"`
	ResourceIDs map[string]any `json:"resource_ids"`
}

// LoadPlan reads a regional plan's public API.
func LoadPlan(path string) (Desired, error) {
	if path == "" {
		return Desired{}, errors.New("--plan is required")
	}
	wire, err := os.ReadFile(path)
	if err != nil {
		return Desired{}, err
	}
	return ParsePlan(wire)
}

func (p planFile) desired() (Desired, error) {
	if !catalog.IsOCIRegion(p.Region) || catalog.OCIRegion(p.Cell) != p.Region {
		return Desired{}, fmt.Errorf("plan cell %q and region %q are not a catalog cell", p.Cell, p.Region)
	}
	public := p.PublicAPI
	if public == nil || public.MinMbps < 10 || public.MaxMbps < public.MinMbps || public.MaxMbps > 8000 {
		return Desired{}, errors.New("plan public_api must declare load balancer bandwidth: 10 <= min_mbps <= max_mbps <= 8000")
	}
	if public.ListenerPort != 443 {
		return Desired{}, errors.New("plan public_api.listener_port must be 443")
	}
	private, err := netip.ParsePrefix(p.SubnetCIDR)
	if err != nil {
		return Desired{}, fmt.Errorf("private subnet CIDR: %w", err)
	}
	subnet, err := netip.ParsePrefix(public.SubnetCIDR)
	if err != nil || subnet.Overlaps(private) {
		return Desired{}, fmt.Errorf("public API subnet %q must be a CIDR outside the private subnet", public.SubnetCIDR)
	}
	if public.ClientPort < 1 || public.ClientPort > 65535 {
		return Desired{}, errors.New("public API client port must be between 1 and 65535")
	}
	cell := naming.RegionCell(p.Cell)
	var names Names
	for _, n := range []struct {
		target *string
		part   string
	}{{&names.IGW, "igw"}, {&names.Routes, "routes"}, {&names.Security, "security"}, {&names.Subnet, "subnet"},
		{&names.NSG, "nsg"}, {&names.Secret, "origin"}, {&names.LB, ""}} {
		if *n.target, err = cell.API(n.part); err != nil {
			return Desired{}, err
		}
	}
	cellName, err := cell.Name()
	if err != nil {
		return Desired{}, err
	}
	id := func(key string) string { s, _ := p.ResourceIDs[key].(string); return s }
	d := Desired{Cell: cellName, Region: p.Region, Network: id("network_compartment"),
		Control: id("control_compartment"), VCN: id("vcn"), ControllerNSG: id("network_security_group"), WorkloadNSG: id("workload_network_security_group"),
		Vault: id("vault"), Key: id("key"), PrivateCIDR: private.String(), PublicCIDR: subnet.String(),
		// <region>.<service>.terrascale.tech; Atlas fronts the global names.
		APIHost: strings.ToLower(p.Cell) + ".api.terrascale.tech", AuthHost: strings.ToLower(p.Cell) + ".auth.terrascale.tech", ClientPort: public.ClientPort,
		MinMbps: public.MinMbps, MaxMbps: public.MaxMbps, Names: names,
		Owner: p.OrchestratorOwner, Owned: ociresource.Key{Region: p.Cell, Kind: lb.Kind, Name: lb.PublicTerraBase}}
	if d.Owner != "" {
		if err := errors.Join(d.ownership().Validate(), d.Owned.Validate()); err != nil {
			return Desired{}, fmt.Errorf("plan orchestrator_owner: %w", err)
		}
	}
	// Unbound templates remain previewable; operational paths require this
	// reviewed customer CA and uploaded Cloudflare client certificate.
	if public.OriginPull != nil {
		if err := public.OriginPull.Validate(); err != nil {
			return Desired{}, err
		}
		d.OriginPull = *public.OriginPull
	}
	// A cell without database hosts runs TerraBase on its controllers.
	members, controllers := map[string]netip.Addr{}, map[string]netip.Addr{}
	slots := map[string]bool{}
	addresses := map[netip.Addr]bool{}
	for _, h := range p.Hosts {
		if slots[h.Slot] {
			return Desired{}, fmt.Errorf("host slot %q is repeated", h.Slot)
		}
		slots[h.Slot] = true
		ip, err := netip.ParseAddr(h.PrivateIP)
		if err != nil || !private.Contains(ip) {
			return Desired{}, fmt.Errorf("host %s address %q is outside the private subnet", h.Slot, h.PrivateIP)
		}
		if addresses[ip] {
			return Desired{}, fmt.Errorf("host address %q is repeated", h.PrivateIP)
		}
		addresses[ip] = true
		switch {
		case strings.HasPrefix(h.Slot, "controller-"):
			name, err := cell.ControllerSlot(h.Slot)
			if err != nil {
				return Desired{}, err
			}
			d.Auth = append(d.Auth, Backend{name, netip.AddrPortFrom(ip, AuthPort)})
			if public.Orch {
				d.Orch = append(d.Orch, Backend{name, netip.AddrPortFrom(ip, OrchPort)})
			}
			controllers[name] = ip
		case strings.HasPrefix(h.Slot, "member-"):
			letter := strings.TrimPrefix(h.Slot, "member-")
			if len(letter) != 1 || letter[0] < 'a' || letter[0] > 'z' {
				return Desired{}, fmt.Errorf("unsupported member slot %q", h.Slot)
			}
			name, err := cell.Server(naming.Member, int(letter[0]-'a')+1)
			if err != nil {
				return Desired{}, err
			}
			members[name] = ip
		default:
			return Desired{}, fmt.Errorf("unsupported host slot %q", h.Slot)
		}
	}
	slices.SortFunc(d.Auth, func(a, b Backend) int { return strings.Compare(a.Name, b.Name) })
	slices.SortFunc(d.Orch, func(a, b Backend) int { return strings.Compare(a.Name, b.Name) })
	if public.Orch {
		d.OrchHost = strings.ToLower(p.Cell) + ".orch.terrascale.tech"
	}
	if len(members) == 0 {
		maps.Copy(members, controllers)
	}
	for name, ip := range members {
		d.Members = append(d.Members, Backend{name, netip.AddrPortFrom(ip, uint16(d.ClientPort))})
	}
	slices.SortFunc(d.Members, func(a, b Backend) int { return strings.Compare(a.Name, b.Name) })
	for _, name := range public.TerraBaseMembers {
		ip, ok := members[name]
		if !ok || slices.ContainsFunc(d.TerraBase, func(b Backend) bool { return b.Name == name }) {
			return Desired{}, fmt.Errorf("public_api.terrabase_members %q is not a distinct planned member", name)
		}
		d.TerraBase = append(d.TerraBase, Backend{name, netip.AddrPortFrom(ip, uint16(d.ClientPort))})
	}
	if len(d.TerraBase) == 0 || len(d.Auth) == 0 {
		return Desired{}, errors.New("plan needs public_api.terrabase_members and controllers for ts-auth")
	}
	return d, nil
}

// Rule is one stateful TCP rule: the source of an ingress rule or the
// destination of an egress rule, and its destination port.
type Rule struct {
	CIDR string
	Port int
}

func (r Rule) json(side string) map[string]any {
	return map[string]any{"protocol": tcp, side: r.CIDR, side + "Type": "CIDR_BLOCK", "isStateless": false,
		"tcpOptions": map[string]any{"destinationPortRange": map[string]any{"min": r.Port, "max": r.Port}}}
}

// listed parses an NSG rule from its CLI-shaped listing; ok is false for any
// rule other than a stateful single-port TCP ingress from a CIDR and any
// source port.
func listed(row map[string]any) (r Rule, ok bool) {
	options, _ := row["tcp-options"].(map[string]any)
	ports, _ := options["destination-port-range"].(map[string]any)
	low, high := fmt.Sprint(ports["min"]), fmt.Sprint(ports["max"])
	port, err := strconv.Atoi(low)
	ok = err == nil && low == high && options["source-port-range"] == nil && row["direction"] == "INGRESS" && row["protocol"] == tcp &&
		row["source-type"] == "CIDR_BLOCK" && row["is-stateless"] != true
	return Rule{fmt.Sprint(row["source"]), port}, ok
}

// Egress is the public subnet's security list egress: the load balancer
// reaches the members' client port and ts-auth. It admits nothing inbound;
// the load balancer's NSG admits Cloudflare.
func (d Desired) Egress() []Rule {
	rules := []Rule{{d.PrivateCIDR, d.ClientPort}, {d.PrivateCIDR, AuthPort}}
	if d.OrchHost != "" {
		rules = append(rules, Rule{d.PrivateCIDR, OrchPort})
	}
	return rules
}

// OriginRules are the load balancer NSG's ingress rules for Cloudflare's ranges.
func OriginRules(ranges []string) []Rule {
	var rules []Rule
	for _, cidr := range ranges {
		rules = append(rules, Rule{cidr, 80}, Rule{cidr, 443})
	}
	return rules
}

func backends(list []Backend) []any {
	out := make([]any, len(list))
	for i, b := range list {
		out[i] = map[string]any{"ipAddress": b.Addr.Addr().String(), "port": b.Addr.Port()}
	}
	return out
}

func health(port int) map[string]any { return healthAt(port, HealthPath) }

func healthAt(port int, path string) map[string]any {
	return map[string]any{"protocol": "HTTP", "port": port, "urlPath": path, "returnCode": 200,
		"intervalInMillis": 10000, "timeoutInMillis": 3000, "retries": 3}
}

// backendSets sends TerraBase over TLS verified against the member CA and
// ts-auth over HTTP, each health-checked on GET /readyz.
func (d Desired) backendSets() map[string]map[string]any {
	sets := map[string]map[string]any{
		"terrabase": {"policy": "ROUND_ROBIN", "backends": backends(d.TerraBase), "healthChecker": health(d.ClientPort),
			"sslConfiguration": map[string]any{"certificateName": memberCA, "verifyPeerCertificate": true, "verifyDepth": 1}},
		"ts-auth": {"policy": "ROUND_ROBIN", "backends": backends(d.Auth), "healthChecker": health(AuthPort)},
	}
	sets[primarySet] = maps.Clone(sets["terrabase"])
	// The Machines API speaks TLS with each controller's signed certificate,
	// which the cell CA signs directly.
	if d.OrchHost != "" {
		sets["ts-orch"] = map[string]any{"policy": "ROUND_ROBIN", "backends": backends(d.Orch), "healthChecker": healthAt(OrchPort, OrchHealthPath),
			"sslConfiguration": map[string]any{"certificateName": cellCA, "verifyPeerCertificate": true, "verifyDepth": 1}}
	}
	return sets
}

// httpsListener is the HTTPS listener for a backend set's hostname, serving
// certificate and requiring Cloudflare's origin-pull client certificate. The
// terrabase listener routes Management requests by managementRoutes.
func (d Desired) httpsListener(set, certificate string) map[string]any {
	listener := map[string]any{"defaultBackendSetName": set, "port": 443, "protocol": "HTTP", "hostnameNames": []string{set},
		"sslConfiguration":        map[string]any{"certificateName": certificate, "verifyPeerCertificate": true, "verifyDepth": 1},
		"connectionConfiguration": map[string]any{"idleTimeout": IdleTimeout}, "ruleSetNames": []string{"security-headers"}}
	if set == "terrabase" {
		listener["routingPolicyName"] = managementRoutes
	}
	return listener
}

// loadBalancer is the load balancer's configuration: HTTPS on 443 routed by
// hostname, each listener requiring Cloudflare's client certificate, and 80
// redirecting to HTTPS. TerraBase backends speak TLS verified against the
// member CA.
func (d Desired) loadBalancer(origin, key, members, cell string) map[string]string {
	header := func(name, value string) map[string]any {
		return map[string]any{"action": "ADD_HTTP_RESPONSE_HEADER", "header": name, "value": value}
	}
	certificates := map[string]any{
		originCertificate: map[string]any{"certificateName": originCertificate, "publicCertificate": origin, "privateKey": key, "caCertificate": d.OriginPull.CACertificate},
		memberCA:          map[string]any{"certificateName": memberCA, "caCertificate": members}}
	if d.OrchHost != "" {
		certificates[cellCA] = map[string]any{"certificateName": cellCA, "caCertificate": cell}
	}
	hostnames := map[string]any{}
	listeners := map[string]any{"http": map[string]any{"defaultBackendSetName": "terrabase", "port": 80, "protocol": "HTTP", "ruleSetNames": []string{"https-redirect"}}}
	for _, h := range d.hosts() {
		hostnames[h.set] = map[string]any{"name": h.set, "hostname": h.name}
		listeners[h.set] = d.httpsListener(h.set, originCertificate)
	}
	// OCI creates a load balancer without routing policies; apply adds
	// managementRoutes once it exists (routeManagement).
	delete(listeners["terrabase"].(map[string]any), "routingPolicyName")
	return map[string]string{
		"shape-details": command.JSON(map[string]any{"minimumBandwidthInMbps": d.MinMbps, "maximumBandwidthInMbps": d.MaxMbps}),
		"certificates":  command.JSON(certificates),
		"hostnames":     command.JSON(hostnames),
		"backend-sets":  command.JSON(d.backendSets()),
		"listeners":     command.JSON(listeners),
		"rule-sets": command.JSON(map[string]any{
			"https-redirect": map[string]any{"items": []any{map[string]any{"action": "REDIRECT", "responseCode": 301,
				"conditions":  []any{map[string]any{"attributeName": "PATH", "attributeValue": "/", "operator": "PREFIX_MATCH"}},
				"redirectUri": map[string]any{"protocol": "HTTPS", "host": "{host}", "port": 443, "path": "{path}", "query": "{query}"}}}},
			"security-headers": map[string]any{"items": []any{
				header("Strict-Transport-Security", "max-age=31536000; includeSubDomains"), header("X-Content-Type-Options", "nosniff")}}}),
	}
}

func names(list []Backend) string {
	parts := make([]string, len(list))
	for i, b := range list {
		parts[i] = fmt.Sprintf("%s %s", b.Name, b.Addr)
	}
	return strings.Join(parts, ", ")
}

// Preview lists every resource, certificate and record the edge uses.
func (d Desired) Preview() []string {
	lines := []string{
		fmt.Sprintf("internet-gateway %s: enabled in the cell VCN", d.Names.IGW),
		fmt.Sprintf("route-table %s: 0.0.0.0/0 to %s", d.Names.Routes, d.Names.IGW),
		fmt.Sprintf("security-list %s: no ingress; egress %s to %s", d.Names.Security, ports(d.Egress()), d.PrivateCIDR),
		fmt.Sprintf("subnet %s: %s, %s, %s", d.Names.Subnet, d.PublicCIDR, d.Names.Routes, d.Names.Security),
		fmt.Sprintf("network-security-group %s: tcp/80 and tcp/443 from each Cloudflare IPv4 range only (public-api origin-ips)", d.Names.NSG),
		fmt.Sprintf("nsg-rule %s: tcp/%d from %s (load balancer to TerraBase)", or(d.WorkloadNSG, "workload NSG"), d.ClientPort, d.PublicCIDR),
		fmt.Sprintf("nsg-rule %s: tcp/%d from %s (load balancer to ts-auth)", or(d.ControllerNSG, "controller NSG"), AuthPort, d.PublicCIDR),
		fmt.Sprintf("vault-secret %s: Cloudflare Origin CA certificate and RSA key for %s, %d days (public-api cert)", d.Names.Secret, strings.Join(d.hostNames(), " and "), originValidityDays),
		fmt.Sprintf("load-balancer %s: public, flexible %d-%d Mbps, NSG %s, idle timeout %ds", d.Names.LB, d.MinMbps, d.MaxMbps, d.Names.NSG, IdleTimeout),
		fmt.Sprintf("listener https %s: :443, Origin CA certificate, requires the customer origin-pull client certificate, to backend set terrabase", d.APIHost),
		fmt.Sprintf("listener https %s: :443, Origin CA certificate, requires the customer origin-pull client certificate, to backend set ts-auth", d.AuthHost),
		"listener http: :80, 301 to https",
		fmt.Sprintf("backend-set terrabase: seeded with %s, then owned by the controller (%s), TLS verified against the member CA, GET %s",
			names(d.TerraBase), or(ownedBy(d), "tag it before oci_reconcile.public_lb"), HealthPath),
		fmt.Sprintf("backend-set %s: the same, for /v1/management requests (routing policy %s)", primarySet, managementRoutes),
		fmt.Sprintf("backend-set ts-auth: %s, GET %s", names(d.Auth), HealthPath),
		fmt.Sprintf("cloudflare: SSL Full (strict) for %s, custom zone Authenticated Origin Pulls on; requires public_api.origin_pull CA and certificate ID (oci-region dns)", strings.Join(d.hostNames(), " and ")),
	}
	if d.OrchHost != "" {
		lines = append(lines[:len(lines)-1],
			fmt.Sprintf("nsg-rule %s: tcp/%d from %s (load balancer to the Machines API)", or(d.ControllerNSG, "controller NSG"), OrchPort, d.PublicCIDR),
			fmt.Sprintf("listener https %s: :443, Origin CA certificate, requires the customer origin-pull client certificate, to backend set ts-orch", d.OrchHost),
			fmt.Sprintf("backend-set ts-orch: %s, TLS verified against the cell CA, GET %s (cell spec machines_api)", names(d.Orch), OrchHealthPath),
			lines[len(lines)-1])
	}
	for _, name := range d.hostNames() {
		lines = append(lines, fmt.Sprintf("dns-record %s: A to the %s public IP, proxied (oci-region dns)", name, d.Names.LB))
	}
	return lines
}

// ports lists rules' ports, e.g. tcp/9465 and tcp/8080.
func ports(rules []Rule) string {
	var parts []string
	for _, r := range rules {
		parts = append(parts, fmt.Sprintf("tcp/%d", r.Port))
	}
	return strings.Join(parts, " and ")
}

// ownedBy names the ownership apply stamps, or nothing without an owner.
func ownedBy(d Desired) string {
	if d.Owner == "" {
		return ""
	}
	return fmt.Sprintf("freeform ownership %s for %s", d.Owned, d.Owner)
}

func or(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

// step is one planned change and the call that applies it.
type step struct {
	what string
	do   func(context.Context) error
}

// run prints each step and, with apply, applies them in order.
func run(ctx context.Context, steps []step, apply bool, out io.Writer) error {
	for _, s := range steps {
		if !apply {
			fmt.Fprintln(out, "plan: "+s.what)
			continue
		}
		if err := s.do(ctx); err != nil {
			return fmt.Errorf("%s: %w", s.what, err)
		}
		fmt.Fprintln(out, "applied: "+s.what)
	}
	var err error
	switch {
	case len(steps) == 0:
		_, err = fmt.Fprintln(out, "no changes")
	case !apply:
		_, err = fmt.Fprintf(out, "%d changes planned; rerun with --apply to apply them\n", len(steps))
	}
	return err
}

func Run(ctx context.Context, args []string, out io.Writer) error {
	if len(args) == 0 || slices.Contains([]string{"help", "-h", "--help"}, args[0]) {
		_, err := io.WriteString(out, usage)
		return err
	}
	sub := args[0]
	if !slices.Contains([]string{"preview", "cert", "apply", "origin-ips"}, sub) {
		return fmt.Errorf("unknown public-api command %q", sub)
	}
	fs := flag.NewFlagSet("oci-region public-api "+sub, flag.ContinueOnError)
	fs.SetOutput(out)
	planPath := fs.String("plan", "", "regional plan JSON")
	var apply bool
	var memberCAPath, cellCAPath string
	switch sub {
	case "cert", "origin-ips":
		fs.BoolVar(&apply, "apply", false, "make the planned changes; without it, only print them")
	case "apply":
		fs.StringVar(&memberCAPath, "member-ca", "", "member CA certificate (PEM) the load balancer trusts for TerraBase")
		fs.StringVar(&cellCAPath, "cell-ca", "", "cell CA certificate (PEM) the load balancer trusts for the Machines API; with public_api.orch")
	}
	if err := fs.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected arguments: %v", fs.Args())
	}
	d, err := LoadPlan(*planPath)
	if err != nil {
		return err
	}
	if sub == "preview" {
		_, err = fmt.Fprintf(out, "public-api for %s in %s:\n  %s\n", d.Names.LB, d.Region, strings.Join(d.Preview(), "\n  "))
		return err
	}
	client, err := newClient(d.Region, sub != "origin-ips")
	if err != nil {
		return err
	}
	p := Provisioner{Client: client}
	cloudflare := Cloudflare{BaseURL: cloudflareAPI}
	switch sub {
	case "origin-ips":
		steps, err := p.originSteps(ctx, d, cloudflare)
		if err != nil {
			return err
		}
		return run(ctx, steps, apply, out)
	case "cert":
		if cloudflare.Token, err = token(); err != nil {
			return err
		}
		steps, err := p.certSteps(ctx, d, cloudflare)
		if err != nil {
			return err
		}
		return run(ctx, steps, apply, out)
	}
	if memberCAPath == "" {
		return errors.New("--member-ca is required")
	}
	members, err := os.ReadFile(memberCAPath)
	if err != nil {
		return err
	}
	if (cellCAPath != "") != (d.OrchHost != "") {
		return errors.New("--cell-ca goes with public_api.orch")
	}
	var cell []byte
	if cellCAPath != "" {
		if cell, err = os.ReadFile(cellCAPath); err != nil {
			return err
		}
	}
	r, err := p.Provision(ctx, d, cloudflare, string(members), string(cell))
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

func token() (string, error) {
	t := strings.TrimSpace(os.Getenv(TokenEnv))
	if t == "" {
		return "", fmt.Errorf("Cloudflare API token is required in %s: read OCI Vault secret gru-1-cloudflare-dns-edit-token (docs/secrets.md)", TokenEnv)
	}
	return t, nil
}

// newClient builds the in-binary client and rejects SDK settings that expose secrets.
func newClient(region string, secret bool) (command.Client, error) {
	if secret {
		for _, name := range ociclient.SecretUnsafeEnv {
			if _, set := os.LookupEnv(name); set {
				return nil, fmt.Errorf("%s is refused: this command handles private keys", name)
			}
		}
	}
	return NewSDKClient(region)
}

// NewClient is the region's OCI client for commands that carry no key material.
func NewClient(region string) (command.Client, error) { return newClient(region, false) }

type Provisioner struct {
	Client       command.Client
	Pause        func(context.Context, time.Duration) error
	PollAttempts int
}

func Named(rows []map[string]any, name string) (map[string]any, error) {
	var found map[string]any
	for _, r := range rows {
		if r["display-name"] == name && !slices.Contains([]string{"TERMINATED", "TERMINATING", "DELETED", "DELETING", "PENDING_DELETION"}, fmt.Sprint(r["lifecycle-state"])) {
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

// await re-reads a named resource until ready accepts it.
func (p Provisioner) await(ctx context.Context, what string, read func() (map[string]any, error), ready func(map[string]any) bool) (map[string]any, error) {
	for n := range p.attempts() {
		r, err := read()
		if err != nil {
			return nil, err
		}
		if r != nil && ready(r) {
			return r, nil
		}
		if r != nil && slices.Contains([]string{"FAILED", "DELETED", "DELETING"}, fmt.Sprint(r["lifecycle-state"])) {
			return nil, fmt.Errorf("%s entered %v", what, r["lifecycle-state"])
		}
		if n+1 < p.attempts() {
			if err := p.pause(ctx, 10*time.Second); err != nil {
				return nil, err
			}
		}
	}
	return nil, fmt.Errorf("%s did not become ready", what)
}

// ensureNetwork returns the live VCN resource of kind with this name,
// creating it when permitted. Security and attachments must match the
// reviewed configuration; apply does not repair network drift.
func (p Provisioner) ensureNetwork(ctx context.Context, kind, name string, d Desired, create bool, extra ...string) (string, error) {
	rows, err := p.rows(ctx, "network", kind, "list", "--compartment-id", d.Network, "--vcn-id", d.VCN, "--all")
	if err != nil {
		return "", err
	}
	r, err := Named(rows, name)
	if err != nil {
		return "", err
	}
	if r == nil {
		if !create {
			return "", fmt.Errorf("%s %s does not exist; run public-api apply first", kind, name)
		}
		args := []string{"network", kind, "create", "--compartment-id", d.Network, "--vcn-id", d.VCN, "--display-name", name, "--wait-for-state", "AVAILABLE"}
		if r, err = p.data(ctx, append(args, extra...)...); err != nil {
			return "", err
		}
	}
	config, err := sdkcli.Parse(extra)
	if err != nil {
		return "", err
	}
	ok := r["lifecycle-state"] == "AVAILABLE" && r["compartment-id"] == d.Network && r["vcn-id"] == d.VCN
	switch kind {
	case "internet-gateway":
		ok = ok && r["is-enabled"] == true && r["route-table-id"] == nil
	case "route-table":
		var want []map[string]any
		if err := jsonFlag(config, "route-rules", &want); err != nil {
			return "", err
		}
		live, err := command.Rows(r["route-rules"])
		ok = ok && err == nil && len(live) == len(want)
		if ok {
			for i, rule := range live {
				ok = ok && rule["destination"] == want[i]["destination"] && rule["destination-type"] == want[i]["destinationType"] &&
					rule["network-entity-id"] == want[i]["networkEntityId"]
			}
		}
	case "security-list":
		ingress, err := command.Rows(r["ingress-security-rules"])
		_, hasIngress := r["ingress-security-rules"]
		ok = ok && hasIngress && err == nil && len(ingress) == 0
		egress, err := command.Rows(r["egress-security-rules"])
		want := d.Egress()
		ok = ok && err == nil && len(egress) == len(want)
		for _, row := range egress {
			rule, valid := listed(map[string]any{"direction": "INGRESS", "protocol": row["protocol"], "source": row["destination"],
				"source-type": row["destination-type"], "is-stateless": row["is-stateless"], "tcp-options": row["tcp-options"]})
			i := slices.Index(want, rule)
			ok = ok && valid && i >= 0 && row["is-stateless"] == false && row["udp-options"] == nil && row["icmp-options"] == nil
			if i >= 0 {
				want = slices.Delete(want, i, i+1)
			}
		}
		ok = ok && len(want) == 0
	case "subnet":
		var lists []string
		if err := jsonFlag(config, "security-list-ids", &lists); err != nil {
			return "", err
		}
		ok = ok && r["cidr-block"] == d.PublicCIDR && r["dns-label"] == config.Flags["dns-label"] &&
			r["prohibit-public-ip-on-vnic"] == false && r["prohibit-internet-ingress"] == false &&
			r["route-table-id"] == config.Flags["route-table-id"] && command.JSON(r["security-list-ids"]) == command.JSON(lists)
	}
	if !ok {
		return "", fmt.Errorf("%s %s differs from the reviewed network configuration; inspect drift before retrying", kind, name)
	}
	return command.ID(r)
}

type edgeNetwork struct {
	gateway, routes, security, subnet, nsg string
}

// network resolves the same reviewed network for provisioning and DNS.
// With create false it only reads, including when a resource is missing.
func (p Provisioner) network(ctx context.Context, d Desired, create bool) (edgeNetwork, error) {
	var edge edgeNetwork
	var err error
	edge.gateway, err = p.ensureNetwork(ctx, "internet-gateway", d.Names.IGW, d, create, "--is-enabled", "true")
	if err != nil {
		return edgeNetwork{}, err
	}
	edge.routes, err = p.ensureNetwork(ctx, "route-table", d.Names.Routes, d, create, "--route-rules",
		command.JSON([]any{map[string]any{"destination": "0.0.0.0/0", "destinationType": "CIDR_BLOCK", "networkEntityId": edge.gateway}}))
	if err != nil {
		return edgeNetwork{}, err
	}
	var egress []any
	for _, r := range d.Egress() {
		egress = append(egress, r.json("destination"))
	}
	edge.security, err = p.ensureNetwork(ctx, "security-list", d.Names.Security, d, create,
		"--ingress-security-rules", "[]", "--egress-security-rules", command.JSON(egress))
	if err != nil {
		return edgeNetwork{}, err
	}
	edge.subnet, err = p.ensureNetwork(ctx, "subnet", d.Names.Subnet, d, create, "--cidr-block", d.PublicCIDR, "--dns-label", "public",
		"--prohibit-public-ip-on-vnic", "false", "--route-table-id", edge.routes, "--security-list-ids", command.JSON([]string{edge.security}))
	if err != nil {
		return edgeNetwork{}, err
	}
	edge.nsg, err = p.ensureNetwork(ctx, "nsg", d.Names.NSG, d, create)
	return edge, err
}

func (d Desired) checkAttachments(balancer map[string]any, subnet, nsg string) error {
	if balancer["compartment-id"] != d.Network || command.JSON(balancer["subnet-ids"]) != command.JSON([]string{subnet}) ||
		command.JSON(balancer["network-security-group-ids"]) != command.JSON([]string{nsg}) {
		return fmt.Errorf("load balancer %s subnet or NSG attachments differ from the reviewed network configuration; inspect drift before retrying", d.Names.LB)
	}
	return nil
}

// validateOrigin shares read-only security checks between provisioning and DNS.
func (p Provisioner) validateOrigin(ctx context.Context, d Desired, balancer map[string]any, ranges []string) error {
	if err := d.CheckBalancer(balancer); err != nil {
		return err
	}
	edge, err := p.network(ctx, d, false)
	if err != nil {
		return err
	}
	if err := d.checkAttachments(balancer, edge.subnet, edge.nsg); err != nil {
		return err
	}
	rules, err := p.rows(ctx, "network", "nsg", "rules", "list", "--nsg-id", edge.nsg, "--all")
	if err != nil {
		return err
	}
	return CheckOriginRules(rules, ranges)
}

// syncRules plans the rule changes that leave an NSG with want as ingress;
// with remove, every other rule goes.
func (p Provisioner) syncRules(ctx context.Context, nsg, description string, want []Rule, remove bool) ([]step, error) {
	rows, err := p.rows(ctx, "network", "nsg", "rules", "list", "--nsg-id", nsg, "--all")
	if err != nil {
		return nil, err
	}
	have := map[Rule]bool{}
	var steps, removals []step
	for _, row := range rows {
		r, ok := listed(row)
		if ok && slices.Contains(want, r) && (!remove || !have[r]) {
			have[r] = true
			continue
		}
		if remove {
			id := fmt.Sprint(row["id"])
			removals = append(removals, step{fmt.Sprintf("remove %s rule %s from %v", nsg, id, row["source"]), func(ctx context.Context) error {
				_, err := p.Client.Call(ctx, "network", "nsg", "rules", "remove", "--nsg-id", nsg, "--security-rule-ids", command.JSON([]string{id}))
				return err
			}})
		}
	}
	for _, r := range want {
		if have[r] {
			continue
		}
		rule := r.json("source")
		rule["direction"], rule["description"] = "INGRESS", description
		steps = append(steps, step{fmt.Sprintf("add %s ingress tcp/%d from %s", nsg, r.Port, r.CIDR), func(ctx context.Context) error {
			_, err := p.Client.Call(ctx, "network", "nsg", "rules", "add", "--nsg-id", nsg, "--security-rules", command.JSON([]any{rule}))
			return err
		}})
	}
	// Additions first: a failure part way never leaves Cloudflare locked out.
	steps = append(steps, removals...)
	return steps, nil
}

func (p Provisioner) balancer(ctx context.Context, d Desired) (map[string]any, error) {
	rows, err := p.rows(ctx, "lb", "load-balancer", "list", "--compartment-id", d.Network, "--all")
	if err != nil {
		return nil, err
	}
	return Named(rows, d.Names.LB)
}

func (p Provisioner) nsg(ctx context.Context, d Desired) (string, error) {
	rows, err := p.rows(ctx, "network", "nsg", "list", "--compartment-id", d.Network, "--vcn-id", d.VCN, "--all")
	if err != nil {
		return "", err
	}
	r, err := Named(rows, d.Names.NSG)
	if err != nil || r == nil {
		return "", errors.Join(err, fmt.Errorf("network security group %s does not exist; run public-api apply", d.Names.NSG))
	}
	return command.ID(r)
}

// originSteps plans the load balancer NSG's sync to Cloudflare's ranges.
func (p Provisioner) originSteps(ctx context.Context, d Desired, cloudflare Cloudflare) ([]step, error) {
	if d.Network == "" || d.VCN == "" {
		return nil, errors.New("plan resource_ids.network_compartment and vcn are required")
	}
	ranges, err := cloudflare.OriginIPs(ctx)
	if err != nil {
		return nil, err
	}
	nsg, err := p.nsg(ctx, d)
	if err != nil {
		return nil, err
	}
	return p.syncRules(ctx, nsg, "Cloudflare to the public API", OriginRules(ranges), true)
}

// Provision creates the edge's missing network and load balancer in
// dependency order. Every resource is found by its static name first, so a
// rerun resumes. The origin certificate must already be in Vault.
func (p Provisioner) Provision(ctx context.Context, d Desired, cloudflare Cloudflare, members, cell string) (map[string]any, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := d.OriginPull.Validate(); err != nil {
		return nil, err
	}
	for key, value := range map[string]string{"network_compartment": d.Network, "control_compartment": d.Control, "vcn": d.VCN,
		"network_security_group": d.ControllerNSG, "workload_network_security_group": d.WorkloadNSG, "vault": d.Vault} {
		if value == "" {
			return nil, fmt.Errorf("plan resource_ids.%s is required", key)
		}
	}
	if err := validCA(members); err != nil {
		return nil, err
	}
	if d.OrchHost != "" {
		if err := validCA(cell); err != nil {
			return nil, err
		}
	}
	ranges, err := cloudflare.OriginIPs(ctx)
	if err != nil {
		return nil, err
	}
	balancer, err := p.balancer(ctx, d)
	if err != nil {
		return nil, err
	}
	var origin, key string
	if balancer == nil {
		secret, err := p.secret(ctx, d)
		if err != nil {
			return nil, err
		}
		if secret == nil {
			return nil, fmt.Errorf("vault secret %s does not exist; run public-api cert --apply first", d.Names.Secret)
		}
		if origin, key, err = p.originBundle(ctx, secret, d.hostNames()); err != nil {
			return nil, err
		}
	}
	edge, err := p.network(ctx, d, true)
	if err != nil {
		return nil, err
	}
	if balancer != nil {
		if err := d.checkAttachments(balancer, edge.subnet, edge.nsg); err != nil {
			return nil, err
		}
	}
	for _, sync := range []struct {
		id, description string
		rules           []Rule
		remove          bool
	}{
		{edge.nsg, "Cloudflare to the public API", OriginRules(ranges), true},
		{d.WorkloadNSG, "TerraBase HTTPS from the public API load balancer", []Rule{{d.PublicCIDR, d.ClientPort}}, false},
		{d.ControllerNSG, "ts-auth from the public API load balancer", []Rule{{d.PublicCIDR, AuthPort}}, false},
	} {
		if sync.id == d.ControllerNSG && d.OrchHost != "" {
			sync.rules = append(sync.rules, Rule{d.PublicCIDR, OrchPort})
		}
		steps, err := p.syncRules(ctx, sync.id, sync.description, sync.rules, sync.remove)
		if err != nil {
			return nil, err
		}
		if err := run(ctx, steps, true, io.Discard); err != nil {
			return nil, err
		}
	}
	if balancer == nil {
		args := []string{"lb", "load-balancer", "create", "--compartment-id", d.Network, "--display-name", d.Names.LB,
			"--shape-name", "flexible", "--subnet-ids", command.JSON([]string{edge.subnet}), "--is-private", "false",
			"--network-security-group-ids", command.JSON([]string{edge.nsg})}
		config := d.loadBalancer(origin, key, members, cell)
		for _, flag := range []string{"shape-details", "certificates", "hostnames", "backend-sets", "listeners", "rule-sets"} {
			args = append(args, "--"+flag, config[flag])
		}
		if _, err := p.Client.Call(ctx, args...); err != nil {
			return nil, err
		}
	}
	balancer, err = p.await(ctx, d.Names.LB, func() (map[string]any, error) { return p.balancer(ctx, d) },
		func(r map[string]any) bool { return r["lifecycle-state"] == "ACTIVE" })
	if err != nil {
		return nil, err
	}
	if err := d.checkAttachments(balancer, edge.subnet, edge.nsg); err != nil {
		return nil, err
	}
	// Renaming a host before its certificate names it would serve a mismatch.
	served, _ := field(balancer, "certificates", servedCertificate(balancer), "public-certificate").(string)
	if _, err := checkOriginCertificate(served, d.hostNames(), time.Now()); err != nil {
		return nil, fmt.Errorf("load balancer %s origin certificate: %w; run public-api cert --apply first", d.Names.LB, err)
	}
	if balancer, err = p.converge(ctx, d, balancer); err != nil {
		return nil, err
	}
	if balancer, err = p.routeManagement(ctx, d, balancer); err != nil {
		return nil, err
	}
	if err := d.checkAttachments(balancer, edge.subnet, edge.nsg); err != nil {
		return nil, err
	}
	// Certificates and listeners are fixed at creation; report drift apply
	// cannot repair rather than claim success.
	if !sameCA(balancer, memberCA, members) {
		return nil, fmt.Errorf("load balancer %s trusts a different member CA than --member-ca; add the new CA as another certificate bundle and point backend set terrabase at it", d.Names.LB)
	}
	if d.OrchHost != "" && !sameCA(balancer, cellCA, cell) {
		return nil, fmt.Errorf("load balancer %s trusts a different cell CA than --cell-ca", d.Names.LB)
	}
	if err := p.validateOrigin(ctx, d, balancer, ranges); err != nil {
		return nil, err
	}
	public, err := publicIP(balancer)
	if err != nil {
		return nil, err
	}
	return map[string]any{"internet_gateway": edge.gateway, "public_route_table": edge.routes, "public_security_list": edge.security,
		"public_subnet": edge.subnet, "network_load_balancer": balancer["id"], "load_balancer_nsg": edge.nsg, "public_ip": public.String()}, nil
}

// liveBackends are a live backend set's backends as sorted ip:port.
func liveBackends(balancer map[string]any, set string) []string {
	sets, _ := balancer["backend-sets"].(map[string]any)
	live, _ := sets[set].(map[string]any)
	rows, _ := command.Rows(live["backends"])
	var out []string
	for _, b := range rows {
		out = append(out, fmt.Sprintf("%v:%v", b["ip-address"], b["port"]))
	}
	slices.Sort(out)
	return out
}

// controllerOwned reports whether the controller's oci_reconcile.public_lb
// owns the terrabase backends: only a plan that names orchestrator_owner
// stamps the ownership the controller needs. Without it apply keeps
// converging the set to the seed, as before TS-571.
func (d Desired) controllerOwned() bool { return d.Owner != "" }

// ownership is the controller's freeform ownership for Owned.
func (d Desired) ownership() ociresource.Ownership {
	return ociresource.Ownership{Mode: ociresource.TagModeFreeform, Owner: d.Owner}
}

// freeformTags reads a CLI-shaped load balancer's freeform tags.
func freeformTags(balancer map[string]any) map[string]string {
	tags := map[string]string{}
	live, _ := balancer["freeform-tags"].(map[string]any)
	for name, value := range live {
		tags[name] = fmt.Sprint(value)
	}
	return tags
}

// ownershipTags returns the load balancer's freeform tags with the
// controller's ownership of the terrabase backend set added, or nil when
// they already carry it. A load balancer carrying any other or partial
// ownership claim is refused.
func (d Desired) ownershipTags(balancer map[string]any) (map[string]string, error) {
	tags := freeformTags(balancer)
	if d.ownership().Owns(d.Owned, ociresource.Tags{Freeform: tags}) {
		return nil, nil
	}
	if d.ownership().Claimed(ociresource.Tags{Freeform: tags}) {
		return nil, fmt.Errorf("load balancer %s carries another ts-orchestrator ownership than %s; resolve it by hand", d.Names.LB, d.Owned)
	}
	maps.Copy(tags, d.ownership().Stamp(d.Owned, 0, "").Freeform)
	return tags, nil
}

// converge brings an existing load balancer's bandwidth, hostnames and
// ts-auth backends to the plan, and stamps the controller's ownership of the
// terrabase backend set when the plan names its owner. The terrabase backends belong to the
// controller (oci_reconcile.public_lb), which drains seats during releases;
// rewriting them here would undo that.
func (p Provisioner) converge(ctx context.Context, d Desired, balancer map[string]any) (map[string]any, error) {
	id, err := command.ID(balancer)
	if err != nil {
		return nil, err
	}
	// Ownership comes first: a load balancer another owner claims is refused
	// before anything changes, and one the controller owns is never handed
	// back to an ownerless plan, which would converge its drained seats.
	if d.Owner == "" && d.ownership().Claimed(ociresource.Tags{Freeform: freeformTags(balancer)}) {
		return nil, fmt.Errorf("load balancer %s carries ts-orchestrator ownership; name orchestrator_owner in the plan", d.Names.LB)
	}
	if d.Owner != "" {
		tags, err := d.ownershipTags(balancer)
		if err != nil {
			return nil, err
		}
		if tags != nil {
			if _, err := p.Client.Call(ctx, "lb", "load-balancer", "update", "--load-balancer-id", id, "--freeform-tags", command.JSON(tags)); err != nil {
				return nil, err
			}
			if balancer, err = p.await(ctx, d.Names.LB, func() (map[string]any, error) { return p.balancer(ctx, d) }, func(r map[string]any) bool {
				owned, err := d.ownershipTags(r)
				return r["lifecycle-state"] == "ACTIVE" && owned == nil && err == nil
			}); err != nil {
				return nil, err
			}
		}
	}
	bandwidth := func(r map[string]any) bool {
		return same(field(r, "shape-details", "minimum-bandwidth-in-mbps"), d.MinMbps) && same(field(r, "shape-details", "maximum-bandwidth-in-mbps"), d.MaxMbps)
	}
	if !bandwidth(balancer) {
		if _, err := p.Client.Call(ctx, "lb", "load-balancer", "update-shape", "--load-balancer-id", id, "--shape-name", "flexible",
			"--shape-details", command.JSON(map[string]any{"minimumBandwidthInMbps": d.MinMbps, "maximumBandwidthInMbps": d.MaxMbps})); err != nil {
			return nil, err
		}
		if balancer, err = p.await(ctx, d.Names.LB, func() (map[string]any, error) { return p.balancer(ctx, d) }, func(r map[string]any) bool {
			return r["lifecycle-state"] == "ACTIVE" && bandwidth(r)
		}); err != nil {
			return nil, err
		}
	}
	for _, h := range d.hosts() {
		name, host := h.set, h.name
		if field(balancer, "hostnames", name, "hostname") == host {
			continue
		}
		if _, err := p.Client.Call(ctx, "lb", "hostname", "update", "--load-balancer-id", id, "--name", name, "--hostname", host); err != nil {
			return nil, err
		}
		if balancer, err = p.await(ctx, d.Names.LB, func() (map[string]any, error) { return p.balancer(ctx, d) }, func(r map[string]any) bool {
			return r["lifecycle-state"] == "ACTIVE" && field(r, "hostnames", name, "hostname") == host
		}); err != nil {
			return nil, err
		}
	}
	for name, set := range d.backendSets() {
		if (name == "terrabase" || name == primarySet) && d.controllerOwned() {
			continue
		}
		var want []string
		for _, b := range set["backends"].([]any) {
			want = append(want, fmt.Sprintf("%v:%v", b.(map[string]any)["ipAddress"], b.(map[string]any)["port"]))
		}
		slices.Sort(want)
		if slices.Equal(liveBackends(balancer, name), want) {
			continue
		}
		if _, err := p.Client.Call(ctx, "lb", "backend-set", "update", "--load-balancer-id", id, "--backend-set-name", name, "--details", command.JSON(set)); err != nil {
			return nil, err
		}
		if balancer, err = p.await(ctx, d.Names.LB, func() (map[string]any, error) { return p.balancer(ctx, d) }, func(r map[string]any) bool {
			return r["lifecycle-state"] == "ACTIVE" && slices.Equal(liveBackends(r, name), want)
		}); err != nil {
			return nil, err
		}
	}
	return balancer, nil
}

// routeManagement adds the managementRoutes routing policy and points the
// terrabase listener at it.
func (p Provisioner) routeManagement(ctx context.Context, d Desired, balancer map[string]any) (map[string]any, error) {
	id, err := command.ID(balancer)
	if err != nil {
		return nil, err
	}
	reload := func(ready func(map[string]any) bool) (err error) {
		balancer, err = p.await(ctx, d.Names.LB, func() (map[string]any, error) { return p.balancer(ctx, d) }, func(r map[string]any) bool {
			return r["lifecycle-state"] == "ACTIVE" && ready(r)
		})
		return err
	}
	if field(balancer, "routing-policies", managementRoutes) == nil {
		if _, err := p.Client.Call(ctx, "lb", "routing-policy", "create", "--load-balancer-id", id, "--name", managementRoutes,
			"--condition-language-version", "V1", "--rules", command.JSON(managementRules)); err != nil {
			return nil, err
		}
		if err := reload(func(r map[string]any) bool { return field(r, "routing-policies", managementRoutes) != nil }); err != nil {
			return nil, err
		}
	}
	if field(balancer, "listeners", "terrabase", "routing-policy-name") != managementRoutes {
		if _, err := p.Client.Call(ctx, "lb", "listener", "update", "--load-balancer-id", id, "--listener-name", "terrabase",
			"--details", command.JSON(d.httpsListener("terrabase", servedCertificate(balancer)))); err != nil {
			return nil, err
		}
		if err := reload(func(r map[string]any) bool {
			return field(r, "listeners", "terrabase", "routing-policy-name") == managementRoutes
		}); err != nil {
			return nil, err
		}
	}
	return balancer, nil
}

// publicIP is a load balancer's one public address.
func publicIP(balancer map[string]any) (netip.Addr, error) {
	addresses, err := command.Rows(balancer["ip-addresses"])
	if err != nil {
		return netip.Addr{}, err
	}
	var public []netip.Addr
	for _, a := range addresses {
		if ip, err := netip.ParseAddr(fmt.Sprint(a["ip-address"])); a["is-public"] == true && err == nil {
			public = append(public, ip)
		}
	}
	if len(public) != 1 {
		return netip.Addr{}, fmt.Errorf("load balancer %v has %d public addresses, want 1", balancer["display-name"], len(public))
	}
	return public[0], nil
}

// RunDNS validates the origin without OCI writes before planning Cloudflare
// changes, including on a dry run.
func (p Provisioner) RunDNS(ctx context.Context, d Desired, cloudflare Cloudflare, apply bool, out io.Writer) error {
	if d.Network == "" || d.VCN == "" {
		return errors.New("plan resource_ids.network_compartment and vcn are required")
	}
	balancer, err := p.balancer(ctx, d)
	if err != nil {
		return err
	}
	if balancer == nil || balancer["lifecycle-state"] != "ACTIVE" {
		return fmt.Errorf("load balancer %s is not ACTIVE; run public-api apply first", d.Names.LB)
	}
	ranges, err := cloudflare.OriginIPs(ctx)
	if err != nil {
		return err
	}
	if err := p.validateOrigin(ctx, d, balancer, ranges); err != nil {
		return err
	}
	address, err := publicIP(balancer)
	if err != nil {
		return err
	}
	steps, err := cloudflare.edgeSteps(ctx, d.hostNames(), address, d.Cell, d.OriginPull)
	if err != nil {
		return err
	}
	return run(ctx, steps, apply, out)
}

func RunDNS(ctx context.Context, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("oci-region dns", flag.ContinueOnError)
	fs.SetOutput(out)
	planPath := fs.String("plan", "", "regional plan JSON")
	apply := fs.Bool("apply", false, "make the planned changes; without it, only print them")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected arguments: %v", fs.Args())
	}
	d, err := LoadPlan(*planPath)
	if err != nil {
		return err
	}
	t, err := token()
	if err != nil {
		return err
	}
	client, err := newClient(d.Region, false)
	if err != nil {
		return err
	}
	return Provisioner{Client: client}.RunDNS(ctx, d, Cloudflare{BaseURL: cloudflareAPI, Token: t}, *apply, out)
}
