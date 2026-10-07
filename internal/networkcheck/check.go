// Package networkcheck observes mesh coexistence without changing a host.
package networkcheck

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"regexp"
	"slices"
	"strings"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/logscan"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/naming"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/netbird/sshlogin"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/networkplan"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociregion/catalog"
)

const usage = `Usage: ts-orch network check [--all] [--host SSH_ALIAS]... [--node NETBIRD_NAME]... [--vault-id OCID] [--netbird COMMAND]

Read-only Linux check: addresses and all routing tables (IPv4 + IPv6),
NetBird connectivity and DNS scoping. PCs/user clients also require Tailscale,
MagicDNS and live reachability through both meshes; servers require NetBird only.
Without targets checks this host. --all checks delta, beta, mariogk-dev and
every regional server visible to the operator's NetBird client. --host uses
strict, batch SSH for PCs/clients; --node checks a regional server through the
existing Vault-backed NetBird SSH login. Server NetBird DNS may be disabled.
No install, enrollment, routes, DNS settings or services are changed.
Exit 0 means every requested host passed; missing meshes and failed or
unavailable checks fail. Run disconnected user clients locally when online.
`

// Collect only public status, never daemon configuration or credentials.
// Record separators keep multiline JSON and resolver output unambiguous.
const snapshotCommand = `set -eu
part() { printf '\036%s\n' "$1"; }
part hostname; hostname
part addresses; ip -j address show
part routes4; ip -j -4 route show table all
part routes6; ip -j -6 route show table all
part netbird-wt0; sudo -n netbird-wt0 status --json 2>/dev/null || printf 'null\n'
part netbird; netbird status --json 2>/dev/null || printf 'null\n'
part netbird-ops; sudo -n podman exec -i ts-netbird-ops netbird status --json 2>/dev/null || printf 'null\n'
part tailscale; tailscale status --json 2>/dev/null || printf 'null\n'
part dns; LC_ALL=C resolvectl status 2>/dev/null || true
part resolvconf; cat /etc/resolv.conf
`

type target struct {
	name string
	node bool
}

type address struct {
	Name string `json:"ifname"`
	Info []struct {
		Local string `json:"local"`
		Bits  int    `json:"prefixlen"`
		Scope string `json:"scope"`
	} `json:"addr_info"`
}

type route struct {
	Destination string `json:"dst"`
	Device      string `json:"dev"`
	Type        string `json:"type"`
}

type nbStatus struct {
	IP         string `json:"netbirdIp"`
	Name       string `json:"fqdn"`
	Management struct {
		Connected bool `json:"connected"`
	} `json:"management"`
	Signal struct {
		Connected bool `json:"connected"`
	} `json:"signal"`
	Peers struct {
		Details []struct {
			Name   string `json:"fqdn"`
			IP     string `json:"netbirdIp"`
			Status string `json:"status"`
		} `json:"details"`
	} `json:"peers"`
}

type tsPeer struct {
	Name   string   `json:"DNSName"`
	IPs    []string `json:"TailscaleIPs"`
	Online bool     `json:"Online"`
}

type tsStatus struct {
	State  string `json:"BackendState"`
	Self   tsPeer
	Peers  map[string]tsPeer `json:"Peer"`
	Suffix string            `json:"MagicDNSSuffix"`
}

type snapshot struct {
	hostname, dns, resolvconf string
	addresses                 []address
	routes                    []route
	nb                        nbStatus
	ts                        tsStatus
}

// fetch is the existing process boundary; tests substitute recorded hosts.
type fetch func(context.Context, target, string) ([]byte, error)

func Run(ctx context.Context, args []string, out io.Writer) error {
	if len(args) == 0 || args[0] == "--help" || args[0] == "help" {
		_, err := io.WriteString(out, usage)
		return err
	}
	if args[0] != "check" {
		return errors.New("network supports check; use ts-orch network --help")
	}
	flags := flag.NewFlagSet("network check", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	all := flags.Bool("all", false, "check all T3 hosts and visible regional nodes")
	vault := flags.String("vault-id", "", "NetBird automation Vault")
	nb := flags.String("netbird", "netbird", "operator NetBird command")
	var targets []target
	flags.Func("host", "PC/client SSH alias, repeatable", func(s string) error {
		if !regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9@.-]{0,100}$`).MatchString(s) {
			return errors.New("invalid SSH host alias")
		}
		targets = append(targets, target{name: s})
		return nil
	})
	flags.Func("node", "regional NetBird peer, repeatable", func(s string) error {
		if err := naming.Validate(s); err != nil {
			return fmt.Errorf("--node requires a regional NetBird peer; use --host for PCs/clients: %w", err)
		}
		targets = append(targets, target{name: s, node: true})
		return nil
	})
	if err := flags.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			_, err = io.WriteString(out, usage)
		}
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("network check accepts no positional arguments")
	}
	if *all {
		for _, host := range []string{"delta", "beta", "mariogk-dev"} {
			targets = append(targets, target{name: host})
		}
		peers, err := sshlogin.Peers(ctx, *nb)
		if err != nil {
			return fmt.Errorf("discover regional nodes: %w", err)
		}
		nodes := logscan.Servers(peers)
		if len(nodes) == 0 {
			return errors.New("no regional nodes discovered; cannot verify --all")
		}
		for _, name := range nodes {
			targets = append(targets, target{name: name, node: true})
		}
	}
	if len(targets) == 0 {
		targets = append(targets, target{name: "local"})
	}
	for _, t := range targets {
		if t.node && *vault == "" {
			return errors.New("--node and --all require --vault-id")
		}
	}
	read := func(ctx context.Context, t target, command string) ([]byte, error) {
		ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
		defer cancel()
		if t.node {
			var stdout, stderr bytes.Buffer
			err := sshlogin.Session(ctx, *vault, *nb, []string{"root@" + t.name, shellCommand(command)}, nil, &stdout, &stderr)
			return stdout.Bytes(), err
		}
		var cmd *exec.Cmd
		local, _ := os.Hostname()
		if t.name == "local" || t.name == local {
			cmd = exec.CommandContext(ctx, "sh", "-c", command)
		} else {
			cmd = exec.CommandContext(ctx, "ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "-o", "ConnectTimeout=10", "--", t.name, shellCommand(command))
		}
		return cmd.Output()
	}
	return checkTargets(ctx, slices.Compact(targets), out, read)
}

func shellCommand(command string) string {
	return "sh -c '" + strings.ReplaceAll(command, "'", "'\"'\"'") + "'"
}

func checkTargets(ctx context.Context, targets []target, out io.Writer, read fetch) error {
	failed := 0
	for _, t := range targets {
		wire, err := read(ctx, t, snapshotCommand)
		var s snapshot
		if err == nil {
			s, err = parseSnapshot(wire)
		}
		if err == nil {
			err = checkIdentity(t, s)
		}
		if err == nil {
			err = check(ctx, t, s, read)
		}
		if err != nil {
			fmt.Fprintf(out, "FAIL %s (%s): %s\n", t.name, s.hostname, strings.ReplaceAll(err.Error(), "\n", "; "))
			failed++
		} else {
			checks := "scoped NetBird DNS; MagicDNS; both meshes reachable"
			if t.node {
				checks = "NetBird DNS scoped or disabled; NetBird reachable"
			}
			fmt.Fprintf(out, "OK %s (%s): disjoint routes; %s\n", t.name, s.hostname, checks)
		}
	}
	if failed > 0 {
		return fmt.Errorf("network check failed on %d of %d hosts", failed, len(targets))
	}
	return nil
}

func checkIdentity(t target, s snapshot) error {
	if t.node {
		peer, _, _ := strings.Cut(s.nb.Name, ".")
		if peer != t.name {
			return fmt.Errorf("target %s reports NetBird identity %s", t.name, s.nb.Name)
		}
	} else if slices.Contains([]string{"delta", "beta", "mariogk-dev"}, t.name) && s.hostname != t.name {
		return fmt.Errorf("target %s reports hostname %s", t.name, s.hostname)
	}
	return nil
}

func parseSnapshot(wire []byte) (snapshot, error) {
	var s snapshot
	if len(wire) > 4<<20 {
		return s, errors.New("host status exceeds 4 MiB")
	}
	parts := map[string]string{}
	for _, section := range strings.Split(string(wire), "\x1e")[1:] {
		name, body, ok := strings.Cut(section, "\n")
		if !ok || parts[name] != "" {
			return s, errors.New("invalid host status sections")
		}
		parts[name] = strings.TrimSpace(body)
	}
	s.hostname, s.dns, s.resolvconf = parts["hostname"], parts["dns"], parts["resolvconf"]
	for name, into := range map[string]any{"addresses": &s.addresses, "tailscale": &s.ts} {
		if err := json.Unmarshal([]byte(parts[name]), into); err != nil {
			return s, fmt.Errorf("invalid %s status", name)
		}
	}
	for _, name := range []string{"routes4", "routes6"} {
		var rows []route
		if err := json.Unmarshal([]byte(parts[name]), &rows); err != nil {
			return s, fmt.Errorf("invalid %s status", name)
		}
		s.routes = append(s.routes, rows...)
	}
	for _, name := range []string{"netbird-wt0", "netbird", "netbird-ops"} {
		var status nbStatus
		if json.Unmarshal([]byte(parts[name]), &status) == nil && status.Management.Connected &&
			strings.HasSuffix(status.Name, ".nb.ts.internal") {
			s.nb = status
			break
		}
	}
	if s.hostname == "" || len(s.addresses) == 0 {
		return s, errors.New("missing host identity or addresses")
	}
	return s, nil
}

func check(ctx context.Context, t target, s snapshot, read fetch) error {
	var failures []error
	add := func(err error) {
		if err != nil {
			failures = append(failures, err)
		}
	}
	client := !t.node
	add(checkRoutes(s, client))
	add(checkDNS(s, client))
	if !s.nb.Management.Connected || !s.nb.Signal.Connected {
		add(errors.New("TerraScale NetBird management/signal is disconnected or absent"))
	}
	if client && (s.ts.State != "Running" || len(s.ts.Self.IPs) == 0) {
		add(errors.New("Tailscale is not Running/enrolled"))
	}
	// NetBird server policy admits cross-region 9443, operators use SSH 22.
	var nbName, nbIP string
	port := 22
	region := serverRegion(s.nb.Name)
	if region != "" {
		port = 9443
	}
	for _, peer := range s.nb.Peers.Details {
		if peer.Status != "Connected" || !strings.HasSuffix(peer.Name, ".nb.ts.internal") {
			continue
		}
		peerRegion := serverRegion(peer.Name)
		if peerRegion == "" || peerRegion == region {
			continue
		}
		// Split-cell controllers do not serve TerraBase. Probe database
		// members or the role-free nodes used by colocated cells instead.
		name, _, _ := strings.Cut(peer.Name, ".")
		if port == 9443 && !naming.IsNode(name, peerRegion) &&
			!(naming.Validate(name) == nil && strings.HasPrefix(name, peerRegion+"-1-"+naming.Member+"-") && !strings.HasSuffix(name, "-data")) {
			continue
		}
		if nbName == "" || peer.Name < nbName {
			nbName, nbIP = peer.Name, peer.IP
		}
	}
	if nbName == "" {
		add(errors.New("no connected regional NetBird peer for a live probe"))
	} else if ip, err := netip.ParseAddr(nbIP); err != nil || !netip.MustParsePrefix(networkplan.Mesh).Contains(ip) {
		add(errors.New("NetBird probe address is outside the mesh reservation"))
	} else {
		command := fmt.Sprintf("timeout 5 bash -c ':</dev/tcp/%s/%d'", ip, port)
		if _, err := read(ctx, t, command); err != nil {
			add(fmt.Errorf("NetBird TCP %s:%d unreachable", ip, port))
		}
		if client {
			add(checkLookup(ctx, t, nbName, nbIP, read))
		}
	}
	if !client {
		return errors.Join(failures...)
	}
	var ts tsPeer
	for _, peer := range s.ts.Peers {
		if peer.Online && len(peer.IPs) > 0 && (ts.Name == "" || peer.Name < ts.Name) {
			ts = peer
		}
	}
	if ts.Name == "" {
		add(errors.New("no online Tailscale peer for a live probe"))
	} else if ip, err := netip.ParseAddr(ts.IPs[0]); err != nil || !netip.MustParsePrefix(networkplan.Tailscale).Contains(ip) {
		add(errors.New("Tailscale probe address is outside CGNAT"))
	} else {
		if _, err := read(ctx, t, "tailscale ping --c 1 --timeout 5s "+ip.String()); err != nil {
			add(fmt.Errorf("Tailscale peer %s unreachable", ip))
		}
		add(checkLookup(ctx, t, ts.Name, ip.String(), read))
	}
	return errors.Join(failures...)
}

func serverRegion(name string) string {
	for _, region := range catalog.Names() {
		if strings.HasPrefix(name, "ts-"+region+"-") || strings.HasPrefix(name, region+"-1-") {
			return region
		}
	}
	return ""
}

func checkLookup(ctx context.Context, t target, name, expected string, read fetch) error {
	if !regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9.-]{0,253}$`).MatchString(name) {
		return errors.New("invalid mesh DNS name")
	}
	wire, err := read(ctx, t, "timeout 5 getent ahostsv4 "+name)
	if err == nil {
		for _, line := range strings.Split(string(wire), "\n") {
			fields := strings.Fields(line)
			if len(fields) > 0 && fields[0] == expected {
				return nil
			}
		}
	}
	return fmt.Errorf("native DNS %s does not resolve to %s", name, expected)
}

func checkRoutes(s snapshot, client bool) error {
	meshIP, _ := netip.ParsePrefix(s.nb.IP)
	meshDevice, tsDevice := "", ""
	for _, iface := range s.addresses {
		for _, info := range iface.Info {
			ip, _ := netip.ParseAddr(info.Local)
			if meshIP.IsValid() && ip == meshIP.Addr() {
				meshDevice = iface.Name
			}
			if slices.Contains(s.ts.Self.IPs, info.Local) {
				tsDevice = iface.Name
			}
		}
	}
	if meshDevice == "" {
		return errors.New("NetBird must own a host interface")
	}
	if (client && tsDevice == "") || meshDevice == tsDevice {
		return errors.New("both meshes must own separate host interfaces")
	}
	mesh4, mesh6 := netip.MustParsePrefix(networkplan.Mesh), netip.MustParsePrefix(networkplan.MeshIPv6)
	ts4, ts6 := netip.MustParsePrefix(networkplan.Tailscale), netip.MustParsePrefix(networkplan.TailscaleIPv6)
	if meshIP.Masked() != mesh4 {
		return fmt.Errorf("NetBird address %s differs from planned %s", meshIP, mesh4)
	}
	var failures []error
	for i, iface := range s.addresses {
		for _, info := range iface.Info {
			ip, err := netip.ParseAddr(info.Local)
			if err != nil {
				return errors.New("invalid interface address")
			}
			p := netip.PrefixFrom(ip, info.Bits).Masked()
			if !p.IsValid() {
				return errors.New("invalid interface prefix length")
			}
			if iface.Name != meshDevice && iface.Name != tsDevice && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() &&
				(p.Overlaps(mesh4) || p.Overlaps(mesh6) || p.Overlaps(ts4) || p.Overlaps(ts6)) {
				failures = append(failures, fmt.Errorf("%s %s overlaps mesh space", iface.Name, p))
			}
			if ip.IsLoopback() || ip.IsLinkLocalUnicast() {
				continue
			}
			for _, other := range s.addresses[i+1:] {
				for _, candidate := range other.Info {
					qIP, _ := netip.ParseAddr(candidate.Local)
					q := netip.PrefixFrom(qIP, candidate.Bits).Masked()
					if !qIP.IsLoopback() && !qIP.IsLinkLocalUnicast() && p.Overlaps(q) {
						failures = append(failures, fmt.Errorf("%s %s overlaps %s %s", iface.Name, p, other.Name, q))
					}
				}
			}
		}
	}
	for _, r := range s.routes {
		if r.Type == "local" || r.Type == "broadcast" || r.Type == "multicast" {
			continue
		}
		p, err := netip.ParsePrefix(r.Destination)
		if err != nil {
			if ip, err := netip.ParseAddr(r.Destination); err == nil {
				p = netip.PrefixFrom(ip, ip.BitLen())
			} else if r.Destination == "default" {
				if r.Device == meshDevice {
					failures = append(failures, errors.New("NetBird installs a default route"))
				}
				continue
			} else {
				return fmt.Errorf("invalid route %q", r.Destination)
			}
		}
		if p.Bits() == 0 {
			if r.Device == meshDevice {
				failures = append(failures, errors.New("NetBird installs a default route"))
			}
			continue
		} // ordinary default gateways are not allocations
		if (p.Overlaps(mesh4) || p.Overlaps(mesh6)) && r.Device != meshDevice {
			failures = append(failures, fmt.Errorf("route %s via %s overlaps NetBird", p, r.Device))
		}
		if (p.Overlaps(ts4) || p.Overlaps(ts6)) && (tsDevice == "" || r.Device != tsDevice) {
			failures = append(failures, fmt.Errorf("route %s via %s overlaps Tailscale", p, r.Device))
		}
		if r.Device == meshDevice {
			for _, iface := range s.addresses {
				if iface.Name == meshDevice || iface.Name == tsDevice {
					continue
				}
				for _, info := range iface.Info {
					ip, _ := netip.ParseAddr(info.Local)
					if !ip.IsLoopback() && !ip.IsLinkLocalUnicast() && p.Overlaps(netip.PrefixFrom(ip, info.Bits).Masked()) {
						failures = append(failures, fmt.Errorf("NetBird route %s overlaps %s", p, iface.Name))
					}
				}
			}
		}
	}
	return errors.Join(failures...)
}

func meshInterface(s snapshot) string {
	ip, err := netip.ParsePrefix(s.nb.IP)
	if err != nil {
		return ""
	}
	for _, iface := range s.addresses {
		for _, address := range iface.Info {
			if address.Local == ip.Addr().String() {
				return iface.Name
			}
		}
	}
	return ""
}

func checkDNS(s snapshot, client bool) error {
	var failures []error
	if s.dns == "" {
		return errors.New("DNS scope inspection unavailable (requires systemd-resolved)")
	}
	device, scoped := meshInterface(s), false
	// A resolver in resolv.conf is global, even when MagicDNS is also listed.
	for _, line := range strings.Split(s.resolvconf, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] != "nameserver" {
			continue
		}
		ip, err := netip.ParseAddr(fields[1])
		if err == nil && (netip.MustParsePrefix(networkplan.Mesh).Contains(ip) || netip.MustParsePrefix(networkplan.MeshIPv6).Contains(ip)) {
			failures = append(failures, errors.New("NetBird is a global resolv.conf nameserver"))
		}
	}
	// Check every NetBird link, including another installed account/client.
	links := regexp.MustCompile(`(?m)^Link [0-9]+ \(([^)]+)\)`).FindAllStringSubmatchIndex(s.dns, -1)
	// A stub resolv.conf hides global systemd-resolved nameservers.
	global := s.dns
	if len(links) > 0 {
		global = s.dns[:links[0][0]]
	}
	for _, value := range strings.Fields(global) {
		server, _, _ := strings.Cut(value, "#") // resolved may display a TLS server name
		ip, err := netip.ParseAddr(server)
		if err != nil {
			endpoint, _ := netip.ParseAddrPort(server)
			ip = endpoint.Addr()
		}
		ip = ip.WithZone("")
		if netip.MustParsePrefix(networkplan.Mesh).Contains(ip) || netip.MustParsePrefix(networkplan.MeshIPv6).Contains(ip) {
			domains, _ := resolverDomains(global)
			failures = append(failures, fmt.Errorf("NetBird is a global systemd-resolved nameserver (DNS domains: %s)", strings.Join(domains, " ")))
			break
		}
	}
	for i, loc := range links {
		name := s.dns[loc[2]:loc[3]]
		end := len(s.dns)
		if i+1 < len(links) {
			end = links[i+1][0]
		}
		section := s.dns[loc[1]:end]
		isNB := name == device || strings.HasPrefix(name, "nb-") || strings.HasPrefix(name, "wt")
		if isNB && strings.Contains(section, "Current Scopes: DNS") {
			if strings.Contains(section, "+DefaultRoute") || strings.Contains(section, "Default Route: yes") {
				failures = append(failures, fmt.Errorf("NetBird DNS on %s takes the default route", name))
			}
			domain, present := resolverDomains(section)
			if !present {
				failures = append(failures, fmt.Errorf("NetBird DNS on %s has no own-zone scope", name))
			}
			for _, d := range domain {
				d = strings.TrimPrefix(d, "~")
				if name == device && d == "nb.ts.internal" {
					scoped = true
				}
				if d != "nb.ts.internal" && d != "gru.ts.internal" && d != "200.10.in-addr.arpa" &&
					d != "2.f.5.6.2.8.1.2.0.0.2.0.c.9.d.f.ip6.arpa" &&
					!strings.HasSuffix(d, ".nb.ts.internal") && !strings.HasSuffix(d, ".gru.ts.internal") {
					failures = append(failures, fmt.Errorf("NetBird DNS on %s hijacks zone %s", name, d))
				}
			}
		}
	}
	if client && !scoped {
		failures = append(failures, errors.New("NetBird own-zone DNS scope is absent"))
	}
	if client && !strings.Contains(s.dns, "100.100.100.100") && !strings.Contains(s.resolvconf, "nameserver 100.100.100.100") {
		failures = append(failures, errors.New("Tailscale MagicDNS resolver is absent"))
	}
	return errors.Join(failures...)
}

func resolverDomains(section string) ([]string, bool) {
	lines := strings.Split(section, "\n")
	for i, line := range lines {
		if _, value, ok := strings.Cut(line, "DNS Domain:"); ok {
			domains := strings.Fields(value)
			for _, next := range lines[i+1:] {
				if strings.Contains(next, ":") {
					break
				}
				domains = append(domains, strings.Fields(next)...)
			}
			return domains, len(domains) > 0
		}
	}
	return nil, false
}
