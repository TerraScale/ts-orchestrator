package networkcheck

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func goodSnapshot(t *testing.T) snapshot {
	t.Helper()
	wire := "\x1ehostname\ndelta\n" +
		"\x1eaddresses\n" + `[{"ifname":"nb-wt0","addr_info":[{"local":"10.200.87.10","prefixlen":16}]},{"ifname":"tailscale0","addr_info":[{"local":"100.77.52.68","prefixlen":32},{"local":"fd7a:115c:a1e0::1","prefixlen":128}]},{"ifname":"eth0","addr_info":[{"local":"10.10.10.10","prefixlen":24}]}]` +
		"\x1eroutes4\n" + `[{"dst":"default","dev":"eth0"},{"dst":"10.200.0.0/16","dev":"nb-wt0"},{"dst":"100.115.156.95","dev":"tailscale0"},{"dst":"10.10.10.0/24","dev":"eth0"}]` +
		"\x1eroutes6\n" + `[{"dst":"fd7a:115c:a1e0::/48","dev":"tailscale0"}]` +
		"\x1enetbird-wt0\n" + `{"netbirdIp":"10.200.87.10/16","fqdn":"delta.nb.ts.internal","management":{"connected":true},"signal":{"connected":true},"peers":{"details":[{"fqdn":"ts-gru-1.nb.ts.internal","netbirdIp":"10.200.87.215","status":"Connected"}]}}` +
		"\x1etailscale\n" + `{"BackendState":"Running","Self":{"DNSName":"delta.tail057f.ts.net.","TailscaleIPs":["100.77.52.68","fd7a:115c:a1e0::1"]},"MagicDNSSuffix":"tail057f.ts.net","Peer":{"beta":{"DNSName":"beta.tail057f.ts.net.","TailscaleIPs":["100.115.156.95"],"Online":true}}}` +
		"\x1edns\nLink 6 (nb-wt0)\n Current Scopes: DNS\n Protocols: -DefaultRoute\n DNS Servers: 10.200.87.10\n DNS Domain: ~nb.ts.internal ~gru.ts.internal\n Default Route: no\nLink 5 (tailscale0)\n DNS Servers: 100.100.100.100\n DNS Domain: tail057f.ts.net ~ts.net\n" +
		"\x1eresolvconf\nnameserver 127.0.0.53\n"
	s, err := parseSnapshot([]byte(wire))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func probe(ctx context.Context, target target, command string) ([]byte, error) {
	switch {
	case strings.Contains(command, "getent ahostsv4 ts-gru-1"):
		return []byte("10.200.87.215 STREAM\n"), nil
	case strings.Contains(command, "getent ahostsv4 beta"):
		return []byte("100.115.156.95 STREAM\n"), nil
	default:
		return nil, nil
	}
}

func TestCheckRejectsFalseCoexistence(t *testing.T) {
	tests := []struct {
		name, want string
		change     func(*snapshot)
	}{
		{"healthy", "", func(s *snapshot) {}},
		{"tailscale absent", "not Running/enrolled", func(s *snapshot) { s.ts = tsStatus{} }},
		{"wrong mesh", "differs from planned", func(s *snapshot) { s.nb.IP = "10.200.87.10/8" }},
		{"mesh disconnected", "management/signal", func(s *snapshot) { s.nb.Signal.Connected = false }},
		{"LAN overlaps", "overlaps NetBird", func(s *snapshot) { s.routes = append(s.routes, route{Destination: "10.0.0.0/8", Device: "eth0"}) }},
		{"bridge overlaps", "overlaps mesh space", func(s *snapshot) { s.addresses[2].Name = "podman0"; s.addresses[2].Info[0].Local = "10.200.1.1" }},
		{"TS routed by NB", "overlaps Tailscale", func(s *snapshot) { s.routes = append(s.routes, route{Destination: "100.64.0.0/10", Device: "nb-wt0"}) }},
		{"IPv6 collision", "overlaps Tailscale", func(s *snapshot) {
			s.routes = append(s.routes, route{Destination: "fd7a:115c:a1e0::/48", Device: "nb-wt0"})
		}},
		{"DNS default", "takes the default route", func(s *snapshot) { s.dns = strings.ReplaceAll(s.dns, "-DefaultRoute", "+DefaultRoute") }},
		{"DNS root zone", "hijacks zone .", func(s *snapshot) { s.dns = strings.ReplaceAll(s.dns, "~gru.ts.internal", "~.") }},
		{"own reverse zones", "", func(s *snapshot) {
			s.dns = strings.ReplaceAll(s.dns, "~gru.ts.internal", "~gru.ts.internal ~200.10.in-addr.arpa ~2.f.5.6.2.8.1.2.0.0.2.0.c.9.d.f.ip6.arpa")
		}},
		{"Tailscale reverse hijack", "hijacks zone 100.in-addr.arpa", func(s *snapshot) { s.dns = strings.ReplaceAll(s.dns, "~gru.ts.internal", "~100.in-addr.arpa") }},
		{"NetBird default route", "installs a default route", func(s *snapshot) { s.routes = append(s.routes, route{Destination: "default", Device: "nb-wt0"}) }},
		{"DNS parent zone", "hijacks zone ts.internal", func(s *snapshot) { s.dns = strings.ReplaceAll(s.dns, "~gru.ts.internal", "~ts.internal") }},
		{"MagicDNS removed", "resolver is absent", func(s *snapshot) { s.dns = strings.ReplaceAll(s.dns, "100.100.100.100", "1.1.1.1") }},
		{"global NetBird resolver", "global resolv.conf", func(s *snapshot) { s.resolvconf = "nameserver 10.200.87.10\nnameserver 100.100.100.100\n" }},
		{"stub hides global NetBird resolver", "global systemd-resolved nameserver (DNS domains: ~.)", func(s *snapshot) {
			s.dns = "Global\n DNS Servers: 10.200.87.10\n DNS Domain: ~.\n" + s.dns
		}},
		{"stub hides global IPv6 NetBird fallback", "global systemd-resolved nameserver", func(s *snapshot) {
			s.dns = "Global\n DNS Servers: 100.100.100.100\n Fallback DNS Servers: 1.1.1.1\n                       fd9c:200:2182:65f2::1\n DNS Domain: ~.\n" + s.dns
		}},
		{"global NetBird own-zone resolver", "global systemd-resolved nameserver", func(s *snapshot) {
			s.dns = "Global\n DNS Servers: 10.200.87.10\n DNS Domain: ~nb.ts.internal\n" + s.dns
		}},
		{"global NetBird resolver with TLS name and port", "global systemd-resolved nameserver", func(s *snapshot) {
			s.dns = "Global\n DNS Servers: 10.200.87.10:53#resolver.nb.ts.internal\n DNS Domain: ~.\n" + s.dns
		}},
		{"global MagicDNS preserved", "", func(s *snapshot) {
			s.dns = "Global\n DNS Servers: 100.100.100.100\n DNS Domain: ~. tail057f.ts.net\n" + s.dns
		}},
		{"DNS inspection absent", "scope inspection unavailable", func(s *snapshot) { s.dns = ""; s.resolvconf = "nameserver 100.100.100.100\n" }},
		{"DNS scope absent", "own-zone DNS scope is absent", func(s *snapshot) { s.dns = strings.ReplaceAll(s.dns, "~nb.ts.internal", "") }},
		{"custom NetBird interface hijack", "hijacks zone .", func(s *snapshot) {
			s.addresses[0].Name = "overlay0"
			s.dns = strings.ReplaceAll(s.dns, "nb-wt0", "overlay0")
			s.dns = strings.ReplaceAll(s.dns, "~gru.ts.internal", "~.")
			for i := range s.routes {
				if s.routes[i].Device == "nb-wt0" {
					s.routes[i].Device = "overlay0"
				}
			}
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := goodSnapshot(t)
			tt.change(&s)
			err := check(t.Context(), target{name: "local"}, s, probe)
			if tt.want == "" && err != nil || tt.want != "" && (err == nil || !strings.Contains(err.Error(), tt.want)) {
				t.Fatalf("want %q, got %v", tt.want, err)
			}
		})
	}
}

func TestConnectedInterfacesDoNotReplaceLiveChecks(t *testing.T) {
	for _, missing := range []string{"dev/tcp", "tailscale ping", "getent"} {
		t.Run(missing, func(t *testing.T) {
			read := func(ctx context.Context, target target, command string) ([]byte, error) {
				if strings.Contains(command, missing) {
					return nil, errors.New("failed")
				}
				return probe(ctx, target, command)
			}
			if err := check(t.Context(), target{name: "local"}, goodSnapshot(t), read); err == nil {
				t.Fatal("failed live probe accepted")
			}
		})
	}
}

func TestSnapshotSelectsTerraScaleContainerAndRejectsIncompleteReads(t *testing.T) {
	s := goodSnapshot(t)
	var wire bytes.Buffer
	for name, value := range map[string]any{"addresses": s.addresses, "routes4": s.routes, "routes6": []route{}, "tailscale": s.ts, "netbird-wt0": nbStatus{}, "netbird-ops": s.nb} {
		data, _ := json.Marshal(value)
		fmt.Fprintf(&wire, "\x1e%s\n%s\n", name, data)
	}
	wire.WriteString("\x1ehostname\nmariogk-dev\n")
	parsed, err := parseSnapshot(wire.Bytes())
	if err != nil || parsed.nb.Name != s.nb.Name {
		t.Fatalf("container selection: %v, %v", parsed.nb, err)
	}
	if _, err := parseSnapshot([]byte("\x1ehostname\nunreadable\n")); err == nil {
		t.Fatal("incomplete snapshot accepted")
	}
	if _, err := parseSnapshot(append(wire.Bytes(), []byte("\x1eaddresses\n[]")...)); err == nil {
		t.Fatal("duplicate section accepted")
	}
}

func TestFleetContinuesAfterUnreadableHostAndExitsUnsuccessfully(t *testing.T) {
	var visited []string
	read := func(ctx context.Context, target target, command string) ([]byte, error) {
		visited = append(visited, target.name)
		return nil, errors.New("unreadable")
	}
	var out bytes.Buffer
	err := checkTargets(t.Context(), []target{{name: "delta"}, {name: "beta"}}, &out, read)
	if err == nil || len(visited) != 2 || !strings.Contains(out.String(), "FAIL beta") {
		t.Fatalf("incomplete fleet check: %v %s", err, out.String())
	}
}

func TestTargetIdentityAndBridgeLANCrossCheck(t *testing.T) {
	s := goodSnapshot(t)
	if err := checkIdentity(target{name: "beta"}, s); err == nil {
		t.Fatal("beta accepted delta")
	}
	if err := checkIdentity(target{name: "ts-gru-1", node: true}, s); err == nil {
		t.Fatal("regional target accepted delta")
	}
	s.hostname = "gru-1-ctl-1"
	s.nb.Name = "ts-gru-1.nb.ts.internal"
	if err := checkIdentity(target{name: "ts-gru-1", node: true}, s); err != nil {
		t.Fatal(err)
	}
	s = goodSnapshot(t)
	bridge := s.addresses[2]
	bridge.Name = "podman0"
	s.addresses = append(s.addresses, bridge)
	if err := checkRoutes(s, true); err == nil || !strings.Contains(err.Error(), "overlaps podman0") {
		t.Fatalf("bridge/LAN collision accepted: %v", err)
	}
}

func TestServerRequiresNetBirdWithoutTailscaleOrClientDNS(t *testing.T) {
	tests := []struct {
		name, want string
		change     func(*snapshot)
	}{
		{"healthy", "", func(s *snapshot) {}},
		{"NetBird disconnected", "management/signal", func(s *snapshot) { s.nb.Signal.Connected = false }},
		{"NetBird interface absent", "NetBird must own", func(s *snapshot) { s.addresses = s.addresses[1:] }},
		{"live NetBird probe", "unreachable", func(s *snapshot) {}},
		{"CGNAT route", "overlaps Tailscale", func(s *snapshot) { s.routes = append(s.routes, route{Destination: "100.64.0.0/10", Device: "nb-wt0"}) }},
		{"Tailscale IPv6 route", "overlaps Tailscale", func(s *snapshot) {
			s.routes = append(s.routes, route{Destination: "fd7a:115c:a1e0::/48", Device: "nb-wt0"})
		}},
		{"NetBird default route", "installs a default route", func(s *snapshot) { s.routes = append(s.routes, route{Destination: "default", Device: "nb-wt0"}) }},
		{"NetBird DNS hijack", "hijacks zone .", func(s *snapshot) { s.dns += "Link 3 (nb-wt0)\n Current Scopes: DNS\n DNS Domain: ~.\n" }},
		{"DNS inspection absent", "scope inspection unavailable", func(s *snapshot) { s.dns = "" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := goodSnapshot(t)
			s.hostname, s.nb.Name, s.ts = "ts-fra-1", "ts-fra-1.nb.ts.internal", tsStatus{}
			s.addresses = []address{s.addresses[0], s.addresses[2]}
			s.addresses[1].Info[0].Local, s.addresses[1].Info[0].Bits = "10.253.0.11", 25
			s.routes = []route{{Destination: "10.200.0.0/16", Device: "nb-wt0"}, {Destination: "10.253.0.0/25", Device: "eth0"}}
			s.dns = "Link 2 (eth0)\n Current Scopes: DNS\n DNS Servers: 169.254.169.254\n DNS Domain: fra1.oraclevcn.com\n"
			tt.change(&s)
			read := func(ctx context.Context, target target, command string) ([]byte, error) {
				if strings.Contains(command, "tailscale") || strings.Contains(command, "getent") {
					t.Fatalf("server required a client-only probe: %s", command)
				}
				if tt.name == "live NetBird probe" && strings.Contains(command, "dev/tcp") {
					return nil, errors.New("unreachable")
				}
				return probe(ctx, target, command)
			}
			err := check(t.Context(), target{name: "ts-fra-1", node: true}, s, read)
			if tt.want == "" && err != nil || tt.want != "" && (err == nil || !strings.Contains(err.Error(), tt.want)) {
				t.Fatalf("want %q, got %v", tt.want, err)
			}
			if tt.name == "healthy" {
				if err := check(t.Context(), target{name: "local"}, s, probe); err == nil || !strings.Contains(err.Error(), "not Running/enrolled") {
					t.Fatalf("same unenrolled snapshot passed as a PC/client: %v", err)
				}
			}
		})
	}
}

func TestPCIsNotARegionalNode(t *testing.T) {
	if err := Run(t.Context(), []string{"check", "--node", "delta"}, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "regional NetBird peer") {
		t.Fatalf("PC accepted as a server: %v", err)
	}
}

func TestRegionalProbeIncludesFutureCatalogRegions(t *testing.T) {
	s := goodSnapshot(t)
	s.nb.Name = "ts-fra-1.nb.ts.internal"
	var command string
	read := func(ctx context.Context, target target, value string) ([]byte, error) {
		if strings.Contains(value, "dev/tcp") {
			command = value
		}
		return probe(ctx, target, value)
	}
	if err := check(t.Context(), target{name: "ts-fra-1", node: true}, s, read); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(command, "10.200.87.215/9443") {
		t.Fatalf("server probe used wrong policy port: %s", command)
	}
}

func TestServerProbeSkipsSplitCellControllers(t *testing.T) {
	s := goodSnapshot(t)
	s.nb.Name = "ts-sfo-1.nb.ts.internal"
	peer := s.nb.Peers.Details[0]
	s.nb.Peers.Details = nil
	for i, name := range []string{"gru-1-ctl-1", "gru-1-gw-1", "gru-1-db-1-data", "gru-1-db-0", "gru-1-db-1"} {
		peer.Name = name + ".nb.ts.internal"
		peer.IP = fmt.Sprintf("10.200.87.%d", i+1)
		s.nb.Peers.Details = append(s.nb.Peers.Details, peer)
	}
	var commands []string
	read := func(ctx context.Context, target target, command string) ([]byte, error) {
		commands = append(commands, command)
		if !strings.Contains(command, "10.200.87.5/9443") {
			return nil, errors.New("no TerraBase listener")
		}
		return nil, nil
	}
	if err := check(t.Context(), target{name: "ts-sfo-1", node: true}, s, read); err != nil {
		t.Fatal(err)
	}
	if len(commands) != 1 {
		t.Fatalf("unexpected probes: %v", commands)
	}
	s.nb.Peers.Details = s.nb.Peers.Details[:4]
	if err := check(t.Context(), target{name: "ts-sfo-1", node: true}, s, read); err == nil || !strings.Contains(err.Error(), "no connected regional") {
		t.Fatalf("non-serving peers accepted as TerraBase endpoints: %v", err)
	}
}
