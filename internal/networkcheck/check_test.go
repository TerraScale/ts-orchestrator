package networkcheck

import (
	"bytes"
	"encoding/json"
	"fmt"
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
