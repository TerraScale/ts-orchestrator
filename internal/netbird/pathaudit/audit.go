// Package pathaudit observes NetBird control-plane connections over NetBird SSH.
package pathaudit

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/logscan"
	"github.com/TerraScale/ts-orchestrator/internal/netbird"
	"github.com/TerraScale/ts-orchestrator/internal/netbird/sshlogin"
)

const usage = `Usage: ts-orch netbird path-audit --vault-id OCID --expected-ip IP [--netbird COMMAND] [--node NAME]...

Read every selected server through NetBird SSH, or every discovered server
when --node is absent. Check management, signal and WebSocket relay readiness,
their common FQDN, host resolution and every active daemon TCP 443 socket.
Exit 0 means these observations match the expected IP on every selected node.
This read-only audit does not prove STUN packet routing, mesh ICMP, replication
or failover. It never restarts a daemon, changes DNS or blocks traffic.
`

// RemoteCommand only reads status, resolution and sockets; it works with the
// existing client, so an audit needs no server installation or daemon restart.
// Socket data enters jq on stdin to avoid Linux's per-argument size limit.
const RemoteCommand = `set -eu
status=$(/usr/local/bin/netbird status --json | jq '{daemonStatus,management,signal,relays}')
pid=$(systemctl show --property=MainPID --value netbird.service)
addresses=$(getent ahosts netbird.terrascale.tech)
sockets=$(ss -Hnpt state established '( dport = :443 )')
printf '%s\n' "$sockets" | jq -Rs --argjson status "$status" --arg pid "$pid" --arg addresses "$addresses" '{status:$status,pid:$pid,addresses:$addresses,sockets:(split("\n") | map(select(contains("(\"netbird\",pid=" + $pid + ","))) | join("\n"))}'`

type endpoint struct {
	URL       string `json:"url"`
	Connected bool   `json:"connected"`
}

type snapshot struct {
	Status struct {
		DaemonStatus string   `json:"daemonStatus"`
		Management   endpoint `json:"management"`
		Signal       endpoint `json:"signal"`
		Relays       struct {
			Details []struct {
				URI       string `json:"uri"`
				Available bool   `json:"available"`
				Transport string `json:"transport"`
			} `json:"details"`
		} `json:"relays"`
	} `json:"status"`
	PID       string `json:"pid"`
	Addresses string `json:"addresses"`
	Sockets   string `json:"sockets"`
}

// Fetch reads one node. Errors must not include raw client output or credentials.
type Fetch func(context.Context, string) ([]byte, error)

// Run executes the operator audit without changing a server.
func Run(ctx context.Context, args []string, out io.Writer) error {
	flags := flag.NewFlagSet("netbird path-audit", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	vault := flags.String("vault-id", "", "Vault holding the automation login")
	client := flags.String("netbird", "netbird", "NetBird client command")
	expected := flags.String("expected-ip", "", "reviewed control-plane destination")
	var nodes []string
	flags.Func("node", "server peer name, repeatable", func(name string) error {
		nodes = append(nodes, name)
		return nil
	})
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			_, err = io.WriteString(out, usage)
			return err
		}
		return err
	}
	ip, err := netip.ParseAddr(*expected)
	if err != nil || ip.Zone() != "" || ip.Is4In6() || !ip.IsGlobalUnicast() || *vault == "" || flags.NArg() != 0 {
		return errors.New("path-audit requires --vault-id, --expected-ip (unicast IP), and no positional arguments")
	}
	if len(nodes) == 0 {
		peers, err := sshlogin.Peers(ctx, *client)
		if err != nil {
			return errors.New("path-audit cannot discover server peers")
		}
		nodes = logscan.Servers(peers)
	}
	return Audit(ctx, out, nodes, ip, func(ctx context.Context, node string) ([]byte, error) {
		var body bytes.Buffer
		if err := sshlogin.Session(ctx, *vault, *client, []string{"root@" + node, RemoteCommand}, nil, &body, io.Discard); err != nil {
			return nil, errors.New("NetBird SSH observation failed")
		}
		return body.Bytes(), nil
	})
}

// Audit reports every node even if one fails; an empty selection cannot pass.
func Audit(ctx context.Context, out io.Writer, nodes []string, expected netip.Addr, fetch Fetch) error {
	if len(nodes) == 0 {
		return errors.New("path-audit found no server peers")
	}
	seen := map[string]string{}
	for _, node := range nodes {
		seen[node] = ""
	}
	if len(logscan.Servers(seen)) != len(nodes) {
		return errors.New("path-audit requires unique server peer names")
	}
	var failures []error
	for _, node := range nodes {
		readCtx, cancel := context.WithTimeout(ctx, 45*time.Second)
		body, err := fetch(readCtx, node)
		cancel()
		if err == nil {
			err = inspect(body, expected)
		}
		if err != nil {
			failure := fmt.Errorf("%s: %w", node, err)
			failures = append(failures, failure)
			if _, err := fmt.Fprintf(out, "FAIL %s\n", failure); err != nil {
				return err
			}
		} else if _, err := fmt.Fprintf(out, "OK %s: NetBird SSH, control-plane FQDN and TCP 443 destination %s\n", node, expected); err != nil {
			return err
		}
	}
	return errors.Join(failures...)
}

func inspect(body []byte, expected netip.Addr) error {
	var s snapshot
	if len(body) > 1<<20 || json.Unmarshal(body, &s) != nil {
		return errors.New("invalid or oversized node observation")
	}
	host, _ := url.Parse(netbird.DefaultManagementURL)
	for _, endpoint := range []endpoint{s.Status.Management, s.Status.Signal} {
		u, err := url.Parse(endpoint.URL)
		if s.Status.DaemonStatus != "Connected" || !endpoint.Connected || err != nil ||
			u.Scheme != "https" || u.User != nil || u.Hostname() != host.Hostname() || u.Port() != "" && u.Port() != "443" ||
			u.Path != "" && u.Path != "/" || u.RawQuery != "" || u.Fragment != "" {
			return errors.New("management or signal is disconnected or uses a different HTTPS endpoint")
		}
	}
	secureRelay := false
	for _, relay := range s.Status.Relays.Details {
		if strings.HasPrefix(relay.URI, "stun:") {
			if relay.URI != "stun:"+host.Hostname()+":3478" {
				return errors.New("STUN uses a different endpoint")
			}
			continue
		}
		u, err := url.Parse(relay.URI)
		if err != nil || u.Scheme != "rels" || u.User != nil || u.Hostname() != host.Hostname() || u.Port() != "443" {
			return errors.New("secure relay uses a different endpoint")
		}
		if relay.Available && relay.Transport != "ws" {
			return errors.New("secure relay transport needs UDP path evidence; this audit requires WebSocket")
		}
		secureRelay = secureRelay || relay.Available
	}
	if !secureRelay {
		return errors.New("no available secure relay")
	}
	resolved := false
	for line := range strings.SplitSeq(s.Addresses, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		ip, err := netip.ParseAddr(fields[0])
		if err != nil || ip.Unmap() != expected {
			return errors.New("host resolution differs from the expected destination")
		}
		resolved = true
	}
	pid, err := strconv.Atoi(s.PID)
	if !resolved || err != nil || pid <= 0 {
		return errors.New("missing host resolution or active NetBird daemon PID")
	}
	connections := 0
	for line := range strings.SplitSeq(s.Sockets, "\n") {
		if !strings.Contains(line, `("netbird",pid=`+strconv.Itoa(pid)+",") {
			continue
		}
		fields := strings.Fields(line)
		// ss state established prints Recv-Q, Send-Q, local, peer, users.
		if len(fields) < 5 {
			return errors.New("cannot parse an active NetBird socket")
		}
		address, port, err := net.SplitHostPort(fields[3])
		if err != nil {
			return errors.New("cannot parse an active NetBird socket destination")
		}
		if port != "443" {
			continue
		}
		ip, err := netip.ParseAddr(address)
		if err != nil || ip.Unmap() != expected {
			return errors.New("an active NetBird TCP 443 socket uses a different destination")
		}
		connections++
	}
	if connections == 0 {
		return errors.New("no active NetBird daemon TCP 443 socket")
	}
	return nil
}
