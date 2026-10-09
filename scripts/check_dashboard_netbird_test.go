package scripts

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Exercise the shipped script without contacting OCI or any controller. The
// fixture checks token transport as well as the pass/fail report contract.
func TestDashboardNetbirdCheck(t *testing.T) {
	for _, mode := range []string{"blocked-host", "green", "equivalent-aaaa", "dns-change", "name-ipv6", "extra-a", "extra-aaaa", "health-wrong-peer", "topology-wrong-peer", "html", "empty-nodes", "multiple-json", "bad-a", "bad-aaaa", "missing-aaaa", "inventory-fail", "inventory-mismatch", "missing-peer", "duplicate-peer", "inventory-no-ipv6", "tcp-fail", "health-503", "topology-401", "vault-fail", "bad-route", "route-missing", "interface-missing", "ambiguous-interface", "non-wireguard-interface", "disconnected-client", "interface-change", "alternate-interface"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			fixture := filepath.Join(dir, "fixture")
			if err := os.WriteFile(fixture, []byte(dashboardFixture), 0o700); err != nil {
				t.Fatal(err)
			}
			for _, name := range []string{"oci", "netbird", "getent", "nc", "curl", "hostname", "ip"} {
				if err := os.Symlink(fixture, filepath.Join(dir, name)); err != nil {
					t.Fatal(err)
				}
			}
			log := filepath.Join(dir, "argv")
			cmd := exec.CommandContext(t.Context(), "bash", "-x", "check-dashboard-netbird")
			cmd.Env = append(os.Environ(), "PATH="+dir+":"+os.Getenv("PATH"), "NB=netbird", "CHECK_MODE="+mode, "CHECK_LOG="+log, "TMPDIR="+dir)
			output, err := cmd.CombinedOutput()
			green := mode == "green" || mode == "equivalent-aaaa" || mode == "dns-change" || mode == "name-ipv6" || mode == "alternate-interface"
			if (err == nil) != green {
				t.Fatalf("mode %s: %v\n%s", mode, err, output)
			}
			if mode == "blocked-host" {
				if !strings.Contains(string(output), "Run only on delta, beta or mariogk-dev.") {
					t.Fatalf("missing host restriction: %s", output)
				}
				args, err := os.ReadFile(log)
				if err != nil || string(args) != "hostname -s\n" {
					t.Fatalf("blocked host ran network commands: %s (%v)", args, err)
				}
				return
			}
			if strings.Count(string(output), "\n| ts-") != 18 {
				t.Fatalf("expected all 18 transport rows:\n%s", output)
			}
			args, err := os.ReadFile(log)
			if err != nil {
				t.Fatal(err)
			}
			for _, token := range []string{"fixture-gru-secret", "fixture-sfo-secret"} {
				if strings.Contains(string(output)+string(args), token) {
					t.Fatal("token leaked into output or argv")
				}
			}
			switch mode {
			case "inventory-fail", "inventory-mismatch", "missing-peer", "duplicate-peer":
				if strings.Contains(string(args), ":9463/topology") || !strings.Contains(string(output), "IDENTITY-FAIL") {
					t.Fatal("unverified inventory received an authenticated request")
				}
				if strings.Count(string(args), "nc ") != 12 || strings.Count(string(args), "/healthz") != 12 {
					t.Fatal("inventory failure suppressed unauthenticated IPv4 or name probes")
				}
			case "bad-route", "route-missing", "interface-missing", "ambiguous-interface", "non-wireguard-interface", "disconnected-client":
				if strings.Contains(string(args), ":9463/topology") || !strings.Contains(string(output), "TRANSPORT-FAIL") {
					t.Fatal("unverified transport received an authenticated request")
				}
				if strings.Count(string(args), "nc ") != 18 || strings.Count(string(args), "/healthz") != 18 {
					t.Fatal("transport failure suppressed unauthenticated probes")
				}
			case "interface-change":
				if strings.Contains(string(args), "AUTH-SENT") || !strings.Contains(string(output), "CONNECT-FAIL") {
					t.Fatal("interface disappearance sent a token or was accepted")
				}
			case "health-wrong-peer", "health-503":
				if strings.Contains(string(args), ":9463/topology") {
					t.Fatal("failed health preflight received an authenticated request")
				}
			case "inventory-no-ipv6":
				if strings.Count(string(args), ":9463/topology") != 6 {
					t.Fatal("valid IPv4 inventory without IPv6 did not retain its authenticated IPv4 probes")
				}
			}
			if strings.Contains(string(args), "BAD-TRANSPORT") {
				t.Fatal("authenticated request was not bound to the selected client's interface")
			}
			if strings.Contains(string(args), "BAD-PIN") {
				t.Fatal("authenticated name request was not pinned to a validated DNS address")
			}
			for _, ip := range []string{"10.200.87.215", "10.200.38.135", "10.200.168.164", "10.200.112.213", "10.200.122.37", "10.200.63.195"} {
				if !green && !strings.Contains(string(args), "netbird ssh --no-browser root@"+ip+" ss -ltnp | grep 9463") {
					t.Fatalf("missing diagnostic for inventory IP %s", ip)
				}
			}
			for _, line := range strings.Split(string(args), "\n") {
				if strings.HasPrefix(line, "curl ") && strings.Contains(line, ".nb.ts.internal:9463/topology") {
					switch mode {
					case "bad-a", "bad-aaaa", "extra-a", "extra-aaaa", "missing-aaaa", "inventory-fail", "health-wrong-peer":
						t.Fatal("invalid DNS or endpoint identity received an authenticated name request")
					}
				}
			}
			if (mode == "health-wrong-peer" || mode == "topology-wrong-peer") && !strings.Contains(string(output), "WRONG-PEER") {
				t.Fatal("wrong responding endpoint was accepted")
			}
			if strings.Contains(string(args), "BAD-AUTH") {
				t.Fatal("topology did not use its regional token via a private header file")
			}
			if green {
				if strings.Count(string(args), "curl --disable ") != 36 || strings.Count(string(args), "nc ") != 18 {
					t.Fatal("expected 18 TCP probes and 36 HTTP requests ignoring curlrc")
				}
				if !strings.Contains(string(output), "18/18 acceptance rows passed") || strings.Contains(string(args), "ssh ") {
					t.Fatalf("incorrect green report:\n%s", output)
				}
				if strings.Count(string(args), "nc -6 -z -w 3 fd9c:200::1 9463") != 6 {
					t.Fatal("IPv6 probes did not use the canonical address without a prefix length")
				}
			} else if !strings.Contains(string(output), "remote listen address (NetBird SSH)") || !strings.Contains(string(output), "LISTEN 0 4096 127.0.0.1:9463") {
				t.Fatalf("missing failing-controller diagnostic:\n%s", output)
			}
			if mode == "html" && !strings.Contains(string(output), "INVALID-JSON") {
				t.Fatal("HTML HTTP 200 was accepted as topology JSON")
			}
			entries, err := os.ReadDir(dir)
			if err != nil {
				t.Fatal(err)
			}
			for _, entry := range entries {
				if entry.IsDir() {
					t.Fatal("temporary credentials were not cleaned up")
				}
			}
		})
	}
}

const dashboardFixture = `#!/usr/bin/env bash
set -eu
tool=${0##*/}
printf '%s %s\n' "$tool" "$*" >> "$CHECK_LOG"
case $tool in
  hostname)
    if [[ $CHECK_MODE == blocked-host ]]; then printf 'mariogk-desktop\n'; else printf 'mariogk-dev\n'; fi
    ;;
  netbird)
    if [[ $1 == ssh ]]; then
      [[ $2 == --no-browser && $3 == root@10.200.* && $4 == 'ss -ltnp | grep 9463' ]] || exit 1
      [[ -z $(cat) ]] || exit 1
      printf 'LISTEN 0 4096 127.0.0.1:9463 0.0.0.0:*\n'
      exit
    fi
    [[ $CHECK_MODE != inventory-fail ]] || exit 1
    status=Connected
    [[ $CHECK_MODE != disconnected-client ]] || status=Disconnected
    printf '{"daemonStatus":"%s","netbirdIp":"10.200.0.33/16","peers":{"details":[' "$status"
    separator= ipv6=fd9c:200::1
    [[ $CHECK_MODE != inventory-no-ipv6 ]] || ipv6=
    [[ $CHECK_MODE != equivalent-aaaa ]] || ipv6=FD9C:0200:0000:0000:0000:0000:0000:0001/64
    [[ $CHECK_MODE != missing-peer ]] || { printf ' ]}}'; exit; }
    for pair in ts-gru-1:10.200.87.215 ts-gru-2:10.200.38.135 ts-gru-3:10.200.168.164 ts-sfo-1:10.200.112.213 ts-sfo-2:10.200.122.37 ts-sfo-3:10.200.63.195; do
      ip=${pair#*:}
      [[ $CHECK_MODE != inventory-mismatch ]] || ip=10.200.0.1
      printf '%s{"fqdn":"%s.nb.ts.internal","netbirdIp":"%s","netbirdIpv6":"%s"}' "$separator" "${pair%%:*}" "$ip" "$ipv6"
      separator=,
      if [[ $CHECK_MODE == duplicate-peer ]]; then
        printf ',{"fqdn":"%s.nb.ts.internal","netbirdIp":"%s","netbirdIpv6":"%s"}' "${pair%%:*}" "$ip" "$ipv6"
      fi
    done
    printf ']}}'
    ;;
  ip)
    interface=wt-fixture
    [[ $CHECK_MODE != alternate-interface ]] || interface=wg-ops-test
    if [[ $* == *'addr show'* ]]; then
      [[ $CHECK_MODE != interface-missing ]] || { printf '[]'; exit; }
      kind=wireguard
      [[ $CHECK_MODE != non-wireguard-interface ]] || kind=dummy
      printf '[{"ifname":"%s","linkinfo":{"info_kind":"%s"},"addr_info":[{"local":"10.200.0.33"}]}' "$interface" "$kind"
      [[ $CHECK_MODE != ambiguous-interface ]] || printf ',{"ifname":"wt-other","linkinfo":{"info_kind":"wireguard"},"addr_info":[{"local":"10.200.0.33"}]}'
      printf ']'
    else
      [[ $CHECK_MODE != route-missing ]] || exit 2
      [[ $CHECK_MODE != bad-route ]] || interface=eth0
      printf '[{"dev":"%s"}]' "$interface"
    fi
    ;;
  oci)
    [[ $CHECK_MODE != vault-fail ]] || exit 1
    if [[ $* == *gru-1-orch-dashboard-token* ]]; then
      printf fixture-gru-secret | base64
    else
      printf fixture-sfo-secret | base64
    fi
    ;;
  getent)
    if [[ $1 == ahostsv6 ]]; then
      if [[ $2 == *:* ]]; then
        case $2 in
          fd9c:200::1|FD9C:0200:0000:0000:0000:0000:0000:0001|fd9c:200:0:0:0:0:0:1) ip=fd9c:200::1 ;;
          fd9c:200::2) ip=fd9c:200::2 ;;
          *) exit 2 ;;
        esac
        printf '%s STREAM %s\n' "$ip" "$2"
        exit
      fi
      [[ $CHECK_MODE != missing-aaaa ]] || exit 2
      if [[ $CHECK_MODE == bad-aaaa ]]; then ip=fd9c:200::2; else ip=fd9c:200::1; fi
      [[ $CHECK_MODE != equivalent-aaaa ]] || ip=fd9c:200:0:0:0:0:0:1
      printf '%s STREAM %s\n' "$ip" "$2"
      [[ $CHECK_MODE != extra-aaaa ]] || printf 'fd9c:200::2 STREAM %s\n' "$2"
    else
      case $2 in
        ts-gru-1.*) ip=10.200.87.215 ;;
        ts-gru-2.*) ip=10.200.38.135 ;;
        ts-gru-3.*) ip=10.200.168.164 ;;
        ts-sfo-1.*) ip=10.200.112.213 ;;
        ts-sfo-2.*) ip=10.200.122.37 ;;
        ts-sfo-3.*) ip=10.200.63.195 ;;
      esac
      [[ $CHECK_MODE != bad-a ]] || ip=10.200.0.1
      printf '%s STREAM %s\n' "$ip" "$2"
      [[ $CHECK_MODE != extra-a ]] || printf '10.200.0.1 STREAM %s\n' "$2"
    fi
    ;;
  nc) [[ $CHECK_MODE != tcp-fail ]] ;;
  curl)
    output= header= url= pin= interface=
    while (($#)); do
      case $1 in
        --interface) interface=$2; shift 2 ;;
        --resolve) pin=$2; shift 2 ;;
        --output) output=$2; shift 2 ;;
        --header) [[ $2 != @* ]] || header=${2#@}; shift 2 ;;
        --connect-timeout|--max-time|--write-out|--noproxy) shift 2 ;;
        http://*) url=$1; shift ;;
        *) shift ;;
      esac
    done
    if [[ -n $header ]]; then
      expected_interface=wt-fixture
      [[ $CHECK_MODE != alternate-interface ]] || expected_interface=wg-ops-test
      if [[ $interface != "if!$expected_interface" ]]; then
        printf 'BAD-TRANSPORT\n' >> "$CHECK_LOG"
        exit 1
      fi
      [[ $CHECK_MODE != interface-change ]] || exit 45
      printf 'AUTH-SENT\n' >> "$CHECK_LOG"
    fi
    host=${url#http://}; host=${host%:9463/*}
    case $host in
      ts-*.nb.ts.internal)
        case $host in
          ts-gru-1.*) remote=10.200.87.215 ;;
          ts-gru-2.*) remote=10.200.38.135 ;;
          ts-gru-3.*) remote=10.200.168.164 ;;
          ts-sfo-1.*) remote=10.200.112.213 ;;
          ts-sfo-2.*) remote=10.200.122.37 ;;
          ts-sfo-3.*) remote=10.200.63.195 ;;
        esac
        [[ $CHECK_MODE != name-ipv6 ]] || remote=fd9c:200::1
        if [[ $url == */topology ]]; then
          expected_pin=$remote
          [[ $expected_pin != *:* ]] || expected_pin="[$expected_pin]"
          if [[ $pin != "$host:9463:$expected_pin" ]]; then
            printf 'BAD-PIN\n' >> "$CHECK_LOG"
            # Model a changed DNS answer at the authenticated request.
            [[ $CHECK_MODE != dns-change ]] || remote=10.200.0.1
          fi
        fi
        ;;
      *) remote=${host#[}; remote=${remote%]} ;;
    esac
    if [[ $url == */healthz ]]; then
      [[ -z $header ]] || exit 1
      printf ok > "$output"
      [[ $CHECK_MODE != health-wrong-peer ]] || remote=10.200.0.1
      if [[ $CHECK_MODE == health-503 ]]; then printf '503 %s' "$remote"; else printf '200 %s' "$remote"; fi
    else
      if [[ $header == *gru-1-orch-dashboard-token.header ]]; then
        token=fixture-gru-secret
      else
        token=fixture-sfo-secret
      fi
      if [[ $(cat "$header") != "Authorization: Bearer $token" || $(stat -c %a "$header") != 600 ]]; then
        printf 'BAD-AUTH\n' >> "$CHECK_LOG"
        exit 1
      fi
      case $CHECK_MODE in
        html) printf '<html>nodes</html>' > "$output" ;;
        empty-nodes) printf '{"nodes":[]}' > "$output" ;;
        multiple-json) printf '{"nodes":[{}]}\n{"nodes":[{}]}' > "$output" ;;
        *) printf '{"nodes":[{"name":"controller"}]}' > "$output" ;;
      esac
      [[ $CHECK_MODE != topology-wrong-peer ]] || remote=10.200.0.1
      if [[ $CHECK_MODE == topology-401 ]]; then printf '401 %s' "$remote"; else printf '200 %s' "$remote"; fi
    fi
    ;;
esac
`
