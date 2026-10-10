// Package accesscheck verifies each controller's private dashboard from the operator's device.
package accesscheck

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/netbird/sshlogin"
	"golang.org/x/net/html"
)

const usage = `Usage: ts-orch dashboard check --gru-token-file FILE --sfo-token-file FILE [--netbird COMMAND] [--timeout 5s]

Read the six controller addresses from the local NetBird client, then curl
/healthz and every authenticated dashboard page by NetBird IP and native DNS.
Requires curl and owner-only token files; never prints tokens or puts them
on a process command line. No proxy, redirect, tunnel or DNS override is used.
Exit 0 requires HTTP 200 with rendered content on every page, at least three
topology nodes and three observed controllers in each /members view.
`

// Run checks GRU and SFO from this device without changing network configuration.
func Run(ctx context.Context, args []string, out io.Writer) error {
	if len(args) == 0 || args[0] == "--help" || args[0] == "help" || args[0] == "-h" {
		_, err := io.WriteString(out, usage)
		return err
	}
	if args[0] != "check" {
		return errors.New("dashboard: expected check; use ts-orch dashboard --help")
	}
	flags := flag.NewFlagSet("dashboard check", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	gru := flags.String("gru-token-file", "", "owner-only file holding the GRU dashboard token")
	sfo := flags.String("sfo-token-file", "", "owner-only file holding the SFO dashboard token")
	netbird := flags.String("netbird", "netbird", "local NetBird command, split on spaces")
	timeout := flags.Duration("timeout", 5*time.Second, "timeout per request")
	if err := flags.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			_, err = io.WriteString(out, usage)
		}
		return err
	}
	if flags.NArg() != 0 || *timeout <= 0 || *gru == "" || *sfo == "" {
		return errors.New("dashboard check requires --gru-token-file, --sfo-token-file, a positive --timeout and no positional arguments")
	}
	tokens := map[string]string{}
	for region, path := range map[string]string{"gru": *gru, "sfo": *sfo} {
		file, err := os.Open(path)
		if err != nil {
			return err
		}
		info, err := file.Stat()
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
			file.Close()
			return fmt.Errorf("%s token file must be a regular owner-only file", region)
		}
		value, err := io.ReadAll(io.LimitReader(file, 4097))
		file.Close()
		token := strings.TrimSpace(string(value))
		clear(value)
		if err != nil || token == "" || len(value) > 4096 || strings.ContainsAny(token, "\r\n\x00") {
			return fmt.Errorf("%s token file must hold one nonempty token of at most 4096 bytes", region)
		}
		tokens[region] = token
	}
	peers, err := sshlogin.Addresses(ctx, *netbird)
	if err != nil {
		return err
	}
	return check(ctx, out, peers, tokens, *timeout, curl)
}

type fetch func(context.Context, string, string, time.Duration) (string, string, string, error)

var paths = []string{"/healthz", "/", "/region", "/insights", "/decisions", "/releases", "/rollouts", "/ci",
	"/topology", "/members", "/nats", "/terrabase", "/storage", "/oci", "/events"}

func check(ctx context.Context, out io.Writer, peers map[string]sshlogin.PeerAddress, tokens map[string]string, timeout time.Duration, get fetch) error {
	var failures []error
	network := netip.MustParsePrefix("10.200.0.0/16")
	for _, region := range []string{"gru", "sfo"} {
		for n := 1; n <= 3; n++ {
			name := fmt.Sprintf("ts-%s-%d", region, n)
			peer := peers[name]
			ip := peer.IP
			address, err := netip.ParseAddr(ip)
			if err != nil || !network.Contains(address) {
				failures = append(failures, fmt.Errorf("%s missing a 10.200.0.0/16 address in NetBird status", name))
				continue
			}
			for _, host := range []string{ip, name + ".nb.ts.internal"} {
				for _, path := range paths {
					url := "http://" + host + ":9463" + path
					status, remoteIP, body, err := get(ctx, url, tokens[region], timeout)
					result := "OK"
					if err != nil {
						result = "FAIL " + err.Error()
						failures = append(failures, fmt.Errorf("%s: curl: %w", url, err))
					} else if status != "200" {
						result = "FAIL HTTP " + status
						failures = append(failures, fmt.Errorf("%s: HTTP %s", url, status))
					} else if remoteIP != ip && (host == ip || peer.IPv6 == "" || remoteIP != peer.IPv6) {
						result = "FAIL resolved to " + remoteIP
						expected := ip
						if host != ip && peer.IPv6 != "" {
							expected += " or " + peer.IPv6
						}
						failures = append(failures, fmt.Errorf("%s: connected to %s, expected %s", url, remoteIP, expected))
					} else if err := rendered(path, body); err != nil {
						result = "FAIL " + err.Error()
						failures = append(failures, fmt.Errorf("%s: %w", url, err))
					}
					if _, err := fmt.Fprintf(out, "%s %s\n", result, url); err != nil {
						return err
					}
				}
			}
		}
	}
	return errors.Join(failures...)
}

func rendered(path, body string) error {
	if path == "/healthz" {
		return nil
	}
	root, err := html.Parse(strings.NewReader(body))
	if err != nil {
		return fmt.Errorf("dashboard HTML is unreadable: %w", err)
	}
	var content *html.Node
	for node := range root.Descendants() {
		for _, attribute := range node.Attr {
			if attribute.Key == "id" && attribute.Val == "content" {
				content = node
			}
		}
	}
	if content == nil {
		return errors.New("dashboard content is missing")
	}
	text, nodes, members := false, map[string]bool{}, map[string]bool{}
	for node := range content.Descendants() {
		if node.Type == html.TextNode && strings.TrimSpace(node.Data) != "" {
			heading := false
			for parent := range node.Ancestors() {
				switch parent.Data {
				case "h1", "h2", "h3", "h4", "h5", "h6", "script", "style":
					heading = true
				}
				for _, attribute := range parent.Attr {
					if attribute.Key == "class" && slices.Contains(strings.Fields(attribute.Val), "page-head") {
						heading = true
					}
				}
			}
			text = text || !heading
		}
		for _, attribute := range node.Attr {
			if node.Data == "g" && attribute.Key == "data-node" && attribute.Val != "" {
				nodes[attribute.Val] = true
			}
			if node.Data == "a" && attribute.Key == "href" {
				link, err := url.Parse(attribute.Val)
				if err != nil || link.IsAbs() || link.Host != "" {
					continue
				}
				member, found := strings.CutPrefix(link.Path, "/members/")
				if !found || member == "" || strings.Contains(member, "/") {
					continue
				}
				for parent := range node.Ancestors() {
					if parent.Data == "tbody" {
						members[member] = true
						break
					}
				}
			}
		}
	}
	if !text {
		return errors.New("dashboard content is empty")
	}
	if path == "/topology" && len(nodes) < 3 {
		return fmt.Errorf("topology has %d nodes, need at least 3", len(nodes))
	}
	if path == "/members" && len(members) < 3 {
		return fmt.Errorf("dashboard has %d observed controllers, need at least 3; check for missing telemetry grants", len(members))
	}
	return nil
}

func curl(ctx context.Context, url, token string, timeout time.Duration) (string, string, string, error) {
	seconds := strconv.FormatFloat(timeout.Seconds(), 'f', -1, 64)
	cmd := exec.CommandContext(ctx, "curl", "--disable", "--silent", "--noproxy", "*", "--max-time", seconds,
		"--max-filesize", "2097152", "--write-out", "\n%{http_code} %{remote_ip}", "--config", "-", url)
	// curl reads the secret through stdin, never argv or a temporary file.
	escaped := strings.NewReplacer("\\", "\\\\", "\"", "\\\"").Replace(token)
	cmd.Stdin = strings.NewReader("header = \"Authorization: Bearer " + escaped + "\"\n")
	output, err := cmd.Output()
	if exit, ok := errors.AsType[*exec.ExitError](err); ok && exit.ExitCode() == 63 {
		err = fmt.Errorf("dashboard response exceeds 2 MiB: %w", err)
	}
	body, result, _ := strings.CutLast(string(output), "\n")
	status, remoteIP, _ := strings.Cut(strings.TrimSpace(result), " ")
	return status, remoteIP, body, err
}
