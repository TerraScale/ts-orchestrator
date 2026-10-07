// Package accesscheck verifies each controller's private dashboard from the operator's device.
package accesscheck

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/netbird/sshlogin"
)

const usage = `Usage: ts-orch dashboard check --gru-token-file FILE --sfo-token-file FILE [--netbird COMMAND] [--timeout 5s]

Read the six controller addresses from the local NetBird client, then curl
/healthz and authenticated /topology by NetBird IP and by native DNS name.
Requires curl and owner-only token files; never prints tokens or puts them
on a process command line. No proxy, redirect, tunnel or DNS override is used.
Exit 0 means all 24 requests returned HTTP 200.
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
	peers, err := sshlogin.Peers(ctx, *netbird)
	if err != nil {
		return err
	}
	return check(ctx, out, peers, tokens, *timeout, curl)
}

type fetch func(context.Context, string, string, time.Duration) (string, string, error)

func check(ctx context.Context, out io.Writer, peers, tokens map[string]string, timeout time.Duration, get fetch) error {
	var failures []error
	network := netip.MustParsePrefix("10.200.0.0/16")
	for _, region := range []string{"gru", "sfo"} {
		for n := 1; n <= 3; n++ {
			name := fmt.Sprintf("ts-%s-%d", region, n)
			ip := peers[name]
			address, err := netip.ParseAddr(ip)
			if err != nil || !network.Contains(address) {
				failures = append(failures, fmt.Errorf("%s missing a 10.200.0.0/16 address in NetBird status", name))
				continue
			}
			for _, host := range []string{ip, name + ".nb.ts.internal"} {
				for _, path := range []string{"/healthz", "/topology"} {
					url := "http://" + host + ":9463" + path
					status, remoteIP, err := get(ctx, url, tokens[region], timeout)
					result := "OK"
					if err != nil {
						result = "FAIL " + err.Error()
						failures = append(failures, fmt.Errorf("%s: curl: %w", url, err))
					} else if status != "200" {
						result = "FAIL HTTP " + status
						failures = append(failures, fmt.Errorf("%s: HTTP %s", url, status))
					} else if remoteIP != ip {
						result = "FAIL resolved to " + remoteIP
						failures = append(failures, fmt.Errorf("%s: connected to %s, expected %s", url, remoteIP, ip))
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

func curl(ctx context.Context, url, token string, timeout time.Duration) (string, string, error) {
	seconds := strconv.FormatFloat(timeout.Seconds(), 'f', -1, 64)
	cmd := exec.CommandContext(ctx, "curl", "--disable", "--silent", "--noproxy", "*", "--max-time", seconds,
		"--output", os.DevNull, "--write-out", "%{http_code} %{remote_ip}", "--config", "-", url)
	// curl reads the secret through stdin, never argv or a temporary file.
	escaped := strings.NewReplacer("\\", "\\\\", "\"", "\\\"").Replace(token)
	cmd.Stdin = strings.NewReader("header = \"Authorization: Bearer " + escaped + "\"\n")
	output, err := cmd.Output()
	status, remoteIP, _ := strings.Cut(strings.TrimSpace(string(output)), " ")
	return status, remoteIP, err
}
