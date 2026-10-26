package releasepush

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

// EnsureFirewall puts a tcp/4222 ACCEPT above the Ubuntu OCI image's INPUT
// REJECT. It runs on every start, so nothing needs to persist the rule.
func EnsureFirewall(ctx context.Context) error { return OpenTCP(ctx, Port) }

// OpenTCP puts a tcp/port ACCEPT above the Ubuntu OCI image's INPUT REJECT.
func OpenTCP(ctx context.Context, port int) error { return open(ctx, "tcp", port) }

// OpenUDP puts a udp/port ACCEPT above the Ubuntu OCI image's INPUT REJECT.
func OpenUDP(ctx context.Context, port int) error { return open(ctx, "udp", port) }

func open(ctx context.Context, proto string, port int) error {
	rule := []string{"INPUT", "-p", proto, "--dport", strconv.Itoa(port), "-j", "ACCEPT"}
	if exec.CommandContext(ctx, "iptables", append([]string{"-C"}, rule...)...).Run() == nil {
		return nil
	}
	insert := append([]string{"-I", "INPUT", "1"}, rule[1:]...)
	if output, err := exec.CommandContext(ctx, "iptables", insert...).CombinedOutput(); err != nil {
		return fmt.Errorf("iptables %v: %w: %s", insert, err, output)
	}
	return nil
}

// CloseTCP removes only the exact ACCEPT rule owned by OpenTCP. This keeps
// legacy plaintext wire private until the edge has claimed its public port.
func CloseTCP(ctx context.Context, port int) error {
	rule := []string{"INPUT", "-p", "tcp", "--dport", strconv.Itoa(port), "-j", "ACCEPT"}
	for range 64 {
		output, err := exec.CommandContext(ctx, "iptables", append([]string{"-w", "2", "-C"}, rule...)...).CombinedOutput()
		if err != nil {
			var exit *exec.ExitError
			if errors.As(err, &exit) && exit.ExitCode() == 1 && strings.Contains(string(output), "Bad rule") {
				return nil
			}
			return fmt.Errorf("check wire firewall rule: %w: %s", err, output)
		}
		if output, err := exec.CommandContext(ctx, "iptables", append([]string{"-w", "2", "-D"}, rule...)...).CombinedOutput(); err != nil {
			return fmt.Errorf("remove wire firewall rule: %w: %s", err, output)
		}
	}
	return fmt.Errorf("too many duplicate wire firewall rules")
}
