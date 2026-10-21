package releasepush

import (
	"context"
	"fmt"
	"os/exec"
	"strconv"
)

// EnsureFirewall puts a tcp/4222 ACCEPT above the Ubuntu OCI image's INPUT
// REJECT. It runs on every start, so nothing needs to persist the rule.
func EnsureFirewall(ctx context.Context) error {
	rule := []string{"INPUT", "-p", "tcp", "--dport", strconv.Itoa(Port), "-j", "ACCEPT"}
	if exec.CommandContext(ctx, "iptables", append([]string{"-C"}, rule...)...).Run() == nil {
		return nil
	}
	insert := append([]string{"-I", "INPUT", "1"}, rule[1:]...)
	if output, err := exec.CommandContext(ctx, "iptables", insert...).CombinedOutput(); err != nil {
		return fmt.Errorf("iptables %v: %w: %s", insert, err, output)
	}
	return nil
}
