package swarmruntime

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"os/exec"
	"strconv"
)

func OpenFirewall(ctx context.Context, privateIP, vcnCIDR string) error {
	vcn, err := netip.ParsePrefix(vcnCIDR)
	ip, ipErr := netip.ParseAddr(privateIP)
	if ipErr != nil || !ip.Is4() {
		return fmt.Errorf("SwarmKit firewall requires a private IPv4 address: %s", privateIP)
	}
	if err != nil || !vcn.Contains(ip) || vcn.Bits() == 0 {
		vcn = netip.PrefixFrom(ip, 16).Masked()
		slog.WarnContext(ctx, "IMDS VCN CIDR unavailable; restricting SwarmKit to private address /16", "source", vcn.String())
	}
	rule := []string{"INPUT", "-s", vcn.Masked().String(), "-p", "tcp", "--dport", strconv.Itoa(SwarmPort), "-j", "ACCEPT"}
	if exec.CommandContext(ctx, "iptables", append([]string{"-C"}, rule...)...).Run() != nil {
		insert := append([]string{"-I", "INPUT", "1"}, rule[1:]...)
		if output, err := exec.CommandContext(ctx, "iptables", insert...).CombinedOutput(); err != nil {
			return fmt.Errorf("iptables %v: %w: %s", insert, err, output)
		}
	}
	broad := []string{"INPUT", "-p", "tcp", "--dport", strconv.Itoa(SwarmPort), "-j", "ACCEPT"}
	for exec.CommandContext(ctx, "iptables", append([]string{"-C"}, broad...)...).Run() == nil {
		if output, err := exec.CommandContext(ctx, "iptables", append([]string{"-D"}, broad...)...).CombinedOutput(); err != nil {
			return fmt.Errorf("remove unrestricted SwarmKit firewall rule: %w: %s", err, output)
		}
	}
	return ctx.Err()
}
