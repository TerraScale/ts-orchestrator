package swarmruntime

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"os/exec"
	"strconv"
	"sync"
)

var firewallCIDRLog sync.Once

func VCNPrefix(privateIP, vcnCIDR string) (netip.Prefix, bool, error) {
	ip, err := netip.ParseAddr(privateIP)
	if err != nil || !ip.Is4() {
		return netip.Prefix{}, false, fmt.Errorf("the VCN needs a private IPv4 address: %s", privateIP)
	}
	vcn, err := netip.ParsePrefix(vcnCIDR)
	if err != nil || !vcn.Contains(ip) || vcn.Bits() == 0 {
		return netip.PrefixFrom(ip, 16).Masked(), false, nil
	}
	return vcn.Masked(), true, nil
}

func OpenFirewall(ctx context.Context, privateIP, vcnCIDR string) error {
	vcn, known, err := VCNPrefix(privateIP, vcnCIDR)
	if err != nil {
		return err
	}
	if !known {
		firewallCIDRLog.Do(func() {
			slog.InfoContext(ctx, "IMDS VCN CIDR unavailable; restricting SwarmKit to private address /16", "source", vcn.String())
		})
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
