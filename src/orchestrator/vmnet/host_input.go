package vmnet

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

// Each rule admits one declared post-NAT endpoint tuple. The full run ID in
// its comment is also required for deletion; cleanup never uses rule numbers.
func hostInputCommands(tools ToolPaths, prefix, runID string, uplinks []RegionUplink, forwards []EndpointForward, remove bool) []Command {
	var commands []Command
	for _, forward := range forwards {
		for _, uplink := range uplinks {
			if uplink.Region != forward.Region {
				continue
			}
			args := []string{"-w", "5", "-t", "filter", "-I", "INPUT", "1"}
			if remove {
				args = []string{"-w", "5", "-t", "filter", "-D", "INPUT"}
			}
			args = append(args, "-i", uplink.RootDevice, "-s", uplink.RegionAddress+"/32", "-d", forward.HostAddress+"/32", "-p", string(forward.Protocol), "--dport", strconv.Itoa(int(forward.HostPort)), "-m", "comment", "--comment", "vmnet:"+prefix+":"+runID+":"+string(forward.Region), "-j", "ACCEPT")
			commands = append(commands, command(tools.IPTables, args...))
		}
	}
	return commands
}

func admittedHostInput(args []string) bool {
	if len(args) < 6 || strings.Join(args[:4], " ") != "-w 5 -t filter" || args[5] != "INPUT" {
		return false
	}
	start := 6
	switch args[4] {
	case "-I":
		if len(args) < 7 || args[6] != "1" {
			return false
		}
		start = 7
	case "-D":
	default:
		return false
	}
	rule := args[start:]
	if len(rule) != 16 || rule[0] != "-i" || rule[2] != "-s" || rule[4] != "-d" || rule[6] != "-p" || rule[8] != "--dport" || rule[10] != "-m" || rule[11] != "comment" || rule[12] != "--comment" || rule[14] != "-j" || rule[15] != "ACCEPT" {
		return false
	}
	owner := strings.Split(rule[13], ":")
	if len(owner) != 4 || owner[0] != "vmnet" || validIdentifier(owner[1], "prefix", 5) != nil || !runIDPattern.MatchString(owner[2]) || !validRegion(RegionCode(owner[3])) {
		return false
	}
	if rule[1] != uplinkDevice(owner[1], owner[2], RegionCode(owner[3]), true) || rule[5] != hostServiceAddress(owner[2]).String()+"/32" {
		return false
	}
	source, err := netip.ParsePrefix(rule[3])
	if err != nil || !source.Addr().Is4() || source.Bits() != 32 || source.String() != rule[3] || !netip.MustParsePrefix("198.18.0.0/16").Contains(source.Addr()) {
		return false
	}
	port, err := strconv.ParseUint(rule[9], 10, 16)
	return err == nil && port > 0 && strconv.FormatUint(port, 10) == rule[9] && (rule[7] == "tcp" || rule[7] == "udp" && port == 18123)
}

func iptablesMulticall(path string) bool {
	switch filepath.Base(path) {
	case "xtables-nft-multi", "xtables-legacy-multi":
		return true
	}
	return false
}

func iptablesArguments(path string, args []string) []string {
	if iptablesMulticall(path) {
		return append([]string{"iptables"}, args...)
	}
	return append([]string(nil), args...)
}

func (r *HostRunner) executeHostInput(ctx context.Context, args []string, cleanup bool) error {
	if !admittedHostInput(args) || cleanup && args[4] != "-D" {
		return errors.New("vmnet: host input command is not admitted")
	}
	output, err := r.runIPTables(ctx, args)
	if err == nil {
		return nil
	}
	var exit *exec.ExitError
	if cleanup && errors.As(err, &exit) && exit.ExitCode() == 1 && strings.Contains(output, "Bad rule (does a matching rule exist in that chain?)") {
		return nil
	}
	return fmt.Errorf("vmnet: host input rule: %w: %s", err, output)
}

func (r *HostRunner) runIPTables(ctx context.Context, args []string) (string, error) {
	if err := validateHostTool("iptables", r.tools.IPTables); err != nil {
		return "", err
	}
	process := exec.CommandContext(ctx, r.tools.IPTables, iptablesArguments(r.tools.IPTables, args)...)
	var output limitedOutput
	process.Stdout, process.Stderr = &output, &output
	process.Env = []string{"LC_ALL=C", "LANG=C", "PATH=/run/current-system/sw/bin:/usr/sbin:/usr/bin:/sbin:/bin"}
	err := process.Run()
	return output.String(), err
}

// Collision checks are read-only and precede the durable intent. A recovered
// owned rule must be cleaned through its journal before a new apply.
func (r *HostRunner) checkHostInputCollision(ctx context.Context, commands []Command) error {
	for _, command := range commands {
		if command.Executable != r.tools.IPTables {
			continue
		}
		args := append([]string(nil), command.Args...)
		args[4] = "-C"
		args = append(args[:6], args[7:]...)
		output, err := r.runIPTables(ctx, args)
		if err == nil {
			return errors.New("vmnet: existing owned host input rule requires journal cleanup")
		}
		var exit *exec.ExitError
		if !errors.As(err, &exit) || exit.ExitCode() != 1 || !strings.Contains(output, "Bad rule (does a matching rule exist in that chain?)") {
			return fmt.Errorf("vmnet: inspect host input rule: %w: %s", err, output)
		}
	}
	return nil
}
