// Package dns configures operator DNS without changing the server enrollment defaults.
package dns

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

const binary = "/usr/local/lib/ts-orch-netbird-dns"

// system.control is a persistent systemd unit search path and remains writable
// when NixOS owns /etc/systemd/system as an immutable store symlink.
const unitDir = "/etc/systemd/system.control"

const subscriber = "/etc/ts-orch-netbird-dns-resolv.conf"

// Run plans or installs native operator DNS. The split resolver is for a
// host-network container whose NetBird resolver cannot configure its host.
func Run(ctx context.Context, args []string, out io.Writer) error {
	if len(args) > 0 && args[0] == "enable" {
		args = args[1:]
	}
	fs := flag.NewFlagSet("netbird dns", flag.ContinueOnError)
	fs.SetOutput(out)
	command := fs.String("netbird", "netbird", "NetBird command, split on spaces")
	configDir := fs.String("config-dir", "", "native client config.d directory (NixOS)")
	split := fs.Bool("split-resolver", false, "route nb.ts.internal to a host-network container resolver")
	upstream := fs.String("upstream", "", "existing default DNS server (required for split-resolver)")
	apply := fs.Bool("apply", false, "install and start persistent DNS configuration")
	refresh := fs.Bool("refresh", false, "reapply installed split resolver routing (systemd)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || len(strings.Fields(*command)) == 0 || strings.ContainsAny(*command+*configDir, "\n\r\x00%") {
		return errors.New("netbird dns requires a command and no positional arguments or control characters")
	}
	if _, err := netip.ParseAddr(*upstream); (*split || *upstream != "") && err != nil {
		return errors.New("upstream must be an IP address")
	}
	if *configDir != "" && (!filepath.IsAbs(*configDir) || *split) {
		return errors.New("config-dir must be absolute and is only for native DNS")
	}
	if *refresh {
		if os.Geteuid() != 0 {
			return errors.New("netbird dns --refresh must run as root")
		}
		return route(ctx, *command)
	}
	if *split {
		fmt.Fprintf(out, "Install host systemd-resolved if absent; default DNS %s; route only ~nb.ts.internal to the local NetBird resolver; install ts-orch-netbird-dns.service/timer; resolvconf subscriber points host DNS to 127.0.0.53.\n", *upstream)
	} else {
		fmt.Fprintln(out, "Enable native NetBird DNS with a brief overlay down/up reconnect; preserve identity, server routing and default DNS configuration.")
		if *configDir != "" {
			fmt.Fprintf(out, "Write owned override %s/90-ts-orchestrator-dns.json (DisableDNS=false).\n", *configDir)
		}
	}
	if !*apply {
		return nil
	}
	if os.Geteuid() != 0 {
		return errors.New("netbird dns --apply must run as root")
	}
	if *split {
		return install(ctx, *command, *upstream)
	}
	if *configDir != "" {
		if err := write(filepath.Join(*configDir, "90-ts-orchestrator-dns.json"), []byte("{\"DisableDNS\":false}\n"), 0644); err != nil {
			return err
		}
	}
	argv := strings.Fields(*command)
	// NetBird ignores `up` flags while already connected. Disconnect the overlay
	// first so the DNS change takes effect without replacing the peer identity.
	if err := run(ctx, argv[0], append(argv[1:], "down")...); err != nil {
		return err
	}
	return run(ctx, argv[0], append(argv[1:], "up", "--disable-dns=false")...)
}

func run(ctx context.Context, name string, args ...string) error {
	// Keep authentication material in subprocess diagnostics out of CLI output.
	if err := exec.CommandContext(ctx, name, args...).Run(); err != nil {
		return fmt.Errorf("%s failed: %w", name, err)
	}
	return nil
}

// mkdir creates only the owned directory; it preserves permissions of any
// existing directory. Chmod after creation handles an operator's umask 077.
func mkdir(path string) error {
	if err := os.Mkdir(path, 0755); err != nil {
		if errors.Is(err, os.ErrExist) {
			return nil
		}
		return err
	}
	return os.Chmod(path, 0755)
}

func write(path string, data []byte, mode os.FileMode) error {
	if err := os.WriteFile(path, data, mode); err != nil {
		return err
	}
	return os.Chmod(path, mode)
}

func install(ctx context.Context, command, upstream string) error {
	if err := mkdir(unitDir); err != nil {
		return err
	}
	if err := run(ctx, "systemctl", "is-active", "--quiet", "systemd-resolved.service"); err != nil {
		if _, err := os.Stat("/run/current-system/sw/lib/systemd/systemd-resolved"); err != nil {
			return errors.New("systemd-resolved must be installed before split-resolver setup")
		}
		// NixOS disabled services retain their executable but have no unit.
		if _, err := os.Lstat(filepath.Join(unitDir, "systemd-resolved.service")); errors.Is(err, os.ErrNotExist) {
			unit := "[Unit]\nDescription=Network Name Resolution (ts-orch operator DNS)\nAfter=network.target\n[Service]\nType=notify\nExecStart=/run/current-system/sw/lib/systemd/systemd-resolved\nRestart=on-failure\n[Install]\nWantedBy=multi-user.target\n"
			if err := write(filepath.Join(unitDir, "systemd-resolved.service"), []byte(unit), 0644); err != nil {
				return err
			}
		}
	}
	if err := mkdir("/etc/systemd/resolved.conf.d"); err != nil {
		return err
	}
	settings, err := os.ReadFile(subscriber)
	if errors.Is(err, os.ErrNotExist) {
		original, err := os.ReadFile("/etc/resolv.conf")
		if err != nil {
			return err
		}
		settings = []byte("nameserver 127.0.0.53\n")
		for line := range strings.SplitSeq(string(original), "\n") {
			fields := strings.Fields(line)
			if len(fields) > 1 && (fields[0] == "search" || fields[0] == "options") {
				settings = append(settings, []byte(strings.Join(fields, " ")+"\n")...)
			}
		}
		if err := write(subscriber, settings, 0644); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	domains := "~."
	for line := range strings.SplitSeq(string(settings), "\n") {
		if fields := strings.Fields(line); len(fields) > 1 && fields[0] == "search" {
			domains += " " + strings.Join(fields[1:], " ")
		}
	}
	conf := "[Resolve]\nDNS=" + upstream + "\nDomains=" + domains + "\nFallbackDNS=\nDNSStubListener=yes\n"
	if err := write("/etc/systemd/resolved.conf.d/90-ts-orchestrator-netbird.conf", []byte(conf), 0644); err != nil {
		return err
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	body, err := os.ReadFile(exe)
	if err != nil {
		return err
	}
	for _, directory := range []string{"/usr/local", filepath.Dir(binary)} {
		if err := mkdir(directory); err != nil {
			return err
		}
	}
	// Stage beside the executable so later installs can update an in-use binary.
	if err := write(binary+".new", body, 0755); err != nil {
		return err
	}
	if err := os.Rename(binary+".new", binary); err != nil {
		return err
	}
	unit := "[Unit]\nDescription=TerraScale operator NetBird split DNS\nAfter=network-online.target systemd-resolved.service\nWants=network-online.target\nRequires=systemd-resolved.service\n[Service]\nType=oneshot\nEnvironment=PATH=/run/current-system/sw/bin:/usr/local/bin:/usr/bin:/bin\nExecStart=" + binary + " netbird dns --refresh --netbird " + strconv.Quote(command) + "\n"
	timer := "[Unit]\nDescription=Refresh TerraScale operator NetBird split DNS\n[Timer]\nOnBootSec=15s\nOnUnitActiveSec=30s\n[Install]\nWantedBy=timers.target\n"
	for name, content := range map[string]string{"ts-orch-netbird-dns.service": unit, "ts-orch-netbird-dns.timer": timer} {
		if err := write(filepath.Join(unitDir, name), []byte(content), 0644); err != nil {
			return err
		}
	}
	if err := run(ctx, "systemctl", "daemon-reload"); err != nil {
		return err
	}
	for target, name := range map[string]string{"multi-user.target": "systemd-resolved.service", "timers.target": "ts-orch-netbird-dns.timer"} {
		wants := filepath.Join(unitDir, target+".wants")
		if err := mkdir(wants); err != nil {
			return err
		}
		if err := os.Symlink(filepath.Join(unitDir, name), filepath.Join(wants, name)); err != nil && !errors.Is(err, os.ErrExist) {
			return err
		}
	}
	if err := run(ctx, "systemctl", "daemon-reload"); err != nil {
		return err
	}
	if err := run(ctx, "systemctl", "restart", "systemd-resolved.service"); err != nil {
		return err
	}
	if err := run(ctx, "systemctl", "start", "ts-orch-netbird-dns.timer"); err != nil {
		return err
	}
	return run(ctx, "systemctl", "start", "ts-orch-netbird-dns.service")
}

func route(ctx context.Context, command string) error {
	argv := strings.Fields(command)
	body, err := exec.CommandContext(ctx, argv[0], append(argv[1:], "status", "--json")...).Output()
	if err != nil {
		return errors.New("cannot read NetBird resolver address")
	}
	var status struct {
		IP    string `json:"netbirdIp"`
		State string `json:"daemonStatus"`
	}
	if err := json.Unmarshal(body, &status); err != nil || status.State != "Connected" {
		return errors.New("NetBird must be connected before configuring DNS")
	}
	prefix, err := netip.ParsePrefix(status.IP)
	if err != nil || !prefix.Addr().IsPrivate() {
		return errors.New("NetBird resolver IP must be private")
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		return err
	}
	link := ""
	for _, iface := range interfaces {
		addresses, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, address := range addresses {
			if addr, err := netip.ParsePrefix(address.String()); err == nil && addr.Addr() == prefix.Addr() {
				link = iface.Name
			}
		}
	}
	if link == "" {
		return errors.New("NetBird resolver must use the host network interface")
	}
	for _, args := range [][]string{{"dns", link, prefix.Addr().String()}, {"domain", link, "~nb.ts.internal"}, {"default-route", link, "no"}} {
		if err := run(ctx, "resolvectl", args...); err != nil {
			return err
		}
	}
	c := exec.CommandContext(ctx, "resolvconf", "-a", "ts-orch-netbird-dns", "-x")
	settings, err := os.ReadFile(subscriber)
	if err != nil {
		return err
	}
	c.Stdin = strings.NewReader(string(settings))
	if err := c.Run(); err != nil {
		return fmt.Errorf("resolvconf subscriber failed: %w", err)
	}
	return nil
}
