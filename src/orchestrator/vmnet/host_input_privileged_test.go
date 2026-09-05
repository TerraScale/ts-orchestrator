package vmnet

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestHostInputNamespaceProbe(t *testing.T) {
	if os.Getenv("TS_VMNET_INPUT_PROBE") != "1" {
		t.Skip("namespace subprocess helper")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	protocol, target, source := os.Getenv("TS_VMNET_INPUT_PROTOCOL"), os.Getenv("TS_VMNET_INPUT_TARGET"), os.Getenv("TS_VMNET_INPUT_SOURCE")
	dialer := net.Dialer{}
	if source != "" {
		if protocol == "udp4" {
			dialer.LocalAddr = &net.UDPAddr{IP: net.ParseIP(source)}
		} else {
			dialer.LocalAddr = &net.TCPAddr{IP: net.ParseIP(source)}
		}
	}
	conn, err := dialer.DialContext(ctx, protocol, target)
	if err == nil {
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(400 * time.Millisecond))
		_, err = conn.Write([]byte("vmnet-proof"))
		if err == nil {
			response := make([]byte, 11)
			_, err = io.ReadFull(conn, response)
			if err == nil && string(response) != "vmnet-proof" {
				err = fmt.Errorf("unexpected echo %q", response)
			}
		}
	}
	wantAllowed := os.Getenv("TS_VMNET_INPUT_ALLOWED") == "1"
	if (err == nil) != wantAllowed {
		t.Fatalf("allowed=%v actual error=%v", wantAllowed, err)
	}
}

func TestHostInputRealDeclaredTCPAndUDP(t *testing.T) {
	if os.Getenv("TS_VMNET_HOST_INPUT_TEST") != "1" {
		t.Skip("set TS_VMNET_HOST_INPUT_TEST=1 with qualification privileges")
	}
	tools, err := DiscoverHostTools()
	if err != nil {
		t.Fatal(err)
	}
	config := DefaultConfig()
	config.Regions = config.Regions[:1]
	config.Tools = tools
	digest := sha256.Sum256([]byte(t.TempDir()))
	config.RunID = fmt.Sprintf("%x", digest[:16])
	config.Endpoints = []EndpointSpec{{Name: "probe", Region: GRU, Protocol: TCP, GuestPort: 18443, HostPort: 18443}, {Name: "ntp", Region: GRU, Protocol: UDP, GuestPort: 123, HostPort: 18123}}
	plan, err := Plan(config)
	if err != nil {
		t.Fatal(err)
	}
	runner, err := NewHostRunner(tools)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	iptables := func(ctx context.Context, args ...string) error {
		if strings.Contains(filepath.Base(tools.IPTables), "multi") {
			args = append([]string{"iptables"}, args...)
		}
		output, err := exec.CommandContext(ctx, tools.IPTables, args...).CombinedOutput()
		if err != nil {
			return fmt.Errorf("iptables %v: %w: %s", args, err, output)
		}
		return nil
	}
	// This DROP matches only this fixture's unique veth, including before the
	// link exists. Never change policies or insert a broad ambient DROP.
	fixture := []string{"-i", plan.Uplinks[0].RootDevice, "-m", "comment", "--comment", "vmnet-input-fixture-" + config.RunID, "-j", "DROP"}
	if err := iptables(ctx, append([]string{"-w", "5", "-I", "INPUT", "1"}, fixture...)...); err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := iptables(cleanupCtx, append([]string{"-w", "5", "-D", "INPUT"}, fixture...)...); err != nil {
			t.Errorf("remove fixture-only DROP: %v", err)
		}
	}()
	cleaned := false
	defer func() {
		if !cleaned {
			cleanupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			if err := plan.Cleanup.Run(cleanupCtx, runner); err != nil {
				t.Errorf("cleanup owned input rules: %v", err)
			}
		}
	}()
	if err := plan.ApplyWithJournal(ctx, runner, &fakeJournalWriter{}); err != nil {
		t.Fatal(err)
	}
	host := plan.Uplinks[0].HostServiceAddress
	for _, port := range []string{"18443", "18444"} {
		listener, err := net.Listen("tcp4", net.JoinHostPort(host, port))
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		go func() {
			for {
				conn, err := listener.Accept()
				if err != nil {
					return
				}
				go func() {
					defer conn.Close()
					conn.SetDeadline(time.Now().Add(time.Second))
					data := make([]byte, 11)
					if _, err := io.ReadFull(conn, data); err == nil {
						_, _ = conn.Write(data)
					}
				}()
			}
		}()
	}
	for _, port := range []string{"18123", "18124"} {
		socket, err := net.ListenPacket("udp4", net.JoinHostPort(host, port))
		if err != nil {
			t.Fatal(err)
		}
		defer socket.Close()
		go func() {
			buffer := make([]byte, 64)
			for {
				n, peer, err := socket.ReadFrom(buffer)
				if err != nil {
					return
				}
				_, _ = socket.WriteTo(buffer[:n], peer)
			}
		}()
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	probe := func(protocol, port, source string, allowed bool) {
		t.Helper()
		command := exec.CommandContext(ctx, tools.IP, "netns", "exec", plan.Regions[0].Namespace, executable, "-test.run", "^TestHostInputNamespaceProbe$", "-test.v")
		command.Env = append(os.Environ(), "TS_VMNET_INPUT_PROBE=1", "TS_VMNET_INPUT_PROTOCOL="+protocol, "TS_VMNET_INPUT_TARGET="+net.JoinHostPort(host, port), "TS_VMNET_INPUT_SOURCE="+source, fmt.Sprintf("TS_VMNET_INPUT_ALLOWED=%d", map[bool]int{true: 1, false: 0}[allowed]))
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("namespace %s/%s source=%s: %v %s", protocol, port, source, err, output)
		}
	}
	probe("tcp4", "18443", "", true)
	probe("udp4", "18123", "", true)
	probe("tcp4", "18444", "", false)
	probe("udp4", "18124", "", false)
	alternate := netip.MustParsePrefix(plan.Uplinks[0].CIDR).Addr().String()
	if output, err := exec.CommandContext(ctx, tools.IP, "-n", plan.Regions[0].Namespace, "addr", "add", alternate+"/32", "dev", "lo").CombinedOutput(); err != nil {
		t.Fatalf("declare alternate fixture source: %v %s", err, output)
	}
	probe("tcp4", "18443", alternate, false)
	probe("udp4", "18123", alternate, false)
	if err := plan.Cleanup.Run(ctx, runner); err != nil {
		t.Fatal(err)
	}
	cleaned = true
	if err := iptables(ctx, append([]string{"-w", "5", "-C", "INPUT"}, fixture...)...); err != nil {
		t.Fatalf("cleanup deleted unrelated fixture rule: %v", err)
	}
	rulesChecked := 0
	for _, command := range plan.Commands {
		args := command.Args
		for i := 0; i+2 < len(args); i++ {
			if args[i] == "-I" && args[i+1] == "INPUT" && args[i+2] == "1" {
				rulesChecked++
				check := append([]string{"-w", "5", "-C", "INPUT"}, args[i+3:]...)
				if err := iptables(ctx, check...); err == nil {
					t.Fatal("qualification input rule survived cleanup")
				} else if !strings.Contains(err.Error(), "Bad rule (does a matching rule exist in that chain?)") {
					t.Fatalf("cannot prove input rule absence: %v", err)
				}
				break
			}
		}
	}
	if rulesChecked != len(plan.Forwards) {
		t.Fatalf("checked %d owned rules for %d forwards", rulesChecked, len(plan.Forwards))
	}
}
