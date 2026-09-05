//go:build sandboxvm && linux

package vmqualruntime

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/exec"
	"testing"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/vmnet"
	"terrascale.tech/orchestrator/src/orchestrator/vmqual"
)

func TestQualificationNTPNamespaceProbe(t *testing.T) {
	if os.Getenv("TS_VM_NTP_NAMESPACE_PROBE") != "1" {
		t.Skip("namespace subprocess helper")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(ctx, "udp4", os.Getenv("TS_VM_NTP_TARGET"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(2 * time.Second))
	request := make([]byte, 48)
	request[0] = 4<<3 | 3
	sent := time.Now()
	putNTPTime(request[40:48], sent)
	if _, err := conn.Write(request); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 512)
	n, err := conn.Read(reply)
	received := time.Now()
	if err != nil {
		t.Fatalf("real namespace NTP exchange: %v", err)
	}
	reply = reply[:n]
	if n != 48 || reply[0]&7 != 4 || reply[0]>>6 == 3 || reply[1] != 14 || !bytes.Equal(reply[24:32], request[40:48]) {
		t.Fatalf("invalid NTP reply: %x", reply)
	}
	parseTimestamp := func(encoded []byte) time.Time {
		return time.Unix(int64(binary.BigEndian.Uint32(encoded[:4]))-2208988800, int64(uint64(binary.BigEndian.Uint32(encoded[4:8]))*1000000000>>32))
	}
	arrival, departure := parseTimestamp(reply[32:40]), parseTimestamp(reply[40:48])
	if arrival.Before(sent.Add(-time.Millisecond)) || departure.Before(arrival) || departure.After(received.Add(time.Millisecond)) {
		t.Fatalf("NTP timestamps outside measured exchange: sent=%s rx=%s tx=%s received=%s", sent, arrival, departure, received)
	}
	t.Logf("actual NTP reply: bytes=%d stratum=%d leap=%d root_dispersion=%fs roundtrip=%s", n, reply[1], reply[0]>>6, float64(binary.BigEndian.Uint32(reply[8:12]))/65536, received.Sub(sent))
}

func TestQualificationNTPRealNamespaceExchange(t *testing.T) {
	if os.Getenv("TS_VM_NTP_NAMESPACE_TEST") != "1" {
		t.Skip("set TS_VM_NTP_NAMESPACE_TEST=1 with qualification host privileges")
	}
	if _, err := vmqual.SynchronizedHostTime(); err != nil {
		t.Fatalf("real NTP test requires synchronized host: %v", err)
	}
	tools, err := vmnet.DiscoverHostTools()
	if err != nil {
		t.Fatal(err)
	}
	config := vmnet.DefaultConfig()
	config.Tools = tools
	config.Regions = config.Regions[:1]
	digest := sha256.Sum256([]byte(t.TempDir()))
	config.RunID = fmt.Sprintf("%x", digest[:16])
	config.Endpoints = []vmnet.EndpointSpec{{Name: "ntp", Region: vmnet.GRU, Protocol: vmnet.UDP, GuestPort: 123, HostPort: 18123}}
	plan, err := vmnet.Plan(config)
	if err != nil {
		t.Fatal(err)
	}
	runner, err := vmnet.NewHostRunner(tools)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := plan.Cleanup.Run(cleanupCtx, runner); err != nil {
			t.Errorf("NTP network cleanup: %v", err)
		}
		for _, region := range plan.Regions {
			if _, err := os.Stat(region.NamespacePath); !os.IsNotExist(err) {
				t.Errorf("owned NTP namespace remains: %s: %v", region.NamespacePath, err)
			}
		}
	}()
	journal := &vmnet.RecordingRunner{}
	if err := plan.ApplyWithJournal(ctx, runner, journal); err != nil {
		t.Fatal(err)
	}
	service, err := startQualificationTimeService(plan)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := service.Close(); err != nil {
			t.Errorf("NTP listener cleanup: %v", err)
		}
	}()
	// Model the guest NIC with a veth in a second owned namespace. Traffic to
	// gateway:123 must cross the Region bridge and both planned NAT rules.
	probeNamespace := "vmq-ntp-probe-" + config.RunID
	runIP := func(args ...string) {
		t.Helper()
		if output, err := exec.CommandContext(ctx, tools.IP, args...).CombinedOutput(); err != nil {
			t.Fatalf("NTP fixture ip %v: %v %s", args, err, output)
		}
	}
	runIP("netns", "add", probeNamespace)
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if output, err := exec.CommandContext(cleanupCtx, tools.IP, "netns", "del", probeNamespace).CombinedOutput(); err != nil {
			t.Errorf("delete owned NTP probe namespace: %v %s", err, output)
		}
	}()
	runIP("-n", plan.Regions[0].Namespace, "link", "add", "ntp-probe0", "type", "veth", "peer", "name", "eth0", "netns", probeNamespace)
	runIP("-n", plan.Regions[0].Namespace, "link", "set", "ntp-probe0", "master", plan.Regions[0].Bridge)
	runIP("-n", plan.Regions[0].Namespace, "link", "set", "ntp-probe0", "up")
	runIP("-n", probeNamespace, "link", "set", "lo", "up")
	runIP("-n", probeNamespace, "addr", "add", plan.Regions[0].Guests[0].Address+"/24", "dev", "eth0")
	runIP("-n", probeNamespace, "link", "set", "eth0", "up")
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	listener, _ := plan.Listener("ntp")
	for _, probe := range []struct{ name, namespace, target string }{
		{"region-to-host", plan.Regions[0].Namespace, net.JoinHostPort(listener.Address, fmt.Sprint(listener.Port))},
		{"guest-bridge-NAT", probeNamespace, net.JoinHostPort(plan.Regions[0].Gateway, "123")},
	} {
		command := exec.CommandContext(ctx, tools.IP, "netns", "exec", probe.namespace, executable, "-test.run", "^TestQualificationNTPNamespaceProbe$", "-test.v")
		command.Env = append(os.Environ(), "TS_VM_NTP_NAMESPACE_PROBE=1", "TS_VM_NTP_TARGET="+probe.target)
		command.WaitDelay = time.Second
		output, err := command.CombinedOutput()
		if err != nil {
			t.Fatalf("NTP %s process: %v %s", probe.name, err, output)
		}
		t.Logf("%s: %s", probe.name, output)
	}
}

func TestQualificationNTPFixtureRecovery(t *testing.T) {
	runID := os.Getenv("TS_VM_NTP_RECOVERY_RUNID")
	if runID == "" {
		t.Skip("explicit recovery of an interrupted owned NTP-only fixture")
	}
	tools, err := vmnet.DiscoverHostTools()
	if err != nil {
		t.Fatal(err)
	}
	config := vmnet.DefaultConfig()
	config.Tools = tools
	config.Regions = config.Regions[:1]
	config.RunID = runID
	config.Endpoints = []vmnet.EndpointSpec{{Name: "ntp", Region: vmnet.GRU, Protocol: vmnet.UDP, GuestPort: 123, HostPort: 18123}}
	plan, err := vmnet.Plan(config)
	if err != nil {
		t.Fatal(err)
	}
	runner, err := vmnet.NewHostRunner(tools)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := plan.Cleanup.Run(ctx, runner); err != nil {
		t.Fatal(err)
	}
	for _, region := range plan.Regions {
		if _, err := os.Stat(region.NamespacePath); !os.IsNotExist(err) {
			t.Fatalf("recovered namespace remains: %s: %v", region.NamespacePath, err)
		}
	}
}
