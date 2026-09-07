package vmnet

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

const testRunID = "0123456789abcdef0123456789abcdef"

const (
	hostLeaseHelperEnv = "TS_VMNET_HOST_LEASE_HELPER"
	hostLeaseConfigEnv = "TS_VMNET_HOST_LEASE_CONFIG"
	hostLeaseModeEnv   = "TS_VMNET_HOST_LEASE_MODE"
)

func qualifiedConfig(t *testing.T) Config {
	t.Helper()
	config := DefaultConfig()
	digest := sha256.Sum256([]byte(t.Name()))
	config.RunID = fmt.Sprintf("%x", digest[:16])
	config.CoordinationRoot = filepath.Join(t.TempDir(), "coordination")
	config.Tools = testToolPaths(t)
	return config
}

func testToolPaths(t *testing.T) ToolPaths {
	t.Helper()
	directory := t.TempDir()
	paths := make(map[string]string, 4)
	for _, name := range []string{"ip", "tc", "nft", "sysctl", "iptables"} {
		path := filepath.Join(directory, name)
		if err := os.WriteFile(path, []byte("test executable"), 0700); err != nil {
			t.Fatal(err)
		}
		paths[name] = path
	}
	return ToolPaths{IP: paths["ip"], TC: paths["tc"], NFT: paths["nft"], Sysctl: paths["sysctl"], IPTables: paths["iptables"]}
}

type fakeRunner struct {
	commands []Command
	failAt   int
	checkCtx bool
}

type fakeJournalWriter struct {
	writes int
	plan   Journal
	err    error
}

type fakeCleanupRunner struct {
	runs     int
	cleanups int
}

type observingCleanupRunner struct {
	runs             int
	cleanups         []Command
	cancelledContext bool
	missingDeadline  bool
}

type boundFakeRunner struct {
	fakeRunner
	tools ToolPaths
}

type journaledFakeRunner struct {
	fakeRunner
	writes int
}

type blockingJournalRunner struct {
	mu       sync.Mutex
	commands []Command
	writes   int
	started  chan struct{}
	release  chan struct{}
	once     sync.Once
}

type hostLeaseHelperRunner struct {
	hold bool
	once sync.Once
	err  error
}

type hostLeaseHelperProcess struct {
	t       *testing.T
	cmd     *exec.Cmd
	stdin   io.WriteCloser
	scanner *bufio.Scanner
	stderr  strings.Builder
	waited  bool
}

func (r *boundFakeRunner) ToolPaths() ToolPaths { return r.tools }

func (*fakeRunner) vmnetNonHostRunner()             {}
func (*fakeCleanupRunner) vmnetNonHostRunner()      {}
func (*observingCleanupRunner) vmnetNonHostRunner() {}
func (*blockingJournalRunner) vmnetNonHostRunner()  {}
func (*hostLeaseHelperRunner) vmnetNonHostRunner()  {}

func (r *journaledFakeRunner) WriteJournal(context.Context, Journal) error {
	r.writes++
	return nil
}

func (r *blockingJournalRunner) WriteJournal(context.Context, Journal) error {
	r.mu.Lock()
	r.writes++
	r.mu.Unlock()
	return nil
}

func (r *blockingJournalRunner) Run(_ context.Context, executable string, args []string) error {
	r.mu.Lock()
	r.commands = append(r.commands, command(executable, args...))
	r.mu.Unlock()
	r.once.Do(func() {
		close(r.started)
		<-r.release
	})
	return nil
}

func (r *blockingJournalRunner) snapshot() (int, int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.commands), r.writes
}

func (r *hostLeaseHelperRunner) WriteJournal(context.Context, Journal) error { return nil }

func (r *hostLeaseHelperRunner) Run(context.Context, string, []string) error {
	r.once.Do(func() {
		if !r.hold {
			return
		}
		hostLeaseHelperSignal("LOCKED")
		var release [1]byte
		_, r.err = io.ReadFull(os.Stdin, release[:])
	})
	return r.err
}

func hostLeaseHelperSignal(value string) {
	_, _ = fmt.Fprintln(os.Stdout, value)
	_ = os.Stdout.Sync()
}

func startHostLeaseHelper(t *testing.T, config Config, mode string) *hostLeaseHelperProcess {
	t.Helper()
	raw, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	process := &hostLeaseHelperProcess{t: t}
	process.cmd = exec.Command(os.Args[0], "-test.run=^TestHostLeaseHelperProcess$", "-test.count=1")
	process.cmd.Env = append(os.Environ(),
		hostLeaseHelperEnv+"=1",
		hostLeaseConfigEnv+"="+base64.RawStdEncoding.EncodeToString(raw),
		hostLeaseModeEnv+"="+mode,
	)
	stdout, err := process.cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	process.stdin, err = process.cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	process.cmd.Stderr = &process.stderr
	process.scanner = bufio.NewScanner(stdout)
	if err := process.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if process.waited {
			return
		}
		_ = process.cmd.Process.Kill()
		_ = process.cmd.Wait()
	})
	return process
}

func (p *hostLeaseHelperProcess) expect(value string) {
	p.t.Helper()
	if !p.scanner.Scan() {
		p.t.Fatalf("host lease helper stopped before %q: %v; stderr=%s", value, p.scanner.Err(), p.stderr.String())
	}
	if observed := p.scanner.Text(); observed != value {
		p.t.Fatalf("host lease helper signal = %q, want %q; stderr=%s", observed, value, p.stderr.String())
	}
}

func (p *hostLeaseHelperProcess) release() {
	p.t.Helper()
	if _, err := p.stdin.Write([]byte{1}); err != nil {
		p.t.Fatalf("release host lease helper: %v", err)
	}
}

func (p *hostLeaseHelperProcess) wait() {
	p.t.Helper()
	if p.waited {
		return
	}
	p.waited = true
	if err := p.cmd.Wait(); err != nil {
		p.t.Fatalf("host lease helper: %v; stderr=%s", err, p.stderr.String())
	}
}

func TestHostLeaseHelperProcess(t *testing.T) {
	if os.Getenv(hostLeaseHelperEnv) != "1" {
		return
	}
	raw, err := base64.RawStdEncoding.DecodeString(os.Getenv(hostLeaseConfigEnv))
	if err != nil {
		t.Fatal(err)
	}
	var config Config
	if err := json.Unmarshal(raw, &config); err != nil {
		t.Fatal(err)
	}
	plan, err := Plan(config)
	if err != nil {
		t.Fatal(err)
	}
	mode := os.Getenv(hostLeaseModeEnv)
	runner := &hostLeaseHelperRunner{hold: mode == "hold"}
	if err := plan.Apply(context.Background(), runner); err != nil {
		t.Fatal(err)
	}
	hostLeaseHelperSignal("APPLIED")
	if mode == "crash" {
		os.Exit(0)
	}
	var release [1]byte
	if _, err := io.ReadFull(os.Stdin, release[:]); err != nil {
		t.Fatal(err)
	}
	if err := plan.Cleanup.Run(context.Background(), &fakeCleanupRunner{}); err != nil {
		t.Fatal(err)
	}
	hostLeaseHelperSignal("CLEANED")
}

func (f *fakeCleanupRunner) Run(context.Context, string, []string) error {
	f.runs++
	return errors.New("ordinary Run must not handle cleanup")
}

func (f *fakeCleanupRunner) RunCleanup(context.Context, string, []string) error {
	f.cleanups++
	return nil
}

func (f *observingCleanupRunner) Run(context.Context, string, []string) error {
	f.runs++
	return errors.New("ordinary Run must not handle cleanup")
}

func (f *observingCleanupRunner) RunCleanup(ctx context.Context, executable string, args []string) error {
	if ctx.Err() != nil {
		f.cancelledContext = true
	}
	if _, ok := ctx.Deadline(); !ok {
		f.missingDeadline = true
	}
	f.cleanups = append(f.cleanups, Command{Executable: executable, Args: append([]string(nil), args...)})
	return nil
}

func (f *fakeJournalWriter) WriteJournal(_ context.Context, journal Journal) error {
	f.writes++
	f.plan = journal
	return f.err
}

func (f *fakeRunner) Run(ctx context.Context, executable string, args []string) error {
	if f.checkCtx && ctx.Err() != nil {
		return ctx.Err()
	}
	f.commands = append(f.commands, Command{Executable: executable, Args: append([]string(nil), args...)})
	if f.failAt >= 0 && len(f.commands)-1 == f.failAt {
		return errors.New("injected runner failure")
	}
	return nil
}

func TestDefaultPlanIsStableAndCoversNetworkSurfaces(t *testing.T) {
	if StableCIDR(GRU) != "10.77.0.0/24" || StableGateway(SFO) != "10.77.1.1" {
		t.Fatal("launch address allocation changed")
	}
	address, err := StableGuestAddress(FRA, 2)
	if err != nil || address != "10.77.2.11" {
		t.Fatalf("stable guest address = %q, %v", address, err)
	}
	mac, err := StableGuestMAC(FRA, 2)
	if err != nil || mac != "02:fc:77:03:02:01" {
		t.Fatalf("stable guest MAC = %q, %v", mac, err)
	}
	config := qualifiedConfig(t)
	first, err := Plan(config)
	if err != nil {
		t.Fatal(err)
	}
	config.Regions[0], config.Regions[2] = config.Regions[2], config.Regions[0]
	config.Regions[0].Guests[0], config.Regions[0].Guests[1] = config.Regions[0].Guests[1], config.Regions[0].Guests[0]
	second, err := Plan(config)
	if err != nil {
		t.Fatal(err)
	}
	if first.Fingerprint != second.Fingerprint || !reflect.DeepEqual(first.Commands, second.Commands) {
		t.Fatal("declaration order changed the network plan")
	}
	if len(first.Regions) != 3 || len(first.Regions[0].Guests)+len(first.Regions[1].Guests)+len(first.Regions[2].Guests) != 6 {
		t.Fatalf("unexpected launch topology: %+v", first.Regions)
	}
	joined := ""
	for _, c := range first.Commands {
		joined += c.Executable + " " + strings.Join(c.Args, " ") + "\n"
	}
	for _, want := range []string{"netns", "tuntap", "bridge", "nft", "forward", "veth", "route", "sysctl"} {
		if !strings.Contains(joined, want) {
			t.Errorf("plan lacks %s operations", want)
		}
	}
	if len(first.Cleanup.Commands) == 0 || first.Journal.Fingerprint != first.Fingerprint {
		t.Fatal("missing crash cleanup journal")
	}
	for _, region := range first.Regions {
		if region.NamespacePath != "/run/netns/"+region.Namespace {
			t.Fatalf("namespace path = %q for %s", region.NamespacePath, region.Code)
		}
		for _, guest := range region.Guests {
			if !strings.HasPrefix(guest.ID, strings.ToLower(string(region.Code))+"-") || guest.MAC == "" {
				t.Fatalf("unresolved guest identity: %+v", guest)
			}
			for _, command := range first.Commands {
				line := strings.Join(command.Args, " ")
				if strings.Contains(line, guest.Address+"/32") && strings.Contains(line, "dev "+guest.TAP) {
					t.Fatalf("guest address was assigned to host TAP: %s", line)
				}
			}
		}
	}
	for _, command := range first.Commands {
		line := strings.Join(command.Args, " ")
		if strings.Contains(line, " link set ts-v-") && strings.Contains(line, " master ") {
			t.Fatalf("transit veth was bridged instead of routed: %s", line)
		}
	}
}

func TestDefaultPlanOwnsExplicitHostEndpointPath(t *testing.T) {
	plan, err := Plan(qualifiedConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Uplinks) != len(plan.Regions) || len(plan.Forwards) != 5*len(plan.Regions) || len(plan.Listeners) != 5 {
		t.Fatalf("endpoint topology: uplinks=%d forwards=%d listeners=%d", len(plan.Uplinks), len(plan.Forwards), len(plan.Listeners))
	}
	if !reflect.DeepEqual(plan.Uplinks, plan.Cleanup.Uplinks) || !reflect.DeepEqual(plan.Forwards, plan.Cleanup.Forwards) || !reflect.DeepEqual(plan.Listeners, plan.Cleanup.Listeners) || !reflect.DeepEqual(plan.DNSRecords, plan.Cleanup.DNSRecords) {
		t.Fatal("cleanup journal does not retain the complete endpoint manifest")
	}

	rootDevices := make(map[string]bool, len(plan.Uplinks))
	serviceAddress := ""
	serviceOwners := 0
	for index, uplink := range plan.Uplinks {
		if uplink.Region != plan.Regions[index].Code || uplink.RegionNamespace != plan.Regions[index].Namespace || uplink != plan.Regions[index].Uplink {
			t.Fatalf("Region %s uplink does not match its namespace: %+v", plan.Regions[index].Code, uplink)
		}
		if rootDevices[uplink.RootDevice] {
			t.Fatalf("root uplink device %q is shared", uplink.RootDevice)
		}
		rootDevices[uplink.RootDevice] = true
		if serviceAddress == "" {
			serviceAddress = uplink.HostServiceAddress
		}
		if uplink.HostServiceAddress != serviceAddress {
			t.Fatalf("Region %s targets service address %q, want %q", uplink.Region, uplink.HostServiceAddress, serviceAddress)
		}
		if uplink.OwnsServiceAddress {
			serviceOwners++
		}
	}
	if serviceOwners != 1 {
		t.Fatalf("host service address owners = %d, want one", serviceOwners)
	}

	for _, region := range plan.Regions {
		endpoint, ok := plan.Endpoint(region.Code, "artifacts")
		if !ok || endpoint.GuestAddress != region.Gateway || endpoint.GuestPort != 8443 || endpoint.HostAddress != serviceAddress || endpoint.HostPort != 8443 {
			t.Fatalf("Region %s artifact endpoint = %+v, found=%v", region.Code, endpoint, ok)
		}
		backup, ok := plan.Endpoint(region.Code, "backup")
		if !ok || backup.GuestAddress != region.Gateway || backup.GuestPort != 443 || backup.HostAddress != serviceAddress || backup.HostPort != 19443 {
			t.Fatalf("Region %s backup endpoint = %+v, found=%v", region.Code, backup, ok)
		}
		records := plan.RegionDNSRecords(region.Code)
		if len(records) != 2 || records[0] != (DNSRecord{Region: region.Code, Name: "fly.storage.tigris.dev", Type: "A", Address: region.Gateway}) || records[1] != (DNSRecord{Region: region.Code, Name: "releases.terrascale.tech", Type: "A", Address: region.Gateway}) {
			t.Fatalf("Region %s DNS records = %+v", region.Code, records)
		}
	}
	for name, port := range map[string]uint16{"nats": 4222, "artifacts": 8443, "backup": 19443, "smoke": 18080} {
		listener, ok := plan.Listener(name)
		if !ok || listener != (EndpointListener{Name: name, Protocol: TCP, Address: serviceAddress, Port: port}) {
			t.Fatalf("listener %q = %+v, found=%v", name, listener, ok)
		}
	}

	dnat, snat, endpointAccepts, serviceAssignments, uplinkCreations := 0, 0, 0, 0, 0
	for _, command := range plan.Commands {
		args := command.Args
		if contains(args, "masquerade") || contains(args, "0.0.0.0/0") || contains(args, "default") {
			t.Fatalf("plan contains an internet escape or broad forwarding rule: %+v", command)
		}
		if contains(args, "dnat") {
			dnat++
		}
		if contains(args, "snat") {
			snat++
		}
		if contains(args, "accept") {
			for _, uplink := range plan.Uplinks {
				if contains(args, uplink.RegionDevice) {
					endpointAccepts++
				}
			}
		}
		if contains(args, serviceAddress+"/32") && contains(args, "addr") && contains(args, "add") {
			serviceAssignments++
		}
		for _, uplink := range plan.Uplinks {
			if contains(args, "link") && contains(args, "add") && contains(args, uplink.RegionDevice) && contains(args, uplink.RootDevice) && contains(args, "netns") && contains(args, uplink.RegionNamespace) && contains(args, rootLinkAddress(plan.Prefix, plan.RunID, uplink.Region)) {
				uplinkCreations++
			}
		}
	}
	if dnat != len(plan.Forwards) || snat != len(plan.Forwards) || endpointAccepts != len(plan.Forwards) || serviceAssignments != 1 || uplinkCreations != len(plan.Regions) {
		t.Fatalf("endpoint rules: dnat=%d snat=%d accept=%d service-address=%d uplinks=%d", dnat, snat, endpointAccepts, serviceAssignments, uplinkCreations)
	}
}

func TestEndpointLookupRejectsTamperingAndCrossRunTargets(t *testing.T) {
	config := qualifiedConfig(t)
	plan, err := Plan(config)
	if err != nil {
		t.Fatal(err)
	}
	foreignConfig := config
	foreignConfig.RunID = "ffffffffffffffffffffffffffffffff"
	foreign, err := Plan(foreignConfig)
	if err != nil {
		t.Fatal(err)
	}
	owned, ok := plan.Endpoint(GRU, "smoke")
	if !ok {
		t.Fatal("owned smoke endpoint is missing")
	}
	foreignEndpoint, ok := foreign.Endpoint(GRU, "smoke")
	if !ok || foreignEndpoint.HostAddress == owned.HostAddress {
		t.Fatalf("cross-run host targets are not distinct: owned=%+v foreign=%+v", owned, foreignEndpoint)
	}

	tampered := plan.copy()
	for index := range tampered.Forwards {
		if tampered.Forwards[index].Region == GRU && tampered.Forwards[index].Name == "smoke" {
			tampered.Forwards[index].HostAddress = foreignEndpoint.HostAddress
		}
	}
	if endpoint, ok := tampered.Endpoint(GRU, "smoke"); ok || !reflect.DeepEqual(endpoint, EndpointForward{}) {
		t.Fatalf("lookup returned a cross-run target from a tampered plan: %+v", endpoint)
	}
	if _, ok := plan.Endpoint(GRU, "undeclared"); ok {
		t.Fatal("lookup returned an undeclared endpoint")
	}
}

func TestPlanRequiresSafeRunIDAndPinnedTools(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(Config) Config
	}{
		{name: "short run ID", mutate: func(config Config) Config { config.RunID = "0123456789abcdef"; return config }},
		{name: "uppercase run ID", mutate: func(config Config) Config { config.RunID = "0123456789ABCDEF0123456789ABCDEF"; return config }},
		{name: "non-hex run ID", mutate: func(config Config) Config { config.RunID = "gggggggggggggggggggggggggggggggg"; return config }},
		{name: "missing ip", mutate: func(config Config) Config { config.Tools.IP = ""; return config }},
		{name: "relative tc", mutate: func(config Config) Config { config.Tools.TC = "tc"; return config }},
		{name: "unclean nft", mutate: func(config Config) Config { config.Tools.NFT = "/opt/../usr/bin/nft"; return config }},
		{name: "missing sysctl", mutate: func(config Config) Config { config.Tools.Sysctl = ""; return config }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := Plan(test.mutate(qualifiedConfig(t))); err == nil {
				t.Fatal("Plan accepted an unsafe run identity or tool path")
			}
		})
	}
}

func TestPlanUsesOneProcessScopedDefaultRunID(t *testing.T) {
	config := qualifiedConfig(t)
	config.RunID = ""
	first, err := Plan(config)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Plan(config)
	if err != nil {
		t.Fatal(err)
	}
	if first.RunID == "" || first.RunID != second.RunID {
		t.Fatalf("default run ID is empty or changed within one process: %q, %q", first.RunID, second.RunID)
	}
	if len(first.RunID) != 32 {
		t.Fatalf("default run ID length = %d, want 32", len(first.RunID))
	}
	for _, character := range first.RunID {
		if !strings.ContainsRune("0123456789abcdef", character) {
			t.Fatalf("default run ID contains unsafe character %q: %q", character, first.RunID)
		}
	}
}

func TestPlanPinsEveryHostExecutable(t *testing.T) {
	config := qualifiedConfig(t)
	config.Faults = []FaultSpec{{From: GRU, To: SFO, Latency: 25 * time.Millisecond}}
	plan, err := Plan(config)
	if err != nil {
		t.Fatal(err)
	}

	seenNested := map[string]bool{}
	commands := append([]Command(nil), plan.Commands...)
	commands = append(commands, plan.Cleanup.Commands...)
	commands = append(commands, plan.Cleanup.HostInput...)
	for _, command := range commands {
		if !filepath.IsAbs(command.Executable) || filepath.Clean(command.Executable) != command.Executable {
			t.Fatalf("command executable is not clean and absolute: %+v", command)
		}
		if command.Executable != config.Tools.IP && command.Executable != config.Tools.IPTables {
			t.Fatalf("command uses unpinned top-level executable %q", command.Executable)
		}
		if len(command.Args) >= 4 && command.Args[0] == "netns" && command.Args[1] == "exec" {
			nested := command.Args[3]
			if !filepath.IsAbs(nested) || filepath.Clean(nested) != nested {
				t.Fatalf("nested executable is not clean and absolute: %+v", command)
			}
			seenNested[nested] = true
		}
	}
	for name, path := range map[string]string{"nft": config.Tools.NFT, "sysctl": config.Tools.Sysctl, "tc": config.Tools.TC} {
		if !seenNested[path] {
			t.Errorf("plan never used pinned %s executable %q", name, path)
		}
	}
}

func TestPlanHandlesCanonicalPrivateSubnetBoundaries(t *testing.T) {
	tests := []struct {
		name        string
		cidr        string
		address     string
		wantGateway string
	}{
		{name: "slash 24 last usable", cidr: "10.91.0.0/24", address: "10.91.0.254", wantGateway: "10.91.0.1"},
		{name: "nonzero slash 25", cidr: "10.91.0.128/25", address: "10.91.0.254", wantGateway: "10.91.0.129"},
		{name: "slash 30 only guest", cidr: "10.91.0.0/30", address: "10.91.0.2", wantGateway: "10.91.0.1"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := qualifiedConfig(t)
			config.Regions = []RegionSpec{{Code: GRU, CIDR: test.cidr, Guests: []GuestSpec{{ID: "guest", Address: test.address}}}}
			plan, err := Plan(config)
			if err != nil {
				t.Fatal(err)
			}
			if got := plan.Regions[0].Gateway; got != test.wantGateway {
				t.Fatalf("gateway = %q, want %q", got, test.wantGateway)
			}
			if got := plan.Regions[0].Guests[0].Address; got != test.address {
				t.Fatalf("guest address = %q, want %q", got, test.address)
			}
		})
	}
}

func TestPlanRejectsBroadcastAndNonPrivateSubnets(t *testing.T) {
	tests := []struct {
		name    string
		cidr    string
		address string
	}{
		{name: "slash 24 broadcast", cidr: "10.91.0.0/24", address: "10.91.0.255"},
		{name: "slash 30 broadcast", cidr: "10.91.0.0/30", address: "10.91.0.3"},
		{name: "public", cidr: "192.0.2.0/24", address: "192.0.2.10"},
		{name: "loopback", cidr: "127.0.0.0/24", address: "127.0.0.10"},
		{name: "link local transit", cidr: "169.254.240.0/24", address: "169.254.240.10"},
		{name: "reserved private transit", cidr: "10.78.252.0/24", address: "10.78.252.10"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := qualifiedConfig(t)
			config.Regions = []RegionSpec{{Code: GRU, CIDR: test.cidr, Guests: []GuestSpec{{ID: "guest", Address: test.address}}}}
			if _, err := Plan(config); err == nil {
				t.Fatal("Plan accepted an unusable or reserved Region subnet")
			}
		})
	}
}

func TestTransitLinksAreRoutedAndGuestAddressesRemainGuestOwned(t *testing.T) {
	config := qualifiedConfig(t)
	plan, err := Plan(config)
	if err != nil {
		t.Fatal(err)
	}

	transit := transitNames(plan.Commands)
	if len(transit) != 6 {
		t.Fatalf("transit endpoints = %d, want six directed endpoints for three Region pairs", len(transit))
	}

	forwarding := make(map[string]bool)
	transitAddresses := make(map[string]bool)
	routes := 0
	faultDispatches := 0
	for _, command := range plan.Commands {
		args := command.Args
		if contains(args, "master") {
			for endpoint := range transit {
				if contains(args, endpoint) {
					t.Fatalf("transit endpoint %q was attached to a bridge: %+v", endpoint, command)
				}
			}
		}
		if len(args) >= 6 && args[0] == "netns" && args[1] == "exec" && args[3] == config.Tools.Sysctl && contains(args, "net.ipv4.ip_forward=1") {
			forwarding[args[2]] = true
		}
		if contains(args, "route") && contains(args, "via") {
			routes++
		}
		if contains(args, "jump") {
			faultDispatches++
			if !contains(args, "insert") {
				t.Fatalf("fault dispatch does not precede conntrack acceptance: %+v", command)
			}
		}
		for endpoint := range transit {
			if contains(args, endpoint) && contains(args, "addr") {
				for _, argument := range args {
					if strings.HasSuffix(argument, "/30") {
						transitAddresses[endpoint] = true
					}
				}
			}
		}
		for _, region := range plan.Regions {
			for _, guest := range region.Guests {
				if contains(args, "addr") && contains(args, "dev") && contains(args, guest.TAP) {
					for _, argument := range args {
						if argument == guest.Address || strings.HasPrefix(argument, guest.Address+"/") {
							t.Fatalf("guest address %s was assigned to host TAP %s: %+v", guest.Address, guest.TAP, command)
						}
					}
				}
			}
		}
	}
	if len(forwarding) != len(plan.Regions) {
		t.Fatalf("forwarding enabled in %d/%d Region namespaces", len(forwarding), len(plan.Regions))
	}
	if len(transitAddresses) != len(transit) {
		t.Fatalf("routed /30 addresses cover %d/%d transit endpoints", len(transitAddresses), len(transit))
	}
	joined := joinedCommands(plan.Commands)
	for _, address := range []string{"10.78.252.1/30", "10.78.252.2/30", "10.78.252.5/30", "10.78.252.6/30", "10.78.252.9/30", "10.78.252.10/30"} {
		if !strings.Contains(joined, address) {
			t.Errorf("transit plan lacks %s", address)
		}
	}
	if routes < len(transit) {
		t.Fatalf("cross-Region routes = %d, want at least %d", routes, len(transit))
	}
	if faultDispatches != len(transit) {
		t.Fatalf("fault dispatches = %d, want one for each of %d directed links", faultDispatches, len(transit))
	}
}

func TestRunIDScopesEveryOwnedNetworkResource(t *testing.T) {
	firstConfig := qualifiedConfig(t)
	secondConfig := firstConfig
	// Keep the first 12 hexadecimal characters identical so this test catches
	// accidental prefix truncation instead of proving only the easy case.
	secondConfig.RunID = "0123456789abffffffffffffffffffff"
	first, err := Plan(firstConfig)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Plan(secondConfig)
	if err != nil {
		t.Fatal(err)
	}
	if first.RunID != firstConfig.RunID || second.RunID != secondConfig.RunID {
		t.Fatalf("plans lost run identity: %q, %q", first.RunID, second.RunID)
	}
	if first.Fingerprint == second.Fingerprint {
		t.Fatal("distinct run IDs produced the same fingerprint")
	}

	owned := ownedResourceNames(first)
	foreign := ownedResourceNames(second)
	for name := range owned {
		if foreign[name] {
			t.Fatalf("owned network resource %q is shared by distinct run IDs", name)
		}
	}
	for _, command := range first.Cleanup.Commands {
		ownedTarget := false
		for _, argument := range command.Args {
			ownedTarget = ownedTarget || owned[argument]
			if foreign[argument] {
				t.Fatalf("cleanup for run %s targets resource %q owned by run %s: %+v", first.RunID, argument, second.RunID, command)
			}
		}
		if !ownedTarget {
			t.Fatalf("cleanup command has no resource owned by run %s: %+v", first.RunID, command)
		}
	}
	for index := range first.Regions {
		a, b := first.Regions[index], second.Regions[index]
		if a.Namespace == b.Namespace || a.Bridge == b.Bridge || a.NamespacePath == b.NamespacePath {
			t.Fatalf("Region resources are not run-scoped: first=%+v second=%+v", a, b)
		}
		for guestIndex := range a.Guests {
			if a.Guests[guestIndex].TAP == b.Guests[guestIndex].TAP {
				t.Fatalf("guest TAP is not run-scoped: %q", a.Guests[guestIndex].TAP)
			}
		}
	}
	firstTransit, secondTransit := transitNames(first.Commands), transitNames(second.Commands)
	if len(firstTransit) == 0 || len(firstTransit) != len(secondTransit) {
		t.Fatalf("unexpected transit resources: first=%v second=%v", firstTransit, secondTransit)
	}
	for name := range firstTransit {
		if secondTransit[name] {
			t.Fatalf("transit endpoint %q is shared by distinct runs", name)
		}
	}
}

func TestCleanupIsBoundedReplaySafeAndIgnoresCallerCancellation(t *testing.T) {
	plan, err := Plan(qualifiedConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	runner := &observingCleanupRunner{}
	for replay := 0; replay < 2; replay++ {
		if err := plan.Cleanup.Run(ctx, runner); err != nil {
			t.Fatalf("cleanup replay %d failed: %v", replay+1, err)
		}
	}
	if runner.runs != 0 {
		t.Fatalf("cleanup used ordinary Run %d times", runner.runs)
	}
	if runner.cancelledContext {
		t.Fatal("caller cancellation prevented a cleanup command")
	}
	if runner.missingDeadline {
		t.Fatal("a cleanup command ran without a deadline")
	}
	want := 2 * (len(plan.Cleanup.Commands) + len(plan.Cleanup.HostInput) + len(plan.Cleanup.RootLinks))
	if len(runner.cleanups) != want {
		t.Fatalf("cleanup commands across two replays = %d, want %d", len(runner.cleanups), want)
	}
}

func TestCleanupRejectsCrossRunTargetsBeforeMutation(t *testing.T) {
	config := qualifiedConfig(t)
	plan, err := Plan(config)
	if err != nil {
		t.Fatal(err)
	}
	foreignConfig := config
	foreignConfig.RunID = "0123456789abffffffffffffffffffff"
	foreign, err := Plan(foreignConfig)
	if err != nil {
		t.Fatal(err)
	}

	cleanup := plan.CleanupPlan()
	cleanup.Commands[0].Args[2] = foreign.Regions[0].Namespace
	runner := &fakeCleanupRunner{}
	if err := cleanup.Run(context.Background(), runner); err == nil {
		t.Fatal("cleanup accepted a namespace owned by another run")
	}
	if runner.runs != 0 || runner.cleanups != 0 {
		t.Fatalf("invalid cleanup reached runner: runs=%d cleanups=%d", runner.runs, runner.cleanups)
	}

	journal := plan.Journal
	journal.RunID = foreign.RunID
	if err := journal.Validate(); err == nil {
		t.Fatal("journal accepted mismatched cleanup ownership")
	}
}

func TestApplyRejectsTamperedPlanBeforeJournalOrMutation(t *testing.T) {
	plan, err := Plan(qualifiedConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		mutate func(*NetworkPlan)
	}{
		{name: "foreign setup command", mutate: func(plan *NetworkPlan) {
			plan.Commands[0] = command(plan.Tools.IP, "netns", "del", "default")
		}},
		{name: "foreign cleanup command", mutate: func(plan *NetworkPlan) {
			plan.Cleanup.Commands[0] = command(plan.Tools.IP, "netns", "del", "default")
		}},
		{name: "journal ownership", mutate: func(plan *NetworkPlan) {
			plan.Journal.RunID = "ffffffffffffffffffffffffffffffff"
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			tampered := plan.copy()
			test.mutate(&tampered)
			runner := &fakeRunner{failAt: -1}
			writer := &fakeJournalWriter{}
			if err := tampered.ApplyWithJournal(context.Background(), runner, writer); err == nil {
				t.Fatal("ApplyWithJournal accepted a tampered network plan")
			}
			if writer.writes != 0 || len(runner.commands) != 0 {
				t.Fatalf("tampered plan reached privileged boundary: writes=%d commands=%+v", writer.writes, runner.commands)
			}
		})
	}
}

func TestEndpointRulesCannotForwardUndeclaredHostsOrPorts(t *testing.T) {
	config := qualifiedConfig(t)
	config.Regions = []RegionSpec{{Code: GRU, Guests: []GuestSpec{{ID: "member"}}}}
	config.Endpoints = []EndpointSpec{{Name: "api", Region: GRU, Protocol: TCP, GuestPort: 9443, HostPort: 10443, DNSNames: []string{"api.terrascale.test"}}}
	plan, err := Plan(config)
	if err != nil {
		t.Fatal(err)
	}
	endpoint, ok := plan.Endpoint(GRU, "api")
	if !ok {
		t.Fatal("declared endpoint is missing")
	}
	wantedTarget := endpoint.HostAddress + ":10443"
	var endpointRules int
	for _, command := range plan.Commands {
		args := command.Args
		if !contains(args, "dnat") && !contains(args, "snat") && !(contains(args, "accept") && contains(args, plan.Uplinks[0].RegionDevice)) {
			continue
		}
		endpointRules++
		if !contains(args, "tcp") || !contains(args, "10443") && !contains(args, "9443") || contains(args, "10444") || contains(args, "203.0.113.1") {
			t.Fatalf("endpoint rule is not bound to the declared tuple: %+v", command)
		}
		if contains(args, "dnat") && (!contains(args, endpoint.GuestAddress) || !contains(args, "9443") || !contains(args, wantedTarget)) {
			t.Fatalf("DNAT rule differs from the declared mapping: %+v", command)
		}
		if (contains(args, "snat") || contains(args, "accept")) && (!contains(args, endpoint.HostAddress) || !contains(args, "10443")) {
			t.Fatalf("host-side rule differs from the declared mapping: %+v", command)
		}
	}
	if endpointRules != 3 {
		t.Fatalf("endpoint rule count = %d, want one DNAT, SNAT, and filter rule", endpointRules)
	}

	tampered := plan.copy()
	tampered.Commands = append(tampered.Commands, command(plan.Tools.IP, "netns", "exec", plan.Regions[0].Namespace, plan.Tools.NFT, "add", "rule", "inet", networkTable(plan.Prefix, plan.RunID), "forward", "tcp", "dport", "10444", "accept"))
	runner := &fakeRunner{failAt: -1}
	writer := &fakeJournalWriter{}
	if err := tampered.ApplyWithJournal(context.Background(), runner, writer); err == nil {
		t.Fatal("tampered plan forwarded an undeclared port")
	}
	if writer.writes != 0 || len(runner.commands) != 0 {
		t.Fatalf("undeclared forward reached privileged boundary: writes=%d commands=%d", writer.writes, len(runner.commands))
	}
}

func TestExplicitEmptyEndpointSetForwardsNothing(t *testing.T) {
	config := qualifiedConfig(t)
	config.Regions = []RegionSpec{{Code: GRU, Guests: []GuestSpec{{ID: "member"}}}}
	config.Endpoints = []EndpointSpec{}
	plan, err := Plan(config)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Forwards) != 0 || len(plan.Listeners) != 0 || len(plan.DNSRecords) != 0 {
		t.Fatalf("empty declaration resolved endpoints: forwards=%d listeners=%d DNS=%d", len(plan.Forwards), len(plan.Listeners), len(plan.DNSRecords))
	}
	for _, command := range plan.Commands {
		if contains(command.Args, "dnat") || contains(command.Args, "snat") || contains(command.Args, "masquerade") {
			t.Fatalf("empty endpoint declaration emitted forwarding rule: %+v", command)
		}
	}
}

func TestPlanRejectsInvalidEndpointDeclarations(t *testing.T) {
	base := qualifiedConfig(t)
	tests := []struct {
		name      string
		endpoints []EndpointSpec
	}{
		{name: "foreign Region", endpoints: []EndpointSpec{{Name: "api", Region: "IAD", Protocol: TCP, GuestPort: 1, HostPort: 1}}},
		{name: "unsupported protocol", endpoints: []EndpointSpec{{Name: "api", Region: GRU, Protocol: "udp", GuestPort: 1, HostPort: 1}}},
		{name: "zero port", endpoints: []EndpointSpec{{Name: "api", Region: GRU, Protocol: TCP, HostPort: 1}}},
		{name: "duplicate guest port", endpoints: []EndpointSpec{{Name: "one", Region: GRU, Protocol: TCP, GuestPort: 1, HostPort: 1}, {Name: "two", Region: GRU, Protocol: TCP, GuestPort: 1, HostPort: 2}}},
		{name: "shared host port", endpoints: []EndpointSpec{{Name: "one", Region: GRU, Protocol: TCP, GuestPort: 1, HostPort: 1}, {Name: "two", Region: SFO, Protocol: TCP, GuestPort: 2, HostPort: 1}}},
		{name: "inconsistent shared listener", endpoints: []EndpointSpec{{Name: "api", Region: GRU, Protocol: TCP, GuestPort: 1, HostPort: 1}, {Name: "api", Region: SFO, Protocol: TCP, GuestPort: 1, HostPort: 2}}},
		{name: "invalid DNS", endpoints: []EndpointSpec{{Name: "api", Region: GRU, Protocol: TCP, GuestPort: 1, HostPort: 1, DNSNames: []string{"localhost"}}}},
		{name: "duplicate DNS", endpoints: []EndpointSpec{{Name: "api", Region: GRU, Protocol: TCP, GuestPort: 1, HostPort: 1, DNSNames: []string{"api.test", "api.test"}}}},
		{name: "too many DNS names", endpoints: []EndpointSpec{{Name: "api", Region: GRU, Protocol: TCP, GuestPort: 1, HostPort: 1, DNSNames: []string{"a.test", "b.test", "c.test", "d.test", "e.test", "f.test", "g.test", "h.test", "i.test"}}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := base
			config.Endpoints = test.endpoints
			if _, err := Plan(config); err == nil {
				t.Fatal("Plan accepted an invalid endpoint declaration")
			}
		})
	}
	tooMany := base
	tooMany.Endpoints = make([]EndpointSpec, maxPlanForwards+1)
	if _, err := Plan(tooMany); err == nil {
		t.Fatal("Plan accepted too many endpoint declarations")
	}
}

func TestPlanCommandBoundCoversMaximumAdmittedTopology(t *testing.T) {
	config := qualifiedConfig(t)
	config.Regions = nil
	regions := append([]RegionCode(nil), launchRegions...)
	for i := 0; i < 17; i++ {
		regions = append(regions, RegionCode(fmt.Sprintf("A%cA", byte('A'+i))))
	}
	for _, region := range regions {
		spec := RegionSpec{Code: region, CIDR: StableCIDR(region)}
		for guest := 0; guest < 32; guest++ {
			spec.Guests = append(spec.Guests, GuestSpec{ID: fmt.Sprintf("%s-member-%02d", strings.ToLower(string(region)), guest)})
		}
		config.Regions = append(config.Regions, spec)
		for endpoint := 0; endpoint < 16; endpoint++ {
			port := uint16(10000 + endpoint)
			config.Endpoints = append(config.Endpoints, EndpointSpec{Name: fmt.Sprintf("endpoint-%02d", endpoint), Region: region, Protocol: TCP, GuestPort: port, HostPort: port})
		}
	}
	for _, from := range regions {
		for _, to := range regions {
			if from != to {
				config.Faults = append(config.Faults, FaultSpec{From: from, To: to, Latency: time.Millisecond, Partition: true})
			}
		}
	}
	plan, err := Plan(config)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Commands) <= 512 || len(plan.Commands) > maxPlanCommands {
		t.Fatalf("maximum topology command count = %d, bound = %d", len(plan.Commands), maxPlanCommands)
	}
	if err := plan.Validate(); err != nil {
		t.Fatalf("maximum admitted topology produced an invalid plan: %v", err)
	}
}

func TestCleanupRejectsTamperedEndpointManifest(t *testing.T) {
	plan, err := Plan(qualifiedConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	tests := []func(*CleanupPlan){
		func(cleanup *CleanupPlan) { cleanup.Uplinks[0].RootDevice = "eth0" },
		func(cleanup *CleanupPlan) { cleanup.Forwards[0].HostPort++ },
		func(cleanup *CleanupPlan) { cleanup.Listeners[0].Address = "127.0.0.1" },
		func(cleanup *CleanupPlan) { cleanup.DNSRecords[0].Address = "203.0.113.1" },
	}
	for _, mutate := range tests {
		cleanup := plan.CleanupPlan()
		mutate(&cleanup)
		runner := &fakeCleanupRunner{}
		if err := cleanup.Run(context.Background(), runner); err == nil {
			t.Fatal("cleanup accepted a tampered endpoint manifest")
		}
		if runner.runs != 0 || runner.cleanups != 0 {
			t.Fatal("tampered endpoint manifest reached cleanup runner")
		}
	}
}

func TestPlanRejectsRunnerWithDifferentPinnedTools(t *testing.T) {
	config := qualifiedConfig(t)
	plan, err := Plan(config)
	if err != nil {
		t.Fatal(err)
	}
	runner := &boundFakeRunner{fakeRunner: fakeRunner{failAt: -1}, tools: testToolPaths(t)}
	if err := plan.ApplyWithJournal(context.Background(), runner, &fakeJournalWriter{}); err == nil {
		t.Fatal("Apply accepted a runner bound to different host executables")
	}
	if len(runner.commands) != 0 {
		t.Fatalf("mismatched runner received commands: %+v", runner.commands)
	}
}

func TestCleanupNeedsOnlyItsPinnedCleanupBinaries(t *testing.T) {
	config := qualifiedConfig(t)
	plan, err := Plan(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(config.Tools.TC); err != nil {
		t.Fatal(err)
	}
	runner := &fakeCleanupRunner{}
	if err := plan.Cleanup.Run(context.Background(), runner); err != nil {
		t.Fatalf("cleanup depended on an unrelated removed tc binary: %v", err)
	}
	if runner.cleanups != len(plan.Regions)+len(plan.Cleanup.HostInput)+len(plan.Cleanup.RootLinks) {
		t.Fatalf("cleanup commands = %d, want %d", runner.cleanups, len(plan.Regions)+len(plan.Cleanup.HostInput)+len(plan.Cleanup.RootLinks))
	}
}

func TestCleanupRegionManifestIsCompleteAndCanonical(t *testing.T) {
	plan, err := Plan(qualifiedConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*CleanupPlan){
		func(cleanup *CleanupPlan) { cleanup.Regions = cleanup.Regions[:len(cleanup.Regions)-1] },
		func(cleanup *CleanupPlan) {
			cleanup.Regions[0], cleanup.Regions[1] = cleanup.Regions[1], cleanup.Regions[0]
		},
		func(cleanup *CleanupPlan) { cleanup.Commands = cleanup.Commands[:len(cleanup.Commands)-1] },
	} {
		cleanup := plan.CleanupPlan()
		mutate(&cleanup)
		runner := &fakeCleanupRunner{}
		if err := cleanup.Run(context.Background(), runner); err == nil {
			t.Fatal("cleanup accepted an incomplete or noncanonical Region manifest")
		}
		if runner.cleanups != 0 {
			t.Fatalf("invalid cleanup reached runner %d times", runner.cleanups)
		}
	}
}

func TestTAPOwnershipIsExplicitWhenConfigured(t *testing.T) {
	config := qualifiedConfig(t)
	config.TAPUID = 1234
	config.TAPGID = 5678
	config.Regions = []RegionSpec{{Code: GRU, Guests: []GuestSpec{{ID: "gru-member-1"}}}}
	plan, err := Plan(config)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, command := range plan.Commands {
		if contains(command.Args, "tuntap") {
			found = contains(command.Args, "user") && contains(command.Args, "1234") && contains(command.Args, "group") && contains(command.Args, "5678")
		}
	}
	if !found {
		t.Fatal("TAP owner and group were not emitted")
	}
}

func TestFaultsAreDirectionalNetemAndPartition(t *testing.T) {
	config := qualifiedConfig(t)
	config.Faults = []FaultSpec{{
		From: GRU, To: FRA, Latency: 120 * time.Millisecond, Jitter: 15 * time.Millisecond,
		LossPercent: 2.5, BandwidthKbit: 512, Partition: true,
	}}
	plan, err := Plan(config)
	if err != nil {
		t.Fatal(err)
	}
	foundTC, foundDrop := false, false
	for _, c := range plan.Commands {
		if c.Executable == config.Tools.IP && len(c.Args) > 3 && c.Args[0] == "netns" && c.Args[1] == "exec" && c.Args[3] == config.Tools.TC {
			if contains(c.Args, "120ms") && contains(c.Args, "15ms") && contains(c.Args, "2.5%") && contains(c.Args, "512kbit") {
				foundTC = true
			}
		}
		if contains(c.Args, "drop") {
			foundDrop = true
		}
	}
	if !foundTC || !foundDrop {
		t.Fatalf("fault plan tc=%v drop=%v", foundTC, foundDrop)
	}
}

func TestApplyFailureRunsBestEffortCleanup(t *testing.T) {
	plan, err := Plan(qualifiedConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	runner := &fakeRunner{failAt: 3}
	if err := plan.ApplyWithJournal(context.Background(), runner, &fakeJournalWriter{}); err == nil {
		t.Fatal("Apply succeeded despite injected failure")
	}
	if len(runner.commands) != 4+(len(plan.Cleanup.Commands)+len(plan.Cleanup.HostInput)+len(plan.Cleanup.RootLinks)) {
		t.Fatalf("commands after failed apply = %d, want %d", len(runner.commands), 4+(len(plan.Cleanup.Commands)+len(plan.Cleanup.HostInput)+len(plan.Cleanup.RootLinks)))
	}
	// Cleanup proceeds in reverse ownership order and can be replayed.
	before := len(runner.commands)
	_ = plan.Rollback(context.Background(), runner)
	if len(runner.commands) != before+(len(plan.Cleanup.Commands)+len(plan.Cleanup.HostInput)+len(plan.Cleanup.RootLinks)) {
		t.Fatal("rollback did not replay the complete idempotent cleanup plan")
	}
}

func TestCancellationUsesCleanupContext(t *testing.T) {
	plan, err := Plan(qualifiedConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	runner := &fakeRunner{failAt: -1, checkCtx: true}
	if err := plan.ApplyWithJournal(ctx, runner, &fakeJournalWriter{}); err == nil {
		t.Fatal("Apply did not report cancellation")
	}
	if len(runner.commands) != (len(plan.Cleanup.Commands) + len(plan.Cleanup.HostInput) + len(plan.Cleanup.RootLinks)) {
		t.Fatalf("cancellation cleanup commands = %d, want %d", len(runner.commands), (len(plan.Cleanup.Commands) + len(plan.Cleanup.HostInput) + len(plan.Cleanup.RootLinks)))
	}
	if err := plan.Cleanup.Run(context.Background(), &fakeCleanupRunner{}); err != nil {
		t.Fatal(err)
	}
}

func TestApplyWithJournalWritesBeforeRunner(t *testing.T) {
	config := qualifiedConfig(t)
	config.Regions = []RegionSpec{{Code: GRU, Guests: []GuestSpec{{ID: "member"}}}}
	plan, err := Plan(config)
	if err != nil {
		t.Fatal(err)
	}
	writer := &fakeJournalWriter{}
	runner := &fakeRunner{failAt: -1}
	if err := plan.ApplyWithJournal(context.Background(), runner, writer); err != nil {
		t.Fatal(err)
	}
	if writer.writes != 1 || writer.plan.Fingerprint != plan.Fingerprint || len(runner.commands) != len(plan.Commands) {
		t.Fatalf("journal/apply ordering state: writes=%d fingerprint=%q commands=%d", writer.writes, writer.plan.Fingerprint, len(runner.commands))
	}
	if writer.plan.RunID != config.RunID || writer.plan.Cleanup.RunID != config.RunID {
		t.Fatalf("journal lost run identity: journal=%q cleanup=%q", writer.plan.RunID, writer.plan.Cleanup.RunID)
	}
	if !reflect.DeepEqual(writer.plan.Tools, config.Tools) || !reflect.DeepEqual(writer.plan.Cleanup.Tools, config.Tools) {
		t.Fatalf("journal lost pinned tools: journal=%+v cleanup=%+v want=%+v", writer.plan.Tools, writer.plan.Cleanup.Tools, config.Tools)
	}
	if err := plan.Cleanup.Run(context.Background(), &fakeCleanupRunner{}); err != nil {
		t.Fatal(err)
	}
}

func TestNonHostApplyUsesExplicitOwnedCoordinationRoot(t *testing.T) {
	config := qualifiedConfig(t)
	plan, err := Plan(config)
	if err != nil {
		t.Fatal(err)
	}
	if plan.CoordinationRoot != config.CoordinationRoot || plan.Journal.CoordinationRoot != config.CoordinationRoot || plan.Cleanup.CoordinationRoot != config.CoordinationRoot {
		t.Fatal("explicit coordination root was not bound into the plan and recovery journal")
	}
	runner := &fakeRunner{failAt: -1}
	if err := plan.ApplyWithJournal(context.Background(), runner, &fakeJournalWriter{}); err != nil {
		t.Fatalf("non-host Apply with owned coordination root: %v", err)
	}
	info, err := os.Stat(config.CoordinationRoot)
	if err != nil {
		t.Fatal(err)
	}
	if !info.IsDir() || info.Mode().Perm() != 0o700 {
		t.Fatalf("coordination root mode = %v", info.Mode())
	}
	claims, err := filepath.Glob(filepath.Join(config.CoordinationRoot, "*.claim"))
	if err != nil || len(claims) == 0 {
		t.Fatalf("published host claims = %v, %v", claims, err)
	}
	if err := plan.Cleanup.Run(context.Background(), &fakeCleanupRunner{}); err != nil {
		t.Fatal(err)
	}
	claims, err = filepath.Glob(filepath.Join(config.CoordinationRoot, "*.claim"))
	if err != nil || len(claims) != 0 {
		t.Fatalf("claims after cleanup = %v, %v", claims, err)
	}
}

func TestHostRunnerRejectsCallerSelectedCoordinationRoot(t *testing.T) {
	config := qualifiedConfig(t)
	plan, err := Plan(config)
	if err != nil {
		t.Fatal(err)
	}
	runner, err := NewHostRunner(config.Tools)
	if err != nil {
		t.Fatal(err)
	}
	writer := &fakeJournalWriter{}
	if err := plan.ApplyWithJournal(context.Background(), runner, writer); err == nil || !strings.Contains(err.Error(), "non-host recording runner") {
		t.Fatalf("HostRunner custom coordination error = %v", err)
	}
	if writer.writes != 0 {
		t.Fatal("HostRunner reached the journal with a caller-selected lock domain")
	}
}

func TestApplyCannotBypassDurableJournal(t *testing.T) {
	plan, err := Plan(qualifiedConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	plain := &fakeRunner{failAt: -1}
	if err := plan.Apply(context.Background(), plain); err == nil || !strings.Contains(err.Error(), "journal") {
		t.Fatalf("journal-less Apply error = %v", err)
	}
	if len(plain.commands) != 0 {
		t.Fatalf("journal-less Apply mutated host runner: %+v", plain.commands)
	}
	failingRunner := &fakeRunner{failAt: -1}
	failingWriter := &fakeJournalWriter{err: errors.New("storage unavailable")}
	if err := plan.ApplyWithJournal(context.Background(), failingRunner, failingWriter); err == nil {
		t.Fatal("Apply accepted a failed journal write")
	}
	if len(failingRunner.commands) != 0 {
		t.Fatal("failed journal write reached host mutation")
	}

	journaled := &journaledFakeRunner{fakeRunner: fakeRunner{failAt: -1}}
	if err := plan.Apply(context.Background(), journaled); err != nil {
		t.Fatal(err)
	}
	if journaled.writes != 1 || len(journaled.commands) != len(plan.Commands) {
		t.Fatalf("journaled Apply writes=%d commands=%d", journaled.writes, len(journaled.commands))
	}
	if err := plan.Cleanup.Run(context.Background(), &fakeCleanupRunner{}); err != nil {
		t.Fatal(err)
	}
}

func TestConcurrentSameRunApplyExecutesOnePlan(t *testing.T) {
	plan, err := Plan(qualifiedConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	runner := &blockingJournalRunner{started: make(chan struct{}), release: make(chan struct{})}
	released := false
	defer func() {
		if !released {
			close(runner.release)
		}
	}()
	results := make(chan error, 2)
	go func() { results <- plan.Apply(context.Background(), runner) }()
	select {
	case <-runner.started:
	case err := <-results:
		t.Fatalf("first Apply returned before executing a command: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("first Apply did not reach its command")
	}
	go func() { results <- plan.Apply(context.Background(), runner) }()
	select {
	case err := <-results:
		t.Fatalf("same-run Apply escaped serialization while the first command was blocked: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	close(runner.release)
	released = true
	for range 2 {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
	commands, writes := runner.snapshot()
	if writes != 1 || commands != len(plan.Commands) {
		t.Fatalf("concurrent Apply writes=%d commands=%d, want one complete plan", writes, commands)
	}
	if err := plan.Cleanup.Run(context.Background(), &fakeCleanupRunner{}); err != nil {
		t.Fatal(err)
	}
}

func TestHostLeaseSerializesSameRunAcrossProcessesUntilCleanup(t *testing.T) {
	config := qualifiedConfig(t)
	config.RunID = "00000000000000000000000000000040"
	plan, err := Plan(config)
	if err != nil {
		t.Fatal(err)
	}
	collisionConfig := config
	collisionConfig.RunID = "00000000000000000000000000000101"
	collision, err := Plan(collisionConfig)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Uplinks[0].HostServiceAddress != collision.Uplinks[0].HostServiceAddress {
		t.Fatal("live-lock test RunIDs do not share a service address")
	}
	helper := startHostLeaseHelper(t, config, "hold")
	helper.expect("LOCKED")

	for _, phase := range []string{"during apply", "after apply"} {
		runner := &fakeRunner{failAt: -1}
		writer := &fakeJournalWriter{}
		err := plan.ApplyWithJournal(context.Background(), runner, writer)
		if err == nil || !strings.Contains(err.Error(), "active on this host") {
			t.Fatalf("same-run Apply %s error = %v", phase, err)
		}
		if writer.writes != 0 || len(runner.commands) != 0 {
			t.Fatalf("same-run Apply %s reached journal or host mutation", phase)
		}
		collisionRunner := &fakeRunner{failAt: -1}
		collisionWriter := &fakeJournalWriter{}
		err = collision.ApplyWithJournal(context.Background(), collisionRunner, collisionWriter)
		if err == nil || !strings.Contains(err.Error(), "service-address/") || !strings.Contains(err.Error(), "active") {
			t.Fatalf("colliding address Apply %s error = %v", phase, err)
		}
		if collisionWriter.writes != 0 || len(collisionRunner.commands) != 0 {
			t.Fatalf("colliding address Apply %s reached journal or host mutation", phase)
		}
		if phase == "during apply" {
			helper.release()
			helper.expect("APPLIED")
		}
	}

	helper.release()
	helper.expect("CLEANED")
	helper.wait()
	runner := &fakeRunner{failAt: -1}
	if err := collision.ApplyWithJournal(context.Background(), runner, &fakeJournalWriter{}); err != nil {
		t.Fatalf("Apply after external cleanup: %v", err)
	}
	if err := collision.Cleanup.Run(context.Background(), &fakeCleanupRunner{}); err != nil {
		t.Fatal(err)
	}
}

func TestHostClaimsProtectCollidingServiceAddressAfterCrash(t *testing.T) {
	firstConfig := qualifiedConfig(t)
	firstConfig.RunID = "00000000000000000000000000000040"
	secondConfig := firstConfig
	secondConfig.RunID = "00000000000000000000000000000101"
	first, err := Plan(firstConfig)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Plan(secondConfig)
	if err != nil {
		t.Fatal(err)
	}
	if first.Uplinks[0].HostServiceAddress != second.Uplinks[0].HostServiceAddress {
		t.Fatalf("test RunIDs no longer collide: %s != %s", first.Uplinks[0].HostServiceAddress, second.Uplinks[0].HostServiceAddress)
	}

	helper := startHostLeaseHelper(t, firstConfig, "crash")
	helper.expect("APPLIED")
	helper.wait()

	collisionRunner := &fakeRunner{failAt: -1}
	collisionWriter := &fakeJournalWriter{}
	err = second.ApplyWithJournal(context.Background(), collisionRunner, collisionWriter)
	if err == nil || !strings.Contains(err.Error(), "claimed by run "+first.RunID) {
		t.Fatalf("colliding service address error = %v", err)
	}
	if collisionWriter.writes != 0 || len(collisionRunner.commands) != 0 {
		t.Fatal("colliding run reached journal or host mutation")
	}

	recoveryRunner := &fakeRunner{failAt: -1}
	recoveryWriter := &fakeJournalWriter{}
	err = first.ApplyWithJournal(context.Background(), recoveryRunner, recoveryWriter)
	if err == nil || !strings.Contains(err.Error(), "requires cleanup") {
		t.Fatalf("crashed run Apply error = %v", err)
	}
	if recoveryWriter.writes != 0 || len(recoveryRunner.commands) != 0 {
		t.Fatal("crashed run reapplied before cleanup")
	}
	if err := first.Cleanup.Run(context.Background(), &fakeCleanupRunner{}); err != nil {
		t.Fatalf("recover crashed host claims: %v", err)
	}

	if err := second.ApplyWithJournal(context.Background(), collisionRunner, collisionWriter); err != nil {
		t.Fatalf("colliding run remained blocked after recovered cleanup: %v", err)
	}
	if err := second.Cleanup.Run(context.Background(), &fakeCleanupRunner{}); err != nil {
		t.Fatal(err)
	}
}

func TestFailedApplyRequiresCleanupBeforeRetry(t *testing.T) {
	plan, err := Plan(qualifiedConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := plan.ApplyWithJournal(context.Background(), &fakeRunner{failAt: 3}, &fakeJournalWriter{}); err == nil {
		t.Fatal("Apply succeeded despite injected failure")
	}
	retryRunner := &fakeRunner{failAt: -1}
	retryWriter := &fakeJournalWriter{}
	if err := plan.ApplyWithJournal(context.Background(), retryRunner, retryWriter); err == nil || !strings.Contains(err.Error(), "cleanup") {
		t.Fatalf("retry before explicit cleanup error = %v", err)
	}
	if retryWriter.writes != 0 || len(retryRunner.commands) != 0 {
		t.Fatal("retry mutated host state before cleanup replay")
	}
	if err := plan.Cleanup.Run(context.Background(), &fakeCleanupRunner{}); err != nil {
		t.Fatal(err)
	}
	if err := plan.ApplyWithJournal(context.Background(), retryRunner, retryWriter); err != nil {
		t.Fatal(err)
	}
	if err := plan.Cleanup.Run(context.Background(), &fakeCleanupRunner{}); err != nil {
		t.Fatal(err)
	}
}

func TestRunCoordinatorRetiresOnlyAfterSuccessfulCleanup(t *testing.T) {
	plan, err := Plan(qualifiedConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := plan.ApplyWithJournal(context.Background(), &fakeRunner{failAt: -1}, &fakeJournalWriter{}); err != nil {
		t.Fatal(err)
	}
	if !runCoordinatorExists(plan.RunID) {
		t.Fatal("applied run lost its shared coordinator")
	}
	if err := plan.Cleanup.Run(context.Background(), &fakeRunner{failAt: 0}); err == nil {
		t.Fatal("cleanup succeeded despite injected failure")
	}
	if !runCoordinatorExists(plan.RunID) {
		t.Fatal("incomplete cleanup retired its poisoned coordinator")
	}
	if err := plan.Cleanup.Run(context.Background(), &fakeCleanupRunner{}); err != nil {
		t.Fatal(err)
	}
	if runCoordinatorExists(plan.RunID) {
		t.Fatal("successful cleanup retained an inactive coordinator")
	}
}

func runCoordinatorExists(runID string) bool {
	runCoordinatorRegistry.Lock()
	defer runCoordinatorRegistry.Unlock()
	_, ok := runCoordinatorRegistry.entries[runID]
	return ok
}

func TestAppliedRunRejectsDifferentPlanWithSameRunID(t *testing.T) {
	config := qualifiedConfig(t)
	first, err := Plan(config)
	if err != nil {
		t.Fatal(err)
	}
	otherConfig := config
	otherConfig.Prefix = "alt"
	other, err := Plan(otherConfig)
	if err != nil {
		t.Fatal(err)
	}
	if err := first.ApplyWithJournal(context.Background(), &fakeRunner{failAt: -1}, &fakeJournalWriter{}); err != nil {
		t.Fatal(err)
	}
	runner := &fakeRunner{failAt: -1}
	writer := &fakeJournalWriter{}
	if err := other.ApplyWithJournal(context.Background(), runner, writer); err == nil {
		t.Fatal("same run ID applied a different network plan")
	}
	if writer.writes != 0 || len(runner.commands) != 0 {
		t.Fatal("conflicting same-run plan reached journal or host mutation")
	}
	if err := first.Cleanup.Run(context.Background(), &fakeCleanupRunner{}); err != nil {
		t.Fatal(err)
	}
}

func TestValidationRejectsUnsafeDeclarations(t *testing.T) {
	tests := []func(Config) Config{
		func(config Config) Config { config.Prefix = "bad;rm"; return config },
		func(config Config) Config {
			config.Regions = []RegionSpec{{Code: GRU, CIDR: "10.1.0.1/24", Guests: []GuestSpec{{ID: "guest"}}}}
			return config
		},
		func(config Config) Config {
			config.Regions = []RegionSpec{{Code: GRU, Guests: []GuestSpec{{ID: "guest", Address: "192.0.2.1"}}}}
			return config
		},
		func(config Config) Config {
			config.Regions = []RegionSpec{{Code: GRU, Guests: []GuestSpec{{ID: "guest", TAP: "tap;bad"}}}}
			return config
		},
	}
	for i, mutate := range tests {
		config := mutate(qualifiedConfig(t))
		if _, err := Plan(config); err == nil {
			t.Errorf("case %d accepted unsafe declaration", i)
		}
	}
}

func TestCleanupContinuesAfterError(t *testing.T) {
	plan, err := Plan(qualifiedConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	runner := &fakeRunner{failAt: 0}
	if err := plan.Cleanup.Run(context.Background(), runner); err == nil {
		t.Fatal("cleanup hid runner error")
	}
	if len(runner.commands) != (len(plan.Cleanup.Commands) + len(plan.Cleanup.HostInput) + len(plan.Cleanup.RootLinks)) {
		t.Fatalf("cleanup stopped after first error: %d/%d", len(runner.commands), (len(plan.Cleanup.Commands) + len(plan.Cleanup.HostInput) + len(plan.Cleanup.RootLinks)))
	}
	if err := plan.Cleanup.Run(context.Background(), &fakeCleanupRunner{}); err != nil {
		t.Fatal(err)
	}
}

func TestCleanupUsesIdempotentRunnerWhenAvailable(t *testing.T) {
	plan, err := Plan(qualifiedConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	runner := &fakeCleanupRunner{}
	if err := plan.Cleanup.Run(context.Background(), runner); err != nil {
		t.Fatal(err)
	}
	if runner.runs != 0 || runner.cleanups != (len(plan.Cleanup.Commands)+len(plan.Cleanup.HostInput)+len(plan.Cleanup.RootLinks)) {
		t.Fatalf("cleanup dispatch runs=%d cleanups=%d", runner.runs, runner.cleanups)
	}
}

func contains(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}

func transitNames(commands []Command) map[string]bool {
	result := make(map[string]bool)
	for _, command := range commands {
		args := command.Args
		for index := 0; index+9 < len(args); index++ {
			if args[index] == "link" && args[index+1] == "add" && args[index+3] == "type" && args[index+4] == "veth" && args[index+5] == "peer" && args[index+6] == "name" {
				if len(args) >= 2 && args[len(args)-2] == "netns" && args[len(args)-1] == "1" {
					continue
				}
				result[args[index+2]] = true
				result[args[index+7]] = true
			}
		}
	}
	return result
}

func ownedResourceNames(plan NetworkPlan) map[string]bool {
	result := transitNames(plan.Commands)
	for _, uplink := range plan.Uplinks {
		result[uplink.RegionDevice] = true
		result[uplink.RootDevice] = true
		result[uplink.RegionAddress] = true
		result[uplink.RootAddress] = true
		result[uplink.HostServiceAddress] = true
	}
	for _, region := range plan.Regions {
		result[region.Namespace] = true
		result[region.NamespacePath] = true
		result[region.Bridge] = true
		for _, guest := range region.Guests {
			result[guest.TAP] = true
		}
	}
	for _, command := range plan.Commands {
		for index, argument := range command.Args {
			if argument == "table" && index+2 < len(command.Args) && command.Args[index+1] == "inet" {
				result[command.Args[index+2]] = true
			}
		}
	}
	return result
}

func TestOnlyBoundedNTPUDPAllowed(t *testing.T) {
	for _, spec := range []EndpointSpec{
		{Name: "ntp", Region: GRU, Protocol: UDP, GuestPort: 123, HostPort: 18124},
		{Name: "ntp", Region: GRU, Protocol: UDP, GuestPort: 124, HostPort: 18123},
		{Name: "dns", Region: GRU, Protocol: UDP, GuestPort: 123, HostPort: 18123},
	} {
		config := qualifiedConfig(t)
		config.Endpoints = []EndpointSpec{spec}
		if _, err := Plan(config); err == nil {
			t.Fatalf("unbounded UDP admitted: %+v", spec)
		}
	}
	plan, err := Plan(qualifiedConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, region := range plan.Regions {
		forward, ok := plan.Endpoint(region.Code, "ntp")
		if !ok || forward.Protocol != UDP || forward.GuestPort != 123 || forward.HostPort != 18123 || forward.GuestAddress != region.Gateway {
			t.Fatalf("NTP mapping: %+v", forward)
		}
	}
}

func TestBenchmarkHostAddressPoolsAreDisjoint(t *testing.T) {
	uplinkPool := netip.MustParsePrefix("198.18.0.0/16")
	servicePool := netip.MustParsePrefix("198.19.0.0/16")
	for run := 0; run < 1024; run++ {
		id := fmt.Sprintf("%032x", run)
		service := hostServiceAddress(id)
		if !servicePool.Contains(service) || uplinkPool.Contains(service) {
			t.Fatalf("service address outside dedicated pool: %s", service)
		}
		seen := make(map[string]bool)
		for _, region := range launchRegions {
			uplink := regionUplink("vmq", id, region, regionIndex(region), region == GRU)
			cidr := netip.MustParsePrefix(uplink.CIDR)
			if cidr.Bits() != 30 || !uplinkPool.Contains(cidr.Addr()) || !uplinkPool.Contains(netip.MustParseAddr(uplink.RegionAddress)) || !uplinkPool.Contains(netip.MustParseAddr(uplink.RootAddress)) || cidr.Contains(service) || seen[uplink.CIDR] {
				t.Fatalf("invalid benchmark uplink: %+v", uplink)
			}
			seen[uplink.CIDR] = true
		}
	}
}

func TestHostClaimsProtectBenchmarkUplinkCollision(t *testing.T) {
	config := qualifiedConfig(t)
	seen := make(map[string]string)
	firstID, secondID := "", ""
	for run := 0; run < 20000; run++ {
		id := fmt.Sprintf("%032x", run)
		uplink := regionUplink(config.Prefix, id, GRU, 0, true)
		if earlier, ok := seen[uplink.CIDR]; ok && hostServiceAddress(earlier) != hostServiceAddress(id) {
			firstID, secondID = earlier, id
			break
		}
		seen[uplink.CIDR] = id
	}
	if firstID == "" {
		t.Fatal("failed to find bounded pool collision fixture")
	}
	config.RunID = firstID
	first, err := Plan(config)
	if err != nil {
		t.Fatal(err)
	}
	config.RunID = secondID
	second, err := Plan(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := first.ApplyWithJournal(context.Background(), &fakeRunner{failAt: -1}, &fakeJournalWriter{}); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := first.Cleanup.Run(context.Background(), &fakeCleanupRunner{}); err != nil {
			t.Error(err)
		}
	}()
	runner, writer := &fakeRunner{failAt: -1}, &fakeJournalWriter{}
	err = second.ApplyWithJournal(context.Background(), runner, writer)
	if err == nil || !strings.Contains(err.Error(), "uplink-cidr/") {
		t.Fatalf("benchmark collision did not acquire exclusive CIDR claim: %v", err)
	}
	if len(runner.commands) != 0 || writer.writes != 0 {
		t.Fatal("colliding run reached host mutation")
	}
}
