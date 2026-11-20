package oraclehost

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/fleet"
	"github.com/TerraScale/ts-orchestrator/internal/natscell/mesh"
	"github.com/TerraScale/ts-orchestrator/internal/networkplan"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"github.com/TerraScale/ts-orchestrator/internal/releasepush"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
	"github.com/TerraScale/ts-orchestrator/internal/vaultsecret"
	"github.com/nats-io/nats.go"
	"golang.org/x/sys/unix"
)

var netBirdMesh = netip.MustParsePrefix(networkplan.Mesh)

const (
	bridgeName     = "osh-br"
	GatewayAddress = "10.204.0.1"
	subnetCIDR     = "10.204.0.0/24"
	metadataIP     = "169.254.169.254"
)

type Region struct {
	Name          string
	OCIRegion     string
	CompartmentID string
	Hosts         []*Host
}

type Host struct {
	Name       string
	Region     *Region
	Namespace  string
	Address    string
	NetBird    string
	InstanceID string
	Dir        string
	fleet      *Fleet
	mu         sync.Mutex
	events     []Event
	changed    chan struct{}
	process    *exec.Cmd
	done       chan error
}

type Fleet struct {
	Work     string
	Binary   string
	Registry string
	Regions  []*Region
	Hosts    []*Host
	standIn  *standIn
	run      int
}

func New(ctx context.Context, work, binary string, registry string, regions []string, hostsPerRegion []int, pooled ...string) (*Fleet, error) {
	unix.Umask(0o022)
	f := &Fleet{Work: work, Binary: binary, Registry: registry}
	if err := os.MkdirAll(work, 0o755); err != nil {
		return nil, err
	}
	for r, name := range regions {
		entry, ok := catalog.LookupName(name)
		if !ok {
			return nil, fmt.Errorf("%s is not a catalog region", name)
		}
		document, err := fleet.Embedded().Region(name)
		if err != nil {
			return nil, err
		}
		region := &Region{Name: name, OCIRegion: entry.OCIRegion, CompartmentID: document.CompartmentID}
		for i := 1; i <= hostsPerRegion[r]; i++ {
			octet := 10*(r+1) + i
			netBird := netBirdMesh.Addr().As4()
			netBird[3] = byte(octet)
			hostname := fmt.Sprintf("ts-%s-%d", name, i)
			if slices.Contains(pooled, name) {
				hostname = fmt.Sprintf("%s-node-%d", name, i)
			}
			host := &Host{Name: hostname, Region: region, Namespace: fmt.Sprintf("osh-%s-%d", name, i),
				Address: fmt.Sprintf("10.204.0.%d", octet), NetBird: netip.AddrFrom4(netBird).String(),
				InstanceID: fmt.Sprintf("ocid1.instance.oc1.%s.oracleregions%d", entry.OCIRegion, octet), fleet: f, changed: make(chan struct{})}
			host.Dir = filepath.Join(work, host.Name)
			region.Hosts = append(region.Hosts, host)
			f.Hosts = append(f.Hosts, host)
		}
		f.Regions = append(f.Regions, region)
	}
	standIn, pair, err := newStandIn(f)
	if err != nil {
		return nil, err
	}
	f.standIn = standIn
	if err := standIn.writeFiles(work); err != nil {
		return nil, err
	}
	if err := f.network(ctx); err != nil {
		return nil, err
	}
	listen := func(address string) (net.Listener, error) { return net.Listen("tcp", address) }
	metadata, err := listen(metadataIP + ":80")
	if err != nil {
		return nil, err
	}
	standIn.serve(metadata, standIn.metadata)
	cloud, err := listen(GatewayAddress + ":443")
	if err != nil {
		return nil, err
	}
	standIn.serve(tls.NewListener(cloud, &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{*pair}}), standIn.cloud)
	for _, host := range f.Hosts {
		if err := f.prepare(host); err != nil {
			return nil, err
		}
	}
	return f, nil
}

func ip(ctx context.Context, args ...string) error {
	output, err := exec.CommandContext(ctx, "ip", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("ip %s: %w: %s", strings.Join(args, " "), err, bytes.TrimSpace(output))
	}
	return nil
}

func (f *Fleet) network(ctx context.Context) error {
	if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
		return fmt.Errorf("the lane must run in its own mount and network namespace (unshare --mount --net): %w", err)
	}
	for _, dir := range []string{"/run/netns", "/etc/netns"} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
		if err := unix.Mount("tmpfs", dir, "tmpfs", 0, "mode=0755"); err != nil {
			return err
		}
	}
	steps := [][]string{
		{"link", "set", "lo", "up"},
		{"link", "add", bridgeName, "type", "bridge"},
		{"addr", "add", GatewayAddress + "/24", "dev", bridgeName},
		{"addr", "add", metadataIP + "/32", "dev", bridgeName},
		{"link", "set", bridgeName, "up"},
	}
	for _, host := range f.Hosts {
		steps = append(steps,
			[]string{"netns", "add", host.Namespace},
			[]string{"link", "add", host.Namespace, "type", "veth", "peer", "name", "eth0", "netns", host.Namespace},
			[]string{"link", "set", host.Namespace, "master", bridgeName, "up"},
			[]string{"-n", host.Namespace, "link", "set", "lo", "up"},
			[]string{"-n", host.Namespace, "addr", "add", host.Address + "/24", "dev", "eth0"},
			[]string{"-n", host.Namespace, "link", "set", "eth0", "up"},
			[]string{"-n", host.Namespace, "link", "add", "wt0", "type", "dummy"},
			[]string{"-n", host.Namespace, "addr", "add", netip.PrefixFrom(netip.MustParseAddr(host.NetBird), netBirdMesh.Bits()).String(), "dev", "wt0"},
			[]string{"-n", host.Namespace, "link", "set", "wt0", "up"},
			[]string{"-n", host.Namespace, "route", "add", "default", "via", GatewayAddress},
		)
		for _, peer := range f.Hosts {
			if peer != host {
				steps = append(steps, []string{"-n", host.Namespace, "route", "add", peer.NetBird + "/32", "via", peer.Address, "src", host.NetBird})
			}
		}
	}
	for _, step := range steps {
		if err := ip(ctx, step...); err != nil {
			return err
		}
	}
	return nil
}

func (f *Fleet) hosts(self *Host) string {
	var b strings.Builder
	fmt.Fprintf(&b, "127.0.0.1 localhost\n::1 localhost\n127.0.1.1 %s\n", self.Name)
	for _, host := range f.Hosts {
		fmt.Fprintf(&b, "%s %s.nb.ts.internal\n", host.NetBird, host.Name)
	}
	fmt.Fprintf(&b, "%s %s\n", GatewayAddress, strings.Join(f.standIn.names, " "))
	return b.String()
}

func copyFile(source, target string, mode os.FileMode) error {
	data, err := os.ReadFile(source)
	if err != nil {
		return err
	}
	return os.WriteFile(target, data, mode)
}

func (f *Fleet) prepare(host *Host) error {
	for _, dir := range []string{"state", "containerd", "bin"} {
		if err := os.MkdirAll(filepath.Join(host.Dir, dir), 0o755); err != nil {
			return err
		}
	}
	if err := copyFile(f.Binary, filepath.Join(host.Dir, "bin", filepath.Base(installedPath)), 0o755); err != nil {
		return err
	}
	if err := os.Symlink(filepath.Base(installedPath), filepath.Join(host.Dir, "bin", "ts-orch")); err != nil {
		return err
	}
	self, err := os.Executable()
	if err != nil {
		return err
	}
	for _, name := range []string{systemctlCommand, analyzeCommand} {
		if err := copyFile(self, filepath.Join(host.Dir, "bin", name), 0o755); err != nil {
			return err
		}
	}
	for _, name := range []string{"containerd", "containerd-shim-runc-v2"} {
		path, err := exec.LookPath(name)
		if err != nil {
			return err
		}
		if err := copyFile(path, filepath.Join(host.Dir, "bin", name), 0o755); err != nil {
			return err
		}
	}
	netns := filepath.Join("/etc/netns", host.Namespace)
	if err := os.MkdirAll(netns, 0o755); err != nil {
		return err
	}
	for name, content := range map[string]string{
		"hosts":         f.hosts(host),
		"resolv.conf":   "nameserver 127.0.0.1\noptions timeout:1 attempts:1\n",
		"nsswitch.conf": "hosts: files dns\n",
	} {
		if err := os.WriteFile(filepath.Join(netns, name), []byte(content), 0o644); err != nil {
			return err
		}
	}
	cfg, err := json.Marshal(hostConfig{Name: host.Name, Dir: host.Dir, InstanceID: host.InstanceID, CABundle: filepath.Join(f.Work, "ca.pem"), Containerd: "/usr/local/bin/containerd"})
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(host.Dir, "host.json"), cfg, 0o644)
}

func (f *Fleet) hostByAddress(address string) *Host {
	for _, host := range f.Hosts {
		if host.Address == address {
			return host
		}
	}
	return nil
}

func (f *Fleet) Boot(hosts ...*Host) error {
	self, err := os.Executable()
	if err != nil {
		return err
	}
	for _, host := range hosts {
		cmd := exec.Command("ip", "netns", "exec", host.Namespace, "unshare", "--mount", "--uts", "--propagation", "private", self, hostCommand, filepath.Join(host.Dir, "host.json"))
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			return err
		}
		stderr, err := os.Create(filepath.Join(host.Dir, "host.log"))
		if err != nil {
			return err
		}
		cmd.Stderr = stderr
		if err := cmd.Start(); err != nil {
			return err
		}
		host.process, host.done = cmd, make(chan error, 1)
		go host.read(stdout)
		go func() { host.done <- cmd.Wait(); _ = stderr.Close() }()
	}
	return nil
}

func (h *Host) read(stdout io.Reader) {
	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		var event Event
		if json.Unmarshal(scanner.Bytes(), &event) != nil {
			continue
		}
		fmt.Printf("%s %s %s run %d %s %s\n", event.At.Format("15:04:05.000"), h.Name, event.Kind, event.Run, short(event.Revision), event.Detail)
		h.mu.Lock()
		h.events = append(h.events, event)
		close(h.changed)
		h.changed = make(chan struct{})
		h.mu.Unlock()
	}
	h.mu.Lock()
	h.events = append(h.events, Event{At: time.Now(), Kind: "gone"})
	close(h.changed)
	h.changed = make(chan struct{})
	h.mu.Unlock()
}

func short(revision string) string {
	if len(revision) > 12 {
		return revision[:12]
	}
	return revision
}

func (h *Host) Events() []Event {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]Event(nil), h.events...)
}

func (h *Host) WaitEvent(ctx context.Context, match func(Event) bool) (Event, error) {
	return h.WaitEventFrom(ctx, 0, match)
}

func (h *Host) EventCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.events)
}

func (h *Host) WaitEventFrom(ctx context.Context, seen int, match func(Event) bool) (Event, error) {
	for {
		h.mu.Lock()
		events, changed := h.events[seen:], h.changed
		seen = len(h.events)
		h.mu.Unlock()
		for _, event := range events {
			if match(event) {
				return event, nil
			}
			if event.Kind == "gone" {
				return Event{}, fmt.Errorf("%s host process ended: %s", h.Name, h.tail("host.log"))
			}
		}
		select {
		case <-ctx.Done():
			return Event{}, fmt.Errorf("%s: %w; journal tail:\n%s", h.Name, ctx.Err(), h.tail("journal.log"))
		case <-changed:
		}
	}
}

func (h *Host) WaitReady(ctx context.Context, after int, revision string) (Event, error) {
	return h.WaitEvent(ctx, func(e Event) bool {
		return e.Kind == "ready" && e.Run > after && (revision == "" || e.Revision == revision)
	})
}

func (h *Host) LastRun() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	run := 0
	for _, event := range h.events {
		run = max(run, event.Run)
	}
	return run
}

func (h *Host) tail(name string) string {
	data, _ := os.ReadFile(filepath.Join(h.Dir, name))
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	return strings.Join(lines[max(0, len(lines)-40):], "\n")
}

func (h *Host) Signal(signal syscall.Signal) error {
	output, err := exec.Command("ip", "netns", "pids", h.Namespace).Output()
	if err != nil {
		return err
	}
	for _, field := range strings.Fields(string(output)) {
		var pid int
		if _, err := fmt.Sscan(field, &pid); err == nil {
			_ = syscall.Kill(pid, signal)
		}
	}
	return nil
}

func (h *Host) Kill() error {
	if err := h.Signal(syscall.SIGKILL); err != nil {
		return err
	}
	<-h.done
	return nil
}

func (h *Host) ResetRoutes(ctx context.Context, peer *Host, port int) (int, error) {
	output, err := exec.CommandContext(ctx, "ip", "netns", "exec", h.Namespace, "ss", "-K", "-Htn", "state", "established", "dst", peer.Address,
		"and", "(", "dport", "=", fmt.Sprintf(":%d", port), "or", "sport", "=", fmt.Sprintf(":%d", port), ")").CombinedOutput()
	if err != nil {
		return 0, fmt.Errorf("ss -K: %w: %s", err, output)
	}
	return len(strings.Fields(strings.TrimSpace(string(output)))) / 4, nil
}

func (h *Host) Restart() error { return h.process.Process.Signal(syscall.SIGHUP) }

func (h *Host) Install(binary string) error {
	installed := filepath.Join(h.Dir, "bin", filepath.Base(installedPath))
	if err := copyFile(binary, installed+".new", 0o755); err != nil {
		return err
	}
	return os.Rename(installed+".new", installed)
}

func (h *Host) Exec(ctx context.Context, args ...string) ([]byte, error) {
	command := append([]string{"-t", fmt.Sprint(h.process.Process.Pid), "-m", "-n", "-u", "--"}, args...)
	return exec.CommandContext(ctx, "nsenter", command...).CombinedOutput()
}

func (h *Host) Listening(ctx context.Context, port int) (bool, error) {
	output, err := exec.CommandContext(ctx, "ip", "netns", "exec", h.Namespace, "ss", "-Hltn", fmt.Sprintf("sport = :%d", port)).CombinedOutput()
	return strings.TrimSpace(string(output)) != "", err
}

func (h *Host) Established(ctx context.Context, port int) ([]string, error) {
	output, err := exec.CommandContext(ctx, "ip", "netns", "exec", h.Namespace, "ss", "-Htn", "state", "established", fmt.Sprintf("( sport = :%d or dport = :%d )", port, port)).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("ss: %w: %s", err, output)
	}
	peers := []string{}
	for _, line := range strings.Split(strings.TrimSpace(string(output)), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 4 {
			address, _, _ := net.SplitHostPort(fields[3])
			peers = append(peers, strings.TrimPrefix(address, "::ffff:"))
		}
	}
	return peers, nil
}

func (h *Host) Dial(network, address string) (net.Conn, error) {
	runtime.LockOSThread()
	own, err := os.Open("/proc/thread-self/ns/net")
	if err != nil {
		runtime.UnlockOSThread()
		return nil, err
	}
	defer own.Close()
	target, err := os.Open(filepath.Join("/run/netns", h.Namespace))
	if err != nil {
		runtime.UnlockOSThread()
		return nil, err
	}
	defer target.Close()
	if err := unix.Setns(int(target.Fd()), unix.CLONE_NEWNET); err != nil {
		runtime.UnlockOSThread()
		return nil, err
	}
	conn, dialErr := net.DialTimeout(network, address, 5*time.Second)
	if err := unix.Setns(int(own.Fd()), unix.CLONE_NEWNET); err != nil {
		if conn != nil {
			conn.Close()
		}
		return nil, err
	}
	runtime.UnlockOSThread()
	return conn, dialErr
}

func (h *Host) State(path string) string { return filepath.Join(h.Dir, "state", path) }

func (h *Host) Health(ctx context.Context) (releasepush.Reply, error) {
	token, err := os.ReadFile(h.State("mesh/client.token"))
	if err != nil {
		return releasepush.Reply{}, err
	}
	data, err := os.ReadFile(filepath.Join(swarmruntime.NodeCertificates(h.State("")), "swarm-node.crt"))
	if err != nil {
		return releasepush.Reply{}, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return releasepush.Reply{}, fmt.Errorf("host has no node certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return releasepush.Reply{}, err
	}
	conn, err := nats.Connect(fmt.Sprintf("nats://127.0.0.1:%d", mesh.LocalPort), nats.UserInfo(mesh.OrchUser, strings.TrimSpace(string(token))), nats.SetCustomDialer(h), nats.NoReconnect())
	if err != nil {
		return releasepush.Reply{}, err
	}
	defer conn.Close()
	message, err := conn.RequestWithContext(ctx, releasepush.PullSubject(h.Region.Name, cert.Subject.CommonName), []byte(`{"op":"status"}`))
	if err != nil {
		return releasepush.Reply{}, err
	}
	var reply releasepush.Reply
	return reply, json.Unmarshal(message.Data, &reply)
}

func (h *Host) Observation(ctx context.Context) (releasepush.Observation, error) {
	roots := x509.NewCertPool()
	roots.AddCert(h.fleet.standIn.caCert)
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		return h.Dial(network, h.Address+":443")
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport}
	token, err := h.fleet.standIn.token(revisionOf(h.fleet.Binary), "1")
	if err != nil {
		return releasepush.Observation{}, err
	}
	workflow := "TerraScale/ts-orchestrator/.github/workflows/deploy-lag.yml@refs/heads/main"
	for _, identity := range []struct {
		workflow, repository, ref, event, caller string
		status                                   int
	}{
		{workflow, "TerraScale/ts-orchestrator", "refs/heads/main", "schedule", workflow, http.StatusOK},
		{workflow, "TerraScale/ts-orchestrator", "refs/heads/main", "workflow_run", workflow, http.StatusOK},
		{workflow, "TerraScale/ts-orchestrator", "refs/heads/main", "workflow_dispatch", workflow, http.StatusOK},
		{workflow, "TerraScale/ts-orchestrator", "refs/heads/main", "pull_request", workflow, http.StatusUnauthorized},
		{workflow, "TerraScale/ts-orchestrator", "refs/heads/other", "schedule", workflow, http.StatusUnauthorized},
		{workflow, "TerraScale/other", "refs/heads/main", "schedule", workflow, http.StatusUnauthorized},
		{workflow, "TerraScale/ts-orchestrator", "refs/heads/main", "schedule", "TerraScale/ts-orchestrator/.github/workflows/other.yml@refs/heads/main", http.StatusUnauthorized},
	} {
		readToken, err := h.fleet.standIn.identityToken(revisionOf(h.fleet.Binary), "1", map[string]any{"job_workflow_ref": identity.workflow, "workflow_ref": identity.caller, "repository": identity.repository, "ref": identity.ref, "event_name": identity.event})
		if err != nil {
			return releasepush.Observation{}, err
		}
		for _, method := range []string{http.MethodGet, http.MethodPost} {
			request, err := http.NewRequestWithContext(ctx, method, "https://"+h.Region.Name+"."+mesh.Domain+releasepush.ObservationPath, nil)
			if err != nil {
				return releasepush.Observation{}, err
			}
			request.Header.Set("Authorization", "Bearer "+readToken)
			response, err := client.Do(request)
			if err != nil {
				return releasepush.Observation{}, err
			}
			response.Body.Close()
			want := identity.status
			if method == http.MethodPost {
				want = http.StatusMethodNotAllowed
			}
			if response.StatusCode != want {
				return releasepush.Observation{}, fmt.Errorf("deploy-lag observation %s %s: HTTP %d, want %d", identity.event, method, response.StatusCode, want)
			}
		}
	}
	for _, workflow := range []string{
		"TerraScale/ts-orchestrator/.github/workflows/ci.yml@refs/heads/main",
		"TerraScale/ts-orchestrator/.github/workflows/multi-region.yml@refs/heads/main",
		"TerraScale/ts-orchestrator/.github/workflows/app-digests.yml@refs/heads/main",
		"TerraScale/ts-orchestrator/.github/workflows/app-canary.yml@refs/heads/main",
	} {
		otherToken, err := h.fleet.standIn.identityToken(revisionOf(h.fleet.Binary), "1", map[string]any{"job_workflow_ref": workflow, "workflow_ref": workflow, "event_name": "workflow_dispatch"})
		if err != nil {
			return releasepush.Observation{}, err
		}
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+h.Region.Name+"."+mesh.Domain+releasepush.ObservationPath+"?view=deployments", nil)
		if err != nil {
			return releasepush.Observation{}, err
		}
		request.Header.Set("Authorization", "Bearer "+otherToken)
		response, err := client.Do(request)
		if err != nil {
			return releasepush.Observation{}, err
		}
		response.Body.Close()
		if response.StatusCode != http.StatusUnauthorized {
			return releasepush.Observation{}, fmt.Errorf("%s can read deployment details: HTTP %d", workflow, response.StatusCode)
		}
	}
	var observation releasepush.Observation
	for _, probe := range []struct {
		method, token string
		status        int
	}{
		{http.MethodGet, "", http.StatusUnauthorized},
		{http.MethodPost, token, http.StatusMethodNotAllowed},
		{http.MethodGet, token, http.StatusOK},
	} {
		request, err := http.NewRequestWithContext(ctx, probe.method, "https://"+h.Region.Name+"."+mesh.Domain+releasepush.ObservationPath, nil)
		if err != nil {
			return observation, err
		}
		if probe.token != "" {
			request.Header.Set("Authorization", "Bearer "+probe.token)
		}
		response, err := client.Do(request)
		if err != nil {
			return observation, err
		}
		if response.StatusCode != probe.status {
			response.Body.Close()
			return observation, fmt.Errorf("observation %s: HTTP %d, want %d", probe.method, response.StatusCode, probe.status)
		}
		if probe.status == http.StatusOK {
			err = json.NewDecoder(response.Body).Decode(&observation)
		}
		response.Body.Close()
		if err != nil {
			return observation, err
		}
	}
	return observation, nil
}

func (f *Fleet) Secret(name string) (string, int) {
	f.standIn.mu.Lock()
	defer f.standIn.mu.Unlock()
	item := f.standIn.secrets[name]
	if item == nil {
		return "", 0
	}
	return string(item.Versions[len(item.Versions)-1]), len(item.Versions)
}

func (f *Fleet) PinSecret(name string) string {
	f.standIn.mu.Lock()
	defer f.standIn.mu.Unlock()
	item := f.standIn.secrets[name]
	f.standIn.pinned[name] = len(item.Versions)
	return string(item.Versions[len(item.Versions)-1])
}

func (f *Fleet) Terminated(host *Host, gone bool) {
	f.standIn.mu.Lock()
	defer f.standIn.mu.Unlock()
	f.standIn.gone[host.InstanceID] = gone
}

func (f *Fleet) UnpinSecret(name string) {
	f.standIn.mu.Lock()
	defer f.standIn.mu.Unlock()
	delete(f.standIn.pinned, name)
}

func (f *Fleet) WaitSecret(ctx context.Context, name string, match func(string) bool) (string, error) {
	for {
		f.standIn.mu.Lock()
		changed := f.standIn.changed
		item := f.standIn.secrets[name]
		value := ""
		if item != nil {
			value = string(item.Versions[len(item.Versions)-1])
		}
		f.standIn.mu.Unlock()
		if item != nil && match(value) {
			return value, nil
		}
		select {
		case <-ctx.Done():
			return value, fmt.Errorf("Vault secret %s: %w (last %q)", name, ctx.Err(), value)
		case <-changed:
		}
	}
}

func (f *Fleet) Requests() map[string]int { return f.standIn.Requests() }

func (f *Fleet) PutSecret(name, value string) {
	f.standIn.mu.Lock()
	defer f.standIn.mu.Unlock()
	if item := f.standIn.secrets[name]; item != nil {
		item.Versions = append(item.Versions, []byte(value))
	} else {
		digest := sha256.Sum256([]byte(name))
		f.standIn.secrets[name] = &secret{ID: "ocid1.vaultsecret.oc1." + vaultRegion + "." + hex.EncodeToString(digest[:12]), Name: name, VaultID: vaultsecret.SharedVault, Versions: [][]byte{[]byte(value)}}
	}
	f.standIn.notify()
}

func (f *Fleet) VaultAccess() map[string]int {
	f.standIn.mu.Lock()
	defer f.standIn.mu.Unlock()
	return maps.Clone(f.standIn.access)
}

func (f *Fleet) Alias(name, address string) error {
	for _, host := range f.Hosts {
		file, err := os.OpenFile(filepath.Join("/etc/netns", host.Namespace, "hosts"), os.O_APPEND|os.O_WRONLY, 0)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintf(file, "%s %s.nb.ts.internal\n", address, name)
		if closeErr := file.Close(); err == nil {
			err = closeErr
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func (f *Fleet) Close() {
	for _, host := range f.Hosts {
		if host.process != nil {
			_ = host.process.Process.Signal(syscall.SIGINT)
		}
	}
	for _, host := range f.Hosts {
		if host.process != nil {
			select {
			case <-host.done:
			case <-time.After(3 * time.Minute):
				_ = host.process.Process.Kill()
			}
		}
		output, _ := exec.Command("ip", "netns", "pids", host.Namespace).Output()
		for _, field := range strings.Fields(string(output)) {
			var pid int
			if _, err := fmt.Sscan(field, &pid); err == nil {
				_ = syscall.Kill(pid, syscall.SIGKILL)
			}
		}
	}
	f.standIn.close()
}
