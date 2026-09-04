//go:build sandboxvm

package vmqual

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"golang.org/x/crypto/ssh"
	"terrascale.tech/orchestrator/src/orchestrator/sandboxvm"
	"terrascale.tech/orchestrator/src/orchestrator/vmimage"
	"terrascale.tech/orchestrator/src/orchestrator/vmnet"
)

type FileReadinessProbe struct {
	Root     string
	Manifest vmimage.GuestImageManifest
}

var readinessID = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$`)

func (p FileReadinessProbe) Probe(c context.Context, id string) (sandboxvm.Readiness, error) {
	if c == nil {
		return sandboxvm.Readiness{}, errors.New("readiness context is nil")
	}
	if e := c.Err(); e != nil {
		return sandboxvm.Readiness{}, e
	}
	if p.Root == "" || !filepath.IsAbs(p.Root) {
		return sandboxvm.Readiness{}, errors.New("readiness root must be absolute")
	}
	if !readinessID.MatchString(id) || id == "." || id == ".." {
		return sandboxvm.Readiness{}, errors.New("readiness VM id is invalid")
	}
	if err := p.Manifest.Validate(); err != nil {
		return sandboxvm.Readiness{}, err
	}
	path := filepath.Join(p.Root, id+".json")
	if !pathWithin(p.Root, path) {
		return sandboxvm.Readiness{}, errors.New("readiness path escapes root")
	}
	b, e := os.ReadFile(path)
	if e != nil {
		return sandboxvm.Readiness{}, e
	}
	var m vmimage.ReadinessMetadata
	d := json.NewDecoder(strings.NewReader(string(b)))
	d.DisallowUnknownFields()
	if e = d.Decode(&m); e != nil {
		return sandboxvm.Readiness{}, e
	}
	var extra any
	if e = d.Decode(&extra); e != io.EOF {
		return sandboxvm.Readiness{}, errors.New("readiness metadata has trailing JSON")
	}
	if e = m.Validate(p.Manifest, m.SeedDigest); e != nil {
		return sandboxvm.Readiness{}, e
	}
	if !m.IsReady() {
		return sandboxvm.Readiness{}, errors.New("guest readiness gates incomplete")
	}
	return sandboxvm.Readiness{Systemd: m.SystemdPID1, DataDiskMounted: m.DataDiskReady, Network: m.NetworkReady, TSNodeHealthy: m.TSNodeReady, ServiceHealthy: true}, nil
}
func newSandboxVMProvider(c Config) (*sandboxvm.Provider, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	b, e := os.ReadFile(c.ImageManifestPath)
	if e != nil {
		return nil, e
	}
	m, e := vmimage.DecodeManifest(b)
	if e != nil {
		return nil, e
	}
	transport, err := newGuestTransport(c.Root)
	if err != nil {
		return nil, err
	}
	probe := &sshGuestProbe{transport: transport, manifest: m, seedDigests: make(map[string]string), configs: make(map[string]sandboxvm.Config)}
	return sandboxvm.New(sandboxvm.Options{MachineFactory: sandboxvm.NewSDKMachineFactory(), OpenAPIFactory: func(x sandboxvm.Config) (sandboxvm.OpenAPI, error) {
		return sandboxvm.NewUnixSocketOpenAPI(x.SocketPath)
	}, Probe: probe})
}

// guestTransport is a short-lived SSH transport to the forced command in a
// qualification guest. SSH is only used as a bounded test control channel;
// the production service lifecycle remains systemd in the guest.
type guestTransport struct{ keyPath, publicKey string }

func newGuestTransport(root string) (*guestTransport, error) {
	if root == "" || !filepath.IsAbs(root) {
		return nil, errors.New("vmqual: guest transport root must be absolute")
	}
	dir := filepath.Join(root, "ssh")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	key, err := ssh.MarshalPrivateKey(private, "vmqual")
	if err != nil {
		return nil, err
	}
	path := filepath.Join(dir, "id_ed25519")
	if err := os.WriteFile(path, key.Bytes, 0600); err != nil {
		return nil, err
	}
	pub, err := ssh.NewPublicKey(private.Public())
	if err != nil {
		return nil, err
	}
	publicKey := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub)))
	if err := os.WriteFile(path+".pub", []byte(publicKey+"\n"), 0600); err != nil {
		return nil, err
	}
	return &guestTransport{keyPath: path, publicKey: publicKey}, nil
}

func (p *sshGuestProbe) Register(cfg sandboxvm.Config, seedDigest string) {
	p.mu.Lock()
	p.configs[cfg.ID] = cfg
	p.seedDigests[cfg.ID] = seedDigest
	p.mu.Unlock()
}

func newGuestExecutor(cfg sandboxvm.Config) sandboxvm.CommandRunner {
	return sshCommandRunner{keyPath: filepath.Join(filepath.Dir(cfg.StateRoot), "ssh", "id_ed25519"), address: cfg.GuestAddress}
}

type sshCommandRunner struct{ keyPath, address string }

func (r sshCommandRunner) Run(ctx context.Context, command sandboxvm.Command) error {
	transport := &guestTransport{keyPath: r.keyPath}
	response, err := transport.request(ctx, r.address, vmguestRequest{Operation: "execute", Path: command.Path, Args: command.Args})
	if response.Command != nil {
		if command.Stdout != nil {
			_, _ = command.Stdout.Write(response.Command.Stdout)
		}
		if command.Stderr != nil {
			_, _ = command.Stderr.Write(response.Command.Stderr)
		}
		if response.Command.ExitCode != 0 {
			return fmt.Errorf("guest command exited %d: %s", response.Command.ExitCode, response.Command.Error)
		}
	}
	return err
}

func (f *firecrackerFactory) prepareGuest(ctx context.Context, guest Guest, cfg *sandboxvm.Config) (string, error) {
	if f == nil || cfg == nil {
		return "", errors.New("vmqual: guest configuration is missing")
	}
	if f.config.GuestControlPath == "" {
		return "", errors.New("vmqual: guest control binary is missing")
	}
	control, err := os.ReadFile(f.config.GuestControlPath)
	if err != nil {
		return "", fmt.Errorf("vmqual: read guest control: %w", err)
	}
	controlDigest, err := fileSHA256(f.config.GuestControlPath)
	if err != nil {
		return "", err
	}
	network, err := guestNetwork(f.config.NetworkPlan, guest)
	if err != nil {
		return "", err
	}
	seedArtifacts := make([]vmimage.GuestArtifact, 0, 3)
	for _, component := range vmimage.ArtifactComponents() {
		seedArtifacts = append(seedArtifacts, vmimage.GuestArtifact{Component: component, Architecture: vmimage.Architecture(f.image.Manifest.Architecture), Version: "qualification", Source: "/opt/terrascale/" + component + "/qualification/" + component, SHA256: controlDigest, Size: int64(len(control)), Mode: 0755})
	}
	guestSeed, err := vmimage.BuildGuestChannelSeed(vmimage.GuestSeedSpec{Image: f.image.Manifest, Hostname: guest.ID, InstanceID: guest.ID, Region: strings.ToLower(string(guest.Region)), DataDiskPath: "/dev/vdb", Artifacts: seedArtifacts})
	if err != nil {
		return "", err
	}
	publicKey, err := os.ReadFile(filepath.Join(filepath.Dir(f.config.StateRoot), "ssh", "id_ed25519.pub"))
	if err != nil {
		return "", fmt.Errorf("vmqual: read guest SSH public key: %w", err)
	}
	stateDir := filepath.Join(f.config.StateRoot, guest.ID)
	if err := os.MkdirAll(stateDir, 0700); err != nil {
		return "", err
	}
	seed, err := vmimage.BuildNoCloudSeed(vmimage.NoCloudSeedSpec{InstanceID: guest.ID, Hostname: guest.ID, Region: strings.ToLower(string(guest.Region)), Address: network.Address, PrefixBits: 24, Gateway: network.Gateway, MACAddress: network.MAC, Nameservers: []string{"1.1.1.1"}, SSHAuthorizedKey: strings.TrimSpace(string(publicKey)), DataDevice: "/dev/vdb", DataMount: "/var/lib/terrascale", GuestSeed: guestSeed, GuestControl: control})
	if err != nil {
		return "", err
	}
	meta := filepath.Join(stateDir, "meta-data")
	networkPath := filepath.Join(stateDir, "network-config")
	userData := filepath.Join(stateDir, "user-data")
	for path, data := range map[string][]byte{meta: seed.MetaData, networkPath: seed.NetworkConfig, userData: seed.UserData} {
		if err := os.WriteFile(path, data, 0600); err != nil {
			return "", err
		}
	}
	seedPath := filepath.Join(stateDir, "seed.img")
	command := exec.CommandContext(ctx, "cloud-localds", "--network-config="+networkPath, seedPath, userData, meta)
	if output, err := command.CombinedOutput(); err != nil {
		return "", fmt.Errorf("vmqual: build NoCloud seed: %w: %s", err, strings.TrimSpace(string(output)))
	}
	seedDigest, err := fileSHA256(seedPath)
	if err != nil {
		return "", err
	}
	cfg.SeedDrive, cfg.ExpectedSeedDriveSHA256 = seedPath, seedDigest
	cfg.NetworkNamespace, cfg.TapName, cfg.GuestMAC, cfg.GuestAddress = network.NamespacePath, network.TAP, network.MAC, network.Address
	cfg.LogPath, cfg.MetricsPath = filepath.Join(stateDir, "firecracker.log"), filepath.Join(stateDir, "metrics.fifo")
	return vmimage.GuestChannelSeedDigest(guestSeed), nil
}

type resolvedGuestNetwork struct {
	vmnet.GuestNetwork
	Gateway       string
	NamespacePath string
}

func guestNetwork(plan vmnet.NetworkPlan, guest Guest) (resolvedGuestNetwork, error) {
	if len(plan.Regions) == 0 {
		var err error
		plan, err = vmnet.Plan(vmnet.DefaultConfig())
		if err != nil {
			return resolvedGuestNetwork{}, err
		}
	}
	for _, region := range plan.Regions {
		if region.Code == guest.Region {
			for _, network := range region.Guests {
				if network.ID == guest.ID {
					return resolvedGuestNetwork{GuestNetwork: network, Gateway: region.Gateway, NamespacePath: region.NamespacePath}, nil
				}
			}
		}
	}
	return resolvedGuestNetwork{}, fmt.Errorf("vmqual: network plan has no endpoint for %s", guest.ID)
}

type sshGuestProbe struct {
	transport   *guestTransport
	manifest    vmimage.GuestImageManifest
	mu          sync.Mutex
	seedDigests map[string]string
	configs     map[string]sandboxvm.Config
}

func (p *sshGuestProbe) register(id, digest, address string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.seedDigests[id] = digest
	if cfg, ok := p.configs[id]; ok {
		cfg.GuestAddress = address
		p.configs[id] = cfg
	}
}

func (p *sshGuestProbe) setConfig(id string, cfg sandboxvm.Config) {
	p.mu.Lock()
	p.configs[id] = cfg
	p.mu.Unlock()
}

func (p *sshGuestProbe) Probe(ctx context.Context, id string) (sandboxvm.Readiness, error) {
	p.mu.Lock()
	cfg, ok := p.configs[id]
	wantSeed := p.seedDigests[id]
	p.mu.Unlock()
	if !ok || cfg.GuestAddress == "" {
		return sandboxvm.Readiness{}, errors.New("guest network endpoint is not registered")
	}
	response, err := p.transport.request(ctx, cfg.GuestAddress, vmguestRequest{Operation: "probe"})
	if err != nil {
		return sandboxvm.Readiness{}, err
	}
	if response.Probe == nil {
		return sandboxvm.Readiness{}, errors.New("guest probe response is missing")
	}
	probe := response.Probe
	if probe.Systemd.ExitCode != 0 || !strings.Contains(string(probe.PID1.Stdout), "systemd") || probe.CgroupV2.ExitCode != 0 || !strings.Contains(string(probe.CgroupV2.Stdout), "cgroup2") || probe.DataMount.ExitCode != 0 || probe.Network.ExitCode != 0 || probe.Time.ExitCode != 0 || probe.SeedDigest.ExitCode != 0 {
		return sandboxvm.Readiness{}, errors.New("guest readiness diagnostics failed")
	}
	if wantSeed != "" && !strings.HasPrefix(string(probe.SeedDigest.Stdout), wantSeed) {
		return sandboxvm.Readiness{}, errors.New("guest seed digest does not match controller seed")
	}
	services := []string{"ts-node.service", "terrascale-orchestrator.service", "terrabase.service"}
	for _, service := range services {
		active, err := p.transport.request(ctx, cfg.GuestAddress, vmguestRequest{Operation: "execute", Path: "/usr/bin/systemctl", Args: []string{"is-active", service}})
		if err != nil || active.Command == nil || active.Command.ExitCode != 0 || strings.TrimSpace(string(active.Command.Stdout)) != "active" {
			return sandboxvm.Readiness{}, fmt.Errorf("guest service %s is not healthy", service)
		}
	}
	return sandboxvm.Readiness{Systemd: true, DataDiskMounted: true, Network: true, TSNodeHealthy: true, ServiceHealthy: true}, nil
}

type vmguestRequest struct {
	Operation string   `json:"operation"`
	Path      string   `json:"path,omitempty"`
	Args      []string `json:"args,omitempty"`
}
type vmguestResponse struct {
	Error   string                `json:"error,omitempty"`
	Command *vmguestCommandResult `json:"command,omitempty"`
	Probe   *vmguestProbeResult   `json:"probe,omitempty"`
}
type vmguestCommandResult struct {
	ExitCode int    `json:"exitCode"`
	Stdout   []byte `json:"stdout,omitempty"`
	Stderr   []byte `json:"stderr,omitempty"`
	Error    string `json:"error,omitempty"`
}
type vmguestProbeResult struct{ Systemd, PID1, CgroupV2, DataMount, Network, Time, SeedDigest vmguestCommandResult }

func (t *guestTransport) request(ctx context.Context, address string, request vmguestRequest) (vmguestResponse, error) {
	if t == nil || t.keyPath == "" || address == "" {
		return vmguestResponse{}, errors.New("guest transport is not configured")
	}
	requestBytes, err := json.Marshal(struct {
		SchemaVersion int `json:"schemaVersion"`
		vmguestRequest
	}{1, request})
	if err != nil {
		return vmguestResponse{}, err
	}
	command := exec.CommandContext(ctx, "ssh", "-i", t.keyPath, "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null", "-o", "ConnectTimeout=5", "root@"+address)
	command.Stdin = strings.NewReader(string(requestBytes))
	var output, diagnostic limitedBuffer
	command.Stdout, command.Stderr = &output, &diagnostic
	if err := command.Run(); err != nil {
		return vmguestResponse{}, fmt.Errorf("guest control transport: %w: %s", err, diagnostic.String())
	}
	var response vmguestResponse
	if err := json.Unmarshal(output.Bytes(), &response); err != nil {
		return vmguestResponse{}, fmt.Errorf("decode guest control response: %w", err)
	}
	if response.Error != "" {
		return vmguestResponse{}, errors.New(response.Error)
	}
	return response, nil
}

type limitedBuffer struct{ data []byte }

func (b *limitedBuffer) Write(v []byte) (int, error) {
	n := len(v)
	if len(b.data) < 256<<10 {
		b.data = append(b.data, v[:minInt(len(v), 256<<10-len(b.data))]...)
	}
	return n, nil
}
func (b *limitedBuffer) Bytes() []byte  { return b.data }
func (b *limitedBuffer) String() string { return strings.TrimSpace(string(b.data)) }
func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
