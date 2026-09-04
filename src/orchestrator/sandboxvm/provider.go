// Package sandboxvm contains the test-only local VM boundary used by the
// Firecracker qualification suite.
//
// The package deliberately has no dependency on the production orchestrator
// packages.  The Firecracker SDK binding is in a file guarded by the
// "sandboxvm" build tag; normal production builds therefore cannot import the
// SDK or accidentally construct a local VM.
package sandboxvm

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	ErrNotFound       = errors.New("sandboxvm: VM not found")
	ErrConflict       = errors.New("sandboxvm: VM already exists")
	ErrNotRunning     = errors.New("sandboxvm: VM is not running")
	ErrAlreadyStopped = errors.New("sandboxvm: VM is already stopped")
	ErrNotReady       = errors.New("sandboxvm: guest is not ready")
	ErrUnowned        = errors.New("sandboxvm: state directory is not owned by TerraScale")
)

type State string

const (
	StateCreated  State = "created"
	StateStarting State = "starting"
	StateRunning  State = "running"
	StateStopping State = "stopping"
	StateStopped  State = "stopped"
	StateDeleted  State = "deleted"
)

// Config is the complete host-side configuration for one qualification VM.
// Paths are intentionally explicit: no shell, image lookup, or ambient
// credentials are involved in constructing a VM.
type Config struct {
	ID                        string
	Region                    string
	VCPU                      int64
	MemoryMiB                 int64
	KernelImage               string
	RootDrive                 string
	DataDrive                 string
	SeedDrive                 string
	StateRoot                 string
	JailerChrootBaseDir       string
	JailerUID                 *int
	JailerGID                 *int
	JailerNumaNode            *int
	SocketPath                string
	NetworkNamespace          string
	TapName                   string
	GuestMAC                  string
	GuestAddress              string
	KernelArgs                string
	LogPath                   string
	MetricsPath               string
	FirecrackerBinary         string
	JailerBinary              string
	ExpectedVersion           string
	ExpectedKernelSHA256      string
	ExpectedRootDriveSHA256   string
	ExpectedDataDriveSHA256   string
	ExpectedSeedDriveSHA256   string
	ExpectedFirecrackerSHA256 string
	ExpectedJailerSHA256      string
	ReadinessTimeout          time.Duration
	StopTimeout               time.Duration
}

func (c Config) Validate() error {
	normalized, _, err := normalizeConfig(c)
	if err != nil {
		return err
	}
	c = normalized
	if !validID(c.ID) {
		return fmt.Errorf("invalid VM id %q", c.ID)
	}
	if strings.TrimSpace(c.Region) == "" {
		return errors.New("region is required")
	}
	if c.VCPU < 1 {
		return errors.New("vCPU must be at least one")
	}
	if c.MemoryMiB < 256 || c.MemoryMiB > 512 {
		return fmt.Errorf("memory must be between 256 and 512 MiB: %d", c.MemoryMiB)
	}
	for name, p := range map[string]string{"state root": c.StateRoot, "socket": c.SocketPath, "kernel": c.KernelImage, "root drive": c.RootDrive, "data drive": c.DataDrive, "firecracker": c.FirecrackerBinary, "jailer": c.JailerBinary} {
		if p == "" {
			return fmt.Errorf("%s path is required", name)
		}
		if !filepath.IsAbs(p) {
			return fmt.Errorf("%s path must be absolute", name)
		}
	}
	if c.SeedDrive != "" && !filepath.IsAbs(c.SeedDrive) {
		return errors.New("seed drive path must be absolute")
	}
	basenames := make(map[string]string)
	for kind, path := range map[string]string{"firecracker": c.FirecrackerBinary, "kernel": c.KernelImage, "root drive": c.RootDrive, "data drive": c.DataDrive, "seed drive": c.SeedDrive} {
		if path == "" {
			continue
		}
		base := filepath.Base(path)
		if prior, exists := basenames[base]; exists {
			return fmt.Errorf("%s and %s have the same jail basename %q", prior, kind, base)
		}
		basenames[base] = kind
	}
	if c.NetworkNamespace != "" && !filepath.IsAbs(c.NetworkNamespace) {
		return errors.New("network namespace path must be absolute")
	}
	if (c.TapName == "") != (c.GuestMAC == "") {
		return errors.New("tap name and guest MAC must be declared together")
	}
	if c.TapName != "" {
		if len(c.TapName) > 15 || !vmIDPattern.MatchString(c.TapName) {
			return errors.New("tap name must be a safe Linux interface name")
		}
		mac, err := net.ParseMAC(c.GuestMAC)
		if err != nil || len(mac) != 6 || mac[0]&1 != 0 || mac[0]&2 == 0 {
			return errors.New("guest MAC must be a locally administered unicast address")
		}
	}
	for name, path := range map[string]string{"log": c.LogPath, "metrics": c.MetricsPath} {
		if path != "" && (!filepath.IsAbs(path) || !pathWithinRoot(c.StateRoot, path)) {
			return fmt.Errorf("%s path must remain below state root", name)
		}
	}
	if err := ValidateSocketPath(c.SocketPath); err != nil {
		return err
	}
	if c.ReadinessTimeout <= 0 {
		return errors.New("readiness timeout must be positive")
	}
	if c.StopTimeout <= 0 {
		return errors.New("stop timeout must be positive")
	}
	if c.ExpectedVersion == "" {
		return errors.New("expected Firecracker version is required")
	}
	for name, sum := range map[string]string{"kernel": c.ExpectedKernelSHA256, "root drive": c.ExpectedRootDriveSHA256, "data drive": c.ExpectedDataDriveSHA256} {
		if !validSHA256(sum) {
			return fmt.Errorf("%s checksum must be a SHA-256 hex digest", name)
		}
	}
	if c.SeedDrive != "" && !validSHA256(c.ExpectedSeedDriveSHA256) {
		return errors.New("seed drive checksum must be a SHA-256 hex digest")
	}
	for name, sum := range map[string]string{"firecracker": c.ExpectedFirecrackerSHA256, "jailer": c.ExpectedJailerSHA256} {
		if !validSHA256(sum) {
			return fmt.Errorf("%s checksum must be a SHA-256 hex digest", name)
		}
	}
	return nil
}

func (c Config) validate() error { return c.Validate() }

var (
	vmIDPattern   = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$`)
	jailIDPattern = regexp.MustCompile(`^[a-zA-Z0-9-]{1,64}$`)
)

func validID(id string) bool { return jailIDPattern.MatchString(id) }
func validSHA256(s string) bool {
	if len(s) != sha256.Size*2 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

func pathWithinRoot(root, candidate string) bool {
	if !filepath.IsAbs(root) || !filepath.IsAbs(candidate) {
		return false
	}
	relative, err := filepath.Rel(filepath.Clean(root), filepath.Clean(candidate))
	return err == nil && relative != "." && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) && !filepath.IsAbs(relative)
}

const (
	// Firecracker's pathname Unix sockets use sockaddr_un.sun_path, including
	// its terminating NUL byte. Keep the host-visible jail path below that
	// Linux limit and fail before starting a privileged process.
	maxUnixSocketPathBytes = 107
	jailerSocketPath       = "/api.sock"
	DiagnosticLimitBytes   = int64(1 << 20)
	runtimeRecordVersion   = 1
	linuxProcClockTicks    = 100
)

// Paths identifies every host-side file owned by one jailed Firecracker
// instance. The layout is the one implemented by jailer:
// <chroot-base>/<firecracker-basename>/<id>/root.
type Paths struct {
	StateDir     string
	JailRoot     string
	Socket       string
	RootDrive    string
	DataDrive    string
	Log          string
	Metrics      string
	RuntimeState string
}

func normalizeConfig(c Config) (Config, Paths, error) {
	if c.StateRoot == "" || !filepath.IsAbs(c.StateRoot) {
		return Config{}, Paths{}, errors.New("state root path must be absolute")
	}
	if c.FirecrackerBinary == "" || !filepath.IsAbs(c.FirecrackerBinary) {
		return Config{}, Paths{}, errors.New("firecracker path must be absolute")
	}
	if c.JailerChrootBaseDir == "" {
		c.JailerChrootBaseDir = c.StateRoot
	}
	if !filepath.IsAbs(c.JailerChrootBaseDir) || !pathAtOrWithinRoot(c.StateRoot, c.JailerChrootBaseDir) {
		return Config{}, Paths{}, errors.New("jailer chroot base must remain at or below state root")
	}
	uid, gid, err := resolveJailerIdentity(c.JailerUID, c.JailerGID, os.Getuid(), os.Getgid(), os.Geteuid(), os.Getenv("SUDO_UID"), os.Getenv("SUDO_GID"))
	if err != nil {
		return Config{}, Paths{}, err
	}
	c.JailerUID, c.JailerGID = &uid, &gid
	if c.JailerNumaNode == nil {
		value := 0
		c.JailerNumaNode = &value
	}
	if *c.JailerNumaNode < 0 {
		return Config{}, Paths{}, errors.New("jailer NUMA node must be non-negative")
	}
	stateDir := filepath.Join(c.JailerChrootBaseDir, filepath.Base(c.FirecrackerBinary), c.ID)
	paths := Paths{
		StateDir:     stateDir,
		JailRoot:     filepath.Join(stateDir, "root"),
		RootDrive:    c.RootDrive,
		DataDrive:    c.DataDrive,
		Log:          filepath.Join(stateDir, "firecracker.log"),
		Metrics:      filepath.Join(stateDir, "firecracker.metrics"),
		RuntimeState: filepath.Join(stateDir, "runtime.json"),
	}
	paths.Socket = filepath.Join(paths.JailRoot, strings.TrimPrefix(jailerSocketPath, "/"))
	if c.SocketPath != "" && filepath.Clean(c.SocketPath) != paths.Socket {
		return Config{}, Paths{}, fmt.Errorf("socket path must match jailed Firecracker path %s", paths.Socket)
	}
	if c.LogPath != "" && filepath.Clean(c.LogPath) != paths.Log {
		return Config{}, Paths{}, fmt.Errorf("log path must match owned jail path %s", paths.Log)
	}
	if c.MetricsPath != "" && filepath.Clean(c.MetricsPath) != paths.Metrics {
		return Config{}, Paths{}, fmt.Errorf("metrics path must match owned jail path %s", paths.Metrics)
	}
	c.SocketPath, c.LogPath, c.MetricsPath = paths.Socket, paths.Log, paths.Metrics
	if len(c.SocketPath) > maxUnixSocketPathBytes {
		return Config{}, Paths{}, fmt.Errorf("Firecracker API socket path is %d bytes; Linux permits at most %d", len(c.SocketPath), maxUnixSocketPathBytes)
	}
	return c, paths, nil
}

func resolveJailerIdentity(explicitUID, explicitGID *int, currentUID, currentGID, effectiveUID int, sudoUID, sudoGID string) (int, int, error) {
	if (explicitUID == nil) != (explicitGID == nil) {
		return 0, 0, errors.New("jailer UID and GID must be configured together")
	}
	if explicitUID != nil {
		if err := validateJailerIdentity(*explicitUID, *explicitGID); err != nil {
			return 0, 0, err
		}
		return *explicitUID, *explicitGID, nil
	}
	if currentUID > 0 && currentGID > 0 {
		if err := validateJailerIdentity(currentUID, currentGID); err != nil {
			return 0, 0, err
		}
		return currentUID, currentGID, nil
	}
	if currentUID == 0 || effectiveUID == 0 {
		uid, uidErr := strconv.ParseUint(sudoUID, 10, 32)
		gid, gidErr := strconv.ParseUint(sudoGID, 10, 32)
		if uidErr != nil || gidErr != nil || uid == 0 || gid == 0 {
			return 0, 0, errors.New("explicit non-root jailer UID/GID are required when the controller runs as root; set both values or preserve valid SUDO_UID/SUDO_GID")
		}
		return int(uid), int(gid), nil
	}
	return 0, 0, errors.New("jailer UID and GID must both identify a non-root account")
}

func validateJailerIdentity(uid, gid int) error {
	const maxUint32 = uint64(1<<32 - 1)
	if uid <= 0 || gid <= 0 {
		return errors.New("jailer UID and GID must both identify a non-root account")
	}
	if uint64(uid) > maxUint32 || uint64(gid) > maxUint32 {
		return errors.New("jailer UID and GID must fit in unsigned 32-bit values")
	}
	return nil
}

func pathAtOrWithinRoot(root, candidate string) bool {
	if filepath.Clean(root) == filepath.Clean(candidate) {
		return filepath.IsAbs(root)
	}
	return pathWithinRoot(root, candidate)
}

// Version and checksum validation are hooks rather than policy hidden in the
// SDK adapter. This lets the qualification suite test bad artifacts without
// touching the host, while production release policy remains elsewhere.
type ValidationHooks struct {
	Version  func(context.Context, string) error
	Checksum func(context.Context, Artifact) error
}

type Artifact struct {
	Kind    string
	Path    string
	SHA256  string
	Version string
}

func (h ValidationHooks) Validate(ctx context.Context, cfg Config) error {
	if h.Version != nil {
		if err := h.Version(ctx, cfg.ExpectedVersion); err != nil {
			return fmt.Errorf("validate Firecracker version: %w", err)
		}
	}
	artifacts := []Artifact{
		{Kind: "kernel", Path: cfg.KernelImage, SHA256: cfg.ExpectedKernelSHA256},
		{Kind: "root-drive", Path: cfg.RootDrive, SHA256: cfg.ExpectedRootDriveSHA256},
		{Kind: "data-drive", Path: cfg.DataDrive, SHA256: cfg.ExpectedDataDriveSHA256},
	}
	if cfg.SeedDrive != "" {
		artifacts = append(artifacts, Artifact{Kind: "seed-drive", Path: cfg.SeedDrive, SHA256: cfg.ExpectedSeedDriveSHA256})
	}
	if cfg.ExpectedFirecrackerSHA256 != "" {
		artifacts = append(artifacts, Artifact{Kind: "firecracker", Path: cfg.FirecrackerBinary, SHA256: cfg.ExpectedFirecrackerSHA256})
	}
	if cfg.ExpectedJailerSHA256 != "" {
		artifacts = append(artifacts, Artifact{Kind: "jailer", Path: cfg.JailerBinary, SHA256: cfg.ExpectedJailerSHA256})
	}
	for _, a := range artifacts {
		if err := validateArtifact(a); err != nil {
			return fmt.Errorf("validate %s checksum: %w", a.Kind, err)
		}
		if h.Checksum == nil {
			continue
		}
		if err := h.Checksum(ctx, a); err != nil {
			return fmt.Errorf("validate %s checksum: %w", a.Kind, err)
		}
	}
	return nil
}

// ValidateRestart rechecks immutable inputs before constructing another VMM.
// The root and data drives are intentionally writable and are expected to
// differ after the first boot, so restart validates their file identity and
// type without comparing them to their pre-boot digests.
func (h ValidationHooks) ValidateRestart(ctx context.Context, cfg Config) error {
	if h.Version != nil {
		if err := h.Version(ctx, cfg.ExpectedVersion); err != nil {
			return fmt.Errorf("validate Firecracker version: %w", err)
		}
	}
	for name, path := range map[string]string{"root drive": cfg.RootDrive, "data drive": cfg.DataDrive} {
		if err := validateMutableDrive(path); err != nil {
			return fmt.Errorf("validate %s: %w", name, err)
		}
	}
	artifacts := []Artifact{
		{Kind: "kernel", Path: cfg.KernelImage, SHA256: cfg.ExpectedKernelSHA256},
		{Kind: "firecracker", Path: cfg.FirecrackerBinary, SHA256: cfg.ExpectedFirecrackerSHA256},
		{Kind: "jailer", Path: cfg.JailerBinary, SHA256: cfg.ExpectedJailerSHA256},
	}
	if cfg.SeedDrive != "" {
		artifacts = append(artifacts, Artifact{Kind: "seed-drive", Path: cfg.SeedDrive, SHA256: cfg.ExpectedSeedDriveSHA256})
	}
	for _, artifact := range artifacts {
		if err := validateArtifact(artifact); err != nil {
			return fmt.Errorf("validate %s checksum: %w", artifact.Kind, err)
		}
		if h.Checksum != nil {
			if err := h.Checksum(ctx, artifact); err != nil {
				return fmt.Errorf("validate %s checksum: %w", artifact.Kind, err)
			}
		}
	}
	return nil
}

func validateMutableDrive(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("drive must be a regular non-symlink file")
	}
	return nil
}

func validateArtifact(a Artifact) error {
	linkInfo, err := os.Lstat(a.Path)
	if err != nil {
		return err
	}
	if linkInfo.Mode()&os.ModeSymlink != 0 || !linkInfo.Mode().IsRegular() {
		return errors.New("artifact must be a regular non-symlink file")
	}
	f, err := os.Open(a.Path)
	if err != nil {
		return err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return err
	}
	if st.Mode().IsDir() {
		return errors.New("artifact is a directory")
	}
	if (a.Kind == "firecracker" || a.Kind == "jailer") && st.Mode().Perm()&0111 == 0 {
		return errors.New("executable artifact is not executable")
	}
	digest := sha256.New()
	if _, err := io.Copy(digest, f); err != nil {
		return err
	}
	if got := hex.EncodeToString(digest.Sum(nil)); !strings.EqualFold(got, a.SHA256) {
		return fmt.Errorf("digest mismatch: got %s", got)
	}
	return nil
}

// Machine is the small official-SDK-shaped interface needed by the lifecycle
// controller. It is deliberately injectable so unit tests never start VMs.
type Machine interface {
	Start(context.Context) error
	Shutdown(context.Context) error
	StopVMM() error
	Wait(context.Context) error
	Version(context.Context) (string, error)
	Inspect(context.Context) (Inspection, error)
}

type MachineFactory func(context.Context, Config) (Machine, error)

// GuestProbe reports real guest readiness. A running Firecracker process or a
// reachable API socket alone is never considered ready.
type GuestProbe interface {
	Probe(context.Context, string) (Readiness, error)
}

type Readiness struct {
	Systemd         bool
	DataDiskMounted bool
	Network         bool
	TSNodeHealthy   bool
	ServiceHealthy  bool
}

func (r Readiness) Ready() bool {
	return r.Systemd && r.DataDiskMounted && r.Network && r.TSNodeHealthy && r.ServiceHealthy
}

type Inspection struct {
	State            State
	PID              int
	ProcessStartTime uint64
	Executable       string
	ProcessAlive     bool
	SocketReady      bool
	Version          string
	RSSBytes         uint64
	IdleCPU          float64
	CPUSampled       bool
	Diagnostics      DiagnosticObservation
}

type DiagnosticFileObservation struct {
	Path      string
	Bytes     int64
	Truncated bool
}

type DiagnosticObservation struct {
	LimitBytes int64
	Log        DiagnosticFileObservation
	Metrics    DiagnosticFileObservation
}

type Command struct {
	Path   string
	Args   []string
	Dir    string
	Env    []string
	Stdout io.Writer
	Stderr io.Writer
}

// CommandRunner is an injected process boundary. Implementations must use
// exec.CommandContext (or an equivalent safe argv API), never a shell.
type CommandRunner interface {
	Run(context.Context, Command) error
}

type VMInfo struct {
	Config           Config
	State            State
	Ready            bool
	Paths            Paths
	PID              int
	ProcessStartTime uint64
	Executable       string
	Version          string
	RSSBytes         uint64
	IdleCPU          float64
	CPUSampled       bool
	Diagnostics      DiagnosticObservation
}

type ownedState struct {
	Marker       string    `json:"marker"`
	ID           string    `json:"id"`
	Region       string    `json:"region"`
	JailRoot     string    `json:"jailRoot"`
	SocketPath   string    `json:"socketPath"`
	LogPath      string    `json:"logPath"`
	MetricsPath  string    `json:"metricsPath"`
	RuntimeState string    `json:"runtimeState"`
	CreatedAt    time.Time `json:"createdAt"`
}

// RuntimeRecord is persisted after the SDK has started the non-daemonized
// jailer process, observed the Firecracker API, and verified the pinned
// version. PID alone is never sufficient to recover a process because Linux
// can reuse it; StartTimeTicks is field 22 from /proc/<pid>/stat.
type RuntimeRecord struct {
	Version          int        `json:"version"`
	Marker           string     `json:"marker"`
	ID               string     `json:"id"`
	State            State      `json:"state"`
	PID              int        `json:"pid"`
	ProcessStartTime uint64     `json:"processStartTimeTicks"`
	Firecracker      string     `json:"firecrackerVersion"`
	SocketPath       string     `json:"socketPath"`
	LogPath          string     `json:"logPath"`
	MetricsPath      string     `json:"metricsPath"`
	ObservedAt       time.Time  `json:"observedAt"`
	StoppedAt        *time.Time `json:"stoppedAt,omitempty"`
}

const ownershipMarker = "terrascale-sandboxvm-v1"

type instance struct {
	mu               sync.Mutex
	cfg              Config
	paths            Paths
	machine          Machine
	api              OpenAPI
	state            State
	ready            bool
	versionValidated bool
	runtime          RuntimeRecord
	stopDone         chan struct{}
	stopResult       error
	lastCPU          uint64
	lastAt           time.Time
}

type Provider struct {
	mu         sync.Mutex
	instances  map[string]*instance
	factory    MachineFactory
	apiFactory func(Config) (OpenAPI, error)
	probe      GuestProbe
	hooks      ValidationHooks
	runner     CommandRunner
	now        func() time.Time
}

type Options struct {
	MachineFactory MachineFactory
	OpenAPIFactory func(Config) (OpenAPI, error)
	Probe          GuestProbe
	Validation     ValidationHooks
	CommandRunner  CommandRunner
	Now            func() time.Time
}

func New(opts Options) (*Provider, error) {
	if opts.MachineFactory == nil {
		return nil, errors.New("machine factory is required")
	}
	if opts.OpenAPIFactory == nil {
		return nil, errors.New("OpenAPI factory is required")
	}
	if opts.Probe == nil {
		return nil, errors.New("guest readiness probe is required")
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	return &Provider{instances: make(map[string]*instance), factory: opts.MachineFactory, apiFactory: opts.OpenAPIFactory, probe: opts.Probe, hooks: opts.Validation, runner: opts.CommandRunner, now: opts.Now}, nil
}

// RegisterGuest supplies the test-only guest channel endpoint to a readiness
// probe. Keeping this registration on the provider ensures the probe observes
// the exact config used to launch the VM, rather than guessing from an ID.
func (p *Provider) RegisterGuest(cfg Config, seedDigest string) {
	if p == nil {
		return
	}
	if probe, ok := p.probe.(interface{ Register(Config, string) }); ok {
		probe.Register(cfg, seedDigest)
	}
}

func (p *Provider) Create(ctx context.Context, cfg Config) (VMInfo, error) {
	normalized, paths, err := normalizeConfig(cfg)
	if err != nil {
		return VMInfo{}, err
	}
	cfg = normalized
	if err := cfg.validate(); err != nil {
		return VMInfo{}, err
	}
	if err := ctx.Err(); err != nil {
		return VMInfo{}, err
	}
	p.mu.Lock()
	if _, exists := p.instances[cfg.ID]; exists {
		p.mu.Unlock()
		return VMInfo{}, fmt.Errorf("%w: %s", ErrConflict, cfg.ID)
	}
	p.mu.Unlock()
	if err := p.hooks.Validate(ctx, cfg); err != nil {
		return VMInfo{}, err
	}
	if err := prepareOwnedState(paths.StateDir, cfg, p.now()); err != nil {
		return VMInfo{}, err
	}
	machine, err := p.factory(ctx, cfg)
	if err != nil {
		_ = removeOwnedState(paths.StateDir, cfg.ID)
		return VMInfo{}, fmt.Errorf("create machine: %w", err)
	}
	if machine == nil {
		_ = removeOwnedState(paths.StateDir, cfg.ID)
		return VMInfo{}, errors.New("machine factory returned nil machine")
	}
	api, err := p.apiFactory(cfg)
	if err != nil {
		closeMachine(machine)
		_ = removeOwnedState(paths.StateDir, cfg.ID)
		return VMInfo{}, fmt.Errorf("create API adapter: %w", err)
	}
	if api == nil {
		closeMachine(machine)
		_ = removeOwnedState(paths.StateDir, cfg.ID)
		return VMInfo{}, errors.New("OpenAPI factory returned nil adapter")
	}
	i := &instance{cfg: cfg, paths: paths, machine: machine, api: api, state: StateCreated}
	p.mu.Lock()
	if _, exists := p.instances[cfg.ID]; exists {
		p.mu.Unlock()
		closeMachine(machine)
		_ = removeOwnedState(paths.StateDir, cfg.ID)
		return VMInfo{}, fmt.Errorf("%w: %s", ErrConflict, cfg.ID)
	}
	p.instances[cfg.ID] = i
	p.mu.Unlock()
	return i.info(), nil
}

func (p *Provider) get(id string) (*instance, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	i, ok := p.instances[id]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrNotFound, id)
	}
	return i, nil
}

func (p *Provider) Start(ctx context.Context, id string) error {
	i, err := p.get(id)
	if err != nil {
		return err
	}
	i.mu.Lock()
	if err := ctx.Err(); err != nil {
		i.mu.Unlock()
		return err
	}
	if i.state == StateRunning {
		i.mu.Unlock()
		return p.ValidateProcess(ctx, id)
	}
	if i.state == StateDeleted || i.state == StateStarting || i.state == StateStopping {
		i.mu.Unlock()
		return ErrNotRunning
	}
	if i.state == StateStopped {
		if err := p.prepareRestartLocked(ctx, i); err != nil {
			i.mu.Unlock()
			return fmt.Errorf("prepare restart %s: %w", id, err)
		}
	}
	i.state = StateStarting
	if err := i.machine.Start(ctx); err != nil {
		i.state = StateStopped
		abortErr := abortMachine(i.machine, i.cfg.StopTimeout)
		closeMachine(i.machine)
		i.mu.Unlock()
		return errors.Join(fmt.Errorf("start %s: %w", id, err), abortErr)
	}
	version, err := i.machine.Version(ctx)
	if err != nil {
		i.state = StateStopped
		abortErr := abortMachine(i.machine, i.cfg.StopTimeout)
		closeMachine(i.machine)
		i.mu.Unlock()
		return errors.Join(fmt.Errorf("verify running Firecracker version for %s: %w", id, err), abortErr)
	}
	if version != i.cfg.ExpectedVersion {
		i.state = StateStopped
		abortErr := abortMachine(i.machine, i.cfg.StopTimeout)
		closeMachine(i.machine)
		i.mu.Unlock()
		return errors.Join(fmt.Errorf("Firecracker version mismatch: got %q, want %q", version, i.cfg.ExpectedVersion), abortErr)
	}
	inspection, err := i.machine.Inspect(ctx)
	if err != nil {
		i.state = StateStopped
		abortErr := abortMachine(i.machine, i.cfg.StopTimeout)
		closeMachine(i.machine)
		i.mu.Unlock()
		return errors.Join(fmt.Errorf("inspect started Firecracker process for %s: %w", id, err), abortErr)
	}
	inspection.Version = version
	if err := validateRunningInspection(i.cfg, inspection); err != nil {
		i.state = StateStopped
		abortErr := abortMachine(i.machine, i.cfg.StopTimeout)
		closeMachine(i.machine)
		i.mu.Unlock()
		return errors.Join(fmt.Errorf("verify started Firecracker process for %s: %w", id, err), abortErr)
	}
	record := runtimeRecord(i.cfg, i.paths, inspection, p.now())
	if err := writeRuntimeRecord(i.paths.RuntimeState, record); err != nil {
		i.state = StateStopped
		abortErr := abortMachine(i.machine, i.cfg.StopTimeout)
		closeMachine(i.machine)
		i.mu.Unlock()
		return errors.Join(fmt.Errorf("record started Firecracker process for %s: %w", id, err), abortErr)
	}
	i.runtime = record
	i.versionValidated = true
	i.state = inspection.State
	i.stopResult = nil
	i.mu.Unlock()
	return nil
}

// prepareRestartLocked replaces the SDK Machine because the official SDK
// permits one Start call per Machine. The persistent host drives and bounded
// diagnostic files stay in place; only ownership-verified jail artifacts from
// the stopped VMM are removed.
func (p *Provider) prepareRestartLocked(ctx context.Context, i *instance) error {
	if err := p.hooks.ValidateRestart(ctx, i.cfg); err != nil {
		return err
	}
	if err := resetOwnedJail(i.paths.StateDir, i.cfg.ID); err != nil {
		return err
	}
	closeMachine(i.machine)
	machine, err := p.factory(ctx, i.cfg)
	if err != nil {
		return fmt.Errorf("create replacement machine: %w", err)
	}
	if machine == nil {
		return errors.New("replacement machine factory returned nil machine")
	}
	api, err := p.apiFactory(i.cfg)
	if err != nil {
		closeMachine(machine)
		return fmt.Errorf("create replacement API adapter: %w", err)
	}
	if api == nil {
		closeMachine(machine)
		return errors.New("replacement OpenAPI factory returned nil adapter")
	}
	i.machine = machine
	i.api = api
	i.runtime = RuntimeRecord{}
	i.ready = false
	i.versionValidated = false
	i.lastCPU = 0
	i.lastAt = time.Time{}
	return nil
}

func closeMachine(machine Machine) {
	if closer, ok := machine.(interface{ Close() }); ok {
		closer.Close()
	}
}

func abortMachine(machine Machine, timeout time.Duration) error {
	stopErr := machine.StopVMM()
	wait := func() error {
		waitCtx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		return machine.Wait(waitCtx)
	}
	waitErr := wait()
	if errors.Is(waitErr, context.Canceled) || errors.Is(waitErr, context.DeadlineExceeded) {
		stopErr = errors.Join(stopErr, machine.StopVMM())
		waitErr = wait()
	}
	if errors.Is(stopErr, os.ErrProcessDone) {
		stopErr = nil
	}
	if waitErr != nil && !errors.Is(waitErr, context.Canceled) && !errors.Is(waitErr, context.DeadlineExceeded) {
		// A process exit status still proves the SDK child is gone.
		waitErr = nil
	}
	if waitErr == nil {
		return nil
	}
	return fmt.Errorf("abort Firecracker after failed start: %w", errors.Join(stopErr, waitErr))
}

// StartAndWaitReady makes cancellation cleanup explicit: a VM started by this
// operation is stopped if readiness or the caller's context fails.
func (p *Provider) StartAndWaitReady(ctx context.Context, id string) error {
	if err := p.Start(ctx, id); err != nil {
		return err
	}
	if err := p.WaitReady(ctx, id); err != nil {
		_ = p.Stop(context.Background(), id)
		return err
	}
	return nil
}

func (p *Provider) WaitReady(ctx context.Context, id string) error {
	i, err := p.get(id)
	if err != nil {
		return err
	}
	i.mu.Lock()
	if i.state != StateRunning || !i.versionValidated {
		i.mu.Unlock()
		return ErrNotRunning
	}
	timeout := i.cfg.ReadinessTimeout
	i.mu.Unlock()
	probeCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	// A bounded polling loop is portable across the fake and real guest probe.
	t := time.NewTicker(25 * time.Millisecond)
	defer t.Stop()
	for {
		if err := p.ValidateProcess(probeCtx, id); err != nil {
			return fmt.Errorf("%w: %v", ErrNotReady, err)
		}
		r, probeErr := p.probe.Probe(probeCtx, id)
		if probeErr == nil && r.Ready() {
			i.mu.Lock()
			if i.state != StateRunning || !i.versionValidated {
				i.mu.Unlock()
				return ErrNotRunning
			}
			i.ready = true
			i.mu.Unlock()
			return nil
		}
		if probeErr != nil && !errors.Is(probeErr, context.Canceled) && !errors.Is(probeErr, context.DeadlineExceeded) { /* retry until the bounded deadline */
		}
		select {
		case <-probeCtx.Done():
			return fmt.Errorf("%w: %v", ErrNotReady, probeCtx.Err())
		case <-t.C:
		}
	}
}

func (p *Provider) Stop(ctx context.Context, id string) error {
	i, err := p.get(id)
	if err != nil {
		return err
	}
	i.mu.Lock()
	if i.state == StateStopped || i.state == StateCreated {
		i.state = StateStopped
		i.ready = false
		i.versionValidated = false
		i.mu.Unlock()
		return nil
	}
	if i.state == StateDeleted {
		i.mu.Unlock()
		return nil
	}
	if i.state == StateStopping {
		done := i.stopDone
		i.mu.Unlock()
		select {
		case <-done:
			i.mu.Lock()
			result := i.stopResult
			i.mu.Unlock()
			return result
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	i.state = StateStopping
	i.ready = false
	i.stopDone = make(chan struct{})
	i.stopResult = nil
	done := i.stopDone
	machine := i.machine
	timeout := i.cfg.StopTimeout
	i.mu.Unlock()
	stopErr := stopAndConfirm(ctx, machine, timeout)
	i.mu.Lock()
	if stopErr == nil {
		i.state = StateStopped
		i.versionValidated = false
	} else {
		// A timed-out stop is indeterminate. Keep the instance retryable and do
		// not let Delete remove its jail while the recorded process may live.
		i.state = StateRunning
		i.versionValidated = false
	}
	record := i.runtime
	if stopErr == nil && record.PID > 0 {
		now := p.now().UTC()
		record.State = StateStopped
		record.StoppedAt = &now
		record.ObservedAt = now
		i.runtime = record
	}
	i.stopResult = stopErr
	i.mu.Unlock()
	var recordErr error
	if stopErr == nil && record.PID > 0 {
		recordErr = writeRuntimeRecord(i.paths.RuntimeState, record)
	}
	if recordErr != nil {
		stopErr = fmt.Errorf("record stopped Firecracker process for %s: %w", id, recordErr)
		i.mu.Lock()
		i.stopResult = stopErr
		i.mu.Unlock()
	}
	close(done)
	if stopErr != nil {
		return fmt.Errorf("stop %s: %w", id, stopErr)
	}
	return nil
}

// stopAndConfirm first requests the guest-visible Ctrl-Alt-Delete path. If
// that request fails or the VMM does not exit within the bound, it asks the
// SDK to stop the VMM and waits once more. A context error from Wait means the
// process exit is unconfirmed; any other Wait result came from the closed SDK
// exit channel and therefore proves the child has exited.
func stopAndConfirm(ctx context.Context, machine Machine, timeout time.Duration) error {
	if machine == nil {
		return errors.New("machine is not configured")
	}
	forced := false
	var forceErr error
	if err := machine.Shutdown(ctx); err != nil {
		forced = true
		forceErr = machine.StopVMM()
	}
	wait := func() error {
		waitCtx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		return machine.Wait(waitCtx)
	}
	waitErr := wait()
	if errors.Is(waitErr, context.Canceled) || errors.Is(waitErr, context.DeadlineExceeded) {
		if !forced {
			forced = true
			forceErr = machine.StopVMM()
		}
		waitErr = wait()
	}
	if errors.Is(waitErr, context.Canceled) || errors.Is(waitErr, context.DeadlineExceeded) {
		return errors.Join(errors.New("Firecracker process exit was not confirmed"), forceErr, waitErr)
	}
	// Once Wait observes the closed SDK exit channel, a non-nil value is the
	// child's exit status. A signal exit is expected after the forced path.
	return nil
}

// ValidateVersion asks the VMM for its reported version after its API socket
// is available and compares it to the pinned configuration.
func (p *Provider) ValidateVersion(ctx context.Context, id string) error {
	return p.ValidateProcess(ctx, id)
}

func (p *Provider) Reboot(ctx context.Context, id string) error {
	i, err := p.get(id)
	if err != nil {
		return err
	}
	if err := p.ValidateProcess(ctx, id); err != nil {
		return err
	}
	i.mu.Lock()
	if i.state != StateRunning {
		i.mu.Unlock()
		return ErrNotRunning
	}
	i.ready = false
	api := i.api
	i.mu.Unlock()
	if err := api.PatchVM(ctx, "Reboot"); err != nil {
		return fmt.Errorf("reboot %s: %w", id, err)
	}
	return nil
}

func (p *Provider) Inspect(ctx context.Context, id string) (VMInfo, error) {
	i, err := p.get(id)
	if err != nil {
		return VMInfo{}, err
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.state == StateCreated || i.state == StateDeleted || i.state == StateStopping {
		return i.infoLocked(), nil
	}
	info, err := i.machine.Inspect(ctx)
	if err != nil {
		return VMInfo{}, err
	}
	if info.State == "" {
		return VMInfo{}, errors.New("Firecracker inspection returned an empty state")
	}
	if info.PID > 0 {
		info.RSSBytes, info.IdleCPU, info.CPUSampled = i.measureProcess(info.PID, p.now())
	}
	executableMatches, _ := sameExecutable(i.cfg.FirecrackerBinary, info.Executable)
	identityMatches := i.runtime.PID > 0 && info.PID == i.runtime.PID && i.runtime.ProcessStartTime > 0 && info.ProcessStartTime == i.runtime.ProcessStartTime && executableMatches
	if !info.ProcessAlive || !info.SocketReady || !identityMatches {
		info.State = StateStopped
		i.versionValidated = false
	}
	i.state = info.State
	if info.State != StateRunning || info.Version != i.cfg.ExpectedVersion {
		i.ready = false
	}
	result := VMInfo{Config: i.cfg, State: info.State, Ready: i.ready, Paths: i.paths, PID: info.PID, ProcessStartTime: info.ProcessStartTime, Executable: info.Executable, Version: info.Version, RSSBytes: info.RSSBytes, IdleCPU: info.IdleCPU, CPUSampled: info.CPUSampled, Diagnostics: info.Diagnostics}
	return result, nil
}

func (i *instance) measureProcess(pid int, now time.Time) (uint64, float64, bool) {
	cpu, rss, err := processUsage(pid)
	if err != nil {
		return 0, 0, false
	}
	occupied := 0.0
	sampled := false
	if !i.lastAt.IsZero() && now.After(i.lastAt) && cpu >= i.lastCPU {
		sampled = true
		// Linux /proc reports utime and stime in USER_HZ ticks. Linux exposes
		// USER_HZ as 100 for these accounting fields on the supported runner
		// architectures. The quotient is CPU core equivalents, so a multi-vCPU
		// VMM may correctly report a value above one.
		occupied = float64(cpu-i.lastCPU) / (float64(now.Sub(i.lastAt)) / float64(time.Second) * linuxProcClockTicks)
		if occupied < 0 {
			occupied = 0
		}
	}
	i.lastCPU, i.lastAt = cpu, now
	return rss, occupied, sampled
}

type processObservation struct {
	CPUTimeTicks uint64
	StartTime    uint64
	RSSBytes     uint64
	Executable   string
	Alive        bool
}

func observeProcess(pid int) (processObservation, error) {
	if pid <= 0 {
		return processObservation{}, errors.New("invalid process PID")
	}
	stat, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "stat"))
	if err != nil {
		return processObservation{}, err
	}
	text := string(stat)
	closeParen := strings.LastIndexByte(text, ')')
	if closeParen < 0 || closeParen+2 >= len(text) {
		return processObservation{}, errors.New("invalid process stat")
	}
	fields := strings.Fields(text[closeParen+2:])
	if len(fields) < 20 {
		return processObservation{}, errors.New("incomplete process stat")
	}
	user, err := strconv.ParseUint(fields[11], 10, 64)
	if err != nil {
		return processObservation{}, err
	}
	system, err := strconv.ParseUint(fields[12], 10, 64)
	if err != nil {
		return processObservation{}, err
	}
	start, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil {
		return processObservation{}, err
	}
	statm, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "statm"))
	if err != nil {
		return processObservation{}, err
	}
	mem := strings.Fields(string(statm))
	if len(mem) < 2 {
		return processObservation{}, errors.New("incomplete process memory")
	}
	pages, err := strconv.ParseUint(mem[1], 10, 64)
	if err != nil {
		return processObservation{}, err
	}
	alive := fields[0] != "Z" && fields[0] != "X"
	executable := ""
	if alive {
		executable, err = os.Readlink(filepath.Join("/proc", strconv.Itoa(pid), "exe"))
		if err != nil {
			return processObservation{}, err
		}
		if !filepath.IsAbs(executable) || strings.HasSuffix(executable, " (deleted)") {
			return processObservation{}, errors.New("process executable is unavailable")
		}
		executable = filepath.Clean(executable)
	}
	return processObservation{CPUTimeTicks: user + system, StartTime: start, RSSBytes: pages * uint64(os.Getpagesize()), Executable: executable, Alive: alive}, nil
}

func processUsage(pid int) (uint64, uint64, error) {
	observation, err := observeProcess(pid)
	return observation.CPUTimeTicks, observation.RSSBytes, err
}

// ValidateProcess verifies both halves of the host boundary. A process PID
// without its Unix socket (or a socket without a process) is indeterminate and
// is rejected rather than treated as a ready VM.
func (p *Provider) ValidateProcess(ctx context.Context, id string) error {
	i, err := p.get(id)
	if err != nil {
		return err
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.state != StateRunning {
		return ErrNotRunning
	}
	inspection, err := i.machine.Inspect(ctx)
	if err != nil {
		return err
	}
	if inspection.PID <= 0 {
		i.state = StateStopped
		i.ready = false
		i.versionValidated = false
		return errors.New("Firecracker process has no valid PID")
	}
	if !inspection.ProcessAlive {
		i.state = StateStopped
		i.ready = false
		i.versionValidated = false
		return errors.New("Firecracker process is not alive")
	}
	expectedPID := i.runtime.PID
	expectedStart := i.runtime.ProcessStartTime
	expectedExecutable := i.cfg.FirecrackerBinary
	expectedVersion := i.cfg.ExpectedVersion
	versionValidated := i.versionValidated
	if expectedPID <= 0 || inspection.PID != expectedPID || expectedStart == 0 || inspection.ProcessStartTime != expectedStart {
		i.state = StateStopped
		i.ready = false
		i.versionValidated = false
		return errors.New("Firecracker PID start identity changed")
	}
	if matched, matchErr := sameExecutable(expectedExecutable, inspection.Executable); matchErr != nil || !matched {
		i.state = StateStopped
		i.ready = false
		i.versionValidated = false
		if matchErr != nil {
			return fmt.Errorf("verify Firecracker executable: %w", matchErr)
		}
		return errors.New("Firecracker process executable changed")
	}
	if !inspection.SocketReady {
		i.ready = false
		if inspection.State != "" {
			i.state = inspection.State
		}
		return errors.New("Firecracker API socket is not ready")
	}
	if !versionValidated || inspection.Version != expectedVersion {
		i.ready = false
		i.versionValidated = false
		return fmt.Errorf("Firecracker running version is %q, want %q", inspection.Version, expectedVersion)
	}
	if inspection.State != StateRunning {
		i.state = inspection.State
		i.ready = false
		return fmt.Errorf("Firecracker VMM state is %q", inspection.State)
	}
	return nil
}

func (p *Provider) Execute(ctx context.Context, id string, cmd Command) error {
	if p.runner == nil {
		return errors.New("command runner is required")
	}
	if err := validateCommand(cmd); err != nil {
		return err
	}
	i, err := p.get(id)
	if err != nil {
		return err
	}
	if err := p.ValidateProcess(ctx, id); err != nil {
		return ErrNotReady
	}
	i.mu.Lock()
	ready := i.ready
	i.mu.Unlock()
	if !ready {
		return ErrNotReady
	}
	return p.runner.Run(ctx, cmd)
}

// ExecuteCommand is the explicit safe process boundary used by the guest
// channel. It takes the runner as an argument so Provider never owns a hidden
// shell or host process implementation.
func (p *Provider) ExecuteCommand(ctx context.Context, id string, runner CommandRunner, cmd Command) error {
	if runner == nil {
		return errors.New("command runner is required")
	}
	if err := validateCommand(cmd); err != nil {
		return err
	}
	i, err := p.get(id)
	if err != nil {
		return err
	}
	if err := p.ValidateProcess(ctx, id); err != nil {
		return ErrNotReady
	}
	i.mu.Lock()
	ready := i.ready
	i.mu.Unlock()
	if !ready {
		return ErrNotReady
	}
	return runner.Run(ctx, cmd)
}

func validateCommand(c Command) error {
	if filepath.IsAbs(c.Path) == false || c.Path == "/bin/sh" || c.Path == "/bin/bash" || c.Path == "/usr/bin/env" {
		return errors.New("command must be an absolute non-shell executable")
	}
	if c.Dir != "" && !filepath.IsAbs(c.Dir) {
		return errors.New("command directory must be absolute")
	}
	for _, arg := range append([]string{c.Path}, c.Args...) {
		if strings.ContainsAny(arg, ";&|$`\n\r") {
			return errors.New("command contains shell metacharacters")
		}
	}
	return nil
}

func (i *instance) info() VMInfo {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.infoLocked()
}

func (i *instance) infoLocked() VMInfo {
	return VMInfo{Config: i.cfg, State: i.state, Ready: i.ready, Paths: i.paths, PID: i.runtime.PID, ProcessStartTime: i.runtime.ProcessStartTime, Executable: i.cfg.FirecrackerBinary, Version: i.runtime.Firecracker}
}

func (p *Provider) Delete(ctx context.Context, id string) error {
	i, err := p.get(id)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		return err
	}
	if err := p.Stop(ctx, id); err != nil {
		return err
	}
	i.mu.Lock()
	i.state = StateDeleted
	machine := i.machine
	i.mu.Unlock()
	closeMachine(machine)
	if err := removeOwnedState(i.paths.StateDir, id); err != nil {
		return err
	}
	p.mu.Lock()
	delete(p.instances, id)
	p.mu.Unlock()
	return nil
}

func (p *Provider) Close(ctx context.Context) error {
	p.mu.Lock()
	ids := make([]string, 0, len(p.instances))
	for id := range p.instances {
		ids = append(ids, id)
	}
	p.mu.Unlock()
	var errs []error
	for _, id := range ids {
		if err := p.Delete(ctx, id); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func runtimeRecord(cfg Config, paths Paths, inspection Inspection, observedAt time.Time) RuntimeRecord {
	return RuntimeRecord{
		Version:          runtimeRecordVersion,
		Marker:           ownershipMarker,
		ID:               cfg.ID,
		State:            inspection.State,
		PID:              inspection.PID,
		ProcessStartTime: inspection.ProcessStartTime,
		Firecracker:      inspection.Version,
		SocketPath:       paths.Socket,
		LogPath:          paths.Log,
		MetricsPath:      paths.Metrics,
		ObservedAt:       observedAt.UTC(),
	}
}

func validateRunningInspection(cfg Config, inspection Inspection) error {
	if inspection.State != StateRunning {
		return fmt.Errorf("VMM state is %q", inspection.State)
	}
	if inspection.PID <= 0 || inspection.ProcessStartTime == 0 || !inspection.ProcessAlive {
		return errors.New("VMM process identity is incomplete")
	}
	matched, err := sameExecutable(cfg.FirecrackerBinary, inspection.Executable)
	if err != nil {
		return fmt.Errorf("verify VMM executable: %w", err)
	}
	if !matched {
		return fmt.Errorf("VMM executable is %q, want %q", inspection.Executable, cfg.FirecrackerBinary)
	}
	if !inspection.SocketReady {
		return errors.New("VMM API socket is unavailable")
	}
	if inspection.Version != cfg.ExpectedVersion {
		return fmt.Errorf("VMM version is %q, want %q", inspection.Version, cfg.ExpectedVersion)
	}
	return nil
}

func sameExecutable(expected, observed string) (bool, error) {
	if !filepath.IsAbs(expected) || !filepath.IsAbs(observed) || strings.HasSuffix(observed, " (deleted)") {
		return false, errors.New("process executable paths must be live absolute paths")
	}
	expectedPath, err := filepath.EvalSymlinks(expected)
	if err != nil {
		return false, err
	}
	observedPath, err := filepath.EvalSymlinks(observed)
	if err != nil {
		return false, err
	}
	expectedInfo, err := os.Stat(expectedPath)
	if err != nil {
		return false, err
	}
	observedInfo, err := os.Stat(observedPath)
	if err != nil {
		return false, err
	}
	return filepath.Clean(expectedPath) == filepath.Clean(observedPath) && os.SameFile(expectedInfo, observedInfo), nil
}

func writeRuntimeRecord(path string, record RuntimeRecord) error {
	if err := record.validate(filepath.Dir(path)); err != nil {
		return err
	}
	b, err := json.Marshal(record)
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".runtime-*.json")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(0600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	parent, err := os.Open(dir)
	if err != nil {
		return err
	}
	err = parent.Sync()
	closeErr := parent.Close()
	return errors.Join(err, closeErr)
}

func (r RuntimeRecord) validate(stateDir string) error {
	if r.Version != runtimeRecordVersion || r.Marker != ownershipMarker || !validID(r.ID) {
		return errors.New("invalid Firecracker runtime record identity")
	}
	if r.PID <= 0 || r.ProcessStartTime == 0 || r.Firecracker == "" || r.ObservedAt.IsZero() {
		return errors.New("incomplete Firecracker runtime record")
	}
	expected := map[string]struct{ got, want string }{
		"socket":  {r.SocketPath, filepath.Join(stateDir, "root", strings.TrimPrefix(jailerSocketPath, "/"))},
		"log":     {r.LogPath, filepath.Join(stateDir, "firecracker.log")},
		"metrics": {r.MetricsPath, filepath.Join(stateDir, "firecracker.metrics")},
	}
	for name, paths := range expected {
		if paths.got != paths.want {
			return fmt.Errorf("Firecracker runtime %s path does not match owned state", name)
		}
	}
	if r.State != StateRunning && r.State != StateStopped {
		return fmt.Errorf("invalid Firecracker runtime state %q", r.State)
	}
	if r.State == StateRunning && r.StoppedAt != nil || r.State == StateStopped && r.StoppedAt == nil {
		return errors.New("Firecracker runtime stop timestamp does not match state")
	}
	return nil
}

// ReadRuntimeRecord returns only a record anchored by the exact ownership
// marker. Cleanup or recovery code can then call VerifyRunningProcess before
// signaling a PID retained across a controller crash.
func ReadRuntimeRecord(stateDir, id string) (RuntimeRecord, error) {
	marker, err := readOwnedState(stateDir, id)
	if err != nil {
		return RuntimeRecord{}, err
	}
	recordInfo, err := os.Lstat(marker.RuntimeState)
	if err != nil {
		return RuntimeRecord{}, err
	}
	if !recordInfo.Mode().IsRegular() || recordInfo.Mode()&os.ModeSymlink != 0 || recordInfo.Mode().Perm() != 0600 || recordInfo.Size() > 64<<10 {
		return RuntimeRecord{}, errors.New("unsafe Firecracker runtime record")
	}
	recordData, err := os.ReadFile(marker.RuntimeState)
	if err != nil {
		return RuntimeRecord{}, err
	}
	if len(recordData) > 64<<10 {
		return RuntimeRecord{}, errors.New("oversized Firecracker runtime record")
	}
	var record RuntimeRecord
	if err := decodeSingleJSON(recordData, &record); err != nil {
		return RuntimeRecord{}, err
	}
	if record.ID != id || record.SocketPath != marker.SocketPath || record.LogPath != marker.LogPath || record.MetricsPath != marker.MetricsPath {
		return RuntimeRecord{}, ErrUnowned
	}
	if err := record.validate(stateDir); err != nil {
		return RuntimeRecord{}, err
	}
	return record, nil
}

// VerifyRunningProcess rejects PID reuse, a dead process, a changed executable,
// or a missing API socket. Version 1 of the shared runtime record predates its
// executable field, so crash recovery supplies the pinned executable path as
// an argument. The argument is optional only for readers of the old API; code
// that may signal a process must supply it.
func (r RuntimeRecord) VerifyRunningProcess(expectedExecutable ...string) error {
	if len(expectedExecutable) > 1 {
		return errors.New("at most one expected executable may be supplied")
	}
	if r.State != StateRunning {
		return ErrNotRunning
	}
	observation, err := observeProcess(r.PID)
	if err != nil {
		return err
	}
	if !observation.Alive || observation.StartTime != r.ProcessStartTime {
		return errors.New("Firecracker process identity no longer matches runtime record")
	}
	if len(expectedExecutable) == 1 {
		matched, matchErr := sameExecutable(expectedExecutable[0], observation.Executable)
		if matchErr != nil {
			return fmt.Errorf("verify Firecracker executable: %w", matchErr)
		}
		if !matched {
			return errors.New("Firecracker process executable no longer matches runtime owner")
		}
	}
	if !SocketReady(r.SocketPath) {
		return errors.New("Firecracker API socket is unavailable")
	}
	return nil
}

func decodeSingleJSON(data []byte, value any) error {
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("JSON contains trailing data")
	}
	return nil
}

func readOwnedState(dir, id string) (ownedState, error) {
	if !filepath.IsAbs(dir) || !validID(id) {
		return ownedState{}, ErrUnowned
	}
	dirInfo, err := os.Lstat(dir)
	if err != nil {
		return ownedState{}, err
	}
	if !dirInfo.IsDir() || dirInfo.Mode()&os.ModeSymlink != 0 {
		return ownedState{}, ErrUnowned
	}
	markerPath := filepath.Join(dir, "ownership.json")
	markerInfo, err := os.Lstat(markerPath)
	if err != nil {
		return ownedState{}, err
	}
	if !markerInfo.Mode().IsRegular() || markerInfo.Mode()&os.ModeSymlink != 0 || markerInfo.Size() > 16<<10 {
		return ownedState{}, ErrUnowned
	}
	markerData, err := os.ReadFile(markerPath)
	if err != nil {
		return ownedState{}, err
	}
	if len(markerData) > 16<<10 {
		return ownedState{}, ErrUnowned
	}
	var marker ownedState
	if err := decodeSingleJSON(markerData, &marker); err != nil {
		return ownedState{}, ErrUnowned
	}
	expectedJailRoot := filepath.Join(dir, "root")
	if marker.Marker != ownershipMarker || marker.ID != id || strings.TrimSpace(marker.Region) == "" || marker.JailRoot != expectedJailRoot || marker.SocketPath != filepath.Join(expectedJailRoot, strings.TrimPrefix(jailerSocketPath, "/")) || marker.LogPath != filepath.Join(dir, "firecracker.log") || marker.MetricsPath != filepath.Join(dir, "firecracker.metrics") || marker.RuntimeState != filepath.Join(dir, "runtime.json") || marker.CreatedAt.IsZero() {
		return ownedState{}, ErrUnowned
	}
	return marker, nil
}

func activeRecordedProcess(stateDir, id string) (bool, error) {
	record, err := ReadRuntimeRecord(stateDir, id)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if record.State != StateRunning {
		return false, nil
	}
	observation, err := observeProcess(record.PID)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return observation.Alive && observation.StartTime == record.ProcessStartTime, nil
}

func socketAccepting(path string) bool {
	connection, err := net.DialTimeout("unix", path, 50*time.Millisecond)
	if err != nil {
		return false
	}
	_ = connection.Close()
	return true
}

// resetOwnedJail removes only transient SDK and jailer state after process
// exit. Persistent drives and the bounded log and metrics files are outside
// the jail root and survive a restart.
func resetOwnedJail(stateDir, id string) error {
	marker, err := readOwnedState(stateDir, id)
	if err != nil {
		return err
	}
	active, err := activeRecordedProcess(stateDir, id)
	if err != nil {
		return err
	}
	if active || socketAccepting(marker.SocketPath) {
		return errors.New("refusing to reset an active Firecracker jail")
	}
	for _, name := range []string{"firecracker-log.fifo", "firecracker-metrics.fifo"} {
		path := filepath.Join(stateDir, name)
		info, statErr := os.Lstat(path)
		if errors.Is(statErr, os.ErrNotExist) {
			continue
		}
		if statErr != nil {
			return statErr
		}
		if info.Mode()&os.ModeNamedPipe == 0 || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing unexpected transient path %s", path)
		}
		if err := os.Remove(path); err != nil {
			return err
		}
	}
	rootInfo, err := os.Lstat(marker.JailRoot)
	if errors.Is(err, os.ErrNotExist) {
		return syncDirectory(stateDir)
	}
	if err != nil {
		return err
	}
	if !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 {
		return errors.New("refusing unexpected Firecracker jail root")
	}
	if err := os.RemoveAll(marker.JailRoot); err != nil {
		return err
	}
	return syncDirectory(stateDir)
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	syncErr := directory.Sync()
	closeErr := directory.Close()
	return errors.Join(syncErr, closeErr)
}

func prepareOwnedState(dir string, cfg Config, now time.Time) error {
	if err := os.MkdirAll(filepath.Dir(dir), 0700); err != nil {
		return fmt.Errorf("create state parent: %w", err)
	}
	if err := os.Mkdir(dir, 0700); err != nil {
		if errors.Is(err, os.ErrExist) {
			return ErrConflict
		}
		return fmt.Errorf("create state directory: %w", err)
	}
	keep := false
	defer func() {
		if !keep {
			_ = os.RemoveAll(dir)
		}
	}()
	if err := os.Chmod(dir, 0700); err != nil {
		return fmt.Errorf("secure state directory: %w", err)
	}
	_, paths, err := normalizeConfig(cfg)
	if err != nil {
		return err
	}
	marker := ownedState{Marker: ownershipMarker, ID: cfg.ID, Region: cfg.Region, JailRoot: paths.JailRoot, SocketPath: paths.Socket, LogPath: paths.Log, MetricsPath: paths.Metrics, RuntimeState: paths.RuntimeState, CreatedAt: now.UTC()}
	b, err := json.Marshal(marker)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(filepath.Join(dir, "ownership.json"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return ErrConflict
		}
		return fmt.Errorf("create ownership marker: %w", err)
	}
	if _, err = f.Write(b); err != nil {
		_ = f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err := syncDirectory(dir); err != nil {
		return err
	}
	keep = true
	return nil
}

func removeOwnedState(dir, id string) error {
	_, err := readOwnedState(dir, id)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	active, err := activeRecordedProcess(dir, id)
	if err != nil {
		return err
	}
	if active {
		return errors.New("refusing to remove state for a live Firecracker process")
	}
	if err := os.RemoveAll(dir); err != nil {
		return err
	}
	return syncDirectory(filepath.Dir(dir))
}
