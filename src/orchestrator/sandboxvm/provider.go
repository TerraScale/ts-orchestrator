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
	"os"
	"path/filepath"
	"regexp"
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
	StateRoot                 string
	SocketPath                string
	FirecrackerBinary         string
	JailerBinary              string
	ExpectedVersion           string
	ExpectedKernelSHA256      string
	ExpectedRootDriveSHA256   string
	ExpectedDataDriveSHA256   string
	ExpectedFirecrackerSHA256 string
	ExpectedJailerSHA256      string
	ReadinessTimeout          time.Duration
	StopTimeout               time.Duration
}

func (c Config) Validate() error {
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
	for name, sum := range map[string]string{"firecracker": c.ExpectedFirecrackerSHA256, "jailer": c.ExpectedJailerSHA256} {
		if !validSHA256(sum) {
			return fmt.Errorf("%s checksum must be a SHA-256 hex digest", name)
		}
	}
	return nil
}

func (c Config) validate() error { return c.Validate() }

var vmIDPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$`)

func validID(id string) bool { return vmIDPattern.MatchString(id) && id != "." && id != ".." }
func validSHA256(s string) bool {
	if len(s) != sha256.Size*2 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
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

func validateArtifact(a Artifact) error {
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
	State       State
	PID         int
	SocketReady bool
	Version     string
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
	Config Config
	State  State
	Ready  bool
	Paths  Paths
}

type Paths struct{ StateDir, Socket, RootDrive, DataDrive string }

type ownedState struct {
	Marker    string    `json:"marker"`
	ID        string    `json:"id"`
	Region    string    `json:"region"`
	CreatedAt time.Time `json:"createdAt"`
}

const ownershipMarker = "terrascale-sandboxvm-v1"

type instance struct {
	mu       sync.Mutex
	cfg      Config
	paths    Paths
	machine  Machine
	api      OpenAPI
	state    State
	ready    bool
	stopDone chan struct{}
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

func pathsFor(c Config) Paths {
	return Paths{StateDir: filepath.Join(c.StateRoot, c.ID), Socket: c.SocketPath, RootDrive: c.RootDrive, DataDrive: c.DataDrive}
}

func (p *Provider) Create(ctx context.Context, cfg Config) (VMInfo, error) {
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
	paths := pathsFor(cfg)
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
		_ = removeOwnedState(paths.StateDir, cfg.ID)
		return VMInfo{}, fmt.Errorf("create API adapter: %w", err)
	}
	if api == nil {
		_ = removeOwnedState(paths.StateDir, cfg.ID)
		return VMInfo{}, errors.New("OpenAPI factory returned nil adapter")
	}
	i := &instance{cfg: cfg, paths: paths, machine: machine, api: api, state: StateCreated}
	p.mu.Lock()
	if _, exists := p.instances[cfg.ID]; exists {
		p.mu.Unlock()
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
	defer i.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if i.state == StateRunning {
		return nil
	}
	if i.state == StateDeleted || i.state == StateStopping {
		return ErrNotRunning
	}
	i.state = StateStarting
	if err := i.machine.Start(ctx); err != nil {
		i.state = StateStopped
		_ = i.machine.StopVMM()
		return fmt.Errorf("start %s: %w", id, err)
	}
	i.state = StateRunning
	return nil
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
	if i.state != StateRunning {
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
		r, probeErr := p.probe.Probe(probeCtx, id)
		if probeErr == nil && r.Ready() {
			i.mu.Lock()
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
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	i.state = StateStopping
	i.ready = false
	i.stopDone = make(chan struct{})
	done := i.stopDone
	i.mu.Unlock()
	defer close(done)
	stopErr := i.machine.Shutdown(ctx)
	if stopErr != nil {
		fallbackErr := i.machine.StopVMM()
		stopErr = errors.Join(stopErr, fallbackErr)
	}
	waitCtx, cancel := context.WithTimeout(context.Background(), i.cfg.StopTimeout)
	defer cancel()
	waitErr := i.machine.Wait(waitCtx)
	i.mu.Lock()
	i.state = StateStopped
	i.mu.Unlock()
	if stopErr != nil && !errors.Is(stopErr, os.ErrProcessDone) {
		return fmt.Errorf("stop %s: %w", id, stopErr)
	}
	if waitErr != nil && !errors.Is(waitErr, os.ErrProcessDone) && !errors.Is(waitErr, context.Canceled) {
		return fmt.Errorf("wait for %s: %w", id, waitErr)
	}
	return nil
}

// ValidateVersion asks the VMM for its reported version after its API socket
// is available and compares it to the pinned configuration.
func (p *Provider) ValidateVersion(ctx context.Context, id string) error {
	i, err := p.get(id)
	if err != nil {
		return err
	}
	i.mu.Lock()
	expected := i.cfg.ExpectedVersion
	i.mu.Unlock()
	got, err := i.machine.Version(ctx)
	if err != nil {
		return err
	}
	if got != expected {
		return fmt.Errorf("Firecracker version mismatch: got %q, want %q", got, expected)
	}
	return nil
}

func (p *Provider) Reboot(ctx context.Context, id string) error {
	i, err := p.get(id)
	if err != nil {
		return err
	}
	i.mu.Lock()
	if i.state != StateRunning {
		i.mu.Unlock()
		return ErrNotRunning
	}
	i.ready = false
	i.mu.Unlock()
	if err := i.api.PatchVM(ctx, "Reboot"); err != nil {
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
	info, err := i.machine.Inspect(ctx)
	if err != nil {
		return VMInfo{}, err
	}
	info.State = i.state
	return VMInfo{Config: i.cfg, State: i.state, Ready: i.ready && info.SocketReady, Paths: i.paths}, nil
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
	state := i.state
	i.mu.Unlock()
	if state != StateRunning {
		return ErrNotRunning
	}
	inspection, err := i.machine.Inspect(ctx)
	if err != nil {
		return err
	}
	if inspection.PID <= 0 {
		return errors.New("Firecracker process has no valid PID")
	}
	if !inspection.SocketReady {
		return errors.New("Firecracker API socket is not ready")
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
	i.mu.Lock()
	running := i.state == StateRunning && i.ready
	i.mu.Unlock()
	if !running {
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
	i.mu.Lock()
	running := i.state == StateRunning && i.ready
	i.mu.Unlock()
	if !running {
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
	return VMInfo{Config: i.cfg, State: i.state, Ready: i.ready, Paths: i.paths}
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
	i.mu.Unlock()
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

func prepareOwnedState(dir string, cfg Config, now time.Time) error {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create state directory: %w", err)
	}
	if err := os.Chmod(dir, 0700); err != nil {
		return fmt.Errorf("secure state directory: %w", err)
	}
	marker := ownedState{Marker: ownershipMarker, ID: cfg.ID, Region: cfg.Region, CreatedAt: now.UTC()}
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
	if err = f.Close(); err != nil {
		return err
	}
	return nil
}

func removeOwnedState(dir, id string) error {
	b, err := os.ReadFile(filepath.Join(dir, "ownership.json"))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	var marker ownedState
	if json.Unmarshal(b, &marker) != nil || marker.Marker != ownershipMarker || marker.ID != id {
		return ErrUnowned
	}
	return os.RemoveAll(dir)
}
