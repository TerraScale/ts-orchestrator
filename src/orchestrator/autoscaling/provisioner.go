// This file implements the NodeProvisioner seam of the rootless-hosting and
// autoscaling lane: a static recording provisioner for tests, and the local
// process provisioner that runs the node host-agent binary as an
// unprivileged child process through an injectable spawner seam.
package autoscaling

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	autoscalingMaximumNatsUrlLength         = 512
	autoscalingMaximumArgumentCount         = 128
	autoscalingMaximumArgumentLength        = 1024
	autoscalingMaximumEnvironmentCount      = 32
	autoscalingMaximumEnvironmentValueBytes = 1024
	autoscalingMaximumPathLength            = 4096

	// autoscalingXdgRuntimeDirKey is the environment key the provisioner
	// reserves: the runtime directory is derived from the run uid, never
	// injected by a caller.
	autoscalingXdgRuntimeDirKey = "XDG_RUNTIME_DIR"
)

// autoscalingEnvironmentKeyPattern accepts canonical uppercase environment
// variable names.
var autoscalingEnvironmentKeyPattern = regexp.MustCompile(`^[A-Z_][A-Z0-9_]*$`)

// requireAutoscalingAbsolutePath enforces a bounded absolute host path with
// no empty, dot, or dot-dot segments; the filesystem root itself is rejected.
func requireAutoscalingAbsolutePath(value, param string) (string, error) {
	if len(value) < 2 || len(value) > autoscalingMaximumPathLength || !strings.HasPrefix(value, "/") {
		return "", &ArgumentError{
			Param:   param,
			Message: "A bounded absolute path is required.",
		}
	}
	for _, segment := range strings.Split(value[1:], "/") {
		if segment == "" || segment == "." || segment == ".." {
			return "", &ArgumentError{
				Param:   param,
				Message: "Path segments must be nonempty and cannot traverse upward.",
			}
		}
	}
	return value, nil
}

// isAutoscalingSpaceOrControlRune reports whether one rune would let a value
// smuggle whitespace or control bytes into an argument list.
func isAutoscalingSpaceOrControlRune(r rune) bool { return r <= 0x20 || r == 0x7f }

// NodeProcessSpec is the exact child-process envelope of one provisioned node
// host agent: an explicit binary, argv, environment, and the unprivileged uid
// it runs as. XDG_RUNTIME_DIR is deliberately absent from the environment:
// it is derived from RunAsUid, so every spawned agent gets a runtime
// directory of its own and no caller can point a node at someone else's.
type NodeProcessSpec struct {
	BinaryPath string
	NodeId     string
	NatsUrl    string
	Nats       NodeNatsCredentials
	Args       []string
	Env        map[string]string
	RunAsUid   uint32
}

// NodeNatsCredentials is the file-only NATS transport identity passed to a
// provisioned node. The files must have been resolved and validated by the
// composition layer; this package deliberately never receives secret bytes.
// Exactly one of NKeyFile and CredentialsFile is required, together with a
// complete client mTLS tuple.
type NodeNatsCredentials struct {
	NKeyFile        string
	CredentialsFile string
	TlsCaFile       string
	TlsCertFile     string
	TlsKeyFile      string
}

func (c NodeNatsCredentials) validate() error {
	hasNKey := c.NKeyFile != ""
	hasCredentials := c.CredentialsFile != ""
	if hasNKey == hasCredentials {
		return &ArgumentError{Param: "nats", Message: "Exactly one NKey or credentials file is required."}
	}
	identityName, identityPath := "natsNKeyFile", c.NKeyFile
	if !hasNKey {
		identityName, identityPath = "natsCredentialsFile", c.CredentialsFile
	}
	if _, err := requireAutoscalingAbsolutePath(identityPath, identityName); err != nil {
		return err
	}
	if strings.ContainsFunc(identityPath, isAutoscalingSpaceOrControlRune) {
		return &ArgumentError{Param: "nats", Message: "NATS identity paths must be whitespace-free and flag-safe."}
	}
	for name, value := range map[string]string{
		"natsTlsCaFile": c.TlsCaFile, "natsTlsCertFile": c.TlsCertFile,
		"natsTlsKeyFile": c.TlsKeyFile,
	} {
		if value == "" {
			return &ArgumentError{Param: "nats", Message: "NATS identity and complete mTLS file paths are required."}
		}
		if _, err := requireAutoscalingAbsolutePath(value, name); err != nil {
			return err
		}
		if strings.ContainsFunc(value, isAutoscalingSpaceOrControlRune) {
			return &ArgumentError{Param: "nats", Message: "NATS mTLS paths must be whitespace-free and flag-safe."}
		}
	}
	return nil
}

// NewNodeProcessSpec validates one node process spec. The binary path is a
// bounded absolute path, the node id is a bounded canonical token, the NATS
// URL is bounded, whitespace-free, and flag-safe, every argument is bounded
// and control-free and may not claim reserved identity/security flags,
// environment keys are canonical uppercase names that may not override
// XDG_RUNTIME_DIR, and the run uid is nonzero: nothing in this lane ever
// spawns a privileged child.
func NewNodeProcessSpec(
	binaryPath string,
	nodeId string,
	natsUrl string,
	args []string,
	env map[string]string,
	runAsUid uint32,
	nats ...NodeNatsCredentials,
) (NodeProcessSpec, error) {
	if len(nats) != 1 {
		return NodeProcessSpec{}, &ArgumentError{Param: "nats", Message: "A scoped NATS identity and complete mTLS files are required."}
	}
	if err := nats[0].validate(); err != nil {
		return NodeProcessSpec{}, err
	}
	validatedBinary, err := requireAutoscalingAbsolutePath(binaryPath, "binaryPath")
	if err != nil {
		return NodeProcessSpec{}, err
	}
	validatedNode, err := requireAutoscalingToken(nodeId, "nodeId",
		"Node ID must be a lowercase DNS-style token.")
	if err != nil {
		return NodeProcessSpec{}, err
	}
	if natsUrl == "" || len(natsUrl) > autoscalingMaximumNatsUrlLength ||
		strings.HasPrefix(natsUrl, "-") || strings.ContainsFunc(natsUrl, isAutoscalingSpaceOrControlRune) {
		return NodeProcessSpec{}, &ArgumentError{
			Param:   "natsUrl",
			Message: "The NATS URL must be bounded, whitespace-free, and flag-safe.",
		}
	}
	if len(args) > autoscalingMaximumArgumentCount {
		return NodeProcessSpec{}, &ArgumentError{
			Param: "args",
			Message: fmt.Sprintf("Argument input exceeds the bound of %d entries.",
				autoscalingMaximumArgumentCount),
		}
	}
	arguments := make([]string, 0, len(args))
	for _, argument := range args {
		if argument == "" || len(argument) > autoscalingMaximumArgumentLength ||
			isAutoscalingReservedArgument(argument) ||
			strings.ContainsFunc(argument, isAutoscalingSpaceOrControlRune) {
			return NodeProcessSpec{}, &ArgumentError{
				Param:   "args",
				Message: "Arguments must be nonempty, bounded, control-free, and may not claim the identity flags.",
			}
		}
		arguments = append(arguments, argument)
	}
	if len(env) > autoscalingMaximumEnvironmentCount {
		return NodeProcessSpec{}, &ArgumentError{
			Param: "env",
			Message: fmt.Sprintf("Environment input exceeds the bound of %d entries.",
				autoscalingMaximumEnvironmentCount),
		}
	}
	environment := make(map[string]string, len(env))
	for key, value := range env {
		if !autoscalingEnvironmentKeyPattern.MatchString(key) || key == autoscalingXdgRuntimeDirKey {
			return NodeProcessSpec{}, &ArgumentError{
				Param:   "env",
				Message: "Environment keys must be uppercase names and XDG_RUNTIME_DIR is reserved.",
			}
		}
		if len(value) > autoscalingMaximumEnvironmentValueBytes ||
			strings.ContainsFunc(value, isAutoscalingSpaceOrControlRune) {
			return NodeProcessSpec{}, &ArgumentError{
				Param:   "env",
				Message: "Environment values must be bounded and control-free.",
			}
		}
		environment[key] = value
	}
	if runAsUid == 0 {
		return NodeProcessSpec{}, &ArgumentError{
			Param:   "runAsUid",
			Message: "The node host agent must run as a nonzero UID.",
		}
	}
	return NodeProcessSpec{
		BinaryPath: validatedBinary,
		NodeId:     validatedNode,
		NatsUrl:    natsUrl,
		Nats:       nats[0],
		Args:       arguments,
		Env:        environment,
		RunAsUid:   runAsUid,
	}, nil
}

// isAutoscalingReservedArgument keeps caller-supplied ExtraArgs from
// replacing either node identity or any NATS authentication/trust file. The
// provisioner appends those security-owned flags from validated config.
func isAutoscalingReservedArgument(argument string) bool {
	for _, flag := range []string{
		"--node-id", "--nats-url", "--nats-nkey-file", "--nats-credentials-file",
		"--nats-tls-ca-file", "--nats-tls-cert-file", "--nats-tls-key-file",
		"--run-as-uid", "--xdg-runtime-dir", "--podman-binary", "--seccomp-profile",
	} {
		if argument == flag || strings.HasPrefix(argument, flag+"=") {
			return true
		}
	}
	return false
}

// XdgRuntimeDir returns the dedicated XDG runtime directory of this node
// process, derived from the run uid.
func (s NodeProcessSpec) XdgRuntimeDir() string {
	return fmt.Sprintf("/run/user/%d", s.RunAsUid)
}

// childArguments composes the explicit child argv: caller arguments first,
// then the node identity and NATS security flags this lane owns. Secret bytes
// never enter argv; the final values are validated file paths.
func (s NodeProcessSpec) childArguments() []string {
	arguments := make([]string, 0, len(s.Args)+14)
	arguments = append(arguments, s.Args...)
	arguments = append(arguments, "--node-id", s.NodeId, "--nats-url", s.NatsUrl)
	if s.Nats.NKeyFile != "" {
		arguments = append(arguments, "--nats-nkey-file", s.Nats.NKeyFile)
	} else {
		arguments = append(arguments, "--nats-credentials-file", s.Nats.CredentialsFile)
	}
	arguments = append(arguments,
		"--nats-tls-ca-file", s.Nats.TlsCaFile,
		"--nats-tls-cert-file", s.Nats.TlsCertFile,
		"--nats-tls-key-file", s.Nats.TlsKeyFile)
	return arguments
}

// environment renders the explicit child environment: the caller entries
// plus the agent's own XDG runtime directory, sorted by key, with no ambient
// inheritance.
func (s NodeProcessSpec) environment() []string {
	entries := make([]string, 0, len(s.Env)+1)
	for key, value := range s.Env {
		entries = append(entries, key+"="+value)
	}
	entries = append(entries, autoscalingXdgRuntimeDirKey+"="+s.XdgRuntimeDir())
	sort.Strings(entries)
	return entries
}

// ProcessSpawner spawns and terminates the child processes of provisioned
// nodes. The seam exists so tests never really spawn; the production
// implementation is CommandProcessSpawner.
type ProcessSpawner interface {
	// Spawn starts one process described by the spec and returns its pid.
	Spawn(ctx context.Context, spec NodeProcessSpec) (int, error)
	// Terminate delivers SIGTERM to one previously spawned process, waits
	// for it to exit within the spawner's grace period, and fails closed
	// when the pid is not a child of this spawner.
	Terminate(ctx context.Context, pid int) error
}

// StaticNodeProvisioner is the recording NodeProvisioner of tests and wired
// smoke runs: it materializes nothing, revalidates every call, and records
// the requests and retirements in call order.
type StaticNodeProvisioner struct {
	// Provisions records the validated provision requests in call order.
	Provisions []NodeProvisionRequest
	// Retires records the validated retired node ids in call order.
	Retires []string
	// ProvisionError is returned by Provision when non-nil.
	ProvisionError error
	// RetireError is returned by Retire when non-nil.
	RetireError error
}

// NewStaticNodeProvisioner creates one empty recording provisioner.
func NewStaticNodeProvisioner() *StaticNodeProvisioner {
	return &StaticNodeProvisioner{}
}

// Provision revalidates and records one provision request.
func (p *StaticNodeProvisioner) Provision(ctx context.Context, request NodeProvisionRequest) error {
	if ctx == nil {
		return &ArgumentError{Param: "ctx", Message: "The provisioner context must not be nil."}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	validated, err := NewNodeProvisionRequest(
		request.NodeId, request.NodeClass, request.Resources, request.Reason)
	if err != nil {
		return err
	}
	if p.ProvisionError != nil {
		return p.ProvisionError
	}
	p.Provisions = append(p.Provisions, validated)
	return nil
}

// Retire revalidates and records one node retirement.
func (p *StaticNodeProvisioner) Retire(ctx context.Context, nodeId string) error {
	if ctx == nil {
		return &ArgumentError{Param: "ctx", Message: "The provisioner context must not be nil."}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	validated, err := requireAutoscalingToken(nodeId, "nodeId",
		"Node ID must be a lowercase DNS-style token.")
	if err != nil {
		return err
	}
	if p.RetireError != nil {
		return p.RetireError
	}
	p.Retires = append(p.Retires, validated)
	return nil
}

// LocalProcessProvisionerConfig is the explicit configuration of one local
// process provisioner: the host-agent binary every node runs, the regional
// NATS URL the agents connect to, the baseline argv placed before the
// node-specific flags, and the unprivileged uid the agents run as.
type LocalProcessProvisionerConfig struct {
	AgentBinaryPath string
	NatsUrl         string
	Nats            NodeNatsCredentials
	AgentArguments  []string
	RunAsUid        uint32
}

// NewLocalProcessProvisionerConfig validates one provisioner configuration;
// the fields carry the same bounds as a NodeProcessSpec.
func NewLocalProcessProvisionerConfig(
	agentBinaryPath string,
	natsUrl string,
	agentArguments []string,
	runAsUid uint32,
	nats ...NodeNatsCredentials,
) (LocalProcessProvisionerConfig, error) {
	if len(nats) != 1 {
		return LocalProcessProvisionerConfig{}, &ArgumentError{Param: "nats", Message: "A scoped NATS identity and complete mTLS files are required."}
	}
	// A probe spec with a placeholder node token applies the exact spec
	// validation to the shared fields without inventing a second rule set.
	probe, err := NewNodeProcessSpec(agentBinaryPath, "node", natsUrl, agentArguments, nil, runAsUid, nats[0])
	if err != nil {
		return LocalProcessProvisionerConfig{}, err
	}
	return LocalProcessProvisionerConfig{
		AgentBinaryPath: probe.BinaryPath,
		NatsUrl:         probe.NatsUrl,
		Nats:            probe.Nats,
		AgentArguments:  append([]string{}, probe.Args...),
		RunAsUid:        probe.RunAsUid,
	}, nil
}

// LocalProcessNodeProvisioner provisions nodes as unprivileged host-agent
// child processes of this process. Provision spawns the configured binary
// with an explicit argv and environment (its own XDG runtime directory, no
// ambient environment) through the injectable ProcessSpawner seam and
// records the returned pid; Retire terminates exactly the processes this
// provisioner spawned, fail-closed for any node id whose pid was never
// recorded at provision time.
type LocalProcessNodeProvisioner struct {
	config   LocalProcessProvisionerConfig
	spawner  ProcessSpawner
	mutex    sync.Mutex
	children map[string]int
}

// NewLocalProcessNodeProvisioner composes the provisioner from its explicit
// configuration and spawner.
func NewLocalProcessNodeProvisioner(
	config LocalProcessProvisionerConfig,
	spawner ProcessSpawner,
) (*LocalProcessNodeProvisioner, error) {
	validated, err := NewLocalProcessProvisionerConfig(
		config.AgentBinaryPath, config.NatsUrl, config.AgentArguments, config.RunAsUid, config.Nats)
	if err != nil {
		return nil, err
	}
	if spawner == nil {
		return nil, &ArgumentError{
			Param:   "spawner",
			Message: "A process spawner is required.",
		}
	}
	return &LocalProcessNodeProvisioner{
		config:   validated,
		spawner:  spawner,
		children: make(map[string]int),
	}, nil
}

// Provision spawns one node host agent for the request and records its pid.
// A node id is provisioned at most once; the duplicate is an invalid
// operation, not a respawn.
func (p *LocalProcessNodeProvisioner) Provision(ctx context.Context, request NodeProvisionRequest) error {
	if ctx == nil {
		return &ArgumentError{Param: "ctx", Message: "The provisioner context must not be nil."}
	}
	if p == nil || p.spawner == nil {
		return &InvalidOperationError{Message: "The process spawner is unavailable."}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	validated, err := NewNodeProvisionRequest(
		request.NodeId, request.NodeClass, request.Resources, request.Reason)
	if err != nil {
		return err
	}
	spec, err := NewNodeProcessSpec(
		p.config.AgentBinaryPath,
		validated.NodeId,
		p.config.NatsUrl,
		append(append([]string{}, p.config.AgentArguments...),
			"--node-class", validated.NodeClass),
		nil,
		p.config.RunAsUid,
		p.config.Nats)
	if err != nil {
		return err
	}
	// The mutex is held across the spawn so a duplicate node id can never
	// race into a second child process.
	p.mutex.Lock()
	defer p.mutex.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if _, already := p.children[validated.NodeId]; already {
		return &InvalidOperationError{
			Message: fmt.Sprintf("Node %s is already provisioned locally.", validated.NodeId),
		}
	}
	pid, err := p.spawner.Spawn(ctx, spec)
	if err != nil {
		return err
	}
	if pid <= 0 {
		return &InvalidDataError{
			Message: fmt.Sprintf("The process spawner returned an invalid pid for node %s.", validated.NodeId),
		}
	}
	p.children[validated.NodeId] = pid
	return nil
}

// Retire terminates one node host agent this provisioner spawned: SIGTERM,
// then a bounded wait, through the spawner. A node that was never
// provisioned here, or whose retirement already completed, has no recorded
// pid, and the refusal is fail-closed: this provisioner never signals a
// process it cannot prove is its own child.
func (p *LocalProcessNodeProvisioner) Retire(ctx context.Context, nodeId string) error {
	if ctx == nil {
		return &ArgumentError{Param: "ctx", Message: "The provisioner context must not be nil."}
	}
	if p == nil || p.spawner == nil {
		return &InvalidOperationError{Message: "The process spawner is unavailable."}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	validated, err := requireAutoscalingToken(nodeId, "nodeId",
		"Node ID must be a lowercase DNS-style token.")
	if err != nil {
		return err
	}
	p.mutex.Lock()
	pid, ours := p.children[validated]
	if !ours {
		p.mutex.Unlock()
		return &InvalidOperationError{
			Message: fmt.Sprintf("Node %s is not a locally provisioned child.", validated),
		}
	}
	if err := ctx.Err(); err != nil {
		p.mutex.Unlock()
		return err
	}
	delete(p.children, validated)
	p.mutex.Unlock()
	if err := p.spawner.Terminate(ctx, pid); err != nil {
		var escalated *processTerminationEscalatedError
		if errors.As(err, &escalated) {
			// The spawner already killed and reaped the child. Preserve the
			// diagnostic, but do not resurrect a pid that cannot be retried.
			return err
		}
		// Keep the recorded pid so a failed termination stays visible and
		// retryable instead of silently orphaning the child.
		p.mutex.Lock()
		p.children[validated] = pid
		p.mutex.Unlock()
		return err
	}
	return nil
}

// spawnedProcess is one child of the CommandProcessSpawner: its command and
// a channel closed by the wait goroutine once the process is reaped, so
// neither zombies nor double waits are possible.
type spawnedProcess struct {
	command *exec.Cmd
	exited  chan struct{}
}

// processTerminationEscalatedError reports that SIGTERM was ignored but the
// child was successfully killed and reaped. The child is gone, so callers
// must not retain a pid mapping merely because the operation returns an
// error for observability.
type processTerminationEscalatedError struct{ *InvalidOperationError }

// CommandProcessSpawner is the production ProcessSpawner: it spawns the
// host-agent binary via os/exec with dropped credentials, its own process
// group, an explicit environment with no ambient inheritance, and a
// cancellation hook that kills the whole group; it terminates only the
// children it spawned, with SIGTERM first and a bounded SIGKILL escalation.
type CommandProcessSpawner struct {
	terminateGrace time.Duration
	mutex          sync.Mutex
	processes      map[int]*spawnedProcess
}

// NewCommandProcessSpawner creates one spawner with an explicit termination
// grace period between SIGTERM and the SIGKILL escalation.
func NewCommandProcessSpawner(terminateGrace time.Duration) (*CommandProcessSpawner, error) {
	if terminateGrace <= 0 {
		return nil, &ArgumentOutOfRangeError{
			Param:   "terminateGrace",
			Message: "The termination grace period must be positive.",
		}
	}
	return &CommandProcessSpawner{
		terminateGrace: terminateGrace,
		processes:      make(map[int]*spawnedProcess),
	}, nil
}

// Spawn starts one unprivileged child process described by the spec. The
// child runs under the spec's uid with a matching primary gid (the
// user-private-group layout of the rootless node accounts), in its own
// process group, with exactly the rendered environment and argv.
func (s *CommandProcessSpawner) Spawn(ctx context.Context, spec NodeProcessSpec) (int, error) {
	if ctx == nil {
		return 0, &ArgumentError{Param: "ctx", Message: "The spawner context must not be nil."}
	}
	if s == nil {
		return 0, &InvalidOperationError{Message: "The process spawner is unavailable."}
	}
	validated, err := NewNodeProcessSpec(
		spec.BinaryPath, spec.NodeId, spec.NatsUrl, spec.Args, spec.Env, spec.RunAsUid, spec.Nats)
	if err != nil {
		return 0, err
	}
	command := exec.CommandContext(ctx, validated.BinaryPath, validated.childArguments()...)
	command.Env = validated.environment()
	command.SysProcAttr = &syscall.SysProcAttr{
		Setpgid:    true,
		Credential: &syscall.Credential{Uid: validated.RunAsUid, Gid: validated.RunAsUid},
	}
	// Mirror the host command runner: cancellation kills the whole process
	// group, including anything the node agent spawned.
	command.Cancel = func() error {
		if command.Process != nil {
			_ = syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
		}
		return nil
	}
	command.WaitDelay = 2 * time.Second
	if err := command.Start(); err != nil {
		return 0, err
	}
	child := &spawnedProcess{command: command, exited: make(chan struct{})}
	go func() {
		_ = command.Wait()
		close(child.exited)
	}()
	s.mutex.Lock()
	s.processes[command.Process.Pid] = child
	s.mutex.Unlock()
	return command.Process.Pid, nil
}

// Terminate delivers SIGTERM to one spawned child's process group and waits
// for the grace period, then escalates to SIGKILL and waits once more; pids
// this spawner did not spawn are refused fail-closed, because signaling a
// foreign pid by number is exactly the failure this lane forbids.
func (s *CommandProcessSpawner) Terminate(ctx context.Context, pid int) error {
	if ctx == nil {
		return &ArgumentError{Param: "ctx", Message: "The spawner context must not be nil."}
	}
	if pid <= 0 {
		return &ArgumentOutOfRangeError{
			Param:   "pid",
			Message: "A spawned pid is positive.",
		}
	}
	s.mutex.Lock()
	defer s.mutex.Unlock()
	child, ours := s.processes[pid]
	if !ours {
		return &InvalidOperationError{
			Message: fmt.Sprintf("Process %d is not a child of this spawner.", pid),
		}
	}
	if child.command.Process == nil {
		return &InvalidOperationError{
			Message: fmt.Sprintf("Process %d has no process handle.", pid),
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := syscall.Kill(-pid, syscall.SIGTERM); err != nil && !errors.Is(err, syscall.ESRCH) {
		return &InvalidOperationError{
			Message: fmt.Sprintf("Process %d could not be terminated: %v.", pid, err),
		}
	}
	timer := time.NewTimer(s.terminateGrace)
	defer timer.Stop()
	select {
	case <-child.exited:
		delete(s.processes, pid)
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := syscall.Kill(-pid, syscall.SIGKILL); err != nil && !errors.Is(err, syscall.ESRCH) {
		return &InvalidOperationError{
			Message: fmt.Sprintf("Process %d could not be killed: %v.", pid, err),
		}
	}
	timer.Reset(s.terminateGrace)
	select {
	case <-child.exited:
		delete(s.processes, pid)
		return &processTerminationEscalatedError{InvalidOperationError: &InvalidOperationError{Message: fmt.Sprintf(
			"Process %d ignored SIGTERM and was killed after the grace period.", pid)}}
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return &InvalidOperationError{
			Message: fmt.Sprintf("Process %d could not be reaped within the grace period.", pid),
		}
	}
}
