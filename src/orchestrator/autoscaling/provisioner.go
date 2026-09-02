// This file implements the NodeProvisioner seam of the rootless-hosting and
// autoscaling lane: a static recording provisioner for tests, and the local
// process provisioner that runs the node host-agent binary as an
// unprivileged child process through an injectable spawner seam.
package autoscaling

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"terrascale.tech/orchestrator/src/orchestrator/errs"
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
	autoscalingXdgRuntimeDirKey     = "XDG_RUNTIME_DIR"
	processReapedTombstoneTTL       = 5 * time.Minute
	processReapedTombstoneLimit     = 1024
	localProvisionerShutdownTimeout = 30 * time.Second
	processWaitidFallbackAfter      = 250 * time.Millisecond
)

// autoscalingEnvironmentKeyPattern accepts canonical uppercase environment
// variable names.
var autoscalingEnvironmentKeyPattern = regexp.MustCompile(`^[A-Z_][A-Z0-9_]*$`)

// requireAutoscalingAbsolutePath enforces a bounded absolute host path with
// no empty, dot, or dot-dot segments; the filesystem root itself is rejected.
func requireAutoscalingAbsolutePath(value, param string) (string, error) {
	if len(value) < 2 || len(value) > autoscalingMaximumPathLength || !strings.HasPrefix(value, "/") {
		return "", &errs.Argument{
			Param:   param,
			Message: "A bounded absolute path is required.",
		}
	}
	for _, segment := range strings.Split(value[1:], "/") {
		if segment == "" || segment == "." || segment == ".." {
			return "", &errs.Argument{
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
	Args       []string
	Env        map[string]string
	RunAsUid   uint32
}

// NewNodeProcessSpec validates one node process spec. The binary path is a
// bounded absolute path, the node id is a bounded canonical token, the NATS
// URL is bounded, whitespace-free, and flag-safe, every argument is bounded
// and control-free and may not claim the reserved identity flags, environment
// keys are canonical uppercase names that may not override
// XDG_RUNTIME_DIR, and the run uid is nonzero: nothing in this lane ever
// spawns a privileged child.
func NewNodeProcessSpec(
	binaryPath string,
	nodeId string,
	natsUrl string,
	args []string,
	env map[string]string,
	runAsUid uint32,
) (NodeProcessSpec, error) {
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
		return NodeProcessSpec{}, &errs.Argument{
			Param:   "natsUrl",
			Message: "The NATS URL must be bounded, whitespace-free, and flag-safe.",
		}
	}
	if len(args) > autoscalingMaximumArgumentCount {
		return NodeProcessSpec{}, &errs.Argument{
			Param: "args",
			Message: fmt.Sprintf("Argument input exceeds the bound of %d entries.",
				autoscalingMaximumArgumentCount),
		}
	}
	arguments := make([]string, 0, len(args))
	for _, argument := range args {
		if argument == "" || len(argument) > autoscalingMaximumArgumentLength ||
			argument == "--node-id" || argument == "--nats-url" ||
			strings.HasPrefix(argument, "--node-id=") || strings.HasPrefix(argument, "--nats-url=") ||
			strings.ContainsFunc(argument, isAutoscalingSpaceOrControlRune) {
			return NodeProcessSpec{}, &errs.Argument{
				Param:   "args",
				Message: "Arguments must be nonempty, bounded, control-free, and may not claim the identity flags.",
			}
		}
		arguments = append(arguments, argument)
	}
	if len(env) > autoscalingMaximumEnvironmentCount {
		return NodeProcessSpec{}, &errs.Argument{
			Param: "env",
			Message: fmt.Sprintf("Environment input exceeds the bound of %d entries.",
				autoscalingMaximumEnvironmentCount),
		}
	}
	environment := make(map[string]string, len(env))
	for key, value := range env {
		if !autoscalingEnvironmentKeyPattern.MatchString(key) || key == autoscalingXdgRuntimeDirKey {
			return NodeProcessSpec{}, &errs.Argument{
				Param:   "env",
				Message: "Environment keys must be uppercase names and XDG_RUNTIME_DIR is reserved.",
			}
		}
		if len(value) > autoscalingMaximumEnvironmentValueBytes ||
			strings.ContainsFunc(value, isAutoscalingSpaceOrControlRune) {
			return NodeProcessSpec{}, &errs.Argument{
				Param:   "env",
				Message: "Environment values must be bounded and control-free.",
			}
		}
		environment[key] = value
	}
	if runAsUid == 0 {
		return NodeProcessSpec{}, &errs.Argument{
			Param:   "runAsUid",
			Message: "The node host agent must run as a nonzero UID.",
		}
	}
	return NodeProcessSpec{
		BinaryPath: validatedBinary,
		NodeId:     validatedNode,
		NatsUrl:    natsUrl,
		Args:       arguments,
		Env:        environment,
		RunAsUid:   runAsUid,
	}, nil
}

// XdgRuntimeDir returns the dedicated XDG runtime directory of this node
// process, derived from the run uid.
func (s NodeProcessSpec) XdgRuntimeDir() string {
	return fmt.Sprintf("/run/user/%d", s.RunAsUid)
}

// childArguments composes the explicit child argv: the caller arguments
// first, then the identity flags this lane owns, so a node agent always
// learns its own node id and NATS URL last and in that order.
func (s NodeProcessSpec) childArguments() []string {
	arguments := make([]string, 0, len(s.Args)+4)
	arguments = append(arguments, s.Args...)
	arguments = append(arguments, "--node-id", s.NodeId, "--nats-url", s.NatsUrl)
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

// ProcessExitObserver receives a child pid after the spawner has observed its
// exit but before the kernel can reuse that pid. Production process spawners
// implement this so the provisioner can release node-scoped credentials after
// natural exits as well as explicit retirements.
type ProcessExitObserver interface {
	SetProcessExitHandler(func(int))
}

// NodeProvisionerShutdown reconciles every process owned by a provisioner.
// It is optional on the narrow autoscaler seam so static/test provisioners do
// not need lifecycle machinery, but local process provisioners always expose
// it to their host.
type NodeProvisionerShutdown interface {
	Shutdown(context.Context) error
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
		return &errs.Argument{Param: "ctx", Message: "The provisioner context must not be nil."}
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
		return &errs.Argument{Param: "ctx", Message: "The provisioner context must not be nil."}
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
	AgentArguments  []string
	// AgentArgumentsForNode supplies node-scoped authentication arguments.
	// When set, it replaces AgentArguments for each node. The resolver must
	// return a fresh argument slice and must never return another node's credentials.
	AgentArgumentsForNode func(nodeId string) ([]string, error)
	// AgentArgumentsForNodeCommit records node-scoped identity ownership only
	// after the child has started successfully. It is paired with
	// AgentArgumentsForNodeRollback for failed starts.
	AgentArgumentsForNodeCommit func(nodeId string, arguments []string) error
	// AgentArgumentsForNodeRollback releases any tentative resolver state after
	// a failed spawn or failed commit.
	AgentArgumentsForNodeRollback func(nodeId string, arguments []string)
	// AgentArgumentsForNodeRelease releases identity ownership after the child
	// has terminated successfully (including successful SIGKILL escalation).
	// A retryable termination failure deliberately retains ownership.
	AgentArgumentsForNodeRelease func(nodeId string)
	RunAsUid                     uint32
}

// NewLocalProcessProvisionerConfig validates one provisioner configuration;
// the fields carry the same bounds as a NodeProcessSpec.
func NewLocalProcessProvisionerConfig(
	agentBinaryPath string,
	natsUrl string,
	agentArguments []string,
	runAsUid uint32,
) (LocalProcessProvisionerConfig, error) {
	// A probe spec with a placeholder node token applies the exact spec
	// validation to the shared fields without inventing a second rule set.
	probe, err := NewNodeProcessSpec(agentBinaryPath, "node", natsUrl, agentArguments, nil, runAsUid)
	if err != nil {
		return LocalProcessProvisionerConfig{}, err
	}
	return LocalProcessProvisionerConfig{
		AgentBinaryPath: probe.BinaryPath,
		NatsUrl:         probe.NatsUrl,
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
	config           LocalProcessProvisionerConfig
	spawner          ProcessSpawner
	mutex            sync.Mutex
	children         map[string]int
	retiring         map[string]*retirementState
	pendingRollbacks map[string][]string
	releasing        map[string]chan struct{}
	closed           bool
	released         map[string]struct{}
}

type retirementState struct {
	done chan struct{}
	err  error
}

// NewLocalProcessNodeProvisioner composes the provisioner from its explicit
// configuration and spawner.
func NewLocalProcessNodeProvisioner(
	config LocalProcessProvisionerConfig,
	spawner ProcessSpawner,
) (*LocalProcessNodeProvisioner, error) {
	validated, err := NewLocalProcessProvisionerConfig(
		config.AgentBinaryPath, config.NatsUrl, config.AgentArguments, config.RunAsUid)
	if err != nil {
		return nil, err
	}
	validated.AgentArgumentsForNode = config.AgentArgumentsForNode
	validated.AgentArgumentsForNodeCommit = config.AgentArgumentsForNodeCommit
	validated.AgentArgumentsForNodeRollback = config.AgentArgumentsForNodeRollback
	validated.AgentArgumentsForNodeRelease = config.AgentArgumentsForNodeRelease
	if spawner == nil {
		return nil, &errs.Argument{
			Param:   "spawner",
			Message: "A process spawner is required.",
		}
	}
	p := &LocalProcessNodeProvisioner{
		config:           validated,
		spawner:          spawner,
		children:         make(map[string]int),
		retiring:         make(map[string]*retirementState),
		pendingRollbacks: make(map[string][]string),
		releasing:        make(map[string]chan struct{}),
		released:         make(map[string]struct{}),
	}
	if observer, ok := spawner.(ProcessExitObserver); ok {
		observer.SetProcessExitHandler(p.childExited)
	}
	return p, nil
}

// Provision spawns one node host agent for the request and records its pid.
// A node id is provisioned at most once; the duplicate is an invalid
// operation, not a respawn.
func (p *LocalProcessNodeProvisioner) Provision(ctx context.Context, request NodeProvisionRequest) error {
	if ctx == nil {
		return &errs.Argument{Param: "ctx", Message: "The provisioner context must not be nil."}
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
	// The mutex is held across the spawn so a duplicate node id can never
	// race into a second child process or consume resolver state. A release
	// callback is allowed to run outside this mutex, so wait for that callback
	// before reusing the node's identity.
	for {
		p.mutex.Lock()
		if done, releasing := p.releasing[validated.NodeId]; releasing {
			p.mutex.Unlock()
			select {
			case <-done:
				continue
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		break
	}
	locked := true
	defer func() {
		if locked {
			p.mutex.Unlock()
		}
	}()
	if p.closed {
		return &InvalidOperationError{Message: "The local process provisioner is shut down."}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if _, already := p.children[validated.NodeId]; already {
		return &InvalidOperationError{
			Message: fmt.Sprintf("Node %s is already provisioned locally.", validated.NodeId),
		}
	}
	agentArguments := append([]string{}, p.config.AgentArguments...)
	if p.config.AgentArgumentsForNode != nil {
		resolvedArguments, resolveErr := p.config.AgentArgumentsForNode(validated.NodeId)
		if resolveErr != nil {
			if p.config.AgentArgumentsForNodeRollback != nil {
				p.config.AgentArgumentsForNodeRollback(validated.NodeId, resolvedArguments)
			}
			return resolveErr
		}
		agentArguments = resolvedArguments
	}
	spec, err := NewNodeProcessSpec(
		p.config.AgentBinaryPath,
		validated.NodeId,
		p.config.NatsUrl,
		append(agentArguments,
			"--node-class", validated.NodeClass),
		nil,
		p.config.RunAsUid)
	if err != nil {
		if p.config.AgentArgumentsForNodeRollback != nil {
			p.config.AgentArgumentsForNodeRollback(validated.NodeId, agentArguments)
		}
		return err
	}
	pid, err := p.spawner.Spawn(ctx, spec)
	if err != nil {
		// Some spawners can start a child and then observe cancellation before
		// returning. If they return its positive pid, retain ownership while the
		// bounded cleanup is attempted; otherwise a still-live child could outlive
		// this provisioner and its credentials could be reused.
		if pid > 0 {
			p.children[validated.NodeId] = pid
			p.pendingRollbacks[validated.NodeId] = append([]string(nil), agentArguments...)
			p.mutex.Unlock()
			locked = false
			cleanupErr := p.spawner.Terminate(context.Background(), pid)
			p.mutex.Lock()
			locked = true
			if cleanupErr == nil || terminationConfirmed(cleanupErr) {
				delete(p.children, validated.NodeId)
				p.rollbackIdentity(validated.NodeId)
				return err
			}
			return errors.Join(err, cleanupErr)
		}
		if p.config.AgentArgumentsForNodeRollback != nil {
			p.config.AgentArgumentsForNodeRollback(validated.NodeId, agentArguments)
		}
		return err
	}
	if pid <= 0 {
		if p.config.AgentArgumentsForNodeRollback != nil {
			p.config.AgentArgumentsForNodeRollback(validated.NodeId, agentArguments)
		}
		return &InvalidDataError{
			Message: fmt.Sprintf("The process spawner returned an invalid pid for node %s.", validated.NodeId),
		}
	}
	if err := ctx.Err(); err != nil {
		p.children[validated.NodeId] = pid
		p.pendingRollbacks[validated.NodeId] = append([]string(nil), agentArguments...)
		p.mutex.Unlock()
		locked = false
		cleanupErr := p.spawner.Terminate(context.Background(), pid)
		p.mutex.Lock()
		locked = true
		if cleanupErr == nil || terminationConfirmed(cleanupErr) {
			delete(p.children, validated.NodeId)
			p.rollbackIdentity(validated.NodeId)
			return err
		}
		return errors.Join(err, cleanupErr)
	}
	if p.config.AgentArgumentsForNodeCommit != nil {
		if err := p.config.AgentArgumentsForNodeCommit(validated.NodeId, agentArguments); err != nil {
			// Keep ownership before attempting cleanup. A failing commit may
			// have partially reserved identity, and cleanup failure means the
			// child may still be alive with those credentials.
			p.children[validated.NodeId] = pid
			p.pendingRollbacks[validated.NodeId] = append([]string(nil), agentArguments...)
			p.mutex.Unlock()
			locked = false
			cleanupErr := p.spawner.Terminate(context.Background(), pid)
			p.mutex.Lock()
			locked = true
			if cleanupErr == nil || terminationConfirmed(cleanupErr) {
				delete(p.children, validated.NodeId)
				p.rollbackIdentity(validated.NodeId)
				return errors.Join(err, cleanupErr)
			}
			return errors.Join(err, fmt.Errorf("failed to clean up node %s after identity commit failure: %w", validated.NodeId, cleanupErr))
		}
	}
	// The commit callback can block long enough for the request context to be
	// canceled. Never report successful provisioning after that cancellation;
	// record ownership first, then use the same bounded cleanup and rollback
	// path as a cancellation observed immediately after Spawn.
	if err := ctx.Err(); err != nil {
		p.children[validated.NodeId] = pid
		p.pendingRollbacks[validated.NodeId] = append([]string(nil), agentArguments...)
		p.mutex.Unlock()
		locked = false
		cleanupErr := p.spawner.Terminate(context.Background(), pid)
		p.mutex.Lock()
		locked = true
		if cleanupErr == nil || terminationConfirmed(cleanupErr) {
			delete(p.children, validated.NodeId)
			p.rollbackIdentity(validated.NodeId)
			return err
		}
		return errors.Join(err, cleanupErr)
	}
	p.children[validated.NodeId] = pid
	delete(p.released, validated.NodeId)
	p.mutex.Unlock()
	locked = false
	return nil
}

func terminationConfirmed(err error) bool {
	if err == nil {
		return true
	}
	var escalated *processTerminationEscalatedError
	if errors.As(err, &escalated) {
		return true
	}
	var exited *processAlreadyExitedError
	return errors.As(err, &exited)
}

// Shutdown closes the provisioner to new work and reconciles every child it
// owns. Cleanup intentionally uses a fresh context because role shutdown is
// commonly triggered by the cancellation that stopped the role. Any child
// whose termination cannot be confirmed remains recorded, so a later retry
// cannot reuse its node identity or signal an unrelated PID.
func (p *LocalProcessNodeProvisioner) Shutdown(ctx context.Context) error {
	if ctx == nil {
		return &errs.Argument{Param: "ctx", Message: "The provisioner context must not be nil."}
	}
	if p == nil || p.spawner == nil {
		return &InvalidOperationError{Message: "The process spawner is unavailable."}
	}
	p.mutex.Lock()
	p.closed = true
	nodes := make([]string, 0, len(p.children))
	for nodeID := range p.children {
		nodes = append(nodes, nodeID)
	}
	p.mutex.Unlock()
	cleanupCtx := context.Background()
	if deadline, hasDeadline := ctx.Deadline(); hasDeadline {
		var cancel context.CancelFunc
		cleanupCtx, cancel = context.WithDeadline(context.Background(), deadline)
		defer cancel()
	} else {
		var cancel context.CancelFunc
		cleanupCtx, cancel = context.WithTimeout(context.Background(), localProvisionerShutdownTimeout)
		defer cancel()
	}
	sort.Strings(nodes)
	var result error
	for _, nodeID := range nodes {
		for {
			if err := cleanupCtx.Err(); err != nil {
				result = errors.Join(result, err)
				break
			}
			p.mutex.Lock()
			if _, present := p.children[nodeID]; !present {
				p.mutex.Unlock()
				break
			}
			if state, retiring := p.retiring[nodeID]; retiring {
				p.mutex.Unlock()
				select {
				case <-state.done:
				case <-cleanupCtx.Done():
					result = errors.Join(result, cleanupCtx.Err())
					break
				}
				continue
			}
			p.mutex.Unlock()
			// Retire uses the bounded cleanup context so a role cancellation does
			// not skip cleanup, while an explicit shutdown deadline is honored.
			retireResult := make(chan error, 1)
			go func() { retireResult <- p.Retire(cleanupCtx, nodeID) }()
			select {
			case err := <-retireResult:
				if err != nil {
					result = errors.Join(result, err)
				}
			case <-cleanupCtx.Done():
				result = errors.Join(result, cleanupCtx.Err())
			}
			break
		}
	}
	// A child may have exited just before the snapshot and be in the final
	// credential-release callback. Do not report shutdown complete while that
	// callback can still affect identity availability.
	for {
		p.mutex.Lock()
		waiters := make([]chan struct{}, 0, len(p.releasing))
		for _, done := range p.releasing {
			waiters = append(waiters, done)
		}
		p.mutex.Unlock()
		if len(waiters) == 0 {
			break
		}
		for _, done := range waiters {
			select {
			case <-done:
			case <-cleanupCtx.Done():
				result = errors.Join(result, cleanupCtx.Err())
				// A release callback is external code and may be stuck. Do not
				// spin forever after the bounded shutdown deadline; the identity
				// remains reserved while its callback is still registered.
				return result
			}
		}
	}
	return result
}

// Retire terminates one node host agent this provisioner spawned: SIGTERM,
// then a bounded wait, through the spawner. A node that was never
// provisioned here, or whose retirement already completed, has no recorded
// pid, and the refusal is fail-closed: this provisioner never signals a
// process it cannot prove is its own child.
func (p *LocalProcessNodeProvisioner) Retire(ctx context.Context, nodeId string) error {
	if ctx == nil {
		return &errs.Argument{Param: "ctx", Message: "The provisioner context must not be nil."}
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
	if state, busy := p.retiring[validated]; busy {
		p.mutex.Unlock()
		select {
		case <-state.done:
			return state.err
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	state := &retirementState{done: make(chan struct{})}
	p.retiring[validated] = state
	p.mutex.Unlock()
	err = p.spawner.Terminate(ctx, pid)
	p.mutex.Lock()
	// An exit observer may have completed this state while Terminate was
	// waiting. In that case it already removed the child and released its
	// identity; only publish the spawner's diagnostic if the state remains ours.
	if current, stillRetiring := p.retiring[validated]; !stillRetiring || current != state {
		result := state.err
		p.mutex.Unlock()
		// The observer removes a child only after it has established the
		// leader's exit and completed group cleanup, so its result supersedes
		// any late diagnostic returned by a concurrent Terminate call.
		return result
	}
	var release func(string)
	if err != nil {
		var escalated *processTerminationEscalatedError
		var exited *processAlreadyExitedError
		if errors.As(err, &exited) {
			delete(p.children, validated)
			release = p.finishIdentity(validated)
			err = nil
		}
		if errors.As(err, &escalated) {
			delete(p.children, validated)
			release = p.finishIdentity(validated)
			// Preserve the escalation diagnostic for the caller while treating the
			// process as gone for future retirement attempts.
		}
		if !errors.As(err, &exited) && !errors.As(err, &escalated) {
			state.err = err
		}
	}
	if err == nil {
		delete(p.children, validated)
		release = p.finishIdentity(validated)
	}
	state.err = err
	delete(p.retiring, validated)
	close(state.done)
	p.mutex.Unlock()
	if release != nil {
		release(validated)
	}
	return err
}

func (p *LocalProcessNodeProvisioner) rollbackIdentity(nodeID string) {
	arguments, pending := p.pendingRollbacks[nodeID]
	if !pending {
		return
	}
	delete(p.pendingRollbacks, nodeID)
	if p.config.AgentArgumentsForNodeRollback != nil {
		p.config.AgentArgumentsForNodeRollback(nodeID, arguments)
	}
}

func (p *LocalProcessNodeProvisioner) finishIdentity(nodeID string) func(string) {
	if _, done := p.released[nodeID]; done {
		return nil
	}
	p.released[nodeID] = struct{}{}
	if _, pending := p.pendingRollbacks[nodeID]; pending {
		p.rollbackIdentity(nodeID)
		return nil
	}
	if p.config.AgentArgumentsForNodeRelease == nil {
		return nil
	}
	done := make(chan struct{})
	p.releasing[nodeID] = done
	return func(id string) {
		p.config.AgentArgumentsForNodeRelease(id)
		p.mutex.Lock()
		if current, releasing := p.releasing[id]; releasing && current == done {
			delete(p.releasing, id)
			close(done)
		}
		p.mutex.Unlock()
	}
}

func (p *LocalProcessNodeProvisioner) childExited(pid int) {
	if p == nil {
		return
	}
	p.mutex.Lock()
	var nodeID string
	for node, childPID := range p.children {
		if childPID == pid {
			nodeID = node
			delete(p.children, node)
			if state, ok := p.retiring[node]; ok {
				state.err = nil
				delete(p.retiring, node)
				close(state.done)
			}
			break
		}
	}
	var release func(string)
	if nodeID != "" {
		release = p.finishIdentity(nodeID)
	}
	p.mutex.Unlock()
	if release != nil && nodeID != "" {
		release(nodeID)
	}
}

// spawnedProcess is one child of the CommandProcessSpawner. The leader is
// observed with waitid(2) before it is reaped; this keeps its numeric pid
// pinned while the process group is being cleaned up on systems without
// pidfds.
type spawnedProcess struct {
	command          *exec.Cmd
	pid              int
	exited           chan struct{}
	leaderExited     chan struct{}
	observed         chan struct{}
	pidfd            int
	stateMutex       sync.Mutex
	naturalExit      bool
	leaderExitOnce   sync.Once
	observedOnce     sync.Once
	terminateStarted bool
	terminateDone    chan struct{}
	terminateOnce    sync.Once
	terminateErr     error
}

// processTerminationEscalatedError reports that SIGTERM was ignored but the
// child was successfully killed and reaped. The child is gone, so callers
// must not retain a pid mapping merely because the operation returns an
// error for observability.
type processTerminationEscalatedError struct{ *InvalidOperationError }

// processAlreadyExitedError proves that a tracked child was reaped naturally.
// It is distinct from a foreign PID refusal, so the provisioner may release
// the child's credentials without ever signaling a reused PID.
type processAlreadyExitedError struct{ *InvalidOperationError }

// CommandProcessSpawner is the production ProcessSpawner: it spawns the
// host-agent binary via os/exec with dropped credentials, an explicit
// environment with no ambient inheritance, and pidfd-backed cancellation; it
// terminates only the children it spawned, with SIGTERM first and a bounded
// SIGKILL escalation.
type CommandProcessSpawner struct {
	terminateGrace time.Duration
	mutex          sync.Mutex
	processes      map[int]*spawnedProcess
	reaped         map[int]time.Time
	exitHandler    func(int)
	pidfdOpen      func(int) (int, error)
	waitid         func(int, *unix.Siginfo, int) error
}

// NewCommandProcessSpawner creates one spawner with an explicit termination
// grace period between SIGTERM and the SIGKILL escalation.
func NewCommandProcessSpawner(terminateGrace time.Duration) (*CommandProcessSpawner, error) {
	if terminateGrace <= 0 {
		return nil, &errs.ArgumentOutOfRangeError{
			Param:   "terminateGrace",
			Message: "The termination grace period must be positive.",
		}
	}
	return &CommandProcessSpawner{
		terminateGrace: terminateGrace,
		processes:      make(map[int]*spawnedProcess),
		reaped:         make(map[int]time.Time),
		pidfdOpen:      func(pid int) (int, error) { return unix.PidfdOpen(pid, 0) },
		waitid: func(pid int, info *unix.Siginfo, options int) error {
			return unix.Waitid(unix.P_PID, pid, info, options, nil)
		},
	}, nil
}

// SetProcessExitHandler installs the observer used by the provisioner to
// release node-scoped credentials after natural exits. It is intentionally a
// setter so the process spawner remains useful without a provisioner.
func (s *CommandProcessSpawner) SetProcessExitHandler(handler func(int)) {
	if s == nil {
		return
	}
	s.mutex.Lock()
	s.exitHandler = handler
	s.mutex.Unlock()
}

// Spawn starts one unprivileged child process described by the spec. The
// child runs under the spec's uid with a matching primary gid (the
// user-private-group layout of the rootless node accounts), in its own
// process group, with exactly the rendered environment and argv.
func (s *CommandProcessSpawner) Spawn(ctx context.Context, spec NodeProcessSpec) (int, error) {
	if ctx == nil {
		return 0, &errs.Argument{Param: "ctx", Message: "The spawner context must not be nil."}
	}
	if s == nil {
		return 0, &InvalidOperationError{Message: "The process spawner is unavailable."}
	}
	validated, err := NewNodeProcessSpec(
		spec.BinaryPath, spec.NodeId, spec.NatsUrl, spec.Args, spec.Env, spec.RunAsUid)
	if err != nil {
		return 0, err
	}
	credential, err := nodeProcessCredential(os.Geteuid(), os.Getegid(), validated.RunAsUid)
	if err != nil {
		return 0, err
	}
	command := exec.Command(validated.BinaryPath, validated.childArguments()...)
	command.Env = validated.environment()
	command.SysProcAttr = &syscall.SysProcAttr{
		Setpgid:    true,
		Credential: credential,
	}
	if err := command.Start(); err != nil {
		return 0, err
	}
	pid := command.Process.Pid
	type pidfdResult struct {
		fd  int
		err error
	}
	pidfdResults := make(chan pidfdResult)
	pidfdCanceled := make(chan struct{})
	go func() {
		fd := -1
		var openErr error
		if s.pidfdOpen != nil {
			fd, openErr = s.pidfdOpen(pid)
		}
		select {
		case pidfdResults <- pidfdResult{fd: fd, err: openErr}:
		case <-pidfdCanceled:
			if fd >= 0 {
				_ = unix.Close(fd)
			}
		}
	}()
	var fd int
	select {
	case result := <-pidfdResults:
		fd = result.fd
		if result.err != nil {
			// The process-group fallback is safe because the child remains an
			// unreaped child until the watcher has notified ownership and
			// completed group cleanup. No numeric pid can be reused in that
			// interval.
			if result.fd >= 0 {
				_ = unix.Close(result.fd)
			}
			fd = -1
		}
	case <-ctx.Done():
		close(pidfdCanceled)
		// Registration has not happened, so use the freshly established
		// process group identity and reap the leader directly. The pidfd
		// opener closes a descriptor if it completes after this cancellation.
		_ = unix.Kill(-pid, unix.SIGKILL)
		waitResult := make(chan error, 1)
		go func() { waitResult <- command.Wait() }()
		waitTimer := time.NewTimer(s.terminateGrace)
		select {
		case <-waitResult:
		case <-waitTimer.C:
			// The process remains killed and unregistered; the sole wait goroutine
			// finishes when the kernel allows it, while this startup path stays
			// bounded and no identity has been committed yet.
		}
		waitTimer.Stop()
		return 0, ctx.Err()
	}
	child := &spawnedProcess{
		command:       command,
		pid:           pid,
		exited:        make(chan struct{}),
		leaderExited:  make(chan struct{}),
		observed:      make(chan struct{}),
		pidfd:         fd,
		terminateDone: make(chan struct{}),
	}
	s.mutex.Lock()
	s.processes[pid] = child
	s.mutex.Unlock()
	go s.watchChild(child)
	go s.cancelChild(ctx, child)
	if err := ctx.Err(); err != nil {
		// The cancellation watcher may not have run yet. Keep ownership
		// registered while making the cleanup decision, then synchronously
		// wait for the watcher to reap this child before returning failure.
		cleanupErr := s.Terminate(context.Background(), pid)
		if cleanupErr != nil && !terminationConfirmed(cleanupErr) {
			return pid, errors.Join(err, cleanupErr)
		}
		return 0, err
	}
	return pid, nil
}

func (s *CommandProcessSpawner) cancelChild(ctx context.Context, child *spawnedProcess) {
	select {
	case <-ctx.Done():
		// Terminate has its own bounded grace period and group escalation.
		// It is deliberately detached from the canceled context.
		_ = s.Terminate(context.Background(), child.pid)
	case <-child.exited:
	}
}

func (s *CommandProcessSpawner) watchChild(child *spawnedProcess) {
	var waitidErrorSince time.Time
	for {
		var info unix.Siginfo
		waitidFn := s.waitid
		if waitidFn == nil {
			waitidFn = func(pid int, info *unix.Siginfo, options int) error {
				return unix.Waitid(unix.P_PID, pid, info, options, nil)
			}
		}
		err := waitidFn(child.pid, &info, unix.WEXITED|unix.WNOHANG|unix.WNOWAIT)
		if err == nil && info.Signo != 0 {
			break
		}
		if err != nil && !errors.Is(err, unix.EINTR) {
			if waitidErrorSince.IsZero() {
				waitidErrorSince = time.Now()
			}
			if time.Since(waitidErrorSince) >= processWaitidFallbackAfter {
				s.fallbackWatchChild(child)
				return
			}
			time.Sleep(5 * time.Millisecond)
			continue
		}
		waitidErrorSince = time.Time{}
		time.Sleep(5 * time.Millisecond)
	}
	s.finishObservedChild(child)
}

func (s *CommandProcessSpawner) fallbackWatchChild(child *spawnedProcess) {
	// A persistent waitid failure (for example an older or restricted Linux
	// kernel) does not prove that the child exited. Never signal a process from
	// this path: doing so would turn an observation failure into termination of
	// a healthy node. Wait is the ownership-safe fallback and the normal
	// Terminate path can still signal the tracked process when requested.
	waitResult := make(chan error, 1)
	go func() { waitResult <- child.command.Wait() }()
	// Keep the sole Wait call in this goroutine. It may block until the child
	// exits naturally or a caller explicitly terminates it, but ownership stays
	// registered for the entire interval.
	<-waitResult
	s.finishReapedChild(child)
}

func (s *CommandProcessSpawner) finishObservedChild(child *spawnedProcess) {
	child.stateMutex.Lock()
	child.naturalExit = !child.terminateStarted
	child.stateMutex.Unlock()
	child.leaderExitOnce.Do(func() { close(child.leaderExited) })
	s.cleanupGroupAfterLeaderExit(child)
	s.finishReapedChild(child)
}

func (s *CommandProcessSpawner) cleanupGroupAfterLeaderExit(child *spawnedProcess) {
	_ = signalProcessGroup(child, unix.SIGTERM)
	// Once the leader has exited, kill(-pid, 0) reports whether descendants
	// still occupy its process group. Avoid imposing the full grace period on
	// ordinary natural exits with no descendants.
	if processGroupExists(child.pid) {
		timer := time.NewTimer(s.terminateGrace)
		<-timer.C
		_ = signalProcessGroup(child, unix.SIGKILL)
	}
}

func (s *CommandProcessSpawner) finishReapedChild(child *spawnedProcess) {
	// command.Wait/reaping completes before observed is closed and before the
	// provisioner callback releases node credentials.
	if child.command.ProcessState == nil {
		// The normal wait path has not reaped yet. WNOWAIT makes this safe.
		_ = child.command.Wait()
	}
	child.stateMutex.Lock()
	terminateStarted := child.terminateStarted
	if !terminateStarted {
		child.terminateErr = &processAlreadyExitedError{InvalidOperationError: &InvalidOperationError{Message: fmt.Sprintf(
			"Process %d exited naturally and was reaped.", child.pid)}}
	}
	child.stateMutex.Unlock()
	close(child.exited)
	child.leaderExitOnce.Do(func() { close(child.leaderExited) })
	child.observedOnce.Do(func() { close(child.observed) })
	if child.pidfd >= 0 {
		_ = unix.Close(child.pidfd)
	}
	s.mutex.Lock()
	owned := false
	if current, ok := s.processes[child.pid]; ok && current == child {
		delete(s.processes, child.pid)
		s.recordReapedLocked(child.pid, time.Now())
		owned = true
	}
	handler := s.exitHandler
	s.mutex.Unlock()
	// Notify only after the group is cleaned up and Wait has reaped the leader,
	// so the provisioner cannot release credentials while descendants remain.
	if owned && handler != nil {
		handler(child.pid)
	}
	if terminateStarted {
		completeTermination(child, nil)
	}
}

func (s *CommandProcessSpawner) recordReapedLocked(pid int, at time.Time) {
	s.pruneReapedLocked(at)
	s.reaped[pid] = at
	s.pruneReapedLocked(at)
}

func (s *CommandProcessSpawner) pruneReapedLocked(now time.Time) {
	for pid, at := range s.reaped {
		if now.Sub(at) >= processReapedTombstoneTTL {
			delete(s.reaped, pid)
		}
	}
	for len(s.reaped) > processReapedTombstoneLimit {
		var oldestPID int
		var oldest time.Time
		for pid, at := range s.reaped {
			if oldest.IsZero() || at.Before(oldest) {
				oldestPID, oldest = pid, at
			}
		}
		delete(s.reaped, oldestPID)
	}
}

func signalProcessGroup(child *spawnedProcess, signal unix.Signal) error {
	if child.pidfd >= 0 {
		if err := unix.PidfdSendSignal(child.pidfd, signal, nil, 0); err != nil && !errors.Is(err, unix.ESRCH) {
			// A pidfd can become unusable independently of the child (for
			// example after a descriptor fault). The process-group identity is
			// still safe while the child is tracked and unreaped, so fall back
			// to it instead of abandoning descendant cleanup.
		}
	}
	if err := unix.Kill(-child.pid, signal); err != nil && !errors.Is(err, unix.ESRCH) {
		return err
	}
	// ESRCH means the already-observed leader's group is gone; it is a
	// successful cleanup outcome even if pidfd signalling reported an error.
	return nil
}

func processGroupExists(pid int) bool {
	err := unix.Kill(-pid, 0)
	return err == nil || errors.Is(err, unix.EPERM)
}

// nodeProcessCredential returns the credential transition a spawn needs. A
// process already running as the target non-root UID keeps its current
// credentials; asking Linux to set groups again from an unprivileged process
// fails with EPERM. Only uid 0 may switch to another account, and that switch
// keeps the production node-account convention in which uid and primary gid
// are equal.
func nodeProcessCredential(currentUid int, currentGid int, runAsUid uint32) (*syscall.Credential, error) {
	if currentUid < 0 || currentGid < 0 {
		return nil, &InvalidOperationError{Message: "The current process identity is unavailable."}
	}
	if uint32(currentUid) == runAsUid {
		if currentUid == 0 {
			return nil, &InvalidOperationError{Message: "A node host agent must never run as uid 0."}
		}
		return nil, nil
	}
	if currentUid != 0 {
		return nil, &InvalidOperationError{Message: fmt.Sprintf(
			"The unprivileged autoscaler uid %d cannot spawn node uid %d.", currentUid, runAsUid)}
	}
	return &syscall.Credential{Uid: runAsUid, Gid: runAsUid}, nil
}

// Terminate delivers SIGTERM to one spawned child and its process group,
// waits for the bounded watcher cleanup, and reports an escalation diagnostic
// when SIGKILL was required. Pids this spawner did not spawn are refused
// fail-closed, because signaling a foreign pid by number is exactly the
// failure this lane forbids.
func (s *CommandProcessSpawner) Terminate(ctx context.Context, pid int) error {
	if ctx == nil {
		return &errs.Argument{Param: "ctx", Message: "The spawner context must not be nil."}
	}
	if s == nil {
		return &InvalidOperationError{Message: "The process spawner is unavailable."}
	}
	if pid <= 0 {
		return &errs.ArgumentOutOfRangeError{
			Param:   "pid",
			Message: "A spawned pid is positive.",
		}
	}
	s.mutex.Lock()
	child, ours := s.processes[pid]
	if !ours {
		s.pruneReapedLocked(time.Now())
		if _, exited := s.reaped[pid]; exited {
			s.mutex.Unlock()
			return &processAlreadyExitedError{InvalidOperationError: &InvalidOperationError{Message: fmt.Sprintf(
				"Process %d exited naturally and was reaped.", pid)}}
		}
		s.mutex.Unlock()
		return &InvalidOperationError{
			Message: fmt.Sprintf("Process %d is not a child of this spawner.", pid),
		}
	}
	s.mutex.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	child.stateMutex.Lock()
	if child.terminateStarted {
		done := child.terminateDone
		child.stateMutex.Unlock()
		timer := time.NewTimer(s.terminateGrace)
		defer timer.Stop()
		select {
		case <-done:
			child.stateMutex.Lock()
			err := child.terminateErr
			child.stateMutex.Unlock()
			return err
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
			return &InvalidOperationError{Message: fmt.Sprintf(
				"Process %d could not be reaped within the grace period.", pid)}
		}
	}
	select {
	case <-child.leaderExited:
		// Wait for group cleanup and command.Wait before reporting the natural
		// exit to callers that may release node credentials.
		child.stateMutex.Unlock()
		reapTimer := time.NewTimer(s.terminateGrace)
		defer reapTimer.Stop()
		select {
		case <-child.exited:
		case <-ctx.Done():
			return ctx.Err()
		case <-reapTimer.C:
			return &InvalidOperationError{Message: fmt.Sprintf(
				"Process %d could not be reaped within the grace period.", pid)}
		}
		return &processAlreadyExitedError{InvalidOperationError: &InvalidOperationError{Message: fmt.Sprintf(
			"Process %d exited naturally and was reaped.", pid)}}
	default:
	}
	child.terminateStarted = true
	child.stateMutex.Unlock()
	if err := signalProcessGroup(child, unix.SIGTERM); err != nil {
		completeTermination(child, &InvalidOperationError{Message: fmt.Sprintf(
			"Process %d could not be terminated: %v.", pid, err)})
		child.stateMutex.Lock()
		result := child.terminateErr
		child.stateMutex.Unlock()
		return result
	}
	timer := time.NewTimer(s.terminateGrace)
	defer timer.Stop()
	escalated := false
	select {
	case <-child.terminateDone:
		child.stateMutex.Lock()
		err := child.terminateErr
		child.stateMutex.Unlock()
		return err
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		if err := signalProcessGroup(child, unix.SIGKILL); err != nil {
			completeTermination(child, &InvalidOperationError{Message: fmt.Sprintf(
				"Process %d could not be killed: %v.", pid, err)})
		} else if !channelClosed(child.leaderExited) {
			escalated = true
			child.stateMutex.Lock()
			child.terminateErr = &processTerminationEscalatedError{InvalidOperationError: &InvalidOperationError{Message: fmt.Sprintf(
				"Process %d ignored SIGTERM and was killed after the grace period.", pid)}}
			child.stateMutex.Unlock()
		}
	}
	reapTimer := time.NewTimer(s.terminateGrace)
	defer reapTimer.Stop()
	select {
	case <-child.terminateDone:
		child.stateMutex.Lock()
		err := child.terminateErr
		if err == nil && escalated {
			err = &processTerminationEscalatedError{InvalidOperationError: &InvalidOperationError{Message: fmt.Sprintf(
				"Process %d ignored SIGTERM and was killed after the grace period.", pid)}}
		}
		child.stateMutex.Unlock()
		return err
	case <-ctx.Done():
		return ctx.Err()
	case <-reapTimer.C:
		// The SIGKILL was delivered (or the group was already gone), but the
		// leader has not yet been reaped. Keep the child tracked and let its
		// watcher finish ownership cleanup; callers receive a bounded result and
		// may retry later.
		return &InvalidOperationError{Message: fmt.Sprintf(
			"Process %d could not be reaped within the grace period.", pid)}
	}
}

func completeTermination(child *spawnedProcess, err error) {
	child.stateMutex.Lock()
	if child.terminateErr == nil {
		child.terminateErr = err
	}
	child.stateMutex.Unlock()
	child.terminateOnce.Do(func() { close(child.terminateDone) })
}

func channelClosed(channel <-chan struct{}) bool {
	select {
	case <-channel:
		return true
	default:
		return false
	}
}
