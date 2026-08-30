// Command ts-node is the per-node host agent binary of the rootless-hosting
// and autoscaling lane. It owns one NodeId, validates its rootless execution
// context at startup, hosts workloads as rootless systemd user units and as
// rootless podman containers through the workload executor, answers the
// terrascale.node.v1.* request-reply subjects over the regional NATS, and
// publishes periodic heartbeats until it receives SIGINT or SIGTERM.
//
// Every input is an explicit command-line flag; no ambient environment
// variable is read. The default of --run-as-uid and --xdg-runtime-dir derive
// from the current account, mirroring the derivation the node provisioner
// applies when it spawns this binary.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	stdruntime "runtime"

	"terrascale.tech/orchestrator/src/orchestrator/hostagent"
	hostruntime "terrascale.tech/orchestrator/src/orchestrator/runtime"
)

// The defaults of the ts-node flags. The podman binary default follows the
// assignment's lane convention; hosts that install podman elsewhere pass
// --podman-binary explicitly.
const (
	tsNodeDefaultPodmanBinary     = "/usr/bin/podman"
	tsNodeDefaultSeccompProfile   = "/etc/terrascale/seccomp/terrascale-default-v1.json"
	tsNodeDefaultHeartbeatPeriod  = 10 * time.Second
	tsNodeDefaultConnectTimeout   = 5 * time.Second
	tsNodeDefaultCpuQuotaPercent  = 10000
	tsNodeDefaultTasksMax         = 512
	tsNodeDefaultNodeClass        = "greenfield"
	tsNodeHeartbeatMinimumPercent = 1
)

// tsNodeTokenPattern is the bounded canonical node and class token vocabulary
// shared with the host agent contracts.
var tsNodeTokenPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$`)

// isTsNodeSpaceRune reports whether one rune would smuggle whitespace or
// control bytes into a flag value that must stay whitespace-free.
func isTsNodeSpaceRune(r rune) bool { return r <= ' ' || r == 0x7f }

// tsNodeConfiguration is the fully explicit runtime configuration of one node
// host agent after flag parsing.
type tsNodeConfiguration struct {
	NodeId             string
	NodeClass          string
	NatsUrl            string
	PodmanBinaryPath   string
	XdgRuntimeDir      string
	SeccompProfilePath string
	RunAsUid           uint32
	HeartbeatInterval  time.Duration
	ConnectTimeout     time.Duration
	CpuQuotaPercent    int
	TasksMax           int
	LogicalCpuCount    int
}

// parseTsNodeArguments validates the explicit flag vector of the node agent
// and applies the documented defaults. The current uid and the default logical
// CPU count are injected so parsing stays deterministic and testable; the
// run uid must equal the current uid, because the rootless podman context
// must describe the account this process actually runs as.
func parseTsNodeArguments(
	args []string,
	currentUid uint32,
	defaultLogicalCpuCount int,
) (tsNodeConfiguration, error) {
	flags := map[string]string{}
	for index := 0; index < len(args); index++ {
		name := args[index]
		if !strings.HasPrefix(name, "--") || strings.ContainsFunc(name, isTsNodeSpaceRune) {
			return tsNodeConfiguration{}, errors.New(
				"ts-node: every argument must be a --flag value pair")
		}
		if index+1 >= len(args) {
			return tsNodeConfiguration{}, fmt.Errorf(
				"ts-node: the flag %s requires a value", name)
		}
		if _, duplicate := flags[name]; duplicate {
			return tsNodeConfiguration{}, fmt.Errorf(
				"ts-node: the flag %s was given twice", name)
		}
		flags[name] = args[index+1]
		index++
	}
	for name := range flags {
		switch name {
		case "--node-id", "--node-class", "--nats-url", "--podman-binary", "--xdg-runtime-dir",
			"--seccomp-profile", "--run-as-uid", "--heartbeat-interval", "--connect-timeout",
			"--cpu-quota-percent", "--tasks-max", "--logical-cpu-count":
		default:
			return tsNodeConfiguration{}, fmt.Errorf(
				"ts-node: the flag %s is not supported", name)
		}
	}

	nodeId := flags["--node-id"]
	if nodeId == "" {
		return tsNodeConfiguration{}, errors.New(
			"ts-node: --node-id is required and must be a lowercase DNS-style token")
	}
	if !tsNodeTokenPattern.MatchString(nodeId) || len(nodeId) > 63 {
		return tsNodeConfiguration{}, errors.New(
			"ts-node: --node-id is required and must be a lowercase DNS-style token")
	}
	nodeClass := tsNodeDefaultNodeClass
	if value, present := flags["--node-class"]; present {
		nodeClass = value
	}
	if !tsNodeTokenPattern.MatchString(nodeClass) || len(nodeClass) > 63 {
		return tsNodeConfiguration{}, errors.New(
			"ts-node: --node-class must be a lowercase DNS-style token")
	}
	natsUrl := flags["--nats-url"]
	if natsUrl == "" || strings.HasPrefix(natsUrl, "-") ||
		strings.ContainsFunc(natsUrl, isTsNodeSpaceRune) {
		return tsNodeConfiguration{}, errors.New(
			"ts-node: --nats-url is required and must be whitespace-free and flag-safe")
	}

	runAsUid := currentUid
	if value, present := flags["--run-as-uid"]; present {
		parsed, err := strconv.ParseUint(value, 10, 32)
		if err != nil {
			return tsNodeConfiguration{}, errors.New(
				"ts-node: --run-as-uid must be a nonzero numeric uid")
		}
		runAsUid = uint32(parsed)
	}
	if runAsUid == 0 {
		return tsNodeConfiguration{}, errors.New(
			"ts-node must never run as uid 0: rootless hosting is the point of this node agent")
	}
	if runAsUid != currentUid {
		return tsNodeConfiguration{}, fmt.Errorf(
			"ts-node: --run-as-uid %d must equal the current account uid %d", runAsUid, currentUid)
	}

	podmanBinary := tsNodeDefaultPodmanBinary
	if value, present := flags["--podman-binary"]; present {
		podmanBinary = value
	}
	xdgRuntimeDir := fmt.Sprintf("/run/user/%d", runAsUid)
	if value, present := flags["--xdg-runtime-dir"]; present {
		xdgRuntimeDir = value
	}
	seccompProfile := tsNodeDefaultSeccompProfile
	if value, present := flags["--seccomp-profile"]; present {
		seccompProfile = value
	}
	if len(seccompProfile) > 4096 || !strings.HasPrefix(seccompProfile, "/") ||
		strings.Contains(seccompProfile, "/../") {
		return tsNodeConfiguration{}, errors.New(
			"ts-node: --seccomp-profile must be a bounded absolute path")
	}

	heartbeatInterval := tsNodeDefaultHeartbeatPeriod
	if value, present := flags["--heartbeat-interval"]; present {
		parsed, err := time.ParseDuration(value)
		if err != nil || parsed <= 0 {
			return tsNodeConfiguration{}, errors.New(
				"ts-node: --heartbeat-interval must be a positive duration")
		}
		heartbeatInterval = parsed
	}
	connectTimeout := tsNodeDefaultConnectTimeout
	if value, present := flags["--connect-timeout"]; present {
		parsed, err := time.ParseDuration(value)
		if err != nil || parsed <= 0 {
			return tsNodeConfiguration{}, errors.New(
				"ts-node: --connect-timeout must be a positive duration")
		}
		connectTimeout = parsed
	}
	cpuQuotaPercent := tsNodeDefaultCpuQuotaPercent
	if value, present := flags["--cpu-quota-percent"]; present {
		parsed, err := strconv.Atoi(value)
		if err != nil || parsed < tsNodeHeartbeatMinimumPercent || parsed > tsNodeDefaultCpuQuotaPercent {
			return tsNodeConfiguration{}, fmt.Errorf(
				"ts-node: --cpu-quota-percent must be between %d and %d",
				tsNodeHeartbeatMinimumPercent, tsNodeDefaultCpuQuotaPercent)
		}
		cpuQuotaPercent = parsed
	}
	tasksMax := tsNodeDefaultTasksMax
	if value, present := flags["--tasks-max"]; present {
		parsed, err := strconv.Atoi(value)
		if err != nil || parsed < 0 {
			return tsNodeConfiguration{}, errors.New(
				"ts-node: --tasks-max must be a non-negative integer")
		}
		tasksMax = parsed
	}
	logicalCpuCount := defaultLogicalCpuCount
	if value, present := flags["--logical-cpu-count"]; present {
		parsed, err := strconv.Atoi(value)
		if err != nil || parsed < 1 {
			return tsNodeConfiguration{}, errors.New(
				"ts-node: --logical-cpu-count must be a positive integer")
		}
		logicalCpuCount = parsed
	}

	return tsNodeConfiguration{
		NodeId:             nodeId,
		NodeClass:          nodeClass,
		NatsUrl:            natsUrl,
		PodmanBinaryPath:   podmanBinary,
		XdgRuntimeDir:      xdgRuntimeDir,
		SeccompProfilePath: seccompProfile,
		RunAsUid:           runAsUid,
		HeartbeatInterval:  heartbeatInterval,
		ConnectTimeout:     connectTimeout,
		CpuQuotaPercent:    cpuQuotaPercent,
		TasksMax:           tasksMax,
		LogicalCpuCount:    logicalCpuCount,
	}, nil
}

// tsNodePendingRelay forwards the heartbeat pending-allocation count to the
// agent's own workload executor once that executor exists: the agent composes
// its executor internally at construction time, so the metrics source is bound
// first and pointed at the executor immediately after the agent is built.
type tsNodePendingRelay struct {
	mutex   sync.Mutex
	counter interface {
		hostagent.PendingAllocationCounter
		hostagent.RunningAllocationCounter
	}
}

// bind attaches the executor the relay reports pending allocations for.
func (r *tsNodePendingRelay) bind(counter interface {
	hostagent.PendingAllocationCounter
	hostagent.RunningAllocationCounter
}) {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	r.counter = counter
}

// PendingAllocations reports the executor's pending count, or zero before the
// executor is bound.
func (r *tsNodePendingRelay) PendingAllocations() int {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	if r.counter == nil {
		return 0
	}
	return r.counter.PendingAllocations()
}

// RunningAllocations reports the executor's running allocation count through
// the same late-bound relay used for pending allocations.
func (r *tsNodePendingRelay) RunningAllocations() int {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	if r.counter == nil {
		return 0
	}
	return r.counter.RunningAllocations()
}

// composeTsNodeAgent composes the node agent from one validated
// configuration: the rootless podman context is revalidated through
// NewRootlessPodmanContext (fail-closed on uid 0, relative paths, and a
// missing seccomp profile path), the process podman client drives the
// rootless podman adapter and loads the seccomp document named by the
// context, the systemd adapter runs in user-manager mode so native plans
// become user units, and the system metrics source feeds the heartbeat from
// /proc with the running-task gauge relayed from the executor. The stateful
// volume mounts of the podman adapter are empty in this slice: the per-role
// volume bindings of the stateful catalog are not carried on the wire plan
// yet.
func composeTsNodeAgent(configuration tsNodeConfiguration) (*hostagent.HostAgent, error) {
	rootless, err := hostruntime.NewRootlessPodmanContext(
		configuration.PodmanBinaryPath, configuration.XdgRuntimeDir,
		configuration.SeccompProfilePath, configuration.RunAsUid)
	if err != nil {
		return nil, fmt.Errorf("ts-node: the rootless podman context is invalid: %s", err.Error())
	}
	// The runtime directory is part of the rootless identity boundary.  An
	// explicit path must still belong to the UID running this process; merely
	// requiring an absolute path would allow a node agent to use another
	// user's Podman socket and containers.
	expectedRuntimeDir := fmt.Sprintf("/run/user/%d", configuration.RunAsUid)
	if configuration.XdgRuntimeDir != expectedRuntimeDir {
		return nil, errors.New("ts-node: XDG runtime directory must match the run uid")
	}
	podmanClient, err := hostruntime.NewProcessPodmanClient(rootless, hostruntime.ProcessHostCommandRunner{})
	if err != nil {
		return nil, fmt.Errorf("ts-node: the podman client is unavailable: %s", err.Error())
	}
	containerAdapter, err := hostruntime.NewPodmanRootlessHostRuntimeAdapter(podmanClient, nil)
	if err != nil {
		return nil, fmt.Errorf("ts-node: the rootless podman adapter is unavailable: %s", err.Error())
	}
	systemdAdapter := hostruntime.NewSystemdHostRuntimeAdapter(hostruntime.ProcessHostCommandRunner{}, true)
	pending := &tsNodePendingRelay{}
	metrics, err := hostagent.NewSystemMetricsSource(hostagent.SystemMetricsSourceConfig{
		ProcReader:      hostagent.OsProcFileReader{},
		CpuQuotaPercent: configuration.CpuQuotaPercent,
		TasksMax:        configuration.TasksMax,
		LogicalCpuCount: configuration.LogicalCpuCount,
		Pending:         pending,
		Running:         pending,
	})
	if err != nil {
		return nil, fmt.Errorf("ts-node: the metrics source is unavailable: %s", err.Error())
	}
	nodeId, err := hostagent.NewNodeId(configuration.NodeId)
	if err != nil {
		return nil, fmt.Errorf("ts-node: --node-id is invalid: %s", err.Error())
	}
	agent, err := hostagent.NewHostAgent(hostagent.HostAgentConfig{
		NodeId:            nodeId,
		NatsURL:           configuration.NatsUrl,
		ConnectTimeout:    configuration.ConnectTimeout,
		Systemd:           systemdAdapter,
		Container:         containerAdapter,
		Metrics:           metrics,
		HeartbeatInterval: configuration.HeartbeatInterval,
		Now:               time.Now,
	})
	if err != nil {
		return nil, fmt.Errorf("ts-node: the host agent is unavailable: %s", err.Error())
	}
	pending.bind(agent.Executor())
	return agent, nil
}

// runTsNode starts the composed agent and blocks until the start context is
// cancelled or the agent completes on its own, then drains it. The agent
// closes itself on context cancellation, so the final Close is an idempotent
// confirmation.
func runTsNode(ctx context.Context, agent *hostagent.HostAgent) error {
	if err := agent.Start(ctx); err != nil {
		return err
	}
	select {
	case <-ctx.Done():
		// HostAgent closes itself from the start-context watcher, but wait for
		// that graceful drain here before returning to the process entrypoint.
		// Returning immediately could terminate the process while subscriptions
		// are still serving commands.
		_ = agent.Close()
		return ctx.Err()
	case <-agent.Completion():
	}
	return agent.Close()
}

// exitCode mirrors the orchestrator host: SIGINT-driven cancellation exits
// 130, a deadline exits 124, and every other failure exits 1.
func exitCode(err error) int {
	if err == nil {
		return 0
	}
	if errors.Is(err, context.Canceled) {
		return 130
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return 124
	}
	return 1
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	configuration, err := parseTsNodeArguments(os.Args[1:], uint32(os.Getuid()), stdruntime.NumCPU())
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	agent, err := composeTsNodeAgent(configuration)
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if err := runTsNode(ctx, agent); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(exitCode(err))
	}
}
