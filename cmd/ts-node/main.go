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
	"net/url"
	"os"
	"os/signal"
	"regexp"
	stdruntime "runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/nats-io/nats.go"
	"terrascale.tech/orchestrator/src/orchestrator/control"
	"terrascale.tech/orchestrator/src/orchestrator/hostagent"
	hostruntime "terrascale.tech/orchestrator/src/orchestrator/runtime"
)

// The defaults of the ts-node flags. The podman binary default follows the
// assignment's lane convention; hosts that install podman elsewhere pass
// --podman-binary explicitly.
const (
	tsNodeDefaultPodmanBinary     = "/usr/bin/podman"
	tsNodeDefaultSystemctlBinary  = "/usr/bin/systemctl"
	tsNodeDefaultSystemdRunBinary = "/usr/bin/systemd-run"
	tsNodeDefaultSeccompProfile   = "/etc/terrascale/seccomp/terrascale-default-v1.json"
	tsNodeDefaultHeartbeatPeriod  = 10 * time.Second
	tsNodeDefaultConnectTimeout   = 5 * time.Second
	tsNodeDefaultCpuQuotaPercent  = 10000
	tsNodeDefaultTasksMax         = 512
	tsNodeDefaultNodeClass        = "greenfield"
	tsNodeHeartbeatMinimumPercent = 1
	tsNodeMaxReconnects           = 8
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
	NodeId              string
	NodeClass           string
	NatsUrl             string
	NatsNKeyFile        string
	NatsCredentialsFile string
	NatsTlsCaFile       string
	NatsTlsCertFile     string
	NatsTlsKeyFile      string
	PodmanBinaryPath    string
	XdgRuntimeDir       string
	SeccompProfilePath  string
	RunAsUid            uint32
	HeartbeatInterval   time.Duration
	ConnectTimeout      time.Duration
	CpuQuotaPercent     int
	TasksMax            int
	LogicalCpuCount     int
}

// parseTsNodeArguments validates the explicit flag vector of the node agent
// and applies the documented defaults. The real uid, effective uid, and
// default logical CPU count are injected so parsing stays deterministic and
// testable. Both process identities must name the same non-root account.
func parseTsNodeArguments(
	args []string,
	realUid uint32,
	effectiveUid uint32,
	defaultLogicalCpuCount int,
) (tsNodeConfiguration, error) {
	if err := validateTsNodeProcessIdentity(realUid, effectiveUid); err != nil {
		return tsNodeConfiguration{}, err
	}
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
		case "--node-id", "--node-class", "--nats-url", "--nats-nkey-file", "--nats-credentials-file",
			"--nats-tls-ca-file", "--nats-tls-cert-file", "--nats-tls-key-file", "--podman-binary", "--xdg-runtime-dir",
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
	parsedNatsURL, err := url.Parse(natsUrl)
	if natsUrl == "" || strings.HasPrefix(natsUrl, "-") ||
		strings.ContainsFunc(natsUrl, isTsNodeSpaceRune) || err != nil ||
		!parsedNatsURL.IsAbs() || parsedNatsURL.Scheme != "tls" || parsedNatsURL.Host == "" ||
		parsedNatsURL.User != nil || parsedNatsURL.RawQuery != "" || parsedNatsURL.Fragment != "" {
		return tsNodeConfiguration{}, errors.New(
			"ts-node: --nats-url is required and must be an absolute tls:// URL")
	}
	natsNKeyFile := flags["--nats-nkey-file"]
	natsCredentialsFile := flags["--nats-credentials-file"]
	if (strings.TrimSpace(natsNKeyFile) == "") == (strings.TrimSpace(natsCredentialsFile) == "") {
		return tsNodeConfiguration{}, errors.New(
			"ts-node: exactly one of --nats-nkey-file or --nats-credentials-file is required")
	}
	for flag, value := range map[string]string{
		"--nats-nkey-file":        natsNKeyFile,
		"--nats-credentials-file": natsCredentialsFile,
	} {
		if value != "" && (strings.HasPrefix(value, "-") || strings.ContainsFunc(value, isTsNodeSpaceRune)) {
			return tsNodeConfiguration{}, fmt.Errorf(
				"ts-node: %s must be a whitespace-free and flag-safe path", flag)
		}
	}
	tlsPaths := map[string]string{
		"--nats-tls-ca-file":   flags["--nats-tls-ca-file"],
		"--nats-tls-cert-file": flags["--nats-tls-cert-file"],
		"--nats-tls-key-file":  flags["--nats-tls-key-file"],
	}
	for flag, value := range tlsPaths {
		if value == "" || strings.HasPrefix(value, "-") || strings.ContainsFunc(value, isTsNodeSpaceRune) {
			return tsNodeConfiguration{}, fmt.Errorf(
				"ts-node: %s is required and must be a whitespace-free and flag-safe path", flag)
		}
	}
	natsNKeyFile := flags["--nats-nkey-file"]
	natsTlsCaFile := flags["--nats-tls-ca-file"]
	natsTlsCertFile := flags["--nats-tls-cert-file"]
	natsTlsKeyFile := flags["--nats-tls-key-file"]
	natsCredentialValues := []string{natsNKeyFile, natsTlsCaFile, natsTlsCertFile, natsTlsKeyFile}
	suppliedNatsCredentials := 0
	for _, value := range natsCredentialValues {
		if value != "" {
			suppliedNatsCredentials++
		}
	}
	switch {
	case strings.HasPrefix(natsUrl, "nats://"):
		if suppliedNatsCredentials != 0 {
			return tsNodeConfiguration{}, errors.New(
				"ts-node: NATS credential files require a tls:// NATS URL")
		}
	case strings.HasPrefix(natsUrl, "tls://"):
		if suppliedNatsCredentials != len(natsCredentialValues) {
			return tsNodeConfiguration{}, errors.New(
				"ts-node: tls:// NATS requires the NKey, CA, certificate, and key files")
		}
	default:
		return tsNodeConfiguration{}, errors.New(
			"ts-node: --nats-url must use nats:// for local use or tls:// for production")
	}

	runAsUid := effectiveUid
	if value, present := flags["--run-as-uid"]; present {
		parsed, err := strconv.ParseUint(value, 10, 32)
		if err != nil {
			return tsNodeConfiguration{}, errors.New(
				"ts-node: --run-as-uid must be a nonzero numeric uid")
		}
		runAsUid = uint32(parsed)
	}
	if runAsUid == 0 {
		return tsNodeConfiguration{}, errors.New("ts-node must never run as uid 0")
	}
	if runAsUid != effectiveUid {
		return tsNodeConfiguration{}, fmt.Errorf(
			"ts-node: --run-as-uid %d must equal the effective account uid %d", runAsUid, effectiveUid)
	}

	podmanBinary := tsNodeDefaultPodmanBinary
	if value, present := flags["--podman-binary"]; present {
		podmanBinary = value
	}
	systemctlBinary := tsNodeDefaultSystemctlBinary
	if value, present := flags["--systemctl-binary"]; present {
		systemctlBinary = value
	}
	systemdRunBinary := tsNodeDefaultSystemdRunBinary
	if value, present := flags["--systemd-run-binary"]; present {
		systemdRunBinary = value
	}
	xdgRuntimeDir := fmt.Sprintf("/run/user/%d", runAsUid)
	if value, present := flags["--xdg-runtime-dir"]; present {
		xdgRuntimeDir = value
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
		NodeId:              nodeId,
		NodeClass:           nodeClass,
		NatsUrl:             natsUrl,
		NatsNKeyFile:        natsNKeyFile,
		NatsCredentialsFile: natsCredentialsFile,
		NatsTlsCaFile:       tlsPaths["--nats-tls-ca-file"],
		NatsTlsCertFile:     tlsPaths["--nats-tls-cert-file"],
		NatsTlsKeyFile:      tlsPaths["--nats-tls-key-file"],
		PodmanBinaryPath:    podmanBinary,
		XdgRuntimeDir:       xdgRuntimeDir,
		SeccompProfilePath:  seccompProfile,
		RunAsUid:            runAsUid,
		HeartbeatInterval:   heartbeatInterval,
		ConnectTimeout:      connectTimeout,
		CpuQuotaPercent:     cpuQuotaPercent,
		TasksMax:            tasksMax,
		LogicalCpuCount:     logicalCpuCount,
	}, nil
}

func validateTsNodeProcessIdentity(realUid uint32, effectiveUid uint32) error {
	if realUid == 0 || effectiveUid == 0 {
		return errors.New("ts-node must never run with a real or effective uid of 0")
	}
	if realUid != effectiveUid {
		return fmt.Errorf("ts-node: real uid %d does not match effective uid %d", realUid, effectiveUid)
	}
	return nil
}

// tsNodePendingRelay forwards the heartbeat pending-allocation count to the
// agent's own workload executor once that executor exists: the agent composes
// its executor internally at construction time, so the metrics source is bound
// first and pointed at the executor immediately after the agent is built.
type tsNodePendingRelay struct {
	mutex   sync.Mutex
	counter hostagent.PendingAllocationCounter
}

// tsNodeAuthenticatedNatsConnection defers the first authenticated dial until
// HostAgent.Start invokes the transport. This keeps composition side-effect
// free while ensuring the host agent cannot take its unauthenticated URL path.
// The connection is owned here because HostAgent receives it as a wired
// transport; Drain therefore closes the authenticated client as well.
type tsNodeAuthenticatedNatsConnection struct {
	mutex         sync.Mutex
	configuration control.NatsConnectionConfiguration
	connection    hostagent.NatsConnection
	closed        bool
}

func (c *tsNodeAuthenticatedNatsConnection) live() (hostagent.NatsConnection, error) {
	if c == nil {
		return nil, errors.New("ts-node: authenticated NATS connection is unavailable")
	}
	c.mutex.Lock()
	defer c.mutex.Unlock()
	if c.closed {
		return nil, errors.New("ts-node: authenticated NATS connection is closed")
	}
	if c.connection != nil {
		return c.connection, nil
	}
	client, err := control.NatsConnect(context.Background(), c.configuration)
	if err != nil {
		// Do not surface any NATS option or credential material in process
		// errors. The configured file validators already provide diagnostics
		// without reading secret bytes into an error.
		return nil, errors.New("ts-node: authenticated NATS connection failed")
	}
	connection, err := hostagent.NewLiveNatsConnection(client)
	if err != nil {
		client.Close()
		return nil, errors.New("ts-node: authenticated NATS connection failed")
	}
	c.connection = connection
	return connection, nil
}

func (c *tsNodeAuthenticatedNatsConnection) Subscribe(subject string, handler func(*nats.Msg)) (*nats.Subscription, error) {
	connection, err := c.live()
	if err != nil {
		return nil, err
	}
	return connection.Subscribe(subject, handler)
}

func (c *tsNodeAuthenticatedNatsConnection) Publish(subject string, payload []byte) error {
	connection, err := c.live()
	if err != nil {
		return err
	}
	return connection.Publish(subject, payload)
}

func (c *tsNodeAuthenticatedNatsConnection) Request(subject string, payload []byte, timeout time.Duration) (*nats.Msg, error) {
	connection, err := c.live()
	if err != nil {
		return nil, err
	}
	return connection.Request(subject, payload, timeout)
}

func (c *tsNodeAuthenticatedNatsConnection) Flush() error {
	connection, err := c.live()
	if err != nil {
		return err
	}
	return connection.Flush()
}

func (c *tsNodeAuthenticatedNatsConnection) Drain() error {
	if c == nil {
		return nil
	}
	c.mutex.Lock()
	if c.closed {
		c.mutex.Unlock()
		return nil
	}
	c.closed = true
	connection := c.connection
	c.connection = nil
	c.mutex.Unlock()
	if connection == nil {
		return nil
	}
	err := connection.Drain()
	connection.Close()
	return err
}

func (c *tsNodeAuthenticatedNatsConnection) Close() {
	if c == nil {
		return
	}
	c.mutex.Lock()
	if c.closed {
		c.mutex.Unlock()
		return
	}
	c.closed = true
	connection := c.connection
	c.connection = nil
	c.mutex.Unlock()
	if connection != nil {
		connection.Close()
	}
}

// tsNodeNatsConnectionConfiguration resolves the explicit node identity and
// mTLS files through the shared control validators. No credential bytes are
// retained in the returned configuration.
func tsNodeNatsConnectionConfiguration(configuration tsNodeConfiguration) (control.NatsConnectionConfiguration, error) {
	parsed, err := url.Parse(configuration.NatsUrl)
	if err != nil || !parsed.IsAbs() || parsed.Scheme != "tls" || parsed.Host == "" ||
		parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return control.NatsConnectionConfiguration{}, errors.New(
			"ts-node: --nats-url must be an absolute tls:// URL")
	}
	authentication, err := control.NatsAuthenticationFilesResolve(
		configuration.NatsNKeyFile, configuration.NatsCredentialsFile, "TS_NODE_NATS")
	if err != nil {
		return control.NatsConnectionConfiguration{}, errors.New("ts-node: NATS authentication files are invalid")
	}
	if authentication == nil {
		return control.NatsConnectionConfiguration{}, errors.New(
			"ts-node: exactly one NATS NKey or credentials file is required")
	}
	tlsFiles, err := control.NatsTlsFilesResolve(
		configuration.NatsTlsCaFile, configuration.NatsTlsCertFile, configuration.NatsTlsKeyFile,
		"TS_NODE_NATS_TLS")
	if err != nil {
		return control.NatsConnectionConfiguration{}, errors.New("ts-node: NATS mTLS files are invalid")
	}
	if tlsFiles == nil {
		return control.NatsConnectionConfiguration{}, errors.New(
			"ts-node: complete NATS mTLS files are required")
	}
	return control.NatsConnectionConfiguration{
		URL:            parsed.String(),
		Authentication: authentication,
		TLS:            tlsFiles,
		Timeout:        configuration.ConnectTimeout,
		MaxReconnects:  tsNodeMaxReconnects,
	}, nil
}

// bind attaches the executor the relay reports pending allocations for.
func (r *tsNodePendingRelay) bind(counter hostagent.PendingAllocationCounter) {
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

// newTsNodePodmanClient composes the supervised rootless Podman client from
// one validated node configuration. Startup calls Preflight on this exact
// composition before the host agent can accept workload requests.
func newTsNodePodmanClient(configuration tsNodeConfiguration) (*hostruntime.SystemdUserPodmanClient, error) {
	rootless, err := hostruntime.NewRootlessPodmanContext(
		configuration.PodmanBinaryPath, configuration.XdgRuntimeDir,
		configuration.SeccompProfilePath, configuration.RunAsUid)
	if err != nil {
		return nil, fmt.Errorf("ts-node: the rootless podman context is invalid: %s", err.Error())
	}
	// The runtime directory is part of the rootless identity boundary. An
	// explicit path must match the UID running this process; otherwise a node
	// could point at another user's Podman socket and containers.
	expectedRuntimeDir := fmt.Sprintf("/run/user/%d", configuration.RunAsUid)
	if configuration.XdgRuntimeDir != expectedRuntimeDir {
		return nil, errors.New("ts-node: XDG runtime directory must match the run uid")
	}
	natsConfiguration, err := tsNodeNatsConnectionConfiguration(configuration)
	if err != nil {
		return nil, err
	}
	podmanClient, err := hostruntime.NewProcessPodmanClient(rootless, hostruntime.ProcessHostCommandRunner{})
	if err != nil {
		return nil, fmt.Errorf("ts-node: the podman client is unavailable: %s", err.Error())
	}
	supervisedPodmanClient, err := hostruntime.NewSystemdUserPodmanClient(
		podmanClient,
		rootless,
		configuration.SystemctlBinaryPath,
		configuration.SystemdRunBinaryPath,
		commandRunner,
	)
	if err != nil {
		return nil, fmt.Errorf("ts-node: the podman supervisor is unavailable: %s", err.Error())
	}
	return supervisedPodmanClient, nil
}

func preflightTsNode(ctx context.Context, configuration tsNodeConfiguration) error {
	client, err := newTsNodePodmanClient(configuration)
	if err != nil {
		return err
	}
	if err := client.Preflight(ctx); err != nil {
		return fmt.Errorf("ts-node: startup rootless podman preflight failed: %s", err.Error())
	}
	return nil
}

// composeTsNodeAgent composes the node agent from one validated
// configuration: the rootless podman context is revalidated through
// NewRootlessPodmanContext (fail-closed on uid 0 and relative paths), the
// process podman client drives the rootless podman adapter, the systemd
// adapter runs in user-manager mode so native plans become user units, and
// the system metrics source feeds the heartbeat from /proc. The stateful
// volume mounts of the podman adapter are empty in this slice: the per-role
// volume bindings of the stateful catalog are not carried on the wire plan
// yet.
func composeTsNodeAgent(configuration tsNodeConfiguration) (*hostagent.HostAgent, error) {
	var natsOptions []nats.Option
	if strings.HasPrefix(configuration.NatsUrl, "tls://") {
		authentication, err := control.NatsAuthenticationFilesFromNKeyFile(configuration.NatsNKeyFile)
		if err != nil {
			return nil, fmt.Errorf("ts-node: NATS authentication is invalid: %s", err.Error())
		}
		tlsFiles, err := control.NatsTlsFilesResolve(
			configuration.NatsTlsCaFile,
			configuration.NatsTlsCertFile,
			configuration.NatsTlsKeyFile,
			"ts-node NATS",
		)
		if err != nil || tlsFiles == nil {
			if err == nil {
				err = errors.New("the TLS identity is missing")
			}
			return nil, fmt.Errorf("ts-node: NATS TLS is invalid: %s", err.Error())
		}
		natsOptions = append(natsOptions, authentication.Options()...)
		natsOptions = append(natsOptions, tlsFiles.Options()...)
	}
	supervisedPodmanClient, err := newTsNodePodmanClient(configuration)
	if err != nil {
		return nil, err
	}
	commandRunner := hostruntime.ProcessHostCommandRunner{}
	containerAdapter, err := hostruntime.NewPodmanRootlessHostRuntimeAdapter(supervisedPodmanClient, nil)
	if err != nil {
		return nil, fmt.Errorf("ts-node: the rootless podman adapter is unavailable: %s", err.Error())
	}
	systemdAdapter := hostruntime.NewSystemdHostRuntimeAdapter(commandRunner, true)
	pending := &tsNodePendingRelay{}
	metrics, err := hostagent.NewSystemMetricsSource(hostagent.SystemMetricsSourceConfig{
		ProcReader:      hostagent.OsProcFileReader{},
		CpuQuotaPercent: configuration.CpuQuotaPercent,
		TasksMax:        configuration.TasksMax,
		LogicalCpuCount: configuration.LogicalCpuCount,
		Pending:         pending,
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
		Connection:        &tsNodeAuthenticatedNatsConnection{configuration: natsConfiguration},
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

	configuration, err := parseTsNodeArguments(
		os.Args[1:], uint32(os.Getuid()), uint32(os.Geteuid()), stdruntime.NumCPU())
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	preflightContext, cancelPreflight := context.WithTimeout(ctx, configuration.ConnectTimeout)
	err = preflightTsNode(preflightContext, configuration)
	cancelPreflight()
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
