//go:build sandboxvm

package vmqualruntime

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"debug/elf"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"terrascale.tech/orchestrator/src/orchestrator/sandboxvm"
	"terrascale.tech/orchestrator/src/orchestrator/vmguest"
	"terrascale.tech/orchestrator/src/orchestrator/vmimage"
	"terrascale.tech/orchestrator/src/orchestrator/vmnet"
	"terrascale.tech/orchestrator/src/orchestrator/vmqual"
)

var (
	ErrGuestHostKeyChanged = errors.New("vmqual: guest SSH host key changed")
	artifactVersionToken   = regexp.MustCompile(`^[a-z0-9]+(?:[.-][a-z0-9]+)*$`)
	transportRegistry      = struct {
		sync.RWMutex
		byStateRoot map[string]*guestTransport
	}{byStateRoot: make(map[string]*guestTransport)}
)

func newSandboxVMProvider(config vmqual.Config) (*sandboxvm.Provider, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	manifestBytes, err := os.ReadFile(config.ImageManifestPath)
	if err != nil {
		return nil, err
	}
	if _, err := vmimage.DecodeManifest(manifestBytes); err != nil {
		return nil, err
	}
	transport, err := newGuestTransport(config.Root)
	if err != nil {
		return nil, err
	}
	transportRegistry.Lock()
	if transportRegistry.byStateRoot[filepath.Clean(config.StateRoot)] != nil {
		transportRegistry.Unlock()
		return nil, errors.New("vmqual: guest transport is already registered for state root")
	}
	transportRegistry.byStateRoot[filepath.Clean(config.StateRoot)] = transport
	transportRegistry.Unlock()
	probe := &sshGuestProbe{transport: transport, seedDigests: make(map[string]string), configs: make(map[string]sandboxvm.Config)}
	dataFault, err := newDeviceMapperIOFaultAdapter()
	if err != nil {
		_ = releaseGuestTransport(config.StateRoot)
		return nil, err
	}
	return sandboxvm.New(sandboxvm.Options{
		MachineFactory: sandboxvm.NewSDKMachineFactory(),
		OpenAPIFactory: func(vmConfig sandboxvm.Config) (sandboxvm.OpenAPI, error) {
			return sandboxvm.NewUnixSocketOpenAPI(vmConfig.SocketPath)
		},
		Probe:          probe,
		DataDriveFault: dataFault,
	})
}

type guestArtifactInput struct {
	manifest  vmimage.GuestArtifact
	signature []byte
	binary    []byte
}

type guestCredential struct {
	mu        sync.Mutex
	id        string
	address   string
	namespace string
	service   bool
	private   ed25519.PrivateKey
	signer    ssh.Signer
	publicKey string
	hostKey   []byte
	deleted   bool
}

// guestTransport holds private qualification credentials only in process
// memory. Each entry belongs to exactly one VM and is erased on VM deletion.
type guestTransport struct {
	mu          sync.RWMutex
	credentials map[string]*guestCredential
}

func newGuestTransport(root string) (*guestTransport, error) {
	if root == "" || !filepath.IsAbs(root) {
		return nil, errors.New("vmqual: guest transport root must be absolute")
	}
	return &guestTransport{credentials: make(map[string]*guestCredential)}, nil
}

func guestTransportFor(stateRoot string) *guestTransport {
	transportRegistry.RLock()
	transport := transportRegistry.byStateRoot[filepath.Clean(stateRoot)]
	transportRegistry.RUnlock()
	return transport
}

func releaseGuestTransport(stateRoot string) error {
	key := filepath.Clean(stateRoot)
	transportRegistry.Lock()
	transport := transportRegistry.byStateRoot[key]
	delete(transportRegistry.byStateRoot, key)
	transportRegistry.Unlock()
	if transport == nil {
		return nil
	}
	transport.mu.Lock()
	credentials := transport.credentials
	transport.credentials = make(map[string]*guestCredential)
	transport.mu.Unlock()
	for _, credential := range credentials {
		credential.mu.Lock()
		zeroBytes(credential.private)
		zeroBytes(credential.hostKey)
		credential.private, credential.signer, credential.publicKey = nil, nil, ""
		credential.deleted = true
		credential.mu.Unlock()
	}
	if len(credentials) != 0 {
		return fmt.Errorf("vmqual: guest transport retained %d credentials after cleanup", len(credentials))
	}
	return nil
}

func (transport *guestTransport) addGuest(id, address, namespace string, service bool) (string, error) {
	if transport == nil || id == "" || address == "" || !vmqual.CanonicalAbsolute(namespace) {
		return "", errors.New("vmqual: guest credential identity is incomplete")
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}
	signer, err := ssh.NewSignerFromKey(private)
	if err != nil {
		zeroBytes(private)
		return "", err
	}
	publicSSH, err := ssh.NewPublicKey(public)
	if err != nil {
		zeroBytes(private)
		return "", err
	}
	credential := &guestCredential{id: id, address: address, namespace: namespace, service: service, private: private, signer: signer, publicKey: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(publicSSH)))}
	transport.mu.Lock()
	defer transport.mu.Unlock()
	if _, exists := transport.credentials[id]; exists {
		zeroBytes(private)
		return "", fmt.Errorf("vmqual: guest credential already exists for %s", id)
	}
	transport.credentials[id] = credential
	return credential.publicKey, nil
}

func (transport *guestTransport) credential(id string) (*guestCredential, error) {
	if transport == nil {
		return nil, errors.New("vmqual: guest transport is not configured")
	}
	transport.mu.RLock()
	credential := transport.credentials[id]
	transport.mu.RUnlock()
	if credential == nil {
		return nil, fmt.Errorf("vmqual: guest credential is not registered for %s", id)
	}
	return credential, nil
}

func (transport *guestTransport) removeGuest(id string) {
	if transport == nil {
		return
	}
	transport.mu.Lock()
	credential := transport.credentials[id]
	delete(transport.credentials, id)
	transport.mu.Unlock()
	if credential == nil {
		return
	}
	credential.mu.Lock()
	zeroBytes(credential.private)
	zeroBytes(credential.hostKey)
	credential.private, credential.signer, credential.publicKey = nil, nil, ""
	credential.deleted = true
	credential.mu.Unlock()
}

func zeroBytes(data []byte) {
	for index := range data {
		data[index] = 0
	}
}

type guestProbeTransport interface {
	credential(string) (*guestCredential, error)
	request(context.Context, string, string, vmguest.Request) (vmguest.Response, error)
}

type sshGuestProbe struct {
	mu          sync.RWMutex
	transport   guestProbeTransport
	seedDigests map[string]string
	configs     map[string]sandboxvm.Config
}

// request runs one forced-command SSH exchange. The first observed host key
// is bound to the exact VM identity and address, and every later connection
// must present the same key.
func (transport *guestTransport) request(ctx context.Context, id, address string, request vmguest.Request) (vmguest.Response, error) {
	if ctx == nil {
		return vmguest.Response{}, errors.New("vmqual: guest request context is nil")
	}
	if err := request.Validate(); err != nil {
		return vmguest.Response{}, err
	}
	credential, err := transport.credential(id)
	if err != nil {
		return vmguest.Response{}, err
	}
	payload, err := json.Marshal(request)
	if err != nil {
		return vmguest.Response{}, err
	}
	credential.mu.Lock()
	defer credential.mu.Unlock()
	if credential.deleted || credential.signer == nil || credential.address != address {
		return vmguest.Response{}, errors.New("vmqual: guest credential identity changed")
	}
	target := address
	if _, _, splitErr := net.SplitHostPort(target); splitErr != nil {
		target = net.JoinHostPort(target, "22")
	}
	sshConfig := &ssh.ClientConfig{
		User: "root",
		Auth: []ssh.AuthMethod{ssh.PublicKeys(credential.signer)},
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			if hostname != target || remote == nil || remote.String() != target {
				return errors.New("vmqual: guest SSH endpoint identity changed")
			}
			return captureHostKeyLocked(credential, key)
		},
	}
	connection, err := dialGuestNamespace(ctx, credential.namespace, target)
	if err != nil {
		return vmguest.Response{}, err
	}
	defer connection.Close()
	if deadline, ok := ctx.Deadline(); ok {
		if err := connection.SetDeadline(deadline); err != nil {
			return vmguest.Response{}, err
		}
	}
	stopCancellation := context.AfterFunc(ctx, func() { _ = connection.Close() })
	defer stopCancellation()
	clientConnection, channels, requests, err := ssh.NewClientConn(connection, target, sshConfig)
	if err != nil {
		if errors.Is(ctx.Err(), context.Canceled) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return vmguest.Response{}, ctx.Err()
		}
		return vmguest.Response{}, err
	}
	client := ssh.NewClient(clientConnection, channels, requests)
	defer client.Close()
	session, err := client.NewSession()
	if err != nil {
		return vmguest.Response{}, err
	}
	defer session.Close()
	stdout := &limitedBuffer{limit: vmguest.MaxRequestBytes}
	stderr := &limitedBuffer{limit: 64 << 10}
	session.Stdin = bytes.NewReader(append(payload, '\n'))
	session.Stdout = stdout
	session.Stderr = stderr
	if err := session.Run(""); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return vmguest.Response{}, ctxErr
		}
		return vmguest.Response{}, fmt.Errorf("vmqual: guest SSH request failed: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	if stdout.truncated || stderr.truncated {
		return vmguest.Response{}, errors.New("vmqual: guest SSH response exceeded its byte limit")
	}
	if stderr.buffer.Len() != 0 {
		return vmguest.Response{}, fmt.Errorf("vmqual: guest SSH wrote unexpected stderr: %s", strings.TrimSpace(stderr.String()))
	}
	var response vmguest.Response
	decoder := json.NewDecoder(bytes.NewReader(stdout.buffer.Bytes()))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&response); err != nil {
		return vmguest.Response{}, fmt.Errorf("vmqual: decode guest response: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return vmguest.Response{}, errors.New("vmqual: guest response contains trailing JSON")
		}
		return vmguest.Response{}, fmt.Errorf("vmqual: decode trailing guest response: %w", err)
	}
	if err := validateGuestResponse(request, response); err != nil {
		return vmguest.Response{}, err
	}
	return response, nil
}

func captureHostKeyLocked(credential *guestCredential, key ssh.PublicKey) error {
	if credential == nil || key == nil {
		return errors.New("vmqual: guest SSH host key is missing")
	}
	encoded := key.Marshal()
	if len(credential.hostKey) == 0 {
		credential.hostKey = append([]byte(nil), encoded...)
		return nil
	}
	if !bytes.Equal(credential.hostKey, encoded) {
		return fmt.Errorf("%w: %s", ErrGuestHostKeyChanged, credential.id)
	}
	return nil
}

func validateGuestResponse(request vmguest.Request, response vmguest.Response) error {
	if response.SchemaVersion != vmguest.SchemaVersion {
		return fmt.Errorf("vmqual: unsupported guest response schema %d", response.SchemaVersion)
	}
	if response.Error != "" {
		return errors.New(response.Error)
	}
	switch request.Operation {
	case vmguest.OperationProbe:
		if response.Probe == nil || response.Command != nil || len(response.Data) != 0 {
			return errors.New("vmqual: guest probe response shape is invalid")
		}
	case vmguest.OperationExecute:
		if response.Command == nil || response.Probe != nil || len(response.Data) != 0 {
			return errors.New("vmqual: guest command response shape is invalid")
		}
	case vmguest.OperationPut, vmguest.OperationDataWrite:
		if response.Command != nil || response.Probe != nil || len(response.Data) != 0 {
			return errors.New("vmqual: guest write response shape is invalid")
		}
	case vmguest.OperationDataRead:
		if response.Command != nil || response.Probe != nil || len(response.Data) > vmguest.MaxPersistentBytes {
			return errors.New("vmqual: guest read response shape is invalid")
		}
	case vmguest.OperationNetwork:
		if response.Command != nil || response.Probe != nil || len(response.Data) == 0 || len(response.Data) > vmguest.MaxNetworkBytes {
			return errors.New("vmqual: guest network-exchange response shape is invalid")
		}
	default:
		return errors.New("vmqual: guest response operation is not admitted")
	}
	return nil
}

type limitedBuffer struct {
	buffer    bytes.Buffer
	limit     int
	truncated bool
}

func (buffer *limitedBuffer) Write(data []byte) (int, error) {
	written := len(data)
	remaining := buffer.limit - buffer.buffer.Len()
	if remaining > 0 {
		stored := min(len(data), remaining)
		_, _ = buffer.buffer.Write(data[:stored])
	}
	if len(data) > max(remaining, 0) {
		buffer.truncated = true
	}
	return written, nil
}

func (buffer *limitedBuffer) String() string { return buffer.buffer.String() }

func (probe *sshGuestProbe) Register(config sandboxvm.Config, seedDigest string) {
	probe.mu.Lock()
	probe.configs[config.ID], probe.seedDigests[config.ID] = config, seedDigest
	probe.mu.Unlock()
}

func (probe *sshGuestProbe) Probe(ctx context.Context, id string) (sandboxvm.Readiness, error) {
	if probe == nil || probe.transport == nil || ctx == nil {
		return sandboxvm.Readiness{}, errors.New("vmqual: guest readiness probe is not configured")
	}
	probe.mu.RLock()
	config, configured := probe.configs[id]
	seedDigest := probe.seedDigests[id]
	probe.mu.RUnlock()
	if !configured || config.ID != id || config.GuestAddress == "" || seedDigest == "" {
		return sandboxvm.Readiness{}, errors.New("vmqual: guest readiness identity is not registered")
	}
	credential, err := probe.transport.credential(id)
	if err != nil {
		return sandboxvm.Readiness{}, err
	}
	credential.mu.Lock()
	service := credential.service
	credential.mu.Unlock()
	response, err := probe.transport.request(ctx, id, config.GuestAddress, vmguest.Request{SchemaVersion: vmguest.SchemaVersion, Operation: vmguest.OperationProbe})
	if err != nil {
		return sandboxvm.Readiness{}, err
	}
	facts := response.Probe
	if facts == nil {
		return sandboxvm.Readiness{}, errors.New("vmqual: guest readiness facts are missing")
	}
	readiness := sandboxvm.Readiness{
		DataDiskMounted: validDataMount(facts.DataMount),
		Network:         validNetworkFact(facts.Network, config.GuestAddress),
	}
	// "degraded" is the expected overall state while the engine unit awaits
	// its control-plane delivered configuration: its auto-restart cycle marks
	// systemd degraded even though systemd itself is fully running, the same
	// tolerance proveGuestRuntime applies. is-system-running exits 1 for
	// degraded, so the guest channel reports that exit as an error string;
	// only that exact exit is accepted alongside the state word. Unit-level
	// health stays proven by the explicit unit gates below, so a genuinely
	// failed service still fails readiness through its own gate.
	systemdState := strings.TrimSpace(string(facts.Systemd.Stdout))
	systemdClean := len(facts.Systemd.Stderr) == 0 && !facts.Systemd.StdoutTruncated && !facts.Systemd.StderrTruncated
	systemdExit := facts.Systemd.Error == "" && facts.Systemd.ExitCode == 0 || facts.Systemd.ExitCode == 1
	readiness.Systemd = systemdClean && systemdExit && (systemdState == "running" || systemdState == "degraded")
	readiness.Systemd = readiness.Systemd && validSystemdExecutable(facts.PID1) && exactCommandOutput(facts.CgroupV2, "cgroup2fs") && exactCommandOutput(facts.Time, "yes") && validSeedDigest(facts.SeedDigest, seedDigest)
	readiness.TSNodeHealthy, err = probe.unitActive(ctx, id, config.GuestAddress, "terrascale-ts-node.service")
	if err != nil {
		return sandboxvm.Readiness{}, err
	}
	readiness.ServiceHealthy, err = probe.unitActive(ctx, id, config.GuestAddress, "terrascale-orchestrator.service")
	if err != nil {
		return sandboxvm.Readiness{}, err
	}
	if service {
		// The engine's launch configuration is control-plane delivered after
		// initial admission. Until the staged file exists and is non-empty the
		// terrabase unit cannot start, so readiness may only require it once
		// its configuration has actually been staged in the guest.
		configured, configErr := probe.guestExitZero(ctx, id, config.GuestAddress, "/usr/bin/test", "-s", "/opt/terrascale/terrabase/current/terrabase.config")
		if configErr != nil {
			return sandboxvm.Readiness{}, configErr
		}
		if configured {
			active, unitErr := probe.unitActive(ctx, id, config.GuestAddress, "terrascale-terrabase.service")
			if unitErr != nil {
				return sandboxvm.Readiness{}, unitErr
			}
			readiness.ServiceHealthy = readiness.ServiceHealthy && active
		}
	}
	fmt.Fprintf(os.Stderr, "PROBEFACT %s systemd=%v(state=%q) data=%v net=%v tsnode=%v service=%v\n", id, readiness.Systemd, systemdState, readiness.DataDiskMounted, readiness.Network, readiness.TSNodeHealthy, readiness.ServiceHealthy)
	return readiness, nil
}

func (probe *sshGuestProbe) guestExitZero(ctx context.Context, id, address, path string, args ...string) (bool, error) {
	response, err := probe.transport.request(ctx, id, address, vmguest.Request{SchemaVersion: vmguest.SchemaVersion, Operation: vmguest.OperationExecute, Path: path, Args: args})
	if err != nil {
		return false, err
	}
	if response.Command == nil {
		return false, errors.New("vmqual: guest command observation is missing")
	}
	// A command that could not run is an observation failure, not evidence
	// about the configuration: fail the probe instead of relaxing readiness.
	if response.Command.Error != "" {
		return false, fmt.Errorf("vmqual: guest command failed: %s", response.Command.Error)
	}
	return response.Command.ExitCode == 0, nil
}

func (probe *sshGuestProbe) unitActive(ctx context.Context, id, address, unit string) (bool, error) {
	response, err := probe.transport.request(ctx, id, address, vmguest.Request{SchemaVersion: vmguest.SchemaVersion, Operation: vmguest.OperationExecute, Path: "/usr/bin/systemctl", Args: []string{"is-active", unit}})
	if err != nil {
		return false, err
	}
	if response.Command == nil {
		return false, errors.New("vmqual: guest service observation is missing")
	}
	return exactCommandOutput(*response.Command, "active"), nil
}

func exactCommandOutput(result vmguest.CommandResult, expected string) bool {
	return result.ExitCode == 0 && result.Error == "" && !result.StdoutTruncated && !result.StderrTruncated && len(result.Stderr) == 0 && strings.TrimSpace(string(result.Stdout)) == expected
}

func validSystemdExecutable(result vmguest.CommandResult) bool {
	if result.ExitCode != 0 || result.Error != "" || result.StdoutTruncated || result.StderrTruncated || len(result.Stderr) != 0 {
		return false
	}
	executable := strings.TrimSpace(string(result.Stdout))
	return filepath.IsAbs(executable) && filepath.Base(executable) == "systemd"
}

func validDataMount(result vmguest.CommandResult) bool {
	if result.ExitCode != 0 || result.Error != "" || result.StdoutTruncated || result.StderrTruncated || len(result.Stderr) != 0 {
		return false
	}
	fields := strings.Fields(string(result.Stdout))
	return len(fields) == 3 && fields[0] == "/dev/vdb" && fields[1] == "ext4" && fields[2] == "/var/lib/terrascale"
}

func validNetworkFact(result vmguest.CommandResult, expectedAddress string) bool {
	if result.ExitCode != 0 || result.Error != "" || result.StdoutTruncated || result.StderrTruncated || len(result.Stderr) != 0 {
		return false
	}
	text := string(result.Stdout)
	return strings.Contains(text, expectedAddress) && strings.Contains(strings.ToLower(text), "routable")
}

func validSeedDigest(result vmguest.CommandResult, expected string) bool {
	if result.ExitCode != 0 || result.Error != "" || result.StdoutTruncated || result.StderrTruncated || len(result.Stderr) != 0 {
		return false
	}
	fields := strings.Fields(string(result.Stdout))
	return len(fields) == 2 && fields[0] == expected && fields[1] == vmguest.DefaultSeedPath
}

func newGuestExecutor(config sandboxvm.Config) sandboxvm.CommandRunner {
	transport := guestTransportFor(config.StateRoot)
	if transport == nil {
		return nil
	}
	if _, err := transport.credential(config.ID); err != nil {
		return nil
	}
	return &sshCommandRunner{id: config.ID, address: config.GuestAddress, readinessTimeout: config.ReadinessTimeout, transport: transport}
}

type GuestCommandError struct {
	ExitCode        int
	RemoteError     string
	StdoutTruncated bool
	StderrTruncated bool
}

// ExitStatus preserves the remote command status for the one qualification
// probe whose non-zero status is meaningful (systemd's degraded state).
func (err *GuestCommandError) ExitStatus() int {
	if err == nil {
		return -1
	}
	return err.ExitCode
}

func (err *GuestCommandError) Error() string {
	if err == nil {
		return ""
	}
	if err.StdoutTruncated || err.StderrTruncated {
		return fmt.Sprintf("vmqual: guest command output was truncated (exit %d)", err.ExitCode)
	}
	return fmt.Sprintf("vmqual: guest command exited %d: %s", err.ExitCode, err.RemoteError)
}

type sshCommandRunner struct {
	id               string
	address          string
	readinessTimeout time.Duration
	transport        *guestTransport
}

func (runner *sshCommandRunner) Run(ctx context.Context, command sandboxvm.Command) error {
	response, err := runner.Request(ctx, vmguest.Request{SchemaVersion: vmguest.SchemaVersion, Operation: vmguest.OperationExecute, Path: command.Path, Args: append([]string(nil), command.Args...)})
	if err != nil {
		return err
	}
	result := response.Command
	if result == nil {
		return errors.New("vmqual: guest command result is missing")
	}
	var outputErrs []error
	if command.Stdout != nil && len(result.Stdout) != 0 {
		_, writeErr := command.Stdout.Write(result.Stdout)
		outputErrs = append(outputErrs, writeErr)
	}
	if command.Stderr != nil && len(result.Stderr) != 0 {
		_, writeErr := command.Stderr.Write(result.Stderr)
		outputErrs = append(outputErrs, writeErr)
	}
	if err := errors.Join(outputErrs...); err != nil {
		return err
	}
	if result.ExitCode != 0 || result.StdoutTruncated || result.StderrTruncated {
		return &GuestCommandError{ExitCode: result.ExitCode, RemoteError: result.Error, StdoutTruncated: result.StdoutTruncated, StderrTruncated: result.StderrTruncated}
	}
	return nil
}

func (runner *sshCommandRunner) Request(ctx context.Context, request vmguest.Request) (vmguest.Response, error) {
	if runner == nil || runner.transport == nil || runner.id == "" || runner.address == "" {
		return vmguest.Response{}, errors.New("vmqual: guest command runner is not configured")
	}
	return runner.transport.request(ctx, runner.id, runner.address, request)
}

func (runner *sshCommandRunner) Bootstrap(ctx context.Context) error {
	timeout := runner.readinessTimeout
	if timeout <= 0 {
		timeout = 2 * time.Minute
	}
	bootstrapContext, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return runner.waitForControl(bootstrapContext)
}

func (runner *sshCommandRunner) waitForControl(ctx context.Context) error {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	var lastErr error
	for {
		_, err := runner.Request(ctx, vmguest.Request{SchemaVersion: vmguest.SchemaVersion, Operation: vmguest.OperationProbe})
		if err == nil {
			return nil
		}
		if errors.Is(err, ErrGuestHostKeyChanged) {
			return err
		}
		lastErr = err
		select {
		case <-ctx.Done():
			return fmt.Errorf("guest control unavailable: %w", errors.Join(ctx.Err(), lastErr))
		case <-ticker.C:
		}
	}
}

func (runner *sshCommandRunner) Destroy() { runner.transport.removeGuest(runner.id) }

func (factory *firecrackerFactory) prepareGuest(ctx context.Context, guest vmqual.Guest, config *sandboxvm.Config) (string, error) {
	if factory == nil || config == nil {
		return "", errors.New("vmqual: guest configuration is missing")
	}
	if factory.config.GuestControlPath == "" || !filepath.IsAbs(factory.config.GuestControlPath) {
		return "", errors.New("vmqual: guest control binary is missing")
	}
	if err := regularImmutableFile(factory.config.GuestControlPath); err != nil {
		return "", fmt.Errorf("vmqual: guest control binary: %w", err)
	}
	control, err := os.ReadFile(factory.config.GuestControlPath)
	if err != nil {
		return "", fmt.Errorf("vmqual: read guest control: %w", err)
	}
	if len(control) == 0 || len(control) > vmguest.MaxTransferBytes {
		return "", errors.New("vmqual: guest control binary exceeds the transfer limit")
	}
	network, err := guestNetwork(factory.config.NetworkPlan, guest)
	if err != nil {
		return "", err
	}
	if factory.services == nil {
		return "", errors.New("vmqual: qualification services are not configured")
	}
	tsNode, seedArtifacts, err := factory.services.Bootstrap(guest)
	if err != nil {
		return "", err
	}
	defer tsNode.ControllerRun.Clear()
	defer tsNode.OrdinaryAuthority.Clear()
	smokeEndpoint, ok := factory.config.NetworkPlan.Endpoint(guest.Region, "smoke")
	if !ok {
		return "", errors.New("vmqual: guest smoke endpoint is absent from the network plan")
	}
	networkExchangeEndpoint := net.JoinHostPort(smokeEndpoint.GuestAddress, fmt.Sprint(smokeEndpoint.GuestPort))
	transport := guestTransportFor(factory.config.StateRoot)
	if transport == nil {
		return "", errors.New("vmqual: guest transport is not registered")
	}
	publicKey, err := transport.addGuest(guest.ID, network.Address, network.NamespacePath, guest.Service)
	if err != nil {
		return "", err
	}
	credentialOwned := true
	defer func() {
		if credentialOwned {
			transport.removeGuest(guest.ID)
		}
	}()
	guestSeed, err := vmimage.BuildGuestChannelSeed(vmimage.GuestSeedSpec{Image: factory.image.Manifest, Hostname: guest.ID, InstanceID: guest.ID, Region: strings.ToLower(string(guest.Region)), DataDiskPath: "/dev/vdb", NetworkExchangeEndpoint: networkExchangeEndpoint, Artifacts: seedArtifacts})
	if err != nil {
		return "", err
	}
	seed, err := vmimage.BuildNoCloudSeed(vmimage.NoCloudSeedSpec{InstanceID: guest.ID, Hostname: guest.ID, Region: strings.ToLower(string(guest.Region)), Address: network.Address, PrefixBits: 24, Gateway: network.Gateway, MACAddress: network.MAC, Nameservers: []string{"1.1.1.1"}, SSHAuthorizedKey: publicKey, DataDevice: "/dev/vdb", DataMount: "/var/lib/terrascale", GuestSeed: guestSeed, GuestControl: control, TSNode: tsNode})
	if err != nil {
		return "", err
	}
	chronyFiles, err := loadQualificationChrony(ctx, factory.image.Manifest.Architecture)
	if err != nil {
		return "", err
	}
	seed.RootFiles = append(seed.RootFiles, chronyFiles...)
	seedDir := filepath.Join(factory.config.StateRoot, guest.ID)
	if err := requireOwnedDirectory(seedDir); err != nil {
		return "", err
	}
	payloadDir := filepath.Join(seedDir, "nocloud")
	if err := os.Mkdir(payloadDir, 0700); err != nil {
		return "", err
	}
	metaPath, networkPath, userDataPath := filepath.Join(payloadDir, "meta-data"), filepath.Join(payloadDir, "network-config"), filepath.Join(payloadDir, "user-data")
	for path, data := range map[string][]byte{metaPath: seed.MetaData, networkPath: seed.NetworkConfig, userDataPath: seed.UserData} {
		if err := writeNewStateFile(path, data); err != nil {
			return "", err
		}
	}
	if err := injectNoCloudRoot(ctx, config.RootDrive, payloadDir, seed); err != nil {
		return "", err
	}
	rootDigest, err := fileSHA256(config.RootDrive)
	if err != nil {
		return "", err
	}
	config.ExpectedRootDriveSHA256 = rootDigest
	config.NetworkNamespace, config.TapName, config.GuestMAC, config.GuestAddress = network.NamespacePath, network.TAP, network.MAC, network.Address
	credentialOwned = false
	return vmimage.GuestChannelSeedDigest(guestSeed), nil
}

type resolvedGuestNetwork struct {
	NamespacePath string
	TAP           string
	MAC           string
	Address       string
	Gateway       string
}

func guestNetwork(plan vmnet.NetworkPlan, guest vmqual.Guest) (resolvedGuestNetwork, error) {
	if err := plan.Validate(); err != nil {
		return resolvedGuestNetwork{}, fmt.Errorf("vmqual: invalid network plan: %w", err)
	}
	for _, region := range plan.Regions {
		if region.Code != guest.Region {
			continue
		}
		for _, candidate := range region.Guests {
			if candidate.ID == guest.ID {
				return resolvedGuestNetwork{NamespacePath: region.NamespacePath, TAP: candidate.TAP, MAC: candidate.MAC, Address: candidate.Address, Gateway: region.Gateway}, nil
			}
		}
		return resolvedGuestNetwork{}, fmt.Errorf("vmqual: guest %s is absent from the %s network plan", guest.ID, guest.Region)
	}
	return resolvedGuestNetwork{}, fmt.Errorf("vmqual: Region %s is absent from the network plan", guest.Region)
}

func writeNewStateFile(path string, data []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	written, writeErr := file.Write(data)
	if writeErr == nil && written != len(data) {
		writeErr = io.ErrShortWrite
	}
	return errors.Join(writeErr, file.Sync(), file.Close())
}

func requireOwnedDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return errors.New("vmqual: guest seed directory is not a private non-symlink directory")
	}
	return nil
}

func loadProductionArtifacts(config vmqual.Config, architecture vmimage.Architecture) ([]guestArtifactInput, ed25519.PublicKey, error) {
	publicKeyData, _, err := readSecureInput(config.ReleasePublicKeyPath, 128, false)
	if err != nil {
		return nil, nil, fmt.Errorf("vmqual: TS_VM_RELEASE_PUBLIC_KEY: %w", err)
	}
	defer zeroBytes(publicKeyData)
	publicKeyText := publicKeyData
	if len(publicKeyText) == ed25519.PublicKeySize*2+1 && publicKeyText[len(publicKeyText)-1] == '\n' {
		publicKeyText = publicKeyText[:len(publicKeyText)-1]
	}
	if len(publicKeyText) != ed25519.PublicKeySize*2 || string(publicKeyText) != strings.ToLower(string(publicKeyText)) {
		return nil, nil, errors.New("vmqual: release public key must be 64 lowercase hexadecimal characters")
	}
	decodedPublicKey, err := hex.DecodeString(string(publicKeyText))
	if err != nil || len(decodedPublicKey) != ed25519.PublicKeySize {
		return nil, nil, errors.New("vmqual: release public key is not Ed25519")
	}
	publicKey := ed25519.PublicKey(decodedPublicKey)
	type componentInput struct {
		component   string
		environment string
		input       vmqual.ProductionArtifactInput
	}
	components := []componentInput{
		{component: "ts-node", environment: "TS_VM_TS_NODE", input: config.TSNode},
		{component: "orchestrator", environment: "TS_VM_ORCHESTRATOR", input: config.Orchestrator},
		{component: "terrabase", environment: "TS_VM_TERRABASE", input: config.TerraBase},
	}
	controlDigest, err := fileSHA256(config.GuestControlPath)
	if err != nil {
		zeroBytes(publicKey)
		return nil, nil, err
	}
	var artifacts []guestArtifactInput
	var infos []os.FileInfo
	seenDigests := map[string]string{controlDigest: "guest-control"}
	for _, component := range components {
		path := component.input.Path
		data, info, err := readSecureInput(path, vmimage.MaxServiceBinaryBytes, true)
		if err != nil {
			zeroArtifactInputs(artifacts)
			zeroBytes(publicKey)
			return nil, nil, fmt.Errorf("vmqual: %s artifact: %w", component.environment, err)
		}
		for index, prior := range infos {
			if os.SameFile(info, prior) {
				zeroBytes(data)
				zeroArtifactInputs(artifacts)
				zeroBytes(publicKey)
				return nil, nil, fmt.Errorf("vmqual: %s artifact aliases %s", component.component, artifacts[index].manifest.Component)
			}
		}
		if err := validateStaticELF(path, architecture); err != nil {
			zeroBytes(data)
			zeroArtifactInputs(artifacts)
			zeroBytes(publicKey)
			return nil, nil, fmt.Errorf("vmqual: %s artifact: %w", component.component, err)
		}
		digestBytes := sha256.Sum256(data)
		digest := hex.EncodeToString(digestBytes[:])
		if prior, exists := seenDigests[digest]; exists {
			zeroBytes(data)
			zeroArtifactInputs(artifacts)
			zeroBytes(publicKey)
			return nil, nil, fmt.Errorf("vmqual: %s artifact duplicates %s bytes", component.component, prior)
		}
		seenDigests[digest] = component.component
		version := component.input.Version
		if len(version) > 63 || !artifactVersionToken.MatchString(version) {
			zeroBytes(data)
			zeroArtifactInputs(artifacts)
			zeroBytes(publicKey)
			return nil, nil, fmt.Errorf("vmqual: %s_VERSION is not a required safe artifact version", component.environment)
		}
		signature, _, err := readSecureInput(component.input.SignaturePath, ed25519.SignatureSize, false)
		if err != nil {
			zeroBytes(data)
			zeroArtifactInputs(artifacts)
			zeroBytes(publicKey)
			return nil, nil, fmt.Errorf("vmqual: %s_SIGNATURE: %w", component.environment, err)
		}
		if len(signature) != ed25519.SignatureSize || !ed25519.Verify(publicKey, data, signature) {
			zeroBytes(data)
			zeroBytes(signature)
			zeroArtifactInputs(artifacts)
			zeroBytes(publicKey)
			return nil, nil, fmt.Errorf("vmqual: %s detached Ed25519 signature is invalid", component.component)
		}
		artifact := vmimage.GuestArtifact{Component: component.component, Architecture: architecture, Version: version, Source: path, SHA256: digest, Size: info.Size(), Mode: uint32(info.Mode().Perm())}
		artifacts, infos = append(artifacts, guestArtifactInput{manifest: artifact, signature: signature, binary: data}), append(infos, info)
	}
	return artifacts, publicKey, nil
}

func readSecureInput(path string, maximum int64, executable bool) ([]byte, os.FileInfo, error) {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path || maximum <= 0 {
		return nil, nil, errors.New("path must be clean and absolute")
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || resolved != path {
		return nil, nil, errors.New("path must not contain symlinks")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, nil, err
	}
	mode := info.Mode()
	if !mode.IsRegular() || mode&os.ModeSymlink != 0 || mode&0o022 != 0 || info.Size() <= 0 || info.Size() > maximum {
		return nil, nil, errors.New("file must be a bounded regular file and not group/world writable")
	}
	if executable && mode.Perm() != 0o755 {
		return nil, nil, errors.New("binary mode must be 0755")
	}
	if !executable && mode.Perm()&0o111 != 0 {
		return nil, nil, errors.New("data file must not be executable")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return nil, nil, errors.New("file identity changed while opening")
	}
	data, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(data)) != info.Size() {
		zeroBytes(data)
		if err == nil {
			err = errors.New("file changed while reading")
		}
		return nil, nil, err
	}
	return data, info, nil
}

func zeroArtifactInputs(artifacts []guestArtifactInput) {
	for index := range artifacts {
		zeroBytes(artifacts[index].signature)
		zeroBytes(artifacts[index].binary)
	}
}

func validateStaticELF(path string, architecture vmimage.Architecture) error {
	file, err := elf.Open(path)
	if err != nil {
		return errors.New("binary is not ELF")
	}
	defer file.Close()
	if file.Class != elf.ELFCLASS64 || file.Data != elf.ELFDATA2LSB || (file.Type != elf.ET_EXEC && file.Type != elf.ET_DYN) {
		return errors.New("binary ELF format is not admitted")
	}
	wantMachine := elf.EM_X86_64
	if architecture == vmimage.ArchitectureARM64 {
		wantMachine = elf.EM_AARCH64
	}
	if file.Machine != wantMachine {
		return errors.New("binary architecture does not match guest")
	}
	for _, program := range file.Progs {
		if program.Type == elf.PT_INTERP {
			return errors.New("binary requires a dynamic interpreter")
		}
	}
	return nil
}
